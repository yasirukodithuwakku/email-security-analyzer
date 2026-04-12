import os
import csv
import io
import requests
import dns.resolver
import google.generativeai as genai
import email
import re
from dotenv import load_dotenv
from pydantic import BaseModel
from fastapi import FastAPI, File, UploadFile, Request, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone


# --- Auth Packages ---
from passlib.context import CryptContext
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

# --- Database ---
from database import SessionLocal, ScanRecord, User

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY")

# --- Security Config ---
SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

app = FastAPI()

# --- Rate Limiter Setup ---
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Gemini AI Setup ---
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-flash')

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_ai_remediation(domain, spf_status, dmarc_status):
    if not GEMINI_API_KEY:
        return "Gemini API Key missing. Please add it to your .env file."
    prompt = f"I am analyzing the domain: {domain}. SPF is: {spf_status}. DMARC is: {dmarc_status}. Provide a short, 2-sentence actionable recommendation."
    try:
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI Generation failed. Error: {str(e)}"

def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            malicious = response.json()['data']['attributes']['last_analysis_stats'].get('malicious', 0)
            if malicious > 0:
                return {"status": "Vulnerable", "message": f"DANGER: Flagged as malicious by {malicious} vendors!"}
            return {"status": "Secure", "message": "Clean domain."}
        return {"status": "Warning", "message": "Domain not found in VirusTotal."}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            if "v=spf1" in rdata.to_text():
                return {"status": "Secure", "record": rdata.to_text()}
        return {"status": "Warning", "message": "No SPF record found!"}
    except:
        return {"status": "Error", "message": "Error checking SPF."}

def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            if "v=DMARC1" in rdata.to_text():
                return {"status": "Secure", "record": rdata.to_text()}
        return {"status": "Warning", "message": "No DMARC record found!"}
    except:
        return {"status": "Error", "message": "Error checking DMARC."}

def check_dkim(domain):
    common_selectors = ['default', 'google', 'mail', 's1', 's2', 'core']
    for selector in common_selectors:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
            for rdata in answers:
                if "v=DKIM1" in rdata.to_text() or "p=" in rdata.to_text():
                    return {"status": "Secure", "selector": selector, "record": rdata.to_text()}
        except:
            continue
    return {"status": "Info", "message": "No standard DKIM records found."}




class UserCreate(BaseModel):
    username: str
    password: str

@app.post("/api/signup")
async def signup(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    if len(user.password) < 8 or not any(char.isdigit() for char in user.password) or not any(char.isupper() for char in user.password):
        raise HTTPException(
            status_code=400, 
            detail="Weak Password! Must be at least 8 characters, contain 1 uppercase letter and 1 number."
        )

    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, password_hash=hashed_password)
    db.add(new_user)
    db.commit()
    return {"status": "Success", "message": "User account created successfully!"}


@app.post("/api/login")
@limiter.limit("5/minute") 
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer", "username": user.username}



async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user



@app.get("/api/analyze/{domain}")
@limiter.limit("5/minute")
async def analyze_domain(domain: str, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    virustotal = check_virustotal(domain)
    ai_remediation = get_ai_remediation(domain, spf["status"], dmarc["status"])
    
    overall_status = "Secure" if spf["status"] == "Secure" and dmarc["status"] == "Secure" and virustotal["status"] == "Secure" else "Warning"
    if virustotal["status"] == "Vulnerable":
        overall_status = "Vulnerable"
        
    
    db.add(ScanRecord(target=domain, scan_type="Single", risk_status=overall_status, user_id=current_user.id))
    db.commit()

    return {"domain": domain, "spf": spf, "dmarc": dmarc, "dkim": dkim, "virustotal": virustotal, "ai_remediation": ai_remediation}

@app.post("/api/bulk-analyze/")
@limiter.limit("2/minute")
async def analyze_bulk(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    content = await file.read()
    csv_reader = csv.reader(io.StringIO(content.decode('utf-8')))
    bulk_results = []
    for row in csv_reader:
        if not row or not row[0].strip(): continue
        domain = row[0].strip()
        spf = check_spf(domain)
        dmarc = check_dmarc(domain)
        virustotal = check_virustotal(domain)
        status = "Secure" if spf["status"] == "Secure" and dmarc["status"] == "Secure" else "Warning"
        bulk_results.append({"domain": domain, "spf_status": spf["status"], "dmarc_status": dmarc["status"], "virustotal_status": virustotal["status"]})
        
        
        db.add(ScanRecord(target=domain, scan_type="Bulk", risk_status=status, user_id=current_user.id))
    db.commit()
    return {"results": bulk_results}

class URLRequest(BaseModel):
    url: str

@app.post("/api/check-phishing/")
@limiter.limit("10/minute")
async def check_phishing(request_data: URLRequest, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    url = request_data.url
    if not SAFE_BROWSING_API_KEY: return {"status": "Error", "message": "API Key missing."}
    payload = {"client": {"clientId": "analyzer", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    try:
        response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}", json=payload).json()
        if "matches" in response:
            db.add(ScanRecord(target=url, scan_type="Phishing", risk_status="Vulnerable", user_id=current_user.id))
            db.commit()
            return {"status": "Vulnerable", "message": "Warning! Dangerous URL.", "details": response["matches"]}
            
        db.add(ScanRecord(target=url, scan_type="Phishing", risk_status="Secure", user_id=current_user.id))
        db.commit()
        return {"status": "Secure", "message": "Safe URL."}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

@app.get("/api/scan-history/")
async def get_scan_history(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        
        return db.query(ScanRecord).filter(ScanRecord.user_id == current_user.id).order_by(ScanRecord.timestamp.desc()).limit(100).all()
    except:
        return {"status": "Error", "message": "Failed to fetch scan history."}


class HeaderRequest(BaseModel):
    headers: str

@app.post("/api/analyze-header/")
@limiter.limit("10/minute")
async def analyze_email_header(request_data: HeaderRequest, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    raw_headers = request_data.headers
    
    try:
        
        msg = email.message_from_string(raw_headers)

        subject = msg.get('Subject', 'Unknown')
        from_email = msg.get('From', 'Unknown')
        to_email = msg.get('To', 'Unknown')
        date = msg.get('Date', 'Unknown')
        message_id = msg.get('Message-ID', 'Unknown')
        return_path = msg.get('Return-Path', 'Unknown')

        # 2. ගමන් කරපු මාර්ගය (Hops / Received Headers)
        received_headers = msg.get_all('Received') or []
        hops = []
        for i, hop in enumerate(received_headers):
            # IP Address එකක් තියෙනවද කියලා හොයනවා (Regex)
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', hop)
            ip = ip_match.group(0) if ip_match else "Not Found"
            hops.append({
                "hop_number": i + 1, 
                "ip": ip,
                "details": hop.strip()[:150] + "..." # දිග වැඩි නිසා අකුරු 150ක් විතරක් ගමු
            })

        # 3. Authentication ප්‍රතිඵල (SPF, DKIM, DMARC)
        auth_results = msg.get('Authentication-Results', 'No Authentication Info Found')

        results = {
            "basic_info": {
                "Subject": subject,
                "From": from_email,
                "To": to_email,
                "Date": date,
                "Message-ID": message_id,
                "Return_Path": return_path
            },
            "hops": hops,
            "authentication": auth_results
        }

        
        db.add(ScanRecord(target=f"Email: {subject[:30]}", scan_type="Forensic", risk_status="Info", user_id=current_user.id))
        db.commit()

        return {"status": "Success", "data": results}

    except Exception as e:
        return {"status": "Error", "message": f"Failed to parse header. Make sure it is a valid raw email header. Error: {str(e)}"}