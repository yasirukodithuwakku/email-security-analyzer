from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import dns.resolver
import requests
import google.generativeai as genai
import os
from dotenv import load_dotenv
import csv
import io

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Gemini AI Setup
if GEMINI_API_KEY != "AIzaSyACPYmyLy-Xvhf3t2ZDKv-KXQPC2CNfnKw":
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-1.5-flash')

def get_ai_remediation(domain, spf_status, dmarc_status):
    if GEMINI_API_KEY == "YOUR_GEMINI_KEY":
        return "Gemini API Key missing. Add the key to enable AI Auto-Remediation."
    
    prompt = f"""
    You are a Cybersecurity Expert. I am analyzing the domain: {domain}.
    The SPF status is: {spf_status}. 
    The DMARC status is: {dmarc_status}.
    If they are missing or have warnings, provide a short, 2-sentence actionable recommendation or the exact DNS record to fix it. If they are secure, just say "DNS records are properly configured. No remediation needed."
    """
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
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return {"status": "Error", "message": f"DANGER: Flagged as malicious by {malicious} security vendors!"}
            else:
                return {"status": "Secure", "message": "Clean domain. No malicious activity found."}
        return {"status": "Warning", "message": "Domain not found in VirusTotal database."}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            record = rdata.to_text()
            if "v=spf1" in record:
                return {"status": "Secure", "record": record}
        return {"status": "Warning", "message": "No SPF record found!"}
    except Exception as e:
        return {"status": "Error", "message": str(e)}

def check_dmarc(domain):
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            record = rdata.to_text()
            if "v=DMARC1" in record:
                return {"status": "Secure", "record": record}
        return {"status": "Warning", "message": "No DMARC record found!"}
    except Exception as e:
        return {"status": "Error", "message": "Domain does not exist or no record."}

def check_dkim(domain):
    common_selectors = ['default', 'google', 'mail', 's1', 's2', 'core']
    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                record = rdata.to_text()
                if "v=DKIM1" in record or "p=" in record:
                    return {"status": "Secure", "selector": selector, "record": record}
        except:
            continue
    return {"status": "Info", "message": "No standard DKIM records found."}

@app.post("/api/bulk-analyze/")
async def analyze_bulk(file: UploadFile = File(...)):
    
    content = await file.read()
    decoded_content = content.decode('utf-8')
    csv_reader = csv.reader(io.StringIO(decoded_content))
    
    bulk_results = []
    
    for row in csv_reader:
        if not row:
            continue
        domain = row[0].strip()
        if not domain:
            continue
            
        
        spf = check_spf(domain)
        dmarc = check_dmarc(domain)
        virustotal = check_virustotal(domain)
        
        bulk_results.append({
            "domain": domain,
            "spf_status": spf["status"],
            "dmarc_status": dmarc["status"],
            "virustotal_status": virustotal["status"]
        })
        
    return {"results": bulk_results}

