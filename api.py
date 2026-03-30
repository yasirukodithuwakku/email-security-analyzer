from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import dns.resolver

app = FastAPI()

# React එකෙන් එන Request භාරගන්න CORS අවසරය දීම
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# React එකෙන් කතා කරන Endpoint එක
@app.get("/api/analyze/{domain}")
async def analyze_domain(domain: str):
    return {
        "domain": domain,
        "spf": check_spf(domain),
        "dmarc": check_dmarc(domain),
        "dkim": check_dkim(domain)
    }
