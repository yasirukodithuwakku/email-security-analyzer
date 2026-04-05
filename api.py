from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import dns.resolver
import requests

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


VT_API_KEY = "70239e556a7102acd316d0ec46b2b77feb876b86dea02ed5a3425eed06de170c"

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

@app.get("/api/analyze/{domain}")
async def analyze_domain(domain: str):
    return {
        "domain": domain,
        "spf": check_spf(domain),
        "dmarc": check_dmarc(domain),
        "dkim": check_dkim(domain),
        "virustotal": check_virustotal(domain) 
    }
