import dns.resolver

def check_spf(domain):
    print(f"\n--- Checking SPF Record for: {domain} ---")
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for rdata in answers:
            record = rdata.to_text()
            if "v=spf1" in record:
                print(f"[SECURE] SPF Record found:\n{record}")
                spf_found = True
                break
        
        if not spf_found:
            print("[WARNING] No SPF record found! This domain might be vulnerable to email spoofing.")
            
    except Exception as e:
        print(f"[ERROR] Could not fetch SPF records: {e}")
    print("-" * 50)

def check_dmarc(domain):
    print(f"\n--- Checking DMARC Record for: {domain} ---")
    # DMARC records are stored at _dmarc.domain.com
    dmarc_domain = f"_dmarc.{domain}"
    
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = False
        for rdata in answers:
            record = rdata.to_text()
            # A DMARC record always starts with 'v=DMARC1'
            if "v=DMARC1" in record:
                print(f"[SECURE] DMARC Record found:\n{record}")
                dmarc_found = True
                break
                
        if not dmarc_found:
            print("[WARNING] No DMARC record found! Domain lacks strict spoofing protection policies.")
            
    except dns.resolver.NXDOMAIN:
        print("[WARNING] No DMARC record found! (Domain does not exist)")
    except Exception as e:
        print(f"[ERROR] Could not fetch DMARC records: {e}")
    print("-" * 50)

if __name__ == "__main__":
    print("Welcome to the Email Security Analyzer!")
    target_domain = input("Enter the domain to check (e.g., google.com): ")
    
    check_spf(target_domain)
    check_dmarc(target_domain)
