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
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = False
        for rdata in answers:
            record = rdata.to_text()
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

def check_dkim(domain):
    print(f"\n--- Checking DKIM Record for: {domain} ---")
    # We will test a few common selectors since we don't have the exact email header
    common_selectors = ['default', 'google', 'mail', 's1', 's2', 'core']
    dkim_found = False

    for selector in common_selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                record = rdata.to_text()
                if "v=DKIM1" or "p=" in record: # DKIM records have either v=DKIM1 or just the public key (p=)
                    print(f"[SECURE] DKIM Record found (Selector: {selector}):\n{record}")
                    dkim_found = True
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue # Try the next selector if this one doesn't exist
        except Exception:
            pass # Ignore other errors and keep going
            
        if dkim_found:
            break # Stop the loop if we found the record

    if not dkim_found:
        print("[INFO] No standard DKIM records found.")
        print("       (Note: DKIM uses custom 'selectors'. The domain might still have DKIM under a unique selector name).")
    print("-" * 50)

if __name__ == "__main__":
    print("Welcome to the Email Security Analyzer!")
    target_domain = input("Enter the domain to check (e.g., google.com): ")
    
    check_spf(target_domain)
    check_dmarc(target_domain)
    check_dkim(target_domain) # New DKIM function called here
