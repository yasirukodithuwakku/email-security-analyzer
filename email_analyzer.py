import dns.resolver

def check_spf(domain):
    print(f"\n--- Checking SPF Record for: {domain} ---")
    try:
        # Query all TXT records for the given domain
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        
        # Loop through the records to find the SPF string
        for rdata in answers:
            record = rdata.to_text()
            
            # An SPF record always starts with 'v=spf1'
            if "v=spf1" in record:
                print(f"[SECURE] SPF Record found:\n{record}")
                spf_found = True
                break
        
        if not spf_found:
            print("[WARNING] No SPF record found! This domain might be vulnerable to email spoofing.")
            
    except dns.resolver.NoAnswer:
        print("[ERROR] No TXT records found for this domain.")
    except dns.resolver.NXDOMAIN:
        print("[ERROR] Domain does not exist.")
    except Exception as e:
        print(f"[ERROR] Could not fetch records: {e}")
    print("-" * 50)

if __name__ == "__main__":
    print("Welcome to the Email Security Analyzer!")
    # Get the domain from the user
    target_domain = input("Enter the domain to check (e.g., google.com): ")
    check_spf(target_domain)
