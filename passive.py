import socket
import whois
import dns.resolver
import requests
import json

# =========================
# 🧠 Helper Functions
# =========================

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[+] IP Address: {ip}")
        return ip
    except Exception as e:
        print(f"[-] Could not get IP: {e}")
        return None

def whois_info(domain):
    try:
        w = whois.whois(domain)
        print(f"\n[+] WHOIS Info:")
        print(f"  - Registrar: {w.registrar}")
        print(f"  - Creation Date: {w.creation_date}")
        print(f"  - Expiration Date: {w.expiration_date}")
        print(f"  - Name Servers: {w.name_servers}")
        print(f"  - Emails: {w.emails}")
    except Exception as e:
        print(f"[-] WHOIS failed: {e}")

def dns_lookup(domain):
    print(f"\n[+] DNS Records:")
    for record_type in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                print(f"  - {record_type}: {rdata.to_text()}")
        except:
            print(f"  - {record_type}: Not found")

def http_headers(domain):
    try:
        url = f"http://{domain}"
        response = requests.get(url, timeout=5)
        print(f"\n[+] HTTP Headers:")
        for header, value in response.headers.items():
            print(f"  - {header}: {value}")
    except Exception as e:
        print(f"[-] HTTP header fetch failed: {e}")

def find_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url)
        data = json.loads(response.text)

        subdomains = set()
        for entry in data:
            name = entry['name_value']
            for sub in name.split('\n'):
                if domain in sub:
                    subdomains.add(sub.strip())

        print(f"\n[+] Subdomains:")
        for sub in sorted(subdomains):
            print(f"  - {sub}")
    except Exception as e:
        print(f"[-] Subdomain lookup failed: {e}")

def reverse_ip(ip):
    try:
        print(f"\n[+] Reverse IP Lookup:")
        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
        response = requests.get(url)

        # Check for rate limit
        if "API count exceeded" in response.text:
            print("  - Rate limit hit. Try again tomorrow or upgrade membership.")
            return
        elif "error" in response.text.lower():
            print("  - No results found.")
            return

        domains = response.text.splitlines()
        for d in domains:
            print(f"  - {d}")
    except Exception as e:
        print(f"[-] Reverse IP failed: {e}")

def geoip_lookup(ip):
    try:
        print(f"\n[+] IP Geolocation:")
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        data = response.json()
        for key in ['country', 'regionName', 'city', 'org', 'as', 'isp']:
            print(f"  - {key.capitalize()}: {data.get(key)}")
    except Exception as e:
        print(f"[-] Geolocation failed: {e}")

def save_output(domain, output):
    filename = f"{domain}_recon.txt"
    with open(filename, 'w') as f:
        f.write(output)
    print(f"\n[+] Output saved to {filename}")

# =========================
# 🚀 Main Function
# =========================

def main():
    print("=== Passive Recon Tool v2 ===")
    domain = input("Enter target domain (e.g. example.com): ").strip()

    output = []
    ip = get_ip(domain)
    output.append(f"IP Address: {ip}\n")

    # Redirect print to capture output
    import io
    import sys
    old_stdout = sys.stdout
    result = io.StringIO()
    sys.stdout = result

    whois_info(domain)
    dns_lookup(domain)
    http_headers(domain)
    find_subdomains(domain)

    if ip:
        reverse_ip(ip)
        geoip_lookup(ip)

    # Restore stdout and save
    sys.stdout = old_stdout
    final_output = result.getvalue()
    print(final_output)
    save_output(domain, f"IP Address: {ip}\n{final_output}")

if __name__ == "__main__":
    main()
