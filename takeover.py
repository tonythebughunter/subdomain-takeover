import requests
import dns.resolver
import sys

# Color codes
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
RESET = "\033[0m"

SERVICE_SIGNATURES = {
    "vercel": {
        "cname_keywords": ["vercel.app", "vercel-dns.com", "vercel.com"],
        "error_signatures": ["deployment_not_found", "not_found"]
    },
    "heroku": {
        "cname_keywords": ["herokudns.com"],
        "error_signatures": ["no such app", "heroku"]
    },
    "netlify": {
        "cname_keywords": ["netlify.app", "netlifyglobalcdn.com"],
        "error_signatures": ["page not found", "domain not found"]
    },
    "github": {
        "cname_keywords": ["github.io", "githubusercontent.com"],
        "error_signatures": ["there isn't a github pages site here"]
    }
}

def get_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            return str(rdata.target).strip('.').lower()
    except Exception:
        return None

def check_service_takeover(domain, service, signatures):
    try:
        url = f"https://{domain}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        body = response.text.lower()

        for sig in signatures["error_signatures"]:
            if sig in body:
                print(f"{G}[+] POTENTIALLY VULNERABLE: {domain} → {service.upper()}{RESET}")
                return True

    except requests.exceptions.RequestException as e:
        print(f"{R}[!] Error accessing {domain}: {e}{RESET}")
    return False

def main(wordlist):
    with open(wordlist, 'r') as file:
        domains = file.read().splitlines()

    for domain in domains:
        print(f"\n{B}[*] Checking: {domain}{RESET}")
        cname = get_cname(domain)
        if not cname:
            print(f"{R}    [x] No CNAME found.{RESET}")
            continue

        print(f"{Y}    [i] CNAME → {cname}{RESET}")

        found = False
        for service, data in SERVICE_SIGNATURES.items():
            if any(keyword in cname for keyword in data["cname_keywords"]):
                print(f"{Y}    [i] Matched provider: {service}{RESET}")
                if check_service_takeover(domain, service, data):
                    found = True
                    break

        if not found:
            print(f"{R}    [-] No known takeover patterns detected.{RESET}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{R}Usage: python3 takeover_scanner.py domains.txt{RESET}")
        sys.exit(1)
    main(sys.argv[1])
