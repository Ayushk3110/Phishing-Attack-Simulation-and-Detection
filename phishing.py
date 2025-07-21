import re
import urllib.parse
from email.mime.text import MIMEText # For creating email messages
from email.header import Header # For encoding headers
import smtplib # For sending emails (optional, we'll just print for simulation)

print("--- Phishing Attack Simulation and Detection ---")

# --- Part 1: Phishing Email Generation (Simulation) ---
def generate_phishing_email(sender, recipient, subject, body_html, fake_url):
    """
    Generates a simulated phishing email with HTML content.
    For actual sending, you'd configure an SMTP server.
    """
    msg = MIMEText(body_html, 'html', 'utf-8')
    msg['From'] = f"{sender} <{sender.lower().replace(' ', '')}@example.com>" # Spoofed sender
    msg['To'] = recipient
    msg['Subject'] = Header(subject, 'utf-8')

    print(f"\n--- SIMULATED PHISHING EMAIL ({subject}) ---")
    print(f"From: {msg['From']}")
    print(f"To: {msg['To']}")
    print(f"Subject: {msg['Subject']}")
    print("\n--- Email Body (HTML) ---")
    print(body_html)
    print("------------------------------------------")

    # In a real scenario, you'd use smtplib to send:
    # try:
    #     with smtplib.SMTP('your_smtp_server.com', 587) as server:
    #         server.starttls()
    #         server.login('your_email', 'your_password')
    #         server.send_message(msg)
    #     print("Email sent successfully!")
    # except Exception as e:
    #     print(f"Failed to send email: {e}")

    return msg.as_string() # Return the raw email string for analysis


# --- Part 3: Basic Email Phishing Detection ---
def detect_phishing_email(email_content):
    """
    Analyzes email content for common phishing indicators.
    This is a very basic rule-based detection.
    """
    print("\n--- Analyzing Email for Phishing Indicators ---")
    indicators = []

    # 1. Suspicious Keywords
    suspicious_keywords = [
        "urgent", "verify account", "action required", "security alert",
        "password reset", "unusual activity", "click here", "invoice",
        "payment failed", "suspension", "deactivated"
    ]
    for keyword in suspicious_keywords:
        if re.search(r'\b' + re.escape(keyword) + r'\b', email_content, re.IGNORECASE):
            indicators.append(f"Suspicious keyword detected: '{keyword}'")

    # 2. External Links (check if domain in link differs from sender's implied domain)
    # This is a very simplified check. A real one would parse email headers.
    urls = re.findall(r'href=["\'](http[s]?://[^\s"\']+)["\']', email_content)
    sender_domain_match = re.search(r'@([a-zA-Z0-9.-]+)', email_content)
    sender_domain = sender_domain_match.group(1) if sender_domain_match else ""

    for url in urls:
        parsed_url = urllib.parse.urlparse(url)
        link_domain = parsed_url.netloc
        if link_domain and sender_domain and link_domain not in sender_domain:
            indicators.append(f"External link to different domain detected: {url} (from {sender_domain})")
        
        # Check for IP addresses in URL (often suspicious)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.hostname or ''):
            indicators.append(f"IP address used in URL: {url}")

        # Check for URL shorteners (often used in phishing)
        shortener_domains = ["bit.ly", "tinyurl.com", "goo.gl"]
        if any(domain in parsed_url.netloc for domain in shortener_domains):
            indicators.append(f"URL shortener detected: {url}")

    # 3. Generic/Impersonal Greetings
    impersonal_greetings = ["dear customer", "dear user", "valued client"]
    if any(greet in email_content.lower() for greet in impersonal_greetings):
        indicators.append("Impersonal greeting detected.")

    # 4. Urgency/Threatening Language
    urgency_phrases = ["immediately", "act now", "your account will be suspended", "failure to comply"]
    if any(phrase in email_content.lower() for phrase in urgency_phrases):
        indicators.append("Urgency/threatening language detected.")

    if indicators:
        print("Potential Phishing Detected! Indicators found:")
        for indicator in indicators:
            print(f"- {indicator}")
        return True
    else:
        print("No obvious phishing indicators found in this email (based on simple rules).")
        return False

# --- Part 4: Basic URL Phishing Detection ---
def detect_phishing_url(url):
    """
    Analyzes a URL for common phishing characteristics.
    """
    print(f"\n--- Analyzing URL for Phishing Indicators: {url} ---")
    indicators = []
    parsed_url = urllib.parse.urlparse(url)

    # 1. Mismatched Domain (e.g., login.microsoft.com.malicious.com)
    # This is complex to do perfectly without a whitelist, but we can check for multiple subdomains
    domain_parts = parsed_url.netloc.split('.')
    if len(domain_parts) > 2 and domain_parts[-2] != "com" and domain_parts[-2] != "org" and domain_parts[-2] != "net": # Simple check for unusual TLDs
        indicators.append(f"Unusual number of subdomains or suspicious TLD: {parsed_url.netloc}")

    # 2. Typosquatting (e.g., micorsoft.com instead of microsoft.com)
    # This requires a list of known legitimate domains to compare against.
    # For simulation, we'll just show the concept.
    legit_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com"]
    for legit_domain in legit_domains:
        if parsed_url.netloc != legit_domain and len(parsed_url.netloc) == len(legit_domain):
            # Very basic typosquatting check: same length, different domain
            indicators.append(f"Potential typosquatting: '{parsed_url.netloc}' looks similar to '{legit_domain}'")

    # 3. Use of IP address instead of domain name
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.hostname or ''):
        indicators.append(f"IP address used instead of domain name: {parsed_url.hostname}")

    # 4. Long, encoded, or confusing URLs
    if len(url) > 80 or '%' in url or '?' in url: # Simple length and encoding check
        indicators.append(f"Long or encoded URL (might be obfuscated): {url}")

    # 5. Non-standard ports (e.g., :8080, :8443)
    if parsed_url.port and parsed_url.port not in [80, 443]:
        indicators.append(f"Non-standard port used in URL: {parsed_url.port}")

    if indicators:
        print("Potential Phishing URL Detected! Indicators found:")
        for indicator in indicators:
            print(f"- {indicator}")
        return True
    else:
        print("No obvious phishing indicators found in this URL (based on simple rules).")
        return False

# --- Simulation Execution ---
if __name__ == "__main__":
    print("\n--- Running Phishing Simulation ---")

    # --- Scenario 1: Simulated Phishing Email ---
    print("\nScenario 1: Simulating a Phishing Email and Detection")
    phishing_subject = "Urgent: Your Account Requires Immediate Verification"
    phishing_body = """
    <html>
    <body>
        <p>Dear Valued Customer,</p>
        <p>We detected unusual activity on your account. To prevent suspension, please verify your details immediately.</p>
        <p>Click here to verify: <a href="http://127.0.0.1:5000/login">Verify Account Now</a></p>
        <p>Failure to comply will result in account deactivation.</p>
        <p>Sincerely,<br>The Security Team</p>
    </body>
    </html>
    """
    fake_login_url_for_email = "http://127.0.0.1:5000/login"

    simulated_email_content = generate_phishing_email(
        "Service Support", "victim@example.com", phishing_subject, phishing_body, fake_login_url_for_email
    )
    detect_phishing_email(simulated_email_content)

    # --- Scenario 2: Testing URL Detection ---
    print("\nScenario 2: Testing URL Phishing Detection")
    
    # Legit URL
    legit_url = "https://www.google.com/search?q=python+security"
    detect_phishing_url(legit_url)

    # Typosquatting attempt
    typo_url = "https://www.micorsoft.com/login" # Intentionally misspelled
    detect_phishing_url(typo_url)

    # IP address in URL
    ip_url = "http://192.168.1.1:8080/admin"
    detect_phishing_url(ip_url)

    # Long, encoded URL
    encoded_url = "https://example.com/login?redirect=%68%74%74%70%73%3a%2f%2f%6d%61%6c%69%63%69%6f%75%73%2e%63%6f%6d%2f%63%72%65%64%73"
    detect_phishing_url(encoded_url)

    # URL shortener
    short_url = "http://bit.ly/fake-link"
    detect_phishing_url(short_url)

    # Legitimate-looking but slightly off domain
    subdomain_trick = "https://login.microsoft.com.updates.net/verify"
    detect_phishing_url(subdomain_trick)

    print("\n--- Phishing Simulation and Detection Complete ---")
