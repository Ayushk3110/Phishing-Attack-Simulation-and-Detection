# Phishing-Attack-Simulation-and-Detection# Phishing Attack Simulation and Detection

This repository contains a Python script (`phishing.py`) that simulates phishing attacks and demonstrates basic detection mechanisms for both phishing emails and URLs. It's intended for educational purposes to understand how phishing attempts can be crafted and how simple rule-based systems can identify common indicators of such attacks.

## Features

* **Phishing Email Generation**: Simulates the creation of a phishing email with spoofed sender, a deceptive subject, and HTML body content containing a malicious link.
* **Basic Email Phishing Detection**: Analyzes email content for common phishing indicators, including:
    * Suspicious keywords (e.g., "urgent", "verify account", "security alert").
    * External links pointing to domains different from the sender's implied domain.
    * Use of IP addresses in URLs.
    * Detection of URL shorteners.
    * Impersonal greetings (e.g., "Dear Customer").
    * Urgency or threatening language.
* **Basic URL Phishing Detection**: Analyzes URLs for characteristics often found in phishing attempts, such as:
    * Mismatched or unusual number of subdomains.
    * Potential typosquatting (very basic check against a predefined list).
    * Use of IP addresses instead of domain names.
    * Long, encoded, or confusing URLs.
    * Non-standard ports in URLs.

## How to Run

### Prerequisites

* Python 3.x installed on your system.

### Running the Script

1.  **Save the script**: Save the provided Python code as `phishing.py`.
2.  **Open a terminal or command prompt**.
3.  **Navigate to the directory** where you saved `phishing.py`.
4.  **Run the script** using the Python interpreter:

    ```bash
    python phishing.py
    ```

## Script Overview

The script is structured into several parts:

* **`generate_phishing_email(sender, recipient, subject, body_html, fake_url)`**: This function creates a `MIMEText` object representing a simulated phishing email. It prints the email's details and HTML body to the console.
* **`detect_phishing_email(email_content)`**: This function takes the raw email content as a string and applies a set of rules to identify potential phishing indicators. It prints any detected indicators.
* **`detect_phishing_url(url)`**: This function analyzes a given URL for common phishing characteristics and prints any suspicious findings.
* **Simulation Execution (`if __name__ == "__main__":`)**: This block orchestrates two main scenarios:
    * **Scenario 1: Simulated Phishing Email and Detection**: Generates a sample phishing email and then passes its content to the email detection function.
    * **Scenario 2: Testing URL Phishing Detection**: Tests the URL detection function against a series of legitimate-looking and clearly malicious URLs.

## Limitations

* **Basic Rule-Based Detection**: The detection mechanisms are simple and rule-based. Real-world phishing detection systems are far more sophisticated, often employing machine learning, reputation services, and advanced heuristics.
* **No Actual Email Sending**: For safety and simulation purposes, the script does *not* actually send emails. It only prints the simulated email content.
* **Limited Typosquatting Check**: The typosquatting detection is very basic and only checks for domains of similar length against a small, predefined list of legitimate domains.
* **No Header Analysis**: The email detection primarily focuses on the body content and a simplified sender domain extraction, not a full analysis of email headers which can reveal more sophisticated spoofing.

This script serves as a foundational example to understand the principles behind phishing and its detection.
