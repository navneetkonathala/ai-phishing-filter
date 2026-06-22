"""
=============================================================
  AI-Powered Phishing Filter
  Author: [Navneet]
  Description: Scans emails or text files for phishing/spam
               keywords and flags suspicious content.
=============================================================
"""

import os          # For working with files and folders
import re          # For pattern matching (regular expressions)
import sys         # For reading command-line arguments
import json        # For saving scan results in JSON format
import datetime    # For timestamps in the report

# ─────────────────────────────────────────────────────────────
# PHISHING KEYWORD DATABASE
# These are common words/phrases found in phishing emails.
# The higher the weight, the more suspicious the keyword is.
# ─────────────────────────────────────────────────────────────
PHISHING_KEYWORDS = {
    # Urgency tactics — scammers try to make you act fast
    "urgent": 2,
    "immediately": 2,
    "act now": 3,
    "limited time": 2,
    "expires soon": 2,
    "your account will be closed": 4,
    "account suspended": 4,
    "verify your account": 3,
    "confirm your identity": 3,
    "update your information": 2,
    "reactivate your account": 3,

    # Financial bait — fake prizes or money offers
    "you have won": 4,
    "winner": 2,
    "prize": 2,
    "claim your reward": 3,
    "free gift": 2,
    "cash prize": 3,
    "lottery": 3,
    "inheritance": 3,
    "transfer funds": 3,
    "wire transfer": 3,
    "western union": 3,

    # Credential stealing — trying to get your password/info
    "click here": 2,
    "log in now": 2,
    "sign in": 1,
    "enter your password": 4,
    "ssn": 4,
    "social security": 4,
    "credit card number": 4,
    "bank account": 3,
    "billing information": 3,
    "payment details": 3,
    "verify your payment": 3,

    # Threats — scaring the victim
    "legal action": 3,
    "lawsuit": 3,
    "arrest warrant": 4,
    "irs": 2,
    "tax refund": 3,
    "suspended": 2,
    "blocked": 2,
    "unauthorized access": 3,
    "security alert": 2,
    "suspicious activity": 2,

    # Suspicious links/attachments
    "download attachment": 3,
    "open the attachment": 3,
    "click the link": 2,
    "visit our website": 1,
    "http://": 1,   # HTTP (not secure) links are a red flag
    "bit.ly": 3,    # Shortened URLs are often used in phishing
    "tinyurl": 3,
    ".exe": 4,      # Executable files in emails are dangerous
    ".zip": 2,

    # Impersonation
    "dear customer": 2,
    "dear user": 2,
    "dear account holder": 3,
    "paypal": 1,
    "amazon": 1,
    "apple": 1,
    "microsoft": 1,
    "google": 1,
    "your bank": 2,
    "tech support": 2,

    # Too-good-to-be-true offers
    "100% free": 2,
    "no cost": 1,
    "guaranteed": 2,
    "risk free": 2,
    "make money": 2,
    "earn money": 2,
    "work from home": 1,
    "million dollars": 3,
}

# ─────────────────────────────────────────────────────────────
# SUSPICIOUS URL PATTERN
# Detects links that look like they might be malicious.
# Regular expressions (regex) are used to find patterns in text.
# ─────────────────────────────────────────────────────────────
SUSPICIOUS_URL_PATTERN = re.compile(
    r'(https?://[^\s]+)',  # Find any URL starting with http:// or https://
    re.IGNORECASE           # Ignore uppercase/lowercase differences
)

# Domains commonly impersonated in phishing attacks
SUSPICIOUS_DOMAINS = [
    "paypa1.com",     # Notice the "1" instead of "l" — a common trick
    "amaz0n.com",
    "g00gle.com",
    "micros0ft.com",
    "app1e.com",
    "faceb00k.com",
    "netfl1x.com",
    "secure-login",
    "account-verify",
    "update-billing",
]


# ─────────────────────────────────────────────────────────────
# FUNCTION: load_text
# PURPOSE: Reads text from a file or accepts direct text input
# ─────────────────────────────────────────────────────────────
def load_text(source: str) -> str:
    """
    Load text either from a file path or treat the input as raw text.

    Args:
        source (str): A file path OR raw email/text content

    Returns:
        str: The text content to be scanned
    """
    # Check if the input is an actual file that exists on disk
    if os.path.isfile(source):
        # Open and read the file safely using UTF-8 encoding
        with open(source, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        print(f"[INFO] Loaded file: {source} ({len(content)} characters)")
        return content
    else:
        # If it's not a file, treat it as direct text input
        print("[INFO] Scanning provided text directly.")
        return source


# ─────────────────────────────────────────────────────────────
# FUNCTION: scan_keywords
# PURPOSE: Finds phishing keywords in the text and scores them
# ─────────────────────────────────────────────────────────────
def scan_keywords(text: str) -> dict:
    """
    Search the text for all known phishing keywords.

    Args:
        text (str): The email/text content to scan

    Returns:
        dict: A dictionary with found keywords and their risk scores
    """
    # Convert text to lowercase so matching isn't case-sensitive
    # Example: "URGENT" and "urgent" are treated the same
    text_lower = text.lower()

    found_keywords = {}  # We'll store matched keywords here

    # Loop through every keyword in our phishing database
    for keyword, weight in PHISHING_KEYWORDS.items():
        # Check if this keyword appears in the text
        if keyword.lower() in text_lower:
            # Count how many times it appears
            count = text_lower.count(keyword.lower())
            # Save it: keyword → (how many times, risk weight)
            found_keywords[keyword] = {
                "count": count,
                "weight": weight,
                "total_score": count * weight  # More occurrences = higher risk
            }

    return found_keywords


# ─────────────────────────────────────────────────────────────
# FUNCTION: scan_urls
# PURPOSE: Finds URLs in the text and flags suspicious ones
# ─────────────────────────────────────────────────────────────
def scan_urls(text: str) -> list:
    """
    Extract and analyze all URLs found in the text.

    Args:
        text (str): The email/text content to scan

    Returns:
        list: A list of dictionaries with URL info and risk level
    """
    # Use regex to find all URLs in the text
    urls = SUSPICIOUS_URL_PATTERN.findall(text)

    analyzed_urls = []

    for url in urls:
        url_lower = url.lower()
        is_suspicious = False
        reasons = []

        # Check 1: Is it using HTTP instead of HTTPS? (Not encrypted)
        if url_lower.startswith("http://"):
            is_suspicious = True
            reasons.append("Uses insecure HTTP (not HTTPS)")

        # Check 2: Does the URL contain a known suspicious domain?
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url_lower:
                is_suspicious = True
                reasons.append(f"Contains suspicious domain pattern: '{domain}'")

        # Check 3: Is it a URL shortener? (Hides the real destination)
        if any(short in url_lower for short in ["bit.ly", "tinyurl", "t.co", "goo.gl", "ow.ly"]):
            is_suspicious = True
            reasons.append("Uses URL shortener (hides real destination)")

        # Check 4: Excessively long URL (often used to confuse users)
        if len(url) > 100:
            is_suspicious = True
            reasons.append("Unusually long URL")

        # Check 5: URL contains an IP address instead of a domain name
        ip_pattern = re.compile(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.match(url):
            is_suspicious = True
            reasons.append("URL uses IP address instead of domain name")

        analyzed_urls.append({
            "url": url,
            "is_suspicious": is_suspicious,
            "reasons": reasons
        })

    return analyzed_urls


# ─────────────────────────────────────────────────────────────
# FUNCTION: calculate_risk_score
# PURPOSE: Adds up all scores to get a final risk level
# ─────────────────────────────────────────────────────────────
def calculate_risk_score(found_keywords: dict, suspicious_urls: list) -> tuple:
    """
    Calculate the overall phishing risk score.

    Args:
        found_keywords (dict): Keywords found with their scores
        suspicious_urls (list): List of analyzed URLs

    Returns:
        tuple: (total_score, risk_level_string, risk_color_emoji)
    """
    # Add up all keyword scores
    keyword_score = sum(item["total_score"] for item in found_keywords.values())

    # Add points for each suspicious URL found
    url_score = sum(5 for url in suspicious_urls if url["is_suspicious"])

    # Total combined risk score
    total_score = keyword_score + url_score

    # Determine the risk level based on score thresholds
    if total_score == 0:
        return total_score, "SAFE", "✅"
    elif total_score <= 5:
        return total_score, "LOW RISK", "🟡"
    elif total_score <= 15:
        return total_score, "MEDIUM RISK", "🟠"
    elif total_score <= 30:
        return total_score, "HIGH RISK", "🔴"
    else:
        return total_score, "CRITICAL - LIKELY PHISHING", "🚨"


# ─────────────────────────────────────────────────────────────
# FUNCTION: generate_report
# PURPOSE: Creates a readable scan report and saves it
# ─────────────────────────────────────────────────────────────
def generate_report(text: str, found_keywords: dict, suspicious_urls: list,
                    total_score: int, risk_level: str, emoji: str,
                    source_name: str = "input") -> dict:
    """
    Generate a human-readable scan report.

    Args:
        text: Original text that was scanned
        found_keywords: Keywords detected
        suspicious_urls: URLs analyzed
        total_score: Final risk score
        risk_level: Text description of risk
        emoji: Visual indicator emoji
        source_name: Name of the file or 'input'

    Returns:
        dict: Complete report as a dictionary (also saved to JSON)
    """
    # Get current date and time for the report timestamp
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build the report dictionary
    report = {
        "scan_info": {
            "timestamp": timestamp,
            "source": source_name,
            "text_length": len(text),
            "total_risk_score": total_score,
            "risk_level": risk_level
        },
        "keywords_found": found_keywords,
        "urls_analyzed": suspicious_urls,
        "summary": {
            "total_keywords_detected": len(found_keywords),
            "total_urls_found": len(suspicious_urls),
            "suspicious_urls_count": sum(1 for u in suspicious_urls if u["is_suspicious"]),
            "verdict": f"{emoji} {risk_level}"
        }
    }

    return report


# ─────────────────────────────────────────────────────────────
# FUNCTION: print_report
# PURPOSE: Displays the report nicely in the terminal
# ─────────────────────────────────────────────────────────────
def print_report(report: dict) -> None:
    """
    Print the scan report to the terminal in a readable format.

    Args:
        report (dict): The report generated by generate_report()
    """
    print("\n" + "="*60)
    print("         🔍 PHISHING FILTER SCAN REPORT")
    print("="*60)

    info = report["scan_info"]
    print(f"📅 Scan Time   : {info['timestamp']}")
    print(f"📄 Source      : {info['source']}")
    print(f"📝 Text Length : {info['text_length']} characters")
    print(f"⚠️  Risk Score  : {info['total_risk_score']}")
    print(f"🎯 Risk Level  : {report['summary']['verdict']}")
    print("-"*60)

    # Show found keywords
    keywords = report["keywords_found"]
    if keywords:
        print(f"\n🔑 SUSPICIOUS KEYWORDS FOUND ({len(keywords)} total):")
        print("-"*60)
        # Sort by total score (highest first) so worst offenders are at top
        sorted_kw = sorted(keywords.items(), key=lambda x: x[1]["total_score"], reverse=True)
        for kw, data in sorted_kw:
            print(f"  • '{kw}' — found {data['count']}x | weight: {data['weight']} | score: {data['total_score']}")
    else:
        print("\n✅ No suspicious keywords found.")

    # Show URL analysis
    urls = report["urls_analyzed"]
    if urls:
        print(f"\n🌐 URLS ANALYZED ({len(urls)} total):")
        print("-"*60)
        for url_info in urls:
            status = "⚠️  SUSPICIOUS" if url_info["is_suspicious"] else "✅ OK"
            print(f"  {status}: {url_info['url'][:80]}...")  # Truncate long URLs
            for reason in url_info["reasons"]:
                print(f"      → {reason}")
    else:
        print("\n🌐 No URLs detected in the text.")

    print("\n" + "="*60)
    print(f"  FINAL VERDICT: {report['summary']['verdict']}")
    print("="*60 + "\n")


# ─────────────────────────────────────────────────────────────
# FUNCTION: save_report
# PURPOSE: Saves the scan report as a JSON file
# ─────────────────────────────────────────────────────────────
def save_report(report: dict, output_path: str = "scan_report.json") -> None:
    """
    Save the scan report to a JSON file for later review.

    Args:
        report (dict): The scan report
        output_path (str): Where to save the file
    """
    with open(output_path, "w", encoding="utf-8") as f:
        # indent=4 makes the JSON file human-readable with nice formatting
        json.dump(report, f, indent=4)
    print(f"[INFO] Report saved to: {output_path}")


# ─────────────────────────────────────────────────────────────
# FUNCTION: scan
# PURPOSE: Master function — runs the full scan pipeline
# ─────────────────────────────────────────────────────────────
def scan(source: str, save_json: bool = True) -> dict:
    """
    Main scanning function — runs all checks on the given input.

    Args:
        source (str): File path OR raw text to scan
        save_json (bool): Whether to save the report as JSON

    Returns:
        dict: The complete scan report
    """
    print("\n[INFO] Starting phishing scan...")

    # Step 1: Load the text (from file or direct input)
    text = load_text(source)

    # Step 2: Check for phishing keywords
    print("[INFO] Scanning for phishing keywords...")
    found_keywords = scan_keywords(text)

    # Step 3: Analyze URLs in the text
    print("[INFO] Analyzing URLs...")
    suspicious_urls = scan_urls(text)

    # Step 4: Calculate the overall risk score
    total_score, risk_level, emoji = calculate_risk_score(found_keywords, suspicious_urls)

    # Step 5: Generate the full report
    source_name = os.path.basename(source) if os.path.isfile(source) else "direct_input"
    report = generate_report(text, found_keywords, suspicious_urls,
                             total_score, risk_level, emoji, source_name)

    # Step 6: Print the report to terminal
    print_report(report)

    # Step 7: Save the report to a JSON file (optional)
    if save_json:
        save_report(report)

    return report


if __name__ == "__main__":
    print("=" * 60)
    print("   AI-Powered Phishing Filter v1.0")
    print("=" * 60)

    # Check if a file path was passed as a command-line argument
    # Example: python phishing_filter.py email.txt
    if len(sys.argv) > 1:
        input_source = sys.argv[1]  # Get the first argument (file path)
        scan(input_source)
    else:
        # No file given — run on a built-in example phishing email
        print("[INFO] No file provided. Running demo with a sample phishing email.\n")
        print("TIP: Run with a file like this:")
        print("     python phishing_filter.py your_email.txt\n")

        # This is a fake phishing email for demonstration purposes
        SAMPLE_PHISHING_EMAIL = """
        Subject: URGENT: Your PayPal Account Has Been Suspended!

        Dear Customer,

        We have detected suspicious activity on your PayPal account.
        Your account will be closed within 24 hours unless you verify
        your account immediately.

        Click here to confirm your identity and update your billing information:
        http://paypa1-secure-login.bit.ly/verify?id=88234

        You must enter your password, credit card number, and SSN
        to reactivate your account. Act now before it expires!

        Failure to comply may result in legal action.

        PayPal Security Team
        """

        scan(SAMPLE_PHISHING_EMAIL, save_json=True)
