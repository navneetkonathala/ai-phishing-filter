🛡️ AI-Powered Phishing Filter
A Python-based cybersecurity tool that scans emails and text files for phishing/spam indicators and flags suspicious content with a detailed risk report.
---
📌 Features
✅ Scans text or `.txt` email files for 60+ phishing keywords 

✅ Detects and analyzes suspicious URLs (HTTP, shortened links, fake domains)

✅ Assigns a risk score with 5 levels: Safe → Critical

✅ Generates a detailed terminal report + saves a JSON report

✅ Works on Windows, macOS, and Linux

✅ No external libraries required — uses only Python built-ins
---
🚀 Quick Start
Requirements
Python 3.7 or higher
Run on a sample file
```bash
python phishing_filter.py sample_phishing_email.txt
```
Run the built-in demo
```bash
python phishing_filter.py
```
Scan your own email
Save your email as a `.txt` file and run:
```bash
python phishing_filter.py your_email.txt
```
---
📊 Risk Levels
Score	Risk Level	Meaning

0	✅ SAFE	No indicators found

1–5	🟡 LOW RISK	Minor flags — review cautiously

6–15	🟠 MEDIUM RISK	Multiple red flags — be careful

16–30	🔴 HIGH RISK	Strong phishing indicators

31+	🚨 CRITICAL	Almost certainly a phishing attempt

---
📁 Project Structure
```
ai-phishing-filter/
│
├── phishing_filter.py          # Main scanner script
├── sample_phishing_email.txt   # Example phishing email (for testing)
├── sample_safe_email.txt       # Example safe email (for testing)
├── requirements.txt            # Dependencies (none needed!)
└── README.md                   # This file
```
---
🧠 How It Works
Load Text — Reads from a file or accepts direct text
Keyword Scan — Matches against 60+ weighted phishing keywords
URL Analysis — Finds URLs and checks for red flags
Risk Scoring — Calculates total score from all findings
Report Generation — Outputs detailed report to terminal + JSON
---
🔒 Security Note
This tool is intended for educational and awareness purposes. It helps identify common phishing patterns but is not a replacement for professional email security solutions.
---
📄 License
MIT License — Free to use and modify.
