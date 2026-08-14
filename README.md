# Phish Pharm

Phish Pharm is a local Python tool that parses `.eml` files and generates analyst-friendly phishing triage reports.

It is designed to help SOC analysts review common email evidence faster by collecting useful indicators and reputation context in one place.

**Phish Pharm assists analysis — it does not make a final malicious or safe verdict.**

## What It Does

Phish Pharm currently provides:

- Email sender, recipient, subject, and message details
- Quick Checks for common phishing indicators
- SPF, DKIM, and DMARC results
- Sender IP analysis
- AbuseIPDB sender-IP reputation
- URL and Microsoft Safe Links extraction
- VirusTotal URL reputation
- VirusTotal attachment SHA-256 reputation
- RDAP domain registration context
- Attachment and inline-content summaries
- Email body preview
- Received-header routing details
- HTML triage reports

## Quick Start

1. Extract the project ZIP.
2. Make sure **Python 3.10+** is installed and available on PATH.
3. Double-click `Start_Phish_Pharm.bat`.
4. Complete the guided setup if prompted.
5. Drop `.eml` files into `Desktop\Inbox`.
6. Open completed reports from `Desktop\Reports`.
7. Press `Ctrl+C` in the launcher window to stop Phish Pharm.

For additional instructions, see `HOW_TO_USE.txt`.

## First-Run Setup

The Windows launcher checks whether the required Python packages are installed and can install missing requirements after confirmation.

It can also optionally configure:

- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY`

API keys are stored as Windows user environment variables and are not saved inside the project.

Missing API keys do **not** prevent Phish Pharm from running. The affected reputation checks are simply skipped.

RDAP domain registration lookups do not require an API key.

## Reputation Checks

### AbuseIPDB

- Checks the selected sender IP
- Displays abuse confidence, reports, reported activity, ISP, usage type, and country

### VirusTotal

- Retrieves existing reports for extracted URLs
- Retrieves existing reports using attachment SHA-256 hashes
- Does not upload attachments
- Does not submit URLs for new scans
- Uses a limited request budget per report

### RDAP

- Provides domain registration context
- Uses the IANA RDAP bootstrap registry
- Does not visit the domain's website
- Registration information is supporting context, not a verdict

## Safety

Phish Pharm is designed to inspect email evidence without interacting with potentially malicious content.

- URLs are not opened by the tool.
- Unsafe email HTML is not rendered.
- Attachments are not opened or executed.
- Attachments are not uploaded to VirusTotal.
- API keys are not written into reports.
- Analyst review is always required.

Do not commit real phishing emails, credentials, tickets, API keys, or other sensitive information to the repository.

## Current Limitations

- Supports `.eml` files only
- Requires Python
- Watch mode monitors one folder
- Reputation checks depend on provider availability and configured API keys
- Results depend on the evidence available in the original email

---

For normal analyst use, start Phish Pharm with:

`Start_Phish_Pharm.bat`
