# Phish Pharm / Phishing Triage Agent

## Project Overview

Phish Pharm is a Python tool that parses `.eml` phishing-email samples and creates Markdown and HTML triage reports. It is designed to help SOC analysts review email evidence more quickly by collecting common message details in one place.

The tool supports analyst review; it does **not** make a final automated malicious or safe verdict.

## Current Features

- Parses `.eml` email files.
- Extracts sender, recipient, subject, and date fields.
- Shows a body preview.
- Extracts URLs from plain-text and HTML email content.
- Detects Microsoft Safe Links.
- Extracts links from HTML `href`, `src`, `action`, `data`, and `formaction` attributes.
- Summarizes attachments and inline/embedded content.
- Shows SPF, DKIM, and DMARC authentication results.
- Adds compact Quick Checks for:
  - External sender
  - Authentication status
  - URL count
  - Safe Links count
  - Attachment count
  - Reply-To mismatch
  - Return-Path comparison
- Generates both Markdown and HTML reports.

## How to Use

### Prerequisites

Use Python 3.10 or later. The current project uses the Python standard library and does not include a `requirements.txt` file.

Creating a virtual environment is optional, but recommended:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If a future version of the project includes `requirements.txt`, install it with:

```powershell
python -m pip install -r requirements.txt
```

### Run a Sample

From the repository root, run the parser against a specific `.eml` file:

```powershell
python src/main.py "samples\test_email.eml"
```

You can also run the default sample (`samples/test_email.eml`) with no argument:

```powershell
python src/main.py
```

Reports are saved in the `reports/` folder using the input email filename, for example:

- `reports/test_email_report.md`
- `reports/test_email_report.html`

### Watch a Folder

To monitor a folder for new `.eml` files, use the supported watch-mode command:

```powershell
python src/main.py --watch watch_folder
```

## Running Tests

Run the unit tests:

```powershell
python -m unittest discover -s tests -v
```

Run a syntax check:

```powershell
python -m py_compile src/main.py tests/test_url_extraction.py
```

## Safety Notes

- The tool parses email files as text and metadata.
- It does not open URLs.
- It does not render the email's HTML content while parsing.
- It does not send URLs or attachments to external services by default.
- Analysts should still review all report results manually.
- Do not commit real phishing messages, internal tickets, credentials, or other sensitive data to source control.

## Project Status / Next Steps

Possible future improvements include:

- Improve handling for legitimate Return-Path subdomains and third-party bounce domains.
- Add collapsible HTML sections for long URL lists.
- Add more sample emails and tests.
- Add optional reputation checks later, if approved.
