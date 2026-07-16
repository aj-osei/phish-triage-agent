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

### Run an Email File or Folder

The `samples/` folder is for testing and demonstration. In real use, pass the path to any downloaded `.eml` file or a folder containing `.eml` files.

From the repository root:

```powershell
python src/main.py samples/test_email.eml
python src/main.py samples/
python src/main.py "C:\Users\ajosei\Downloads\suspicious_email.eml"
python src/main.py "C:\Users\ajosei\Downloads\phish_emails" --output reports
python src/main.py samples/test_email.eml --format html
```

The `--format` option accepts `md`, `html`, or `both` (the default). Use `--output` to choose a report folder; it is created automatically when needed. Without `--output`, reports are written to `reports/`. Existing reports are not overwritten: duplicate names receive numeric suffixes such as `_1` and `_2`.

You can also run the default sample (`samples/test_email.eml`) with no argument:

```powershell
python src/main.py
```

Reports use the input email filename, for example:

- `reports/test_email_report.md`
- `reports/test_email_report.html`

### Watch Folder Mode

Create an empty folder for incoming email files, then start the watcher:

```powershell
mkdir inbox
python src/main.py --watch inbox --output reports
```

Drop or copy new `.eml` files into `inbox/`. The tool waits for each file to finish copying, then generates reports in `reports/`. The watcher supports the same format choices:

```powershell
python src/main.py --watch inbox --output reports --format html
python src/main.py --watch inbox --output reports --format md
python src/main.py --watch inbox --output reports --format both
```

The watcher only checks that one folder (not subfolders). Stop it with `Ctrl+C`.

### Simple Windows Launcher

For routine analyst use on Windows, double-click `Start_Phish_Pharm.bat` in the project root. The launcher uses the visible Desktop when possible: it prefers a OneDrive Commercial Desktop, then a OneDrive Desktop, and finally `%USERPROFILE%\Desktop`. It creates `Inbox` and `Reports` there if they do not already exist, then starts an HTML-only watcher.

1. Drop `.eml` files into `Desktop\Inbox`.
2. Open the generated HTML reports from `Desktop\Reports`.
3. Press `Ctrl+C` in the launcher window to stop the watcher.

VS Code is not required for normal launcher use, provided Python is installed and the repository files are present. Markdown remains available through the command line with `--format md` or `--format both` when needed.

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
