# Phish Pharm / Phishing Triage Agent

Phish Pharm is a local Python tool that parses `.eml` email files and creates analyst-friendly phishing triage reports.

The goal is to help SOC analysts review email evidence faster by collecting common message details in one place. The tool does **not** make a final malicious or safe verdict.

## MVP Status

Current MVP supports:

- Local `.eml` parsing
- HTML triage reports
- Quick Checks summary
- URL and Microsoft Safe Links extraction
- Optional VirusTotal existing-report URL and attachment-hash reputation lookups
- RDAP domain-registration context for email and URL domains
- SPF, DKIM, and DMARC summaries
- Attachment and inline content summaries
- Received-header hop details
- Windows launcher with Desktop Inbox/Reports workflow

## Quick Start

For normal Windows use:

1. Extract the project ZIP.
2. Make sure Python 3.10+ is installed and added to PATH.
3. Double-click `Start_Phish_Pharm.bat`.
4. Drop `.eml` files into `Desktop\Inbox`.
5. Open generated `.html` reports from `Desktop\Reports`.
6. Press `Ctrl+C` in the launcher window to stop the watcher.

For a shorter user guide, see `HOW_TO_USE.txt`.

## Command Line Usage

Run one email:

```powershell
python src/main.py path\to\email.eml --format html
```

Run a folder of `.eml` files:

```powershell
python src/main.py path\to\folder --output reports --format html
```

Start watch mode:

```powershell
python src/main.py --watch inbox --output reports --format html
```

The CLI also supports `--format md` and `--format both`.

## Reputation API Configuration

Sender-IP and VirusTotal reputation checks are optional. Set API keys before launching the tool or the watch-mode batch file; never place real keys in source files, reports, or GitHub.

### AbuseIPDB

Windows Command Prompt:

```cmd
set ABUSEIPDB_API_KEY=your_key_here
```

PowerShell:

```powershell
$env:ABUSEIPDB_API_KEY="your_key_here"
```

### VirusTotal URL and Attachment Hash Reputation

VirusTotal lookups retrieve existing URL and file-hash reports only. URLs are not visited or submitted for scanning. For normal file attachments, the tool sends only the existing SHA-256 hash to retrieve a report; it never uploads, rescans, opens, or executes the attachment. Inline and embedded content is excluded.

URL and attachment-hash checks share one rolling public-API budget of at most four total requests per report. When both are available, lookups alternate in deterministic order beginning with an attachment hash. Reports can therefore show partial coverage. A zero-detection result does not prove a URL or file is safe, and a real API key must never be committed to GitHub.

Windows Command Prompt:

```cmd
set VIRUSTOTAL_API_KEY=your_key_here
```

PowerShell:

```powershell
$env:VIRUSTOTAL_API_KEY="your_key_here"
```

### Domain Registration Context

Domain registration data is retrieved through RDAP; no additional API key is required. The tool uses the IANA RDAP bootstrap registry to discover the authoritative provider, and does not visit or render represented websites. Up to 10 unique registered domains per report are checked. Domain age is an analyst indicator, not a verdict; privacy-redacted registration data is normal. RDAP failures do not prevent report generation. DomainTools enrichment may be added later if approved.

## Running Tests

```powershell
python -m unittest discover -s tests -v
python -m py_compile src/main.py tests/test_url_extraction.py
```

## Safety Notes

- The tool does not open URLs.
- The tool does not render unsafe email HTML.
- Optional reputation checks send only URLs and attachment SHA-256 hashes to the configured providers; attachments are never uploaded.
- Analyst review is still required.
- Do not commit real phishing emails, tickets, credentials, or sensitive data.

## Known Limitations

- Python must be installed and available on PATH.
- Watch mode monitors one folder only, not subfolders.
- The tool currently supports `.eml` files.
- The tool does not make final verdicts.
- Report quality depends on the data available in the parsed email.

## Possible Future Improvements

- Package as an executable so Python is not required.
- Add a domain reputation provider.
- Add more sample emails and tests.
- Improve handling of legitimate third-party/bounce sender patterns.
