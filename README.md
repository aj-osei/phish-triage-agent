# Phish Pharm / Phishing Triage Agent

Phish Pharm is a local Python tool that parses `.eml` email files and creates analyst-friendly phishing triage reports.

The goal is to help SOC analysts review email evidence faster by collecting common message details in one place. The tool does **not** make a final malicious or safe verdict.

## MVP Status

Current MVP supports:

- Local `.eml` parsing
- HTML triage reports
- Quick Checks summary
- URL and Microsoft Safe Links extraction
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

## Running Tests

```powershell
python -m unittest discover -s tests -v
python -m py_compile src/main.py tests/test_url_extraction.py
```

## Safety Notes

- The tool does not open URLs.
- The tool does not render unsafe email HTML.
- The tool does not send URLs, files, or attachments to external services by default.
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
- Add optional reputation lookups if approved.
- Add more sample emails and tests.
- Improve handling of legitimate third-party/bounce sender patterns.
