# Phish Pharm

Phish Pharm is a local Python tool that reads `.eml` files and creates phishing triage reports.

I made it to help SOC analysts review emails faster by putting useful email details, security checks, and reputation information in one place.

**Phish Pharm helps with analysis, but it does not decide if an email is malicious or safe. The analyst still makes the final call.**

## Demo

https://github.com/user-attachments/assets/36e42d3b-be3f-409c-8ecc-86a2063849db

## Why I Built It

When reviewing phishing emails, analysts usually have to check a lot of different things like the sender, IP address, URLs, attachments, and email authentication results.

I built Phish Pharm to make that process easier. Instead of checking everything separately, the tool collects a lot of that information and puts it into one report.

## What It Does

Phish Pharm can currently:

- Show the sender, recipient, subject, and other email details
- Run Quick Checks for common phishing signs
- Show SPF, DKIM, and DMARC results
- Analyze the sender IP address
- Check sender IP reputation with AbuseIPDB
- Extract URLs and Microsoft Safe Links
- Check URL reputation with VirusTotal
- Check attachment SHA-256 hashes with VirusTotal
- Show domain registration information using RDAP
- Show attachment and inline-content details
- Preview the email body
- Show Received-header routing information
- Generate an HTML triage report

## Technologies Used

- Python 3.10+
- HTML
- Windows batch scripting
- AbuseIPDB API
- VirusTotal API
- RDAP
- IANA RDAP bootstrap registry

## Quick Start

1. Download the project ZIP or clone the repository.
2. Make sure **Python 3.10+** is installed and added to PATH.
3. Double-click `Start_Phish_Pharm.bat`.
4. Follow the setup steps if prompted.
5. Drop `.eml` files into `Desktop\Inbox`.
6. Open completed reports from `Desktop\Reports`.
7. Press `Ctrl+C` in the launcher window when you want to stop Phish Pharm.

For more instructions, see `HOW_TO_USE.txt`.

## First-Time Setup

The Windows launcher checks if the required Python packages are installed.

If anything is missing, it can ask for permission to install the required packages.

It can also help set up these optional API keys:

- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY`

The API keys are saved as Windows user environment variables and are not stored inside the project files.

Phish Pharm can still run without API keys. The reputation checks that need them will just be skipped.

RDAP lookups do not need an API key.

## Reputation Checks

### AbuseIPDB

Phish Pharm can check the selected sender IP and show information such as:

- Abuse confidence score
- Number of reports
- Reported activity
- ISP
- Usage type
- Country

### VirusTotal

Phish Pharm uses VirusTotal to:

- Check existing reports for extracted URLs
- Check existing reports for attachment SHA-256 hashes

The tool does not upload attachments or submit URLs for new scans.

### RDAP

RDAP is used to show domain registration information.

Phish Pharm uses the IANA RDAP bootstrap registry to find the correct RDAP service.

The tool does not visit the domain's website. Domain registration information is only used as extra context for the analyst.

## Safety

Phish Pharm is designed to inspect email evidence without directly interacting with potentially malicious content.

- URLs are not opened
- Unsafe email HTML is not rendered
- Attachments are not opened or executed
- Attachments are not uploaded to VirusTotal
- API keys are not added to reports
- The analyst always makes the final decision

Real phishing emails, passwords, API keys, tickets, or other sensitive information should not be uploaded to the repository.


## Limitations

- Only supports `.eml` files
- Requires Python
- Reputation checks depend on the API service being available
- Some reputation checks require API keys
- Results depend on the information available inside the original email
- Phish Pharm should not be used by itself to decide whether an email is malicious
