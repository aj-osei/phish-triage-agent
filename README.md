# Phish Triage Agent

A Python MVP for helping automate phishing email triage.

## Goal

The goal is to safely parse `.eml` files, extract useful email details, and generate a triage report for analyst review.

## MVP Plan

### Phase 1: Manual Parser
- Read one safe test `.eml` file
- Extract sender, recipient, subject, date, and body preview
- Extract URLs without opening them
- Print the results in the terminal

### Phase 2: Report Generator
- Save the extracted details into a Markdown report

### Phase 3: Folder Watcher
- Watch a folder for new `.eml` files
- Automatically parse new files

### Safety Notes

- Do not use real phishing emails in GitHub
- Do not commit internal screenshots, tickets, API keys, or company data
- Do not render HTML
- Do not open links automatically
- Real samples should only be tested inside the VM
