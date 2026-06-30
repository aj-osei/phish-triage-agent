# Phish Triage Agent

A Python-based MVP for automating parts of phishing email triage.

## Goal

The goal is to parse `.eml` files safely, extract useful triage details, and generate a structured report for analyst review.

## Planned MVP Features

- Read a local `.eml` file
- Extract sender, recipient, subject, and date
- Extract plain text and HTML body content safely
- Extract URLs from the email body
- Generate a Markdown triage report
- Later: watch a folder for new emails
- Later: add reputation checks using tools like VirusTotal or URLScan

## Safety Notes

This project should not render email HTML, open links, or execute attachments. It should only parse email files as text/data.

No real phishing emails, internal tickets, screenshots, API keys, or company data should be committed to this repo.
