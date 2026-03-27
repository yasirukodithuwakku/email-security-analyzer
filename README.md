# Email Security Analyzer (SPF, DKIM, DMARC)

## Overview
A Python-based cybersecurity tool designed to analyze the email security posture of any given domain. This tool fetches and evaluates DNS records to determine if a domain is properly protected against email spoofing and phishing attacks.

## Current Features
* **SPF (Sender Policy Framework) Checker:** Verifies if the domain has a valid SPF record to prevent unauthorized IP addresses from sending emails on its behalf.
* *(Upcoming)* DMARC Analysis
* *(Upcoming)* DKIM Verification

## Prerequisites
* Python 3.x
* `dnspython` library

## Installation & Usage
1. Clone the repository:
   `git clone https://github.com/yasirukodithuwakku/email-security-analyzer.git`
2. Install dependencies:
   `pip install dnspython`
3. Run the tool:
   `python3 email_analyzer.py`

## Educational Purpose
This project was developed to practically demonstrate core concepts in Network Security and Incident Prevention.
