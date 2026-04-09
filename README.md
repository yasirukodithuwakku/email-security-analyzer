# 🛡️ Email Security Analyzer & SOC Dashboard

An Enterprise-Grade, Full-Stack Cybersecurity tool designed to analyze domains and URLs for email spoofing vulnerabilities, malicious activities, and phishing threats. It features an interactive Security Operations Center (SOC) dashboard and AI-driven auto-remediation.

## ✨ Key Features

* **🔍 Single & Bulk Domain Scanning:** Analyzes SPF and DMARC records to prevent email spoofing.
* **🧠 AI Auto-Remediation:** Uses Google Gemini AI to provide instant, actionable fixes for misconfigured DNS records.
* **🦠 Threat Intelligence Integration:** Checks domains against the VirusTotal API and URLs against Google Safe Browsing API.
* **📊 SOC Analytics Dashboard:** Interactive data visualization of scan history and risk distribution using Recharts.
* **🔐 Secure User Authentication:** JWT-based login/signup system with hashed passwords and SQLite database.
* **🛑 Advanced Security:** Built-in API rate limiting and brute-force protection using SlowAPI.

## 🛠️ Technology Stack

* **Frontend:** React.js, Vite, Recharts, Lucide Icons
* **Backend:** Python, FastAPI, SQLAlchemy
* **Database:** SQLite
* **APIs & AI:** Google Gemini (Generative AI), VirusTotal API, Google Safe Browsing API

## 🚀 Getting Started

Follow these steps to set up the project locally.

### Prerequisites
* Python 3.8+
* Node.js & npm

### 1. Backend Setup (FastAPI)
Navigate to the root directory and install the required Python packages:

```bash
# Install dependencies
pip install fastapi uvicorn requests dnspython python-dotenv pydantic sqlalchemy slowapi passlib[bcrypt] python-jose python-multipart google-generativeai


# Run the backend server
uvicorn api:app --reload
