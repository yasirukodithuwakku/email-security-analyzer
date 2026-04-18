# Email Security Analyzer & SOC Dashboard 🛡️

An advanced, enterprise-grade DNS vulnerability scanning and network VAPT tool. This platform helps cybersecurity professionals analyze domain security (SPF, DMARC, DKIM), detect phishing threats, perform network reconnaissance, and receive AI-powered remediation strategies.

## 🚀 Key Features

### 🔍 Security Analysis Tools
* **Single & Bulk Domain Scanner:** Deep analysis of SPF, DMARC, and DKIM records.
* **Phishing URL Scanner:** Integration with Google Safe Browsing API to detect malicious links.
* **Threat Intelligence:** Real-time domain reputation checking via VirusTotal API.
* **Email Header Forensics:** Deep parsing of raw email headers to trace routing hops and IP addresses.
* **Network VAPT:** Subdomain discovery (via crt.sh) and automated open port scanning.

### 🧠 AI Integration
* **AI Auto-Remediation:** Leverages Google Gemini AI to generate actionable, context-aware security recommendations based on scan results.

### 🔒 Enterprise-Level Security & Authentication
* **JWT & HttpOnly Cookies:** Tokens are securely stored in HttpOnly, SameSite=Lax cookies to prevent XSS and CSRF attacks.
* **Bcrypt Hashing:** Passwords are fully hashed before database storage.
* **Brute-Force Protection:** Automated account lockout system after 5 failed login attempts.
* **Secure Password Reset:** JWT-based email reset links with expiration handling.
* **Rate Limiting:** API endpoints are protected against DoS attacks using `slowapi`.

### 📊 SOC Operations
* **Real-time Dashboard:** Live tracking of scan histories with automated risk categorization (Secure, Warning, Critical).
* **Executive PDF Reports:** Generate downloadable, formatted reports of scan results for management.

---

## 🛠️ Tech Stack

* **Frontend:** React (Vite), Axios, Tailwind/Custom CSS, Lucide Icons, html2pdf.
* **Backend:** FastAPI (Python), SQLAlchemy, JWT, Passlib, Uvicorn.
* **Database:** PostgreSQL (Supabase).
* **External APIs:** Google Gemini AI, VirusTotal API, Google Safe Browsing API.

---

## ⚙️ Installation & Setup

### Prerequisites
* Python 3.10+
* Node.js & npm
* PostgreSQL Database (or Supabase account)

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/email-security-analyzer.git](https://github.com/yourusername/email-security-analyzer.git)
cd email-security-analyzer