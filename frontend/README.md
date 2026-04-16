# Email Security Analyzer 🛡️

Advanced DNS vulnerability scanning tool with AI-powered auto-remediation. This project helps security professionals analyze domain security (SPF, DMARC, DKIM), detect phishing URLs, and perform network VAPT.

## 🚀 Key Features
* **Single/Bulk Domain Scanner:** Detailed SPF, DMARC, and DKIM analysis.
* **AI Auto-Remediation:** Actionable security recommendations using Gemini AI.
* **Phishing URL Scanner:** Integration with Google Safe Browsing.
* **Header Forensics:** Deep analysis of raw email headers and routing hops.
* **Network VAPT:** Subdomain discovery and open port scanning.
* **SOC Dashboard:** Real-time scan history and security alerts.

## 🔒 Security Architecture (Bank-Level Security)
This project implements industry-standard security practices to protect user data:

1.  **HttpOnly JWT Authentication:** * Tokens are stored in **HttpOnly Cookies**, making them inaccessible to client-side JavaScript. This provides 100% protection against **XSS (Cross-Site Scripting)** attacks.
    * Cookies are configured with `SameSite=Lax` to mitigate **CSRF** risks while maintaining usability.
2.  **Password Hashing:** * Uses **Bcrypt** with `passlib` for robust password hashing. Plain-text passwords are never stored in the database.
3.  **CORS Policy:** * Strict origin validation using environment variables to ensure only authorized frontend domains can interact with the API.
4.  **Rate Limiting:** * Prevents brute-force and DoS attacks by limiting the number of requests per minute for sensitive endpoints.

## 🛠️ Tech Stack
* **Backend:** FastAPI (Python), SQLAlchemy, PostgreSQL/SQLite.
* **Frontend:** React (Vite), Axios, Tailwind/Custom CSS.
* **AI:** Google Gemini Pro API.
* **Security:** JWT, Bcrypt, HttpOnly Cookies.

## ⚙️ Installation & Setup

### 1. Backend Setup
1. Navigate to the `backend` folder.
2. Install dependencies:
   ```bash
   pip install fastapi uvicorn sqlalchemy passlib[bcrypt] pyjwt python-multipart python-dotenv