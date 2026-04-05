# 🛡️ AI-Powered Email Security & Threat Intelligence Analyzer

A full-stack, automated cybersecurity tool designed for SOC Analysts and Security Engineers to analyze domain reputation and detect email spoofing vulnerabilities. It utilizes advanced DNS scanning combined with real-time Threat Intelligence and Generative AI for automated remediation.

## ✨ Key Features

* **Advanced DNS Vulnerability Scanning:** Deep analysis of SPF, DMARC, and DKIM records to identify email authentication gaps.
* **AI Auto-Remediation (Google Gemini):** Automatically generates context-aware, actionable DNS configurations to fix identified security vulnerabilities.
* **Real-Time Threat Intelligence:** Integrates with the **VirusTotal API** to check domain reputation against 70+ global security vendors and detect malicious activities.
* **Professional Reporting:** Automated, one-click PDF incident report generation for SOC documentation.
* **Interactive UI:** A modern, responsive dashboard built with React.js and Tailwind CSS concepts.

## 💻 Tech Stack

* **Frontend:** React.js, Vite, Axios, html2pdf.js, Lucide-React (Icons)
* **Backend:** Python, FastAPI, Uvicorn
* **Security & APIs:** `dnspython`, Google Gemini AI (Generative AI), VirusTotal API

## 🚀 Getting Started

### Prerequisites
Make sure you have the following installed on your machine:
* Python 3.8+
* Node.js & npm
* API Keys from [VirusTotal](https://www.virustotal.com/) and [Google AI Studio](https://aistudio.google.com/)

### 1. Backend Setup (FastAPI)
1. Navigate to the project root directory.
2. Install the required Python packages:
   ```bash
   pip install fastapi uvicorn dnspython requests google-generativeai --break-system-packages
