import axios from 'axios'
import { Shield, ShieldAlert, ShieldCheck, Search, Loader, Info, Download, Sparkles } from 'lucide-react'
import html2pdf from 'html2pdf.js'
import './index.css'
import BulkScanner from './components/BulkScanner'
import PhishingScanner from './components/PhishingScanner'
import AnalyticsDashboard from './components/AnalyticsDashboard'
import React, { useState, useEffect } from 'react';
import AuthPage from './components/AuthPage';
import EmailHeaderAnalyzer from './components/EmailHeaderAnalyzer';

axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});


axios.interceptors.response.use((response) => {
  return response;
}, (error) => {
  if (error.response && error.response.status === 401) {
    
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    window.location.reload(); 
  }
  return Promise.reject(error);
});

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loggedInUser, setLoggedInUser] = useState('');

 
  useEffect(() => {
    const token = localStorage.getItem('token');
    const user = localStorage.getItem('username');
    if (token && user) {
      setIsAuthenticated(true);
      setLoggedInUser(user);
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIsAuthenticated(false);
    setLoggedInUser('');
  };

 
  


  const [domain, setDomain] = useState('')
  const [scanMode, setScanMode] = useState('single')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [error, setError] = useState(null)

  const analyzeDomain = async (e) => {
    e.preventDefault()
    if (!domain) return
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/analyze/${domain}`)
      setResults(response.data)
    } catch (err) {
      if (err.response && err.response.status === 429) {
        setError("⚠️ Rate limit exceeded! Please wait a minute before trying again.");
      } else {
        setError("Failed to connect to the server. Make sure your Python backend is running.");
      }
    } finally {
      setLoading(false)
    }
  }

  const downloadPDF = () => {
    const element = document.getElementById('report-content');
    const opt = {
      margin:       0.5,
      filename:     `${domain}-security-report.pdf`,
      image:        { type: 'jpeg', quality: 0.98 },
      html2canvas:  { scale: 2, backgroundColor: '#0b1120' },
      jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' }
    };
    html2pdf().set(opt).from(element).save();
  }

  const getStatusIcon = (status) => {
    if (status === 'Secure') return <ShieldCheck className="icon secure" />
    if (status === 'Warning') return <ShieldAlert className="icon warning" />
    if (status === 'Info') return <Info className="icon info" />
    return <Shield className="icon error" />
  }

  if (!isAuthenticated) {
    return <AuthPage onLoginSuccess={() => {
      setIsAuthenticated(true);
      setLoggedInUser(localStorage.getItem('username'));
    }} />;
  }

  return (
    <div className="dashboard">
      <header className="app-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <Shield className="logo-icon" size={36} />
            <div>
              <h1>Email Security Analyzer</h1>
              <p className="subtitle">Advanced DNS vulnerability scanning with AI Auto-Remediation</p>
            </div>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
            <span style={{ color: '#94a3b8' }}>Hello, <b>{loggedInUser}</b></span>
            <button onClick={handleLogout} style={{ padding: '8px 16px', background: 'transparent', border: '1px solid #ef4444', color: '#ef4444', borderRadius: '6px', cursor: 'pointer' }}>
              Logout
            </button>
          </div>
        </div>
      </header>

      <main>
        {/* Scan Mode Toggle Buttons */}
        <div className="scan-mode-toggle">
          <button
            type="button"
            className={scanMode === 'single' ? 'toggle-btn active' : 'toggle-btn'}
            onClick={() => setScanMode('single')}
          >
            Single Domain Scanner
          </button>
          <button
            type="button"
            className={scanMode === 'bulk' ? 'toggle-btn active' : 'toggle-btn'}
            onClick={() => setScanMode('bulk')}
          >
            Bulk Domain Scanner
          </button>
          <button
            type="button"
            className={scanMode === 'phishing' ? 'toggle-btn active' : 'toggle-btn'}
            onClick={() => setScanMode('phishing')}
          >
            Phishing URL Scanner
          </button>
          <button
            type="button"
            className={scanMode === 'dashboard' ? 'toggle-btn active' : 'toggle-btn'}
            onClick={() => setScanMode('dashboard')}
          >
            SOC Dashboard
          </button>

          <button
            type="button"
            className={scanMode === 'forensic' ? 'toggle-btn active' : 'toggle-btn'}
            onClick={() => setScanMode('forensic')}
          >
            Header Forensic
          </button>
        </div>

        {/* Dynamic Tools Container */}
        <div className="tools-container">
          {scanMode === 'single' && (
            <form onSubmit={analyzeDomain} className="search-bar">
              <input
                type="text"
                placeholder="Enter single domain (e.g., google.com)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
              />
          {scanMode === 'forensic' && (
            <div className="bulk-wrapper">
              <EmailHeaderAnalyzer />
            </div>
          )}
              <button type="submit" disabled={loading}>
                {loading ? <Loader className="spin" /> : <Search />}
                {loading ? 'Analyzing...' : 'Analyze'}
              </button>
            </form>
          )}
          
          {scanMode === 'bulk' && (
            <div className="bulk-wrapper">
              <BulkScanner />
            </div>
          )}

          {scanMode === 'phishing' && (
            <div className="bulk-wrapper">
              <PhishingScanner />
            </div>
          )}

          {scanMode === 'dashboard' && (
            <div className="bulk-wrapper">
              <AnalyticsDashboard />
            </div>
          )}

        </div>
        
        {/* Results Section */}
        {scanMode === 'single' && results && (
          <div className="report-wrapper">
            <div className="report-actions">
              <button onClick={downloadPDF} className="download-btn">
                <Download size={18} /> Download PDF Report
              </button>
            </div>

            <div id="report-content" className="pdf-container">
              <h2 className="report-title">Target Domain: <span>{results.domain}</span></h2>
              <div className="results-grid">
                
                <div className="card info ai-glow">
                  <div className="card-header">
                    <Sparkles className="icon info" style={{color: '#a855f7'}} />
                    <h2>AI Auto-Remediation</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge ai-badge">Powered by Gemini AI</span>
                    <p className="message ai-text">{results.ai_remediation}</p>
                  </div>
                </div>

                <div className={`card ${results.spf.status.toLowerCase()}`}>
                  <div className="card-header">
                    {getStatusIcon(results.spf.status)}
                    <h2>SPF Record</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge">{results.spf.status}</span>
                    {results.spf.record ? <p className="code-block">{results.spf.record}</p> : <p className="message">{results.spf.message}</p>}
                  </div>
                </div>

                <div className={`card ${results.dmarc.status.toLowerCase()}`}>
                  <div className="card-header">
                    {getStatusIcon(results.dmarc.status)}
                    <h2>DMARC Policy</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge">{results.dmarc.status}</span>
                    {results.dmarc.record ? <p className="code-block">{results.dmarc.record}</p> : <p className="message">{results.dmarc.message}</p>}
                  </div>
                </div>

                <div className={`card ${results.dkim.status.toLowerCase()}`}>
                  <div className="card-header">
                    {getStatusIcon(results.dkim.status)}
                    <h2>DKIM Signature</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge">{results.dkim.status}</span>
                    {results.dkim.record ? (
                      <>
                        <p className="selector">Selector: <strong>{results.dkim.selector}</strong></p>
                        <p className="code-block truncate">{results.dkim.record}</p>
                      </>
                    ) : <p className="message">{results.dkim.message}</p>}
                  </div>
                </div>

                <div className={`card ${results.virustotal.status.toLowerCase()}`}>
                  <div className="card-header">
                    {getStatusIcon(results.virustotal.status)}
                    <h2>Threat Intelligence</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge">{results.virustotal.status}</span>
                    <p className="message">{results.virustotal.message}</p>
                  </div>
                </div>

              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

export default App