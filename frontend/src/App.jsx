import { useState } from 'react'
import axios from 'axios'
import { Shield, ShieldAlert, ShieldCheck, Search, Loader, Info, Download } from 'lucide-react'
import html2pdf from 'html2pdf.js'
import './index.css'

function App() {
  const [domain, setDomain] = useState('')
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
      setError("Failed to connect to the server. Make sure your Python backend is running.")
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

  return (
    <div className="dashboard">
      <header>
        <h1><Shield className="header-icon" /> Email Security Analyzer</h1>
        <p>Advanced DNS vulnerability scanning for SPF, DMARC, and DKIM</p>
      </header>

      <main>
        <form onSubmit={analyzeDomain} className="search-bar">
          <input
            type="text"
            placeholder="Enter domain (e.g., google.com)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
          />
          <button type="submit" disabled={loading}>
            {loading ? <Loader className="spin" /> : <Search />}
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
        </form>

        {error && <div className="error-message">{error}</div>}

        {results && (
          <div className="report-wrapper">
            <div className="report-actions">
              <button onClick={downloadPDF} className="download-btn">
                <Download size={18} /> Download PDF Report
              </button>
            </div>

            <div id="report-content" className="pdf-container">
              <h2 className="report-title">Target Domain: {results.domain}</h2>
              <div className="results-grid">
                
                {/* SPF Card */}
                <div className={`card ${results.spf.status.toLowerCase()}`}>
                  <div className="card-header">
                    {getStatusIcon(results.spf.status)}
                    <h2>SPF Record</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge">{results.spf.status}</span>
                    {results.spf.record ? (
                      <p className="code-block">{results.spf.record}</p>
                    ) : (
                      <p className="message">{results.spf.message}</p>
                    )}
                  </div>
                </div>

                {/* DMARC Card */}
                <div className={`card ${results.dmarc.status.toLowerCase()}`}>
                  <div className="card-header">
                    {getStatusIcon(results.dmarc.status)}
                    <h2>DMARC Policy</h2>
                  </div>
                  <div className="card-body">
                    <span className="badge">{results.dmarc.status}</span>
                    {results.dmarc.record ? (
                      <p className="code-block">{results.dmarc.record}</p>
                    ) : (
                      <p className="message">{results.dmarc.message}</p>
                    )}
                  </div>
                </div>

                {/* DKIM Card */}
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
                    ) : (
                      <p className="message">{results.dkim.message}</p>
                    )}
                  </div>
                </div>

                {/* Threat Intelligence Card */}
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
