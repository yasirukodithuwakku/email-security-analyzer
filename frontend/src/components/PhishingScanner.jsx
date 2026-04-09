import React, { useState } from 'react';
import axios from 'axios';
import { ShieldAlert, ShieldCheck, Link, Loader } from 'lucide-react';

const PhishingScanner = () => {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleScan = async (e) => {
    e.preventDefault();
    if (!url) return;
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await axios.post("http://127.0.0.1:8000/api/check-phishing/", { url: url });
      setResult(response.data);
    } catch (err) {
      if (err.response && err.response.status === 429) {
        setError("⚠️ Rate limit exceeded! You are scanning too fast. Please wait a minute.");
      } else {
        setError("Failed to connect to the server.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bulk-scanner-card">
      <div className="bulk-header">
        <Link size={28} style={{ color: '#f59e0b' }} />
        <h2>Phishing URL Scanner</h2>
      </div>
      
      <form onSubmit={handleScan} className="search-bar" style={{ marginBottom: '2rem' }}>
        <input
          type="url"
          placeholder="Enter full URL (e.g., https://login.paypal-update.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
        />
        <button type="submit" disabled={loading} style={{ background: '#f59e0b', color: '#0f172a' }}>
          {loading ? <Loader className="spin" size={18} /> : <Link size={18} />}
          {loading ? "Scanning..." : "Scan URL"}
        </button>
      </form>

      {error && <div className="error-message">{error}</div>}

      {result && (
        <div className={`card ${result.status === 'Secure' ? 'secure' : 'warning'}`} style={{ marginTop: '2rem' }}>
          <div className="card-header">
            {result.status === 'Secure' ? <ShieldCheck size={24} className="icon secure" /> : <ShieldAlert size={24} className="icon warning" />}
            <h2>Scan Result: {result.status}</h2>
          </div>
          <div className="card-body">
            <span className={`badge ${result.status === 'Secure' ? 'secure' : 'warning'}`} style={{ marginBottom: '1rem' }}>
              {result.status}
            </span>
            <p className="message" style={{ fontSize: '1.1rem' }}>{result.message}</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default PhishingScanner;