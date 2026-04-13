import React, { useState } from 'react';
import axios from 'axios';
import { Search, Server, ShieldCheck, Mail, Loader } from 'lucide-react';

const EmailHeaderAnalyzer = () => {
  const [headerText, setHeaderText] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const analyzeHeader = async () => {
    if (!headerText.trim()) return;
    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await axios.post("http://127.0.0.1:8000/api/analyze-header/", {
        headers: headerText
      });

      if (response.data.status === "Success") {
        setResults(response.data.data);
      } else {
        setError(response.data.message);
      }
    } catch (err) {
      setError("Failed to connect to the server.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bulk-scanner-card" style={{ maxWidth: '900px' }}>
      <div className="bulk-header">
        <Search size={28} style={{ color: '#3b82f6' }} />
        <h2>Forensic Email Header Analyzer</h2>
      </div>
      <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>Paste the raw email header below to trace its origin, route, and authentication status.</p>

      <textarea
        value={headerText}
        onChange={(e) => setHeaderText(e.target.value)}
        placeholder="Paste Raw Email Header here... (e.g., Delivered-To: user@example.com\nReceived: by 2002:a05:...)"
        style={{ width: '100%', height: '200px', backgroundColor: '#0f172a', color: '#10b981', padding: '1rem', borderRadius: '8px', border: '1px solid #334155', fontFamily: 'monospace', marginBottom: '1rem' }}
      />

      <button 
        onClick={analyzeHeader} 
        disabled={loading}
        style={{ padding: '12px 24px', backgroundColor: '#3b82f6', color: 'white', border: 'none', borderRadius: '8px', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '10px' }}
      >
        {loading ? <Loader className="spin" size={20} /> : <Search size={20} />}
        {loading ? 'Analyzing Header...' : 'Analyze Header'}
      </button>

      {error && <div style={{ marginTop: '1.5rem', padding: '1rem', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid #ef4444', borderRadius: '8px' }}>{error}</div>}

      {results && (
        <div style={{ marginTop: '2rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Basic Info */}
          <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'white', marginBottom: '1rem' }}><Mail size={20} color="#3b82f6"/> Sender & Message Info</h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', color: '#cbd5e1', fontSize: '0.9rem' }}>
              <p><b>From:</b> {results.basic_info.From}</p>
              <p><b>To:</b> {results.basic_info.To}</p>
              <p><b>Subject:</b> {results.basic_info.Subject}</p>
              <p><b>Date:</b> {results.basic_info.Date}</p>
              <p><b>Return-Path:</b> {results.basic_info.Return_Path}</p>
              <p><b>Message-ID:</b> {results.basic_info['Message-ID']}</p>
            </div>
          </div>

          {/* Authentication */}
          <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'white', marginBottom: '1rem' }}><ShieldCheck size={20} color="#10b981"/> Authentication Results</h3>
            <p style={{ color: '#cbd5e1', fontSize: '0.9rem', fontFamily: 'monospace', backgroundColor: '#0f172a', padding: '10px', borderRadius: '5px' }}>
              {results.authentication}
            </p>
          </div>

          {/* Hops */}
          <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'white', marginBottom: '1rem' }}><Server size={20} color="#f59e0b"/> Routing Trail (Hops)</h3>
            {results.hops.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {results.hops.map((hop, index) => (
                  <div key={index} style={{ backgroundColor: '#0f172a', padding: '10px', borderRadius: '5px', fontSize: '0.85rem', color: '#94a3b8' }}>
                    <span style={{ color: '#f59e0b', fontWeight: 'bold' }}>Hop {hop.hop_number}: </span>
                    <span style={{ color: '#10b981', marginRight: '10px' }}>[IP: {hop.ip}]</span>
                    {hop.details}
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>No routing hops found.</p>
            )}
          </div>

        </div>
      )}
    </div>
  );
};

export default EmailHeaderAnalyzer;