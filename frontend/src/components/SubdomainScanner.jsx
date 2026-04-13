import React, { useState } from 'react';
import axios from 'axios';
import { Search, Server, Network, Unlock, Loader, ShieldAlert } from 'lucide-react';

const SubdomainScanner = () => {
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const runNetworkScan = async (e) => {
    e.preventDefault();
    if (!domain) return;
    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await axios.get(`http://127.0.0.1:8000/api/network-scan/${domain}`);
      if (response.data.status === "Success") {
        setResults(response.data);
      } else {
        setError("Failed to scan network.");
      }
    } catch (err) {
      setError("Failed to connect to the server or target took too long to respond.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bulk-scanner-card" style={{ maxWidth: '900px' }}>
      <div className="bulk-header">
        <Network size={28} style={{ color: '#8b5cf6' }} />
        <h2>VAPT: Network & Subdomain Scanner</h2>
      </div>
      <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>Discover hidden subdomains via Certificate Transparency logs and perform active port scanning for open services.</p>

      <form onSubmit={runNetworkScan} style={{ display: 'flex', gap: '10px', marginBottom: '2rem' }}>
        <input
          type="text"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="Enter target domain"
          style={{ flex: 1, padding: '12px', backgroundColor: '#0f172a', color: 'white', border: '1px solid #334155', borderRadius: '8px' }}
          required
        />
        <button 
          type="submit" 
          disabled={loading}
          style={{ padding: '12px 24px', backgroundColor: '#8b5cf6', color: 'white', border: 'none', borderRadius: '8px', cursor: loading ? 'not-allowed' : 'pointer', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '10px' }}
        >
          {loading ? <Loader className="spin" size={20} /> : <Search size={20} />}
          {loading ? 'Scanning...' : 'Start Scan'}
        </button>
      </form>

      {error && <div style={{ marginBottom: '1.5rem', padding: '1rem', backgroundColor: 'rgba(239, 68, 68, 0.1)', color: '#ef4444', border: '1px solid #ef4444', borderRadius: '8px' }}>{error}</div>}

      {results && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Open Ports Section */}
          <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'white', marginBottom: '1rem' }}><Unlock size={20} color="#ef4444"/> Open Ports & Services</h3>
            {results.open_ports.length > 0 ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '10px' }}>
                {results.open_ports.map((portInfo, idx) => (
                  <div key={idx} style={{ backgroundColor: '#0f172a', padding: '10px', borderRadius: '5px', borderLeft: '3px solid #ef4444' }}>
                    <div style={{ color: '#ef4444', fontWeight: 'bold', fontSize: '1.1rem' }}>Port {portInfo.port}</div>
                    <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>{portInfo.service}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '5px' }}><ShieldAlert size={16}/> No common vulnerable ports detected open.</p>
            )}
          </div>

          {/* Subdomains Section */}
          <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '8px', border: '1px solid #334155' }}>
            <h3 style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: 'white', marginBottom: '1rem' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '10px' }}><Server size={20} color="#3b82f6"/> Discovered Subdomains</span>
              <span style={{ fontSize: '0.8rem', backgroundColor: '#3b82f6', padding: '2px 8px', borderRadius: '10px' }}>Total Found: {results.total_subdomains_found}</span>
            </h3>
            
            {results.subdomains.length > 0 ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {results.subdomains.map((sub, idx) => (
                  <span key={idx} style={{ backgroundColor: '#0f172a', color: '#60a5fa', padding: '5px 10px', borderRadius: '5px', fontSize: '0.9rem', border: '1px solid #1e3a8a' }}>
                    {sub}
                  </span>
                ))}
              </div>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: '0.9rem' }}>No subdomains found in Certificate Logs.</p>
            )}
            {results.total_subdomains_found > 20 && (
              <p style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '10px', fontStyle: 'italic' }}>* Displaying top 20 results.</p>
            )}
          </div>

        </div>
      )}
    </div>
  );
};

export default SubdomainScanner;