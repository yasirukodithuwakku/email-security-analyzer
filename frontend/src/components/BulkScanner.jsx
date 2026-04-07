import React, { useState } from 'react';
import axios from 'axios';
import { UploadCloud, AlertCircle, CheckCircle, Loader } from 'lucide-react';

const BulkScanner = () => {
  const [file, setFile] = useState(null);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleUpload = async () => {
    if (!file) return alert("Please select a CSV file first!");
    
    setLoading(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await axios.post("http://127.0.0.1:8000/api/bulk-analyze/", formData, {
        headers: { "Content-Type": "multipart/form-data" }
      });
      setResults(response.data.results);
    } catch (error) {
      console.error("Error uploading file:", error);
      alert("Error processing the file.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bulk-scanner-card">
      <div className="bulk-header">
        <UploadCloud size={28} className="icon info" />
        <h2>Enterprise Bulk Scanner</h2>
      </div>
      
      <div className="bulk-upload-area">
        <input 
          type="file" 
          accept=".csv" 
          onChange={handleFileChange} 
          className="bulk-file-input"
        />
        <button 
          onClick={handleUpload}
          disabled={loading}
          className="bulk-upload-btn"
        >
          {loading ? <Loader className="spin" size={18} /> : <UploadCloud size={18} />}
          {loading ? "Scanning..." : "Upload & Scan"}
        </button>
      </div>

      {results.length > 0 && (
        <div className="bulk-results-container">
          <table className="bulk-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>SPF Record</th>
                <th>DMARC Policy</th>
                <th>Threat Intelligence</th>
              </tr>
            </thead>
            <tbody>
              {results.map((res, index) => (
                <tr key={index}>
                  <td className="domain-name">{res.domain}</td>
                  <td>
                    {res.spf_status === "Secure" || res.spf_status === "Pass" ? 
                      <span className="status-badge secure"><CheckCircle size={16}/> Secure</span> : 
                      <span className="status-badge vulnerable"><AlertCircle size={16}/> Vulnerable</span>}
                  </td>
                  <td>
                    {res.dmarc_status === "Secure" || res.dmarc_status === "Pass" ? 
                      <span className="status-badge secure"><CheckCircle size={16}/> Secure</span> : 
                      <span className="status-badge vulnerable"><AlertCircle size={16}/> Vulnerable</span>}
                  </td>
                  <td>
                     {res.virustotal_status === "Clean" || res.virustotal_status === "Safe" ? 
                      <span className="status-badge secure"><CheckCircle size={16}/> Clean</span> : 
                      <span className="status-badge warning"><AlertCircle size={16}/> Warning</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default BulkScanner;