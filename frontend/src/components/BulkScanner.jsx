import React, { useState } from 'react';
import axios from 'axios';
import { UploadCloud, AlertCircle, CheckCircle } from 'lucide-react';

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
    <div className="bg-gray-800 p-6 rounded-xl border border-gray-700 mt-6 shadow-lg">
      <h2 className="text-xl font-bold text-white mb-4 flex items-center justify-center text-center w-full">
        <UploadCloud className="mr-2 text-blue-400" />
        Bulk Domain Scanner 
      </h2>
      
      <div className="flex items-center space-x-4 mb-6 border-2 border-dashed border-gray-600 p-4 rounded-lg bg-gray-900">
        <input 
          type="file" 
          accept=".csv" 
          onChange={handleFileChange} 
          className="text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-700 cursor-pointer"
        />
        <button 
          onClick={handleUpload}
          disabled={loading}
          className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded-lg transition duration-200"
        >
          {loading ? "Scanning..." : "Upload & Scan"}
        </button>
      </div>

      {results.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left text-gray-300 border-collapse">
            <thead>
              <tr className="bg-gray-700 border-b border-gray-600">
                <th className="p-3 font-semibold">Domain</th>
                <th className="p-3 font-semibold">SPF</th>
                <th className="p-3 font-semibold">DMARC</th>
                <th className="p-3 font-semibold">VirusTotal</th>
              </tr>
            </thead>
            <tbody>
              {results.map((res, index) => (
                <tr key={index} className="border-b border-gray-700 hover:bg-gray-750">
                  <td className="p-3 font-medium text-white">{res.domain}</td>
                  <td className="p-3">
                    {res.spf_status === "Secure" || res.spf_status === "Pass" ? 
                      <span className="text-green-400 flex"><CheckCircle size={18} className="mr-1"/> Secure</span> : 
                      <span className="text-red-400 flex"><AlertCircle size={18} className="mr-1"/> Vulnerable</span>}
                  </td>
                  <td className="p-3">
                    {res.dmarc_status === "Secure" || res.dmarc_status === "Pass" ? 
                      <span className="text-green-400 flex"><CheckCircle size={18} className="mr-1"/> Secure</span> : 
                      <span className="text-red-400 flex"><AlertCircle size={18} className="mr-1"/> Vulnerable</span>}
                  </td>
                  <td className="p-3">
                     {res.virustotal_status === "Clean" || res.virustotal_status === "Safe" ? 
                      <span className="text-green-400 flex"><CheckCircle size={18} className="mr-1"/> Clean</span> : 
                      <span className="text-yellow-400 flex"><AlertCircle size={18} className="mr-1"/> Warning</span>}
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