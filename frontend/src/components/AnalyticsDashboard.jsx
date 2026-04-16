import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Activity, ShieldAlert, ShieldCheck } from 'lucide-react';

const AnalyticsDashboard = () => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await axios.get('/api/scan-history/')
      if (Array.isArray(response.data)) {
        setHistory(response.data);
      }
    } catch (error) {
      console.error("Error fetching history:", error);
    } finally {
      setLoading(false);
    }
  };

  
  const secureCount = history.filter(item => item.risk_status === 'Secure').length;
  const warningCount = history.filter(item => item.risk_status === 'Warning').length;
  const vulnerableCount = history.filter(item => item.risk_status === 'Vulnerable').length;

  const chartData = [
    { name: 'Secure', value: secureCount, color: '#10b981' }, 
    { name: 'Warning', value: warningCount, color: '#f59e0b' },
    { name: 'Vulnerable', value: vulnerableCount, color: '#ef4444' } 
  ];

  if (loading) return <div style={{ color: 'white', textAlign: 'center' }}>Loading Dashboard Data...</div>;

  return (
    <div className="bulk-scanner-card" style={{ maxWidth: '900px' }}>
      <div className="bulk-header">
        <Activity size={28} style={{ color: '#3b82f6' }} />
        <h2>Security Operations Center (SOC) Dashboard</h2>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-around', margin: '2rem 0' }}>
        <div className="card secure" style={{ padding: '1.5rem', textAlign: 'center', flex: 1, margin: '0 10px' }}>
          <ShieldCheck size={32} style={{ margin: '0 auto 10px' }} />
          <h3>Secure Domains</h3>
          <p style={{ fontSize: '2rem', fontWeight: 'bold' }}>{secureCount}</p>
        </div>
        <div className="card warning" style={{ padding: '1.5rem', textAlign: 'center', flex: 1, margin: '0 10px' }}>
          <Activity size={32} style={{ margin: '0 auto 10px' }} />
          <h3>Total Scans</h3>
          <p style={{ fontSize: '2rem', fontWeight: 'bold' }}>{history.length}</p>
        </div>
        <div className="card" style={{ border: '1px solid #ef4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', padding: '1.5rem', textAlign: 'center', flex: 1, margin: '0 10px', borderRadius: '12px' }}>
          <ShieldAlert size={32} color="#ef4444" style={{ margin: '0 auto 10px' }} />
          <h3 style={{ color: '#ef4444' }}>Threats Found</h3>
          <p style={{ fontSize: '2rem', fontWeight: 'bold', color: '#ef4444' }}>{vulnerableCount}</p>
        </div>
      </div>

      {history.length > 0 && (
        <div style={{ height: '300px', width: '100%', marginTop: '2rem' }}>
          <h3 style={{ textAlign: 'center', color: '#94a3b8', marginBottom: '1rem' }}>Overall Risk Distribution</h3>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie data={chartData} cx="50%" cy="50%" innerRadius={60} outerRadius={100} paddingAngle={5} dataKey="value">
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1e293b', border: 'none', borderRadius: '8px', color: 'white' }} />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

export default AnalyticsDashboard;