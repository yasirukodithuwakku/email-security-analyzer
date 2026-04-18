import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ShieldCheck, KeyRound, Loader } from 'lucide-react';

const ResetPasswordPage = () => {
  const [token, setToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  //Loading the token from the URL when the component mounts
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const urlToken = urlParams.get('token');
    
    if (urlToken) {
      setToken(urlToken);
    } else {
      setError("Invalid or missing reset token in the URL.");
    }
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    // Basic client-side validation for password match
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match!");
      setLoading(false);
      return;
    }

    try {
      const response = await axios.post('/api/reset-password', {
        token: token,
        new_password: newPassword
      });
      
      setSuccess(response.data.message);
      setNewPassword('');
      setConfirmPassword('');
      
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', backgroundColor: '#0f172a' }}>
      <div className="bulk-scanner-card" style={{ width: '100%', maxWidth: '400px', padding: '2rem' }}>
        
        <div className="bulk-header" style={{ justifyContent: 'center', marginBottom: '1rem' }}>
          <ShieldCheck size={40} style={{ color: '#3b82f6' }} />
        </div>
        
        <h2 style={{ textAlign: 'center', color: 'white', marginBottom: '1.5rem' }}>
          Set New Password
        </h2>

        {error && <div className="error-message" style={{ marginBottom: '1rem', padding: '10px', borderRadius: '5px' }}>{error}</div>}
        {success && (
          <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#10b981', padding: '10px', borderRadius: '5px', marginBottom: '1rem', border: '1px solid #10b981', textAlign: 'center' }}>
            {success} <br/><br/>
            <a href="/" style={{ color: '#3b82f6', textDecoration: 'underline', fontWeight: 'bold' }}>Go to Login</a>
          </div>
        )}


        {token && !success && (
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            
            <input
              type="password"
              placeholder="New Password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              required
              style={{ padding: '12px', borderRadius: '8px', border: '1px solid #334155', backgroundColor: '#1e293b', color: 'white', fontSize: '1rem' }}
            />

            <input
              type="password"
              placeholder="Confirm New Password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              required
              style={{ padding: '12px', borderRadius: '8px', border: '1px solid #334155', backgroundColor: '#1e293b', color: 'white', fontSize: '1rem' }}
            />

            <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '-5px' }}>
              Password must be at least 8 characters, with 1 uppercase letter and 1 number.
            </div>

            <button type="submit" disabled={loading} style={{ padding: '12px', borderRadius: '8px', backgroundColor: '#3b82f6', color: 'white', fontSize: '1rem', fontWeight: 'bold', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '10px', marginTop: '10px' }}>
              {loading ? <Loader className="spin" size={20} /> : <KeyRound size={20} />}
              {loading ? 'Saving...' : 'Reset Password'}
            </button>
          </form>
        )}
        
      </div>
    </div>
  );
};

export default ResetPasswordPage;