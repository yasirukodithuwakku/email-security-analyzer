import React, { useState } from 'react';
import axios from 'axios';
import { ShieldCheck, UserPlus, LogIn, Loader } from 'lucide-react';

const AuthPage = ({ onLoginSuccess }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      if (isLogin) {
        
        const formData = new URLSearchParams();
        formData.append('username', username);
        formData.append('password', password);

        const response = await axios.post('/api/login', formData, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
        });

        
        localStorage.setItem('token', response.data.access_token);
        localStorage.setItem('username', response.data.username);
        
        onLoginSuccess(); 

      } else {
        
        const response = await axios.post('/api/signup', {
          username: username,
          password: password
        });
        
        setSuccess("Account created successfully! Please log in.");
        setIsLogin(true); 
        setPassword('');
      }
    } catch (err) {
      if (err.response && err.response.data && err.response.data.detail) {
        setError(err.response.data.detail);
      } else {
        setError("Unable to connect to the server. Please check your backend.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh', backgroundColor: '#0f172a' }}>
      <div className="bulk-scanner-card" style={{ width: '100%', maxWidth: '400px', padding: '2rem' }}>
        
        <div className="bulk-header" style={{ justifyContent: 'center', marginBottom: '2rem' }}>
          <ShieldCheck size={40} style={{ color: '#3b82f6' }} />
        </div>
        <h2 style={{ textAlign: 'center', color: 'white', marginBottom: '1.5rem' }}>
          {isLogin ? 'Welcome Back!' : 'Create an Account'}
        </h2>

        {error && <div className="error-message" style={{ marginBottom: '1rem', padding: '10px', borderRadius: '5px' }}>{error}</div>}
        {success && <div style={{ backgroundColor: 'rgba(16, 185, 129, 0.2)', color: '#10b981', padding: '10px', borderRadius: '5px', marginBottom: '1rem', border: '1px solid #10b981' }}>{success}</div>}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={{ padding: '12px', borderRadius: '8px', border: '1px solid #334155', backgroundColor: '#1e293b', color: 'white', fontSize: '1rem' }}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ padding: '12px', borderRadius: '8px', border: '1px solid #334155', backgroundColor: '#1e293b', color: 'white', fontSize: '1rem' }}
          />
          <button type="submit" disabled={loading} style={{ padding: '12px', borderRadius: '8px', backgroundColor: '#3b82f6', color: 'white', fontSize: '1rem', fontWeight: 'bold', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '10px' }}>
            {loading ? <Loader className="spin" size={20} /> : (isLogin ? <LogIn size={20} /> : <UserPlus size={20} />)}
            {loading ? 'Processing...' : (isLogin ? 'Log In' : 'Sign Up')}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '1.5rem', color: '#94a3b8' }}>
          {isLogin ? "Don't have an account? " : "Already have an account? "}
          <span 
            onClick={() => { setIsLogin(!isLogin); setError(''); setSuccess(''); }} 
            style={{ color: '#3b82f6', cursor: 'pointer', fontWeight: 'bold', textDecoration: 'underline' }}
          >
            {isLogin ? 'Sign up here' : 'Log in here'}
          </span>
        </div>

      </div>
    </div>
  );
};

export default AuthPage;