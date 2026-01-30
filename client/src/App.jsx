import React, { useState } from 'react';
import Dashboard from './Dashboard';

function App() {
  const [user, setUser] = useState(null);
  const [step, setStep] = useState('login'); // login, 2fa, dashboard
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    try {
      const res = await fetch('http://localhost:3001/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.ok) {
        setStep('2fa');
        setMessage(data.message); // "Enter OTP..."
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Connection refused. Is backend running?');
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch('http://localhost:3001/api/verify-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, otp })
      });
      const data = await res.json();

      if (res.ok) {
        setUser(data.user);
        setStep('dashboard');
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Connection Error');
    }
  };

  const handleLogout = async () => {
    await fetch('http://localhost:3001/api/logout', { method: 'POST', credentials: 'include' });
    setUser(null);
    setStep('login');
    setUsername('');
    setPassword('');
    setOtp('');
    setMessage('');
  };

  if (step === 'dashboard' && user) {
    return <Dashboard user={user} onLogout={handleLogout} />;
  }

  return (
    <div className="container center-screen" style={{ position: 'relative', overflow: 'hidden' }}>
      {/* Background decoration */}
      <div style={{
        position: 'absolute', top: 0, left: 0, width: '100%', height: '100%',
        pointerEvents: 'none', opacity: 0.2,
        backgroundImage: "url('https://www.transparenttextures.com/patterns/carbon-fibre.png')"
      }}></div>

      <div className="card" style={{ width: '100%', maxWidth: '450px', position: 'relative', zIndex: 10 }}>
        <div className="text-center" style={{ marginBottom: '2rem' }}>
          <h1 className="uppercase" style={{ letterSpacing: '0.1em' }}>Vanguard</h1>
          <div style={{ height: '4px', width: '80px', backgroundColor: 'var(--color-military-accent)', margin: '0.5rem auto' }}></div>
          <p className="uppercase" style={{ fontSize: '0.75rem', letterSpacing: '0.1em' }}>RESTRICTED ACCESS ONLY</p>
        </div>

        {error && <div className="alert alert-error text-center">{error}</div>}
        {message && <div className="alert alert-success text-center">{message}</div>}

        {step === 'login' ? (
          <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', marginBottom: '0.25rem' }}>IDENTIFIER</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="input-field"
                placeholder="Enter Username"
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', marginBottom: '0.25rem' }}>ACCESS CODE</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input-field"
                placeholder="Enter Password"
              />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }}>
              INITIATE LOGIN SEQUENCE
            </button>
            <div className="text-center" style={{ fontSize: '0.75rem', color: 'var(--color-military-600)', marginTop: '1rem' }}>
              <p>Demo Credentials: colonel / sergeant / soldier</p>
              <p>Password: password123</p>
            </div>
          </form>
        ) : (
          <form onSubmit={handleVerifyOtp} style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <div className="text-center" style={{ marginBottom: '1rem' }}>
              <p className="text-accent" style={{ fontSize: '0.875rem' }}>SECURE TOKEN REQUIRED</p>
              <p style={{ fontSize: '0.75rem', color: 'var(--color-military-600)' }}>Check server console for OTP Code</p>
            </div>
            <div>
              <input
                type="text"
                value={otp}
                onChange={e => setOtp(e.target.value)}
                maxLength={6}
                className="input-field text-accent text-center"
                style={{ fontSize: '1.5rem', letterSpacing: '0.5em' }}
                placeholder="000000"
              />
            </div>
            <button type="submit" className="btn btn-accent" style={{ width: '100%' }}>
              VERIFY IDENTITY
            </button>
            <button type="button" onClick={() => setStep('login')} className="btn" style={{ width: '100%', fontSize: '0.75rem', background: 'transparent' }}>
              ABORT SEQUENCE
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default App;
