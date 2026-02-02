import React, { useState, useEffect, useRef } from 'react';
import Dashboard from './Dashboard';

function App() {
  const [user, setUser] = useState(null);
  const [step, setStep] = useState('login'); // login, register, 2fa, dashboard
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  // Typing effect state
  const [typedTitle, setTypedTitle] = useState('');
  const titleText = "VANGUARD COMMAND";

  // Idle Timer
  const idleTimerRef = useRef(null);
  const IDLE_LIMIT = 5 * 60 * 1000; // 5 Minutes

  useEffect(() => {
    let i = 0;
    const typing = setInterval(() => {
      if (i < titleText.length) {
        setTypedTitle(titleText.slice(0, i + 1));
        i++;
      } else {
        clearInterval(typing);
      }
    }, 100);
    return () => clearInterval(typing);
  }, []);

  // Idle Detection System
  useEffect(() => {
    if (!user) return; // Only track when logged in

    const resetTimer = () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      idleTimerRef.current = setTimeout(() => {
        handleLogout(true); // True = auto logout
      }, IDLE_LIMIT);
    };

    // Events to track
    const events = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'];
    events.forEach(e => window.addEventListener(e, resetTimer));

    resetTimer(); // Start timer immediately

    return () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
      events.forEach(e => window.removeEventListener(e, resetTimer));
    };
  }, [user]);

  // Session Persistence
  useEffect(() => {
    const checkSession = async () => {
      try {
        const res = await fetch('http://localhost:3001/api/me', {
          credentials: 'include'
        });
        if (res.ok) {
          const data = await res.json();
          setUser(data.user);
          setStep('dashboard');
        }
      } catch (err) {
        // No active session
      }
    };
    checkSession();
  }, []);

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
        setMessage(data.message);
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Connection refused. Is backend running?');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setMessage('');
    try {
      const res = await fetch('http://localhost:3001/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();

      if (res.ok) {
        setStep('login');
        setMessage(data.message);
        setPassword('');
      } else {
        setError(data.error);
      }
    } catch (err) {
      setError('Registration Failed');
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

  const handleLogout = async (isAuto = false) => {
    try {
      await fetch('http://localhost:3001/api/logout', { method: 'POST', credentials: 'include' });
    } catch (e) {
      // Ignore error on logout
    }
    setUser(null);
    setStep('login');
    setUsername('');
    setPassword('');
    setOtp('');
    setTypedTitle('');

    if (isAuto) {
      setError('SESSION TERMINATED: INACTIVITY DETECTED');
    } else {
      setMessage('');
      setError('');
    }
  };

  if (step === 'dashboard' && user) {
    return <Dashboard user={user} onLogout={() => handleLogout(false)} />;
  }

  // ... (Rest of render remains the same, just keeping the component structure)
  return (
    <div className="container center-screen bg-grid bg-scanlines" style={{ position: 'relative', overflow: 'hidden' }}>

      {/* HUD DECORATIONS (Top Left / Bottom Right) */}
      <div style={{ position: 'absolute', top: '20px', left: '20px', padding: '10px', borderTop: '2px solid var(--color-hud-cyan)', borderLeft: '2px solid var(--color-hud-cyan)', width: '100px', height: '100px', opacity: 0.5 }}></div>
      <div style={{ position: 'absolute', bottom: '20px', right: '20px', padding: '10px', borderBottom: '2px solid var(--color-hud-cyan)', borderRight: '2px solid var(--color-hud-cyan)', width: '100px', height: '100px', opacity: 0.5 }}></div>

      <div className="card" style={{ width: '100%', maxWidth: '500px', position: 'relative', zIndex: 10 }}>
        <div className="text-center" style={{ marginBottom: '2.5rem' }}>
          <h1 className="uppercase text-accent" style={{ fontSize: '2.5rem', letterSpacing: '0.1em', marginBottom: '0.5rem', minHeight: '3rem' }}>
            {typedTitle}<span style={{ animation: 'blink 1s infinite' }}>_</span>
          </h1>
          <div style={{ height: '2px', width: '100px', backgroundColor: 'var(--color-hud-amber)', margin: '0.5rem auto', boxShadow: '0 0 10px var(--color-hud-amber)' }}></div>
          <p className="uppercase" style={{ fontSize: '0.9rem', letterSpacing: '0.3em', color: 'var(--color-hud-dim)' }}>SECURE ACCESS TERMINAL</p>
        </div>

        {error && <div className="alert alert-error text-center">{error}</div>}
        {message && <div className="alert alert-success text-center">{message}</div>}

        {step === 'login' || step === 'register' ? (
          <form onSubmit={step === 'login' ? handleLogin : handleRegister} style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--color-hud-dim)', letterSpacing: '0.1rem' }}>IDENTIFIER</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                className="input-field"
                placeholder="ENTER USERNAME"
                autoComplete="off"
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.85rem', marginBottom: '0.5rem', color: 'var(--color-hud-dim)', letterSpacing: '0.1rem' }}>ACCESS CODE</label>
              <input
                type="password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input-field"
                placeholder="ENTER PASSWORD"
              />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%', fontSize: '1.2rem', padding: '1rem' }}>
              {step === 'login' ? 'INITIATE LOGIN SEQUENCE' : 'SUBMIT REGISTRATION DATA'}
            </button>

            <div className="text-center" style={{ fontSize: '0.9rem', color: 'var(--color-hud-dim)', marginTop: '0.5rem', cursor: 'pointer' }}>
              {step === 'login' ? (
                <span onClick={() => { setStep('register'); setError(''); setMessage(''); }}>[ NEW RECRUIT? REGISTER IDENTITY ]</span>
              ) : (
                <span onClick={() => { setStep('login'); setError(''); setMessage(''); }}>[ ALREADY CLEARED? LOGIN ]</span>
              )}
            </div>

            {step === 'login' && (
              <div className="text-center" style={{ fontSize: '0.8rem', color: 'var(--color-hud-dim)', marginTop: '2rem', borderTop: '1px solid #333', paddingTop: '1rem' }}>
                <p>DEMO ACCESS: colonel / sergeant / soldier</p>
                <p>PWD: password123</p>
              </div>
            )}
          </form>
        ) : (
          <form onSubmit={handleVerifyOtp} style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
            <div className="text-center" style={{ marginBottom: '1rem' }}>
              <p className="text-accent" style={{ fontSize: '1.2rem', animation: 'blink 2s infinite' }}>⚠ SECURE TOKEN REQUIRED ⚠</p>
              <p style={{ fontSize: '0.9rem', color: 'var(--color-hud-dim)', marginTop: '0.5rem' }}>// CHECK SECURE CHANNEL (CONSOLE) FOR OTP //</p>
            </div>
            <div>
              <input
                type="text"
                value={otp}
                onChange={e => setOtp(e.target.value)}
                maxLength={6}
                className="input-field text-accent text-center"
                style={{ fontSize: '2.5rem', letterSpacing: '0.5em', border: '2px solid var(--color-hud-amber)' }}
                placeholder="000000"
              />
            </div>
            <button type="submit" className="btn btn-accent" style={{ width: '100%', fontSize: '1.2rem', padding: '1rem' }}>
              VERIFY IDENTITY
            </button>
            <button type="button" onClick={() => setStep('login')} className="btn" style={{ width: '100%', fontSize: '0.8rem', background: 'transparent', opacity: 0.7 }}>
              ABORT SEQUENCE
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default App;
