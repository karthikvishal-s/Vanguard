import React, { useState, useEffect } from 'react';
import CryptoJS from 'crypto-js';

const Dashboard = ({ user, onLogout }) => {
    const [activeTab, setActiveTab] = useState('overview');
    const [vaultData, setVaultData] = useState(null);
    const [decryptedIntel, setDecryptedIntel] = useState(null);
    const [logistics, setLogistics] = useState([]);
    const [qrCode, setQrCode] = useState(null);
    const [signMessage, setSignMessage] = useState('');
    const [signatureResult, setSignatureResult] = useState(null);
    const [verifyMessage, setVerifyMessage] = useState('');
    const [verifySignature, setVerifySignature] = useState('');
    const [verificationResult, setVerificationResult] = useState(null);
    const [error, setError] = useState('');

    useEffect(() => {
        if (user.role >= 1) fetchQr();
        if (user.role >= 2) fetchLogistics();
    }, [user]);

    const fetchQr = async () => {
        try {
            const res = await fetch('http://localhost:3001/api/me', { credentials: 'include' });
            const data = await res.json();
            if (data.qrCode) setQrCode(data.qrCode);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchLogistics = async () => {
        try {
            const res = await fetch('http://localhost:3001/api/logistics', { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                setLogistics(data.data);
            }
        } catch (err) {
            console.error(err);
        }
    };

    const fetchVault = async () => {
        setError('');
        try {
            const res = await fetch('http://localhost:3001/api/vault', { credentials: 'include' });
            if (res.status === 403) {
                setError('ACCESS DENIED: Insufficient Clearance Level.');
                return;
            }
            const data = await res.json();
            setVaultData(data);
        } catch (err) {
            setError('Connection Error');
        }
    };

    const decryptVault = () => {
        if (!vaultData) return;
        const key = CryptoJS.enc.Hex.parse(vaultData.key);
        const iv = CryptoJS.enc.Hex.parse(vaultData.iv);

        const decrypted = CryptoJS.AES.decrypt(
            { ciphertext: CryptoJS.enc.Hex.parse(vaultData.encryptedData) },
            key,
            { iv: iv }
        );
        setDecryptedIntel(decrypted.toString(CryptoJS.enc.Utf8));
    };

    const handleSign = async () => {
        try {
            const res = await fetch('http://localhost:3001/api/sign', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ message: signMessage })
            });
            const data = await res.json();
            setSignatureResult(data);
        } catch (err) {
            console.error(err);
        }
    };

    const handleVerify = async () => {
        try {
            const res = await fetch('http://localhost:3001/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ message: verifyMessage, signature: verifySignature })
            });
            const data = await res.json();
            setVerificationResult(data);
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div style={{ padding: '2rem', minHeight: '100vh' }}>
            <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--color-military-700)', paddingBottom: '1rem', marginBottom: '2rem' }}>
                <div>
                    <h1 style={{ fontSize: '1.8rem', fontWeight: 'bold', letterSpacing: '0.1em' }} className="uppercase text-accent">Vanguard Command</h1>
                    <p style={{ fontSize: '0.875rem', color: 'var(--color-military-600)' }}>Secure Personnel Management System</p>
                </div>
                <div style={{ textAlign: 'right' }}>
                    <div className="text-accent font-bold">{user.username.toUpperCase()}</div>
                    <div style={{ fontSize: '0.75rem', backgroundColor: 'var(--color-military-800)', padding: '0.25rem 0.5rem', borderRadius: '0.25rem', display: 'inline-block', marginTop: '0.25rem', border: '1px solid var(--color-military-700)' }}>
                        {user.roleName} | LEVEL {user.role}
                    </div>
                </div>
                <button
                    onClick={onLogout}
                    className="btn btn-logout"
                    style={{ marginLeft: '1rem' }}
                >
                    LOGOUT
                </button>
            </header>

            <div className="grid-dashboard">
                {/* Sidebar Navigation */}
                <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <NavBtn label="OVERVIEW" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
                    {user.role >= 1 && <NavBtn label="SERVICE RECORD" active={activeTab === 'record'} onClick={() => setActiveTab('record')} />}
                    {user.role >= 2 && <NavBtn label="LOGISTICS" active={activeTab === 'logistics'} onClick={() => setActiveTab('logistics')} />}
                    {user.role >= 3 && <NavBtn label="TOP SECRET VAULT" active={activeTab === 'vault'} onClick={() => { setActiveTab('vault'); fetchVault(); }} />}
                    {user.role >= 3 && <NavBtn label="SIGN ORDER" active={activeTab === 'sign'} onClick={() => setActiveTab('sign')} />}
                    <NavBtn label="VERIFY INTEGRITY" active={activeTab === 'verify'} onClick={() => setActiveTab('verify')} />
                </nav>

                {/* Main Content Area */}
                <main className="card" style={{ minHeight: '500px' }}>

                    {activeTab === 'overview' && (
                        <div className="text-center" style={{ paddingTop: '3rem' }}>
                            <h2 style={{ marginBottom: '1rem' }}>WELCOME TO VANGUARD</h2>
                            <p>Select a module from the navigation menu.</p>
                            <div style={{ marginTop: '2rem', padding: '1rem', backgroundColor: 'var(--color-military-900)', border: '1px solid var(--color-military-700)', display: 'inline-block', borderRadius: '0.25rem' }}>
                                <p style={{ fontSize: '0.75rem', color: 'var(--color-military-600)', marginBottom: '0.5rem' }}>SYSTEM STATUS</p>
                                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                    <span style={{ width: '12px', height: '12px', backgroundColor: 'var(--color-military-success)', borderRadius: '50%', display: 'inline-block' }}></span>
                                    <span>OPERATIONAL</span>
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'record' && (
                        <div>
                            <h2>PERSONAL SERVICE RECORD</h2>
                            <div style={{ display: 'flex', gap: '2rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
                                <div style={{ backgroundColor: 'white', padding: '0.5rem', borderRadius: '0.25rem' }}>
                                    {qrCode ? <img src={qrCode} alt="ID QR Code" style={{ width: '128px', height: '128px' }} /> : "Generating ID..."}
                                </div>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                    <Detail label="NAME" value={user.username} />
                                    <Detail label="RANK" value={user.roleName} />
                                    <Detail label="CLEARANCE" value={`LEVEL ${user.role}`} />
                                    <Detail label="STATUS" value="ACTIVE DUTY" />
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'logistics' && (
                        <div>
                            <h2>LOGISTICS MANIFEST</h2>
                            {logistics.length === 0 ? <p>Loading manifest...</p> : (
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>ID</th>
                                            <th>ITEM</th>
                                            <th>QTY</th>
                                            <th>STATUS</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {logistics.map(item => (
                                            <tr key={item.id}>
                                                <td style={{ fontFamily: 'monospace' }}>{item.id}</td>
                                                <td>{item.item}</td>
                                                <td>{item.quantity}</td>
                                                <td className={item.status === 'Low' ? 'text-danger' : 'text-success'}>{item.status}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}

                    {activeTab === 'vault' && (
                        <div>
                            <h2>TOP SECRET VAULT</h2>
                            {error && <div className="alert alert-error">{error}</div>}

                            {vaultData ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                                    <div style={{ backgroundColor: 'var(--color-military-900)', padding: '1rem', borderRadius: '0.25rem', border: '1px solid var(--color-military-600)' }}>
                                        <label style={{ fontSize: '0.75rem', color: 'var(--color-military-600)', display: 'block', marginBottom: '0.25rem' }}>ENCRYPTED DATA STREAM</label>
                                        <code style={{ fontSize: '0.75rem', wordBreak: 'break-all', fontFamily: 'monospace' }}>{vaultData.encryptedData}</code>
                                    </div>

                                    <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                                        <button
                                            onClick={decryptVault}
                                            className="btn btn-accent"
                                        >
                                            INITIATE DECRYPTION
                                        </button>
                                        <span style={{ fontSize: '0.75rem', color: 'var(--color-military-600)' }}><br />KEY EXCHANGE ACTIVE</span>
                                    </div>

                                    {decryptedIntel && (
                                        <div style={{ backgroundColor: 'var(--color-military-800)', border: '2px solid var(--color-military-accent)', padding: '1.5rem', borderRadius: '0.25rem', position: 'relative', overflow: 'hidden' }}>
                                            <div style={{ position: 'absolute', top: 0, right: 0, backgroundColor: 'var(--color-military-accent)', color: 'var(--color-military-900)', fontSize: '0.75rem', padding: '0.25rem 0.5rem', fontWeight: 'bold' }}>DECRYPTED</div>
                                            <p style={{ fontSize: '1.125rem', color: 'white', fontWeight: 'bold', letterSpacing: '0.05em' }}>{decryptedIntel}</p>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                !error && <p>Accessing Secure Server...</p>
                            )}
                        </div>
                    )}

                    {activeTab === 'sign' && (
                        <div>
                            <h2>DIGITAL SIGNATURE STATION</h2>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                <div>
                                    <label style={{ display: 'block', marginBottom: '0.5rem' }}>ORDER TEXT</label>
                                    <textarea
                                        className="input-field"
                                        style={{ height: '8rem', resize: 'vertical' }}
                                        value={signMessage}
                                        onChange={e => setSignMessage(e.target.value)}
                                        placeholder="Enter order details..."
                                    ></textarea>
                                </div>
                                <button
                                    onClick={handleSign}
                                    className="btn btn-primary"
                                    style={{ alignSelf: 'flex-start' }}
                                >
                                    SIGN ORDER
                                </button>

                                {signatureResult && (
                                    <div style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', backgroundColor: 'var(--color-military-900)', padding: '1rem', borderRadius: '0.25rem', border: '1px solid var(--color-military-600)' }}>
                                        <div>
                                            <label style={{ fontSize: '0.75rem', color: 'var(--color-military-600)' }}>SHA-256 HASH</label>
                                            <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{signatureResult.hash}</div>
                                        </div>
                                        <div>
                                            <label style={{ fontSize: '0.75rem', color: 'var(--color-military-600)' }}>DIGITAL SIGNATURE</label>
                                            <div style={{ fontSize: '0.75rem', fontFamily: 'monospace', wordBreak: 'break-all', color: 'var(--color-military-accent)' }}>{signatureResult.signature}</div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'verify' && (
                        <div>
                            <h2>INTEGRITY VERIFICATION</h2>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                                <div>
                                    <label style={{ display: 'block', marginBottom: '0.5rem' }}>RECEIVED MESSAGE</label>
                                    <textarea
                                        className="input-field"
                                        style={{ height: '6rem', resize: 'vertical' }}
                                        value={verifyMessage}
                                        onChange={e => setVerifyMessage(e.target.value)}
                                        placeholder="Paste message here..."
                                    ></textarea>
                                </div>
                                <div>
                                    <label style={{ display: 'block', marginBottom: '0.5rem' }}>ATTACHED SIGNATURE</label>
                                    <input
                                        type="text"
                                        className="input-field"
                                        style={{ fontFamily: 'monospace', fontSize: '0.875rem' }}
                                        value={verifySignature}
                                        onChange={e => setVerifySignature(e.target.value)}
                                        placeholder="Paste signature string..."
                                    />
                                </div>
                                <button
                                    onClick={handleVerify}
                                    className="btn btn-primary"
                                    style={{ alignSelf: 'flex-start' }}
                                >
                                    VERIFY INTEGRITY
                                </button>

                                {verificationResult && (
                                    <div className={verificationResult.valid ? 'alert alert-success' : 'alert alert-error'} style={{ marginTop: '1.5rem' }}>
                                        <p style={{ fontWeight: 'bold', display: 'flex', alignItems: 'center' }}>
                                            <span style={{ fontSize: '1.5rem', marginRight: '0.5rem' }}>{verificationResult.valid ? '✓' : '⚠'}</span>
                                            {verificationResult.status}
                                        </p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                </main>
            </div>
        </div>
    );
};

const NavBtn = ({ label, active, onClick }) => (
    <button
        onClick={onClick}
        className={`nav-btn ${active ? 'active' : ''}`}
    >
        {label}
    </button>
);

const Detail = ({ label, value }) => (
    <div style={{ display: 'flex', borderBottom: '1px solid var(--color-military-700)', padding: '0.25rem 0' }}>
        <span style={{ width: '120px', color: 'var(--color-military-600)', fontSize: '0.875rem' }}>{label}</span>
        <span style={{ fontWeight: 'bold' }}>{value.toUpperCase()}</span>
    </div>
);

export default Dashboard;
