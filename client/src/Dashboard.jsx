import React, { useState, useEffect } from 'react';
import CryptoJS from 'crypto-js';
import AccessMatrix from './AccessMatrix';
import SecureMessenger from './SecureMessenger';
import QREncoder from './QREncoder';

const Dashboard = ({ user, onLogout }) => {
    const [activeTab, setActiveTab] = useState('overview');
    const [vaultData, setVaultData] = useState(null);
    const [decryptedIntel, setDecryptedIntel] = useState(null);
    const [logistics, setLogistics] = useState([]);
    const [usersList, setUsersList] = useState([]);
    // const [qrCode, setQrCode] = useState(null); // Removed
    const [signMessage, setSignMessage] = useState('');
    const [signatureResult, setSignatureResult] = useState(null);
    const [verifyMessage, setVerifyMessage] = useState('');
    const [verifySignature, setVerifySignature] = useState('');
    const [verificationResult, setVerificationResult] = useState(null);
    const [error, setError] = useState('');
    const [successMsg, setSuccessMsg] = useState('');

    useEffect(() => {
        if (user.role >= 2) fetchLogistics();
    }, [user]);

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

    const fetchUsers = async () => {
        setSuccessMsg('');
        setError('');
        try {
            const res = await fetch('http://localhost:3001/api/users', { credentials: 'include' });
            if (res.ok) {
                const data = await res.json();
                setUsersList(data.users);
            } else {
                setError('Failed to fetch personnel data.');
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

    const updateUserRole = async (userId, newRole) => {
        setSuccessMsg('');
        setError('');
        try {
            const res = await fetch(`http://localhost:3001/api/users/${userId}/role`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ role: newRole })
            });
            const data = await res.json();
            if (res.ok) {
                setSuccessMsg(data.message);
                fetchUsers(); // Refresh list
            } else {
                setError(data.error);
            }
        } catch (err) {
            setError('Update Failed');
        }
    };

    return (
        <div className="bg-grid bg-scanlines" style={{ padding: '2rem', minHeight: '100vh' }}>

            {/* TOP BAR */}
            <header style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid var(--color-hud-dim)', paddingBottom: '1rem', marginBottom: '2rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ width: '40px', height: '40px', border: '2px solid var(--color-hud-cyan)', display: 'grid', placeItems: 'center', color: 'var(--color-hud-cyan)' }}>
                        <span style={{ fontSize: '1.5rem', lineHeight: 1 }}>V</span>
                    </div>
                    <div>
                        <h1 style={{ fontSize: '2rem', fontWeight: 'bold', letterSpacing: '0.1em', lineHeight: 1 }} className="uppercase text-accent">Vanguard</h1>
                        <p style={{ fontSize: '0.8rem', color: 'var(--color-hud-dim)', letterSpacing: '0.2em' }}>COMMAND CENTER // V 1.0.4</p>
                    </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                    <div className="text-accent font-bold" style={{ fontSize: '1.2rem' }}>{user.username.toUpperCase()}</div>
                    <div style={{ fontSize: '0.8rem', backgroundColor: 'var(--color-hud-gunmetal)', padding: '0.5rem 1rem', display: 'inline-block', marginTop: '0.5rem', border: '1px solid var(--color-hud-cyan)' }}>
                        RANK: <span className="text-accent">{user.roleName}</span> | CLEARANCE: <span className="text-accent">LVL {user.role}</span>
                    </div>
                </div>
                <button
                    onClick={onLogout}
                    className="btn btn-logout"
                    style={{ marginLeft: '2rem' }}
                >
                    [ LOGOUT ]
                </button>
            </header>

            <div className="grid-dashboard">
                {/* HUD SIDEBAR */}
                <nav style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <NavBtn label="MISSION OVERVIEW" active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} />
                    {user.role >= 3 && <NavBtn label="PERSONNEL MGMT" active={activeTab === 'personnel'} onClick={() => { setActiveTab('personnel'); fetchUsers(); }} />}
                    {user.role >= 1 && <NavBtn label="SERVICE RECORD" active={activeTab === 'record'} onClick={() => setActiveTab('record')} />}
                    {user.role >= 2 && <NavBtn label="LOGISTICS DEPT" active={activeTab === 'logistics'} onClick={() => setActiveTab('logistics')} />}
                    {user.role >= 3 && <NavBtn label="SECURE VAULT" active={activeTab === 'vault'} onClick={() => { setActiveTab('vault'); fetchVault(); }} />}
                    {user.role >= 3 && <NavBtn label="COMMS: SIGN" active={activeTab === 'sign'} onClick={() => setActiveTab('sign')} />}

                    <NavBtn label="COMMS: VERIFY" active={activeTab === 'verify'} onClick={() => setActiveTab('verify')} />

                    <div className="my-4 border-t border-gray-700"></div>

                    {user.role >= 1 && <NavBtn label="SECURE UPLINK" active={activeTab === 'messenger'} onClick={() => setActiveTab('messenger')} />}
                    <NavBtn label="DATA LINK (QR)" active={activeTab === 'qr'} onClick={() => setActiveTab('qr')} />
                    <NavBtn label="SECURITY BOARD" active={activeTab === 'matrix'} onClick={() => setActiveTab('matrix')} />

                    <div style={{ marginTop: 'auto', padding: '1rem', border: '1px dashed var(--color-hud-dim)', color: 'var(--color-hud-dim)', fontSize: '0.7rem' }}>
                        <p>SESSION ID: {Math.random().toString(36).substr(2, 9).toUpperCase()}</p>
                        <p>ENCRYPTION: AES-256</p>
                    </div>
                </nav>

                {/* MAIN HUD DISPLAY */}
                <main className="card" style={{ minHeight: '600px', display: 'flex', flexDirection: 'column' }}>

                    {/* Corner accents for the card */}
                    <div style={{ position: 'absolute', top: 0, left: 0, width: '20px', height: '20px', borderTop: '2px solid var(--color-hud-cyan)', borderLeft: '2px solid var(--color-hud-cyan)' }}></div>
                    <div style={{ position: 'absolute', bottom: 0, right: 0, width: '20px', height: '20px', borderBottom: '2px solid var(--color-hud-cyan)', borderRight: '2px solid var(--color-hud-cyan)' }}></div>

                    {activeTab === 'overview' && (
                        <div className="text-center" style={{ paddingTop: '5rem', flex: 1 }}>
                            <h2 style={{ marginBottom: '2rem', fontSize: '2.5rem', letterSpacing: '0.1em' }} className="text-accent">WELCOME COMMANDER</h2>
                            <p style={{ color: 'var(--color-hud-text)', fontSize: '1.2rem', maxWidth: '600px', margin: '0 auto' }}>Secure connection established. Awaiting orders. Select a module from the tactical navigation menu.</p>

                            <div style={{ marginTop: '4rem', display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '2rem' }}>
                                <StatusBox label="SERVER STATUS" value="ONLINE" color="var(--color-hud-green)" />
                                <StatusBox label="DEFCON" value="LEVEL 4" color="var(--color-hud-amber)" />
                                <StatusBox label="INTEL FEED" value="SECURE" color="var(--color-hud-cyan)" />
                            </div>
                        </div>
                    )}

                    {activeTab === 'personnel' && (
                        <div>
                            <h2 className="text-accent uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-dim)', paddingBottom: '0.5rem' }}>// PERSONNEL MANAGEMENT</h2>
                            {error && <div className="alert alert-error">{error}</div>}
                            {successMsg && <div className="alert alert-success">{successMsg}</div>}

                            <table className="table">
                                <thead>
                                    <tr>
                                        <th>OPERATIVE</th>
                                        <th>RANK / ROLE</th>
                                        <th>ACTION PROTOCOLS</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {usersList.map(u => (
                                        <tr key={u._id}>
                                            <td style={{ fontWeight: 'bold', color: 'var(--color-hud-cyan)' }}>{u.username}</td>
                                            <td>{u.roleName}</td>
                                            <td>
                                                {u.role === 1 && (
                                                    <button onClick={() => updateUserRole(u._id, 2)} className="btn btn-primary" style={{ fontSize: '0.8rem', padding: '0.5rem' }}>PROMOTE &gt;&gt; SERGEANT</button>
                                                )}
                                                {u.role === 2 && (
                                                    <button onClick={() => updateUserRole(u._id, 1)} className="btn btn-logout" style={{ fontSize: '0.8rem', padding: '0.5rem' }}>DEMOTE &gt;&gt; SOLDIER</button>
                                                )}
                                                {u.role === 3 && <span style={{ color: 'var(--color-hud-dim)', fontSize: '0.8rem' }}>[ CLASSIFIED ]</span>}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}

                    {activeTab === 'record' && (
                        <div>
                            <h2 className="text-accent uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-dim)', paddingBottom: '0.5rem' }}>// SERVICE RECORD</h2>
                            <div style={{ display: 'flex', gap: '3rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
                                {/* <div style={{ backgroundColor: 'white', padding: '1rem', borderRadius: '4px' }}>
                                    {qrCode ? <img src={qrCode} alt="ID QR Code" style={{ width: '200px', height: '200px' }} /> : "Generating ID..."}
                                </div> */}
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', flex: 1 }}>
                                    <Detail label="OPERATIVE NAME" value={user.username} />
                                    <Detail label="CURRENT RANK" value={user.roleName} />
                                    <Detail label="CLEARANCE LEVEL" value={`LEVEL ${user.role} - ACCESS GRANTED`} />
                                    <Detail label="DUTY STATUS" value="ACTIVE / DEPLOYED" />
                                </div>
                            </div>
                        </div>
                    )}

                    {activeTab === 'logistics' && (
                        <div>
                            <h2 className="text-accent uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-dim)', paddingBottom: '0.5rem' }}>// LOGISTICS MANIFEST</h2>
                            {logistics.length === 0 ? <p>Loading manifest...</p> : (
                                <table className="table">
                                    <thead>
                                        <tr>
                                            <th>ASSET ID</th>
                                            <th>DESCRIPTION</th>
                                            <th>QUANTITY</th>
                                            <th>DEPLY. STATUS</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {logistics.map(item => (
                                            <tr key={item.id}>
                                                <td style={{ fontFamily: 'monospace', color: 'var(--color-hud-dim)' }}>#{item.id}</td>
                                                <td>{item.item}</td>
                                                <td style={{ color: 'var(--color-hud-cyan)' }}>{item.quantity}</td>
                                                <td className={item.status === 'Low' ? 'text-danger' : 'text-success'}>{item.status.toUpperCase()}</td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}

                    {activeTab === 'vault' && (
                        <div>
                            <h2 className="text-warning uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-amber)', paddingBottom: '0.5rem' }}>⚠ TOP SECRET VAULT ⚠</h2>
                            {error && <div className="alert alert-error">{error}</div>}

                            {vaultData ? (
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
                                    <div style={{ backgroundColor: 'black', padding: '1.5rem', border: '1px solid var(--color-hud-dim)', position: 'relative' }}>
                                        <label style={{ fontSize: '0.8rem', color: 'var(--color-hud-dim)', display: 'block', marginBottom: '0.5rem' }}>ENCRYPTED DATA STREAM (AES-256)</label>
                                        <code style={{ fontSize: '0.9rem', wordBreak: 'break-all', fontFamily: 'monospace', color: 'var(--color-hud-red)' }}>{vaultData.encryptedData}</code>
                                    </div>

                                    <div style={{ display: 'flex', alignItems: 'center', gap: '2rem' }}>
                                        <button
                                            onClick={decryptVault}
                                            className="btn btn-accent"
                                            style={{ fontSize: '1.2rem' }}
                                        >
                                            INITIATE DECRYPTION
                                        </button>
                                        <span style={{ fontSize: '0.8rem', color: 'var(--color-hud-dim)' }}>// KEY EXCHANGE PROTOCOL: ACTIVE</span>
                                    </div>

                                    {decryptedIntel && (
                                        <div style={{ backgroundColor: 'rgba(55, 255, 0, 0.1)', border: '2px solid var(--color-hud-green)', padding: '2rem', marginTop: '1rem', position: 'relative', overflow: 'hidden' }}>
                                            <div style={{ position: 'absolute', top: 0, right: 0, backgroundColor: 'var(--color-hud-green)', color: 'black', fontSize: '0.8rem', padding: '0.25rem 1rem', fontWeight: 'bold' }}>DECRYPTED_SUCCESS</div>
                                            <p style={{ fontSize: '1.5rem', color: 'var(--color-hud-green)', fontWeight: 'bold', letterSpacing: '0.05em', fontFamily: 'monospace' }}>{decryptedIntel}</p>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                !error && <p className="text-warning" style={{ animation: 'blink 1s infinite' }}>Establishing Secure Connection...</p>
                            )}
                        </div>
                    )}

                    {activeTab === 'sign' && (
                        <div>
                            <h2 className="text-accent uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-dim)', paddingBottom: '0.5rem' }}>// DIGITAL SIGNATURE STATION</h2>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                                <div>
                                    <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--color-hud-dim)' }}>ORDER CONTENT</label>
                                    <textarea
                                        className="input-field"
                                        style={{ height: '10rem', resize: 'vertical' }}
                                        value={signMessage}
                                        onChange={e => setSignMessage(e.target.value)}
                                        placeholder="ENTER ORDER DETAILS FOR SIGNING..."
                                    ></textarea>
                                </div>
                                <button
                                    onClick={handleSign}
                                    className="btn btn-primary"
                                    style={{ alignSelf: 'flex-start' }}
                                >
                                    GENERATE SIGNATURE
                                </button>

                                {signatureResult && (
                                    <div style={{ marginTop: '2rem', display: 'flex', flexDirection: 'column', gap: '1rem', backgroundColor: 'var(--color-hud-gunmetal)', padding: '1.5rem', border: '1px solid var(--color-hud-cyan)' }}>
                                        <div>
                                            <label style={{ fontSize: '0.8rem', color: 'var(--color-hud-dim)' }}>SHA-256 HASH</label>
                                            <div style={{ fontSize: '0.9rem', fontFamily: 'monospace', wordBreak: 'break-all', color: 'white' }}>{signatureResult.hash}</div>
                                        </div>
                                        <div>
                                            <label style={{ fontSize: '0.8rem', color: 'var(--color-hud-dim)' }}>DIGITAL SIGNATURE</label>
                                            <div style={{ fontSize: '0.9rem', fontFamily: 'monospace', wordBreak: 'break-all', color: 'var(--color-hud-cyan)' }}>{signatureResult.signature}</div>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'verify' && (
                        <div>
                            <h2 className="text-accent uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-dim)', paddingBottom: '0.5rem' }}>// INTEGRITY VERIFICATION</h2>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
                                <div>
                                    <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--color-hud-dim)' }}>RECEIVED MESSAGE PAYLOAD</label>
                                    <textarea
                                        className="input-field"
                                        style={{ height: '8rem', resize: 'vertical' }}
                                        value={verifyMessage}
                                        onChange={e => setVerifyMessage(e.target.value)}
                                        placeholder="PASTE MESSAGE..."
                                    ></textarea>
                                </div>
                                <div>
                                    <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--color-hud-dim)' }}>ATTACHED SIGNATURE STRING</label>
                                    <input
                                        type="text"
                                        className="input-field"
                                        style={{ fontFamily: 'monospace', fontSize: '1rem' }}
                                        value={verifySignature}
                                        onChange={e => setVerifySignature(e.target.value)}
                                        placeholder="PASTE SIGNATURE..."
                                    />
                                </div>
                                <button
                                    onClick={handleVerify}
                                    className="btn btn-primary"
                                    style={{ alignSelf: 'flex-start' }}
                                >
                                    RUN INTEGRITY CHECK
                                </button>

                                {verificationResult && (
                                    <div className={verificationResult.valid ? 'alert alert-success' : 'alert alert-error'} style={{ marginTop: '2rem' }}>
                                        <p style={{ fontWeight: 'bold', display: 'flex', alignItems: 'center', fontSize: '1.2rem' }}>
                                            <span style={{ fontSize: '2rem', marginRight: '1rem' }}>{verificationResult.valid ? '✅' : '⛔'}</span>
                                            {verificationResult.status.toUpperCase()}
                                        </p>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    {activeTab === 'matrix' && (
                        <div className="pt-10">
                            <AccessMatrix />
                        </div>
                    )}

                    {activeTab === 'messenger' && (
                        <div className="pt-5">
                            <SecureMessenger user={user} />
                        </div>
                    )}

                    {activeTab === 'qr' && (
                        <div>
                            <h2 className="text-accent uppercase" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--color-hud-dim)', paddingBottom: '0.5rem' }}>// OPTICAL DATA LINK</h2>
                            <div className="flex justify-center">
                                <div className="w-full max-w-md">
                                    <h3 className="text-accent mb-4 border-l-4 border-cyan-500 pl-2">ENCODE TRANSMISSION</h3>
                                    <QREncoder />
                                </div>
                            </div>
                        </div>
                    )}

                </main>
            </div >
        </div >
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
    <div style={{ display: 'flex', borderBottom: '1px solid rgba(255,255,255,0.1)', padding: '1rem 0' }}>
        <span style={{ width: '180px', color: 'var(--color-hud-dim)', fontSize: '0.9rem', letterSpacing: '1px' }}>{label}</span>
        <span style={{ fontWeight: 'bold', color: 'var(--color-hud-text)', fontSize: '1.1rem' }}>{value.toUpperCase()}</span>
    </div>
);

const StatusBox = ({ label, value, color }) => (
    <div style={{ border: `1px solid ${color}`, padding: '1.5rem', textAlign: 'center', background: 'rgba(0,0,0,0.3)' }}>
        <div style={{ color: 'var(--color-hud-dim)', fontSize: '0.8rem', marginBottom: '0.5rem' }}>{label}</div>
        <div style={{ color: color, fontSize: '1.5rem', fontWeight: 'bold' }}>{value}</div>
    </div>
)

export default Dashboard;
