import React, { useState, useEffect } from 'react';
import CryptoJS from 'crypto-js';
import JSEncrypt from 'jsencrypt';
import axios from 'axios';

const SecureMessenger = ({ user }) => {
    const [messages, setMessages] = useState([]);
    const [recipients, setRecipients] = useState([]);
    const [selectedRecipient, setSelectedRecipient] = useState('');
    const [messageBody, setMessageBody] = useState('');
    const [status, setStatus] = useState('INITIATING SECURE HANDSHAKE...');
    const [keysLoaded, setKeysLoaded] = useState(false);
    const [activeTab, setActiveTab] = useState('inbox'); // inbox, compose

    // --- INITIALIZATION ---
    useEffect(() => {
        const init = async () => {
            try {
                // 1. Fetch My Keys (from Server - now pre-seeded)
                const res = await axios.get('/api/users/me/keys', { withCredentials: true });
                const { privateKey, publicKey } = res.data;

                if (privateKey && publicKey) {
                    // Store locally for JS usage
                    const privateId = `vanguard_priv_${user.username}`;
                    localStorage.setItem(privateId, privateKey);
                    setStatus('UPLINK ESTABLISHED. IDENTITY VERIFIED.');
                    setKeysLoaded(true);
                } else {
                    setStatus('ERROR: KEY PROVISIONING FAILED. CONTACT COMMAND.');
                }
            } catch (err) {
                console.error(err);
                setStatus('CRITICAL FAILURE: KEY SERVER UNREACHABLE.');
            }
        };

        if (user) {
            init();
            fetchEligibleRecipients();
            fetchInbox();
        }
    }, [user.username]);

    // --- API CALLS ---
    const fetchEligibleRecipients = async () => {
        try {
            const res = await axios.get('/api/recipients', { withCredentials: true });
            setRecipients(res.data.recipients);
        } catch (err) {
            console.error(err);
        }
    };

    const fetchInbox = async () => {
        try {
            const res = await axios.get('/api/messages', { withCredentials: true });
            setMessages(res.data.messages);
        } catch (err) {
            console.error(err);
        }
    };

    // --- SENDING ---
    const sendMessage = async (e) => {
        e.preventDefault();
        if (!selectedRecipient || !messageBody) return;
        setStatus('ENCRYPTING PAYLOAD...');

        try {
            // 1. Get Recipient Public Key
            const keyRes = await axios.get(`/api/users/public-key/${selectedRecipient}`, { withCredentials: true });
            const recipientPubKey = keyRes.data.publicKey;

            if (!recipientPubKey) {
                setStatus('TARGET UPLINK OFFLINE (NO PUBLIC KEY).');
                return;
            }

            // 2. Generate AES Session Key
            const secret = CryptoJS.lib.WordArray.random(32).toString();
            const salt = CryptoJS.lib.WordArray.random(16).toString();
            const iv = CryptoJS.lib.WordArray.random(16).toString();

            // 3. Derive Key (PBKDF2)
            const derivedKey = CryptoJS.PBKDF2(secret, CryptoJS.enc.Hex.parse(salt), {
                keySize: 256 / 32,
                iterations: 1000
            });

            // 4. Encrypt Body (AES)
            const encryptedBody = CryptoJS.AES.encrypt(messageBody, derivedKey, {
                iv: CryptoJS.enc.Hex.parse(iv)
            }).toString();

            // 5. Encrypt Session Key (RSA)
            const encrypt = new JSEncrypt();
            encrypt.setPublicKey(recipientPubKey);
            const encryptedKey = encrypt.encrypt(secret);

            if (!encryptedKey) {
                setStatus('ENCRYPTION MODULE FAILURE.');
                return;
            }

            // 6. Transmit
            await axios.post('/api/messages', {
                recipientId: selectedRecipient,
                encryptedContent: encryptedBody,
                encryptedKey: encryptedKey,
                salt: salt,
                iv: iv
            }, { withCredentials: true });

            setStatus('TRANSMISSION SUCCESSFUL.');
            setMessageBody('');
            setActiveTab('inbox');
            fetchInbox();
        } catch (err) {
            console.error(err);
            setStatus('TRANSMISSION INTERRUPTED.');
        }
    };

    // --- DECRYPTION ---
    const decryptMessage = (msg) => {
        try {
            const privateId = `vanguard_priv_${user.username}`;
            const privKey = localStorage.getItem(privateId);

            if (!privKey) return "ERROR: MISSING DECRYPTION KEY";

            const decrypt = new JSEncrypt();
            decrypt.setPrivateKey(privKey);
            const secret = decrypt.decrypt(msg.encryptedKey);

            if (!secret) return "ERROR: INTEGRITY CHECK FAILED";

            const derivedKey = CryptoJS.PBKDF2(secret, CryptoJS.enc.Hex.parse(msg.salt), {
                keySize: 256 / 32,
                iterations: 1000
            });

            const bytes = CryptoJS.AES.decrypt(msg.encryptedContent, derivedKey, {
                iv: CryptoJS.enc.Hex.parse(msg.iv)
            });
            const originalText = bytes.toString(CryptoJS.enc.Utf8);

            return originalText || "ERROR: MALFORMED CIPHERTEXT";
        } catch (err) {
            return "ERROR: DECRYPTION EXCEPTION";
        }
    };

    return (
        <div className="card" style={{ minHeight: '500px' }}>
            {/* COMPONENT HEADER */}
            <div className="flex justify-between items-end mb-6 border-b border-gray-700 pb-2">
                <div>
                    <h2 className="text-2xl font-bold text-accent tracking-widest flex items-center">
                        <span className="w-3 h-3 bg-teal-500 rounded-full mr-3 animate-pulse shadow-[0_0_10px_#00f3ff]"></span>
                        SECURE UPLINK // LEVEL {user.role}
                    </h2>
                    <p className="text-xs text-gray-500 font-mono mt-1">PROTOCOL: AES-256 + RSA-2048 // END-TO-END ENCRYPTED</p>
                </div>

                {/* TABS */}
                <div className="flex space-x-2">
                    <button
                        onClick={() => setActiveTab('inbox')}
                        className={`btn ${activeTab === 'inbox' ? 'btn-primary' : 'border-gray-700 text-gray-500'}`}
                    >
                        INBOX ({messages.length})
                    </button>
                    <button
                        onClick={() => setActiveTab('compose')}
                        className={`btn ${activeTab === 'compose' ? 'btn-primary' : 'border-gray-700 text-gray-500'}`}
                    >
                        TRANSMIT
                    </button>
                    <button
                        onClick={fetchInbox}
                        className="btn border-gray-700 text-gray-500 px-3"
                        title="Refresh"
                    >
                        ↻
                    </button>
                </div>
            </div>

            {/* SYSTEM STATUS BAR */}
            <div className="mb-6 p-2 bg-black border-l-4 border-teal-500 font-mono text-sm text-teal-400 shadow-inner flex justify-between items-center">
                <span>&gt;&gt; SYSTEM STATUS: {status}</span>
                {!keysLoaded && <span className="animate-spin text-teal-500 text-lg">⟳</span>}
            </div>

            {/* CONTENT AREA */}
            <div className="bg-black bg-opacity-30 p-4 rounded border border-gray-800 h-96 relative">
                {/* GRID OVERLAY */}
                <div className="absolute inset-0 bg-grid opacity-10 pointer-events-none"></div>

                {!keysLoaded ? (
                    <div className="h-full flex flex-col items-center justify-center text-accent animate-pulse">
                        <div className="text-4xl mb-4">⚠</div>
                        <p>ESTABLISHING SECURE CONNECTION...</p>
                        <p className="text-xs text-gray-500 mt-2">EXCHANGING KEYS WITH COMMAND SERVER</p>
                    </div>
                ) : (
                    <>
                        {activeTab === 'inbox' && (
                            <div className="h-full overflow-y-auto pr-2 custom-scrollbar space-y-3">
                                {messages.length === 0 ? (
                                    <div className="h-full flex items-center justify-center text-gray-600 font-mono">
                                        [ NO TRANSMISSIONS RECEIVED ]
                                    </div>
                                ) : (
                                    messages.map(msg => (
                                        <div key={msg._id} className="relative group perspective-1000">
                                            <div className="bg-gray-900 border border-gray-700 p-4 rounded hover:border-teal-500 hover:shadow-[0_0_15px_rgba(0,243,255,0.1)] transition-all duration-300">
                                                <div className="flex justify-between items-start mb-2 border-b border-gray-800 pb-2">
                                                    <span className="text-accent font-bold font-mono">
                                                        FROM: {msg.senderName.toUpperCase()}
                                                    </span>
                                                    <span className="text-gray-500 text-xs font-mono">
                                                        {new Date(msg.timestamp).toLocaleString()}
                                                    </span>
                                                </div>
                                                <div className="font-mono text-sm text-green-400 leading-relaxed break-words">
                                                    {decryptMessage(msg)}
                                                </div>
                                                <div className="mt-2 text-right">
                                                    <span className="text-[10px] text-gray-600 uppercase tracking-widest border border-gray-700 px-1 rounded">
                                                        Verified Encrypted
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        )}

                        {activeTab === 'compose' && (
                            <form onSubmit={sendMessage} className="h-full flex flex-col space-y-4">
                                <div>
                                    <label className="block text-gray-500 text-xs font-bold mb-1 tracking-widest">TARGET RECIPIENT</label>
                                    <select
                                        className="input-field w-full bg-gray-900"
                                        value={selectedRecipient}
                                        onChange={(e) => setSelectedRecipient(e.target.value)}
                                        required
                                    >
                                        <option value="">-- SELECT OPERATIVE --</option>
                                        {recipients.map(r => (
                                            <option key={r._id} value={r._id}>
                                                [{r.roleName}] {r.username.toUpperCase()}
                                            </option>
                                        ))}
                                    </select>
                                </div>
                                <div className="flex-1 flex flex-col">
                                    <label className="block text-gray-500 text-xs font-bold mb-1 tracking-widest">MESSAGE CONTENT</label>
                                    <textarea
                                        className="input-field w-full flex-1 bg-gray-900 font-mono text-green-400 p-3"
                                        placeholder="ENTER CLASSIFIED INTEL..."
                                        value={messageBody}
                                        onChange={(e) => setMessageBody(e.target.value)}
                                        required
                                    />
                                </div>
                                <button
                                    type="submit"
                                    className="btn btn-primary w-full py-4 text-center disabled:opacity-50 disabled:cursor-not-allowed"
                                    disabled={!selectedRecipient || !messageBody}
                                >
                                    INITIATE DATA TRANSFER
                                </button>
                            </form>
                        )}
                    </>
                )}
            </div>
        </div>
    );
};

export default SecureMessenger;
