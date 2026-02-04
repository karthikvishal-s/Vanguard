import React from 'react';

const AccessMatrix = () => {
    return (
        <div className="card">
            <div className="access-matrix-header">
                <h2 className="text-2xl font-bold text-accent" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span style={{ fontSize: '1.5rem' }}>⊞</span>
                    SECURITY CLEARANCE PROTOCOLS
                </h2>
                <span style={{
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    color: 'var(--color-hud-dim)',
                    border: '1px solid var(--color-hud-dim)',
                    padding: '4px 8px'
                }}>
                    AUTH_MATRIX_V4.2
                </span>
            </div>

            <div className="cyber-table-container">
                <table className="cyber-table">
                    <thead>
                        <tr>
                            <th className="col-clearance">Clearance</th>
                            <th className="col-designation">Designation</th>
                            <th className="col-privileges">Privileges / Capabilities</th>
                            <th className="col-restriction">Restriction Class</th>
                        </tr>
                    </thead>
                    <tbody>

                        {/* LEVEL 1 */}
                        <tr>
                            <td className="col-clearance text-level-1">LVL_01</td>
                            <td className="col-designation">SOLDIER</td>
                            <td className="col-privileges">
                                <ul className="cyber-list">
                                    <li>Basic Dashboard View</li>
                                    <li>Identity Verification (QR)</li>
                                    <li>Read-Only Systems Inventory</li>
                                </ul>
                            </td>
                            <td className="col-restriction">
                                <span className="restriction-badge text-danger">
                                    [ RESTRICTED ]
                                </span>
                            </td>
                        </tr>

                        {/* LEVEL 2 */}
                        <tr>
                            <td className="col-clearance text-level-2">LVL_02</td>
                            <td className="col-designation">SERGEANT</td>
                            <td className="col-privileges">
                                <ul className="cyber-list">
                                    <li className="text-warning">Inherits Level 1 Clearance</li>
                                    <li>Logistics Manifest View</li>
                                    <li className="highlight">
                                        Secure Uplink (Read/Write Messaging)
                                    </li>
                                </ul>
                            </td>
                            <td className="col-restriction">
                                <span className="restriction-badge text-warning">
                                    [ PARTIAL-ACCESS ]
                                </span>
                            </td>
                        </tr>

                        {/* LEVEL 3 */}
                        <tr>
                            <td className="col-clearance text-level-3">LVL_03</td>
                            <td className="col-designation">COLONEL</td>
                            <td className="col-privileges">
                                <ul className="cyber-list">
                                    <li className="text-danger">Inherits All Lower Clearances</li>
                                    <li>Personnel Management (Promote/Demote)</li>
                                    <li className="danger-highlight">
                                        Classified Vault Access (Top Secret)
                                    </li>
                                    <li className="danger-highlight">
                                        Digital Signing Authority
                                    </li>
                                </ul>
                            </td>
                            <td className="col-restriction">
                                <span className="restriction-badge text-success">
                                    [ UNRESTRICTED ]
                                </span>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div style={{
                marginTop: '1.5rem',
                padding: '1rem',
                background: 'rgba(0,0,0,0.4)',
                borderLeft: '3px solid var(--color-hud-cyan)',
                display: 'flex',
                alignItems: 'start',
                gap: '1rem'
            }}>
                <span style={{ color: 'var(--color-hud-cyan)', fontSize: '1.2rem' }}>ℹ</span>
                <p style={{ fontSize: '0.85rem', color: 'var(--color-hud-text)', lineHeight: '1.6' }}>
                    <strong style={{ color: 'var(--color-hud-cyan)' }}>ENCRYPTION PROTOCOL:</strong> Secure Messaging channels utilize <span style={{ color: '#fff' }}>AES-256</span> for payload and <span style={{ color: '#fff' }}>RSA-2048</span> for key exchange.
                    Keys are strictly bound to terminal session. Unauthorized access attempts trigger immediate lockout.
                </p>
            </div>
        </div>
    );
};

export default AccessMatrix;
