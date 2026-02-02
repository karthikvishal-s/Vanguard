import React from 'react';

const AccessMatrix = () => {
    return (
        <div className="bg-gray-900 border border-gray-700 p-6 rounded-lg shadow-xl mb-8">
            <h2 className="text-2xl font-bold text-teal-400 mb-4 uppercase tracking-wider text-center">
                Security Clearance Protocol Matrix
            </h2>
            <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-gray-800 text-teal-300 border-b border-gray-600">
                            <th className="p-3">Clearance Level</th>
                            <th className="p-3">Rank</th>
                            <th className="p-3">System Access Privileges</th>
                            <th className="p-3">Restriction Class</th>
                        </tr>
                    </thead>
                    <tbody className="text-gray-300">
                        <tr className="border-b border-gray-700 hover:bg-gray-800 transition-colors">
                            <td className="p-3 border-r border-gray-700 font-mono text-teal-500">LEVEL 1</td>
                            <td className="p-3 border-r border-gray-700 font-bold">SOLDIER</td>
                            <td className="p-3 border-r border-gray-700">
                                <ul className="list-disc list-inside text-sm">
                                    <li>Basic Dashboard View</li>
                                    <li>View Personal Identity (QR)</li>
                                    <li>Read Only Access</li>
                                </ul>
                            </td>
                            <td className="p-3 text-red-400 font-mono text-sm">RESTRICTED: NO COMMS / NO LOGISTICS</td>
                        </tr>
                        <tr className="border-b border-gray-700 hover:bg-gray-800 transition-colors">
                            <td className="p-3 border-r border-gray-700 font-mono text-yellow-500">LEVEL 2</td>
                            <td className="p-3 border-r border-gray-700 font-bold">SERGEANT</td>
                            <td className="p-3 border-r border-gray-700">
                                <ul className="list-disc list-inside text-sm">
                                    <li>All Level 1 Privileges</li>
                                    <li>Logistics Logistics Manifest</li>
                                    <li><span className="text-yellow-400 font-bold">Secure Messenger Access (Read/Write)</span></li>
                                </ul>
                            </td>
                            <td className="p-3 text-yellow-600 font-mono text-sm">PARTIAL: LOGISTICS & COMMS</td>
                        </tr>
                        <tr className="hover:bg-gray-800 transition-colors">
                            <td className="p-3 border-r border-gray-700 font-mono text-red-500">LEVEL 3</td>
                            <td className="p-3 border-r border-gray-700 font-bold">COLONEL</td>
                            <td className="p-3 border-r border-gray-700">
                                <ul className="list-disc list-inside text-sm">
                                    <li>All Level 1 & 2 Privileges</li>
                                    <li>Personnel Management (Promote/Demote)</li>
                                    <li>Top Secret Vault Access</li>
                                    <li>Digital Signing Authority</li>
                                </ul>
                            </td>
                            <td className="p-3 text-green-500 font-mono text-sm">UNRESTRICTED: COMMAND ACCESS</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            <div className="mt-4 p-3 bg-gray-800 rounded border border-gray-700">
                <p className="text-xs text-gray-400 font-mono">
                    <span className="text-teal-400 font-bold">NOTE:</span> Secure Messaging channels are encrypted using AES-256 with RSA-2048 Key Exchange. Keys are stored locally on authorized terminals. Unauthorized intercept attempts will be logged.
                </p>
            </div>
        </div>
    );
};

export default AccessMatrix;
