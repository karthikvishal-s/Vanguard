const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const QRCode = require('qrcode');
const crypto = require('crypto');

const app = express();
const PORT = 3001;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174'], // Allow multiple dev ports
    credentials: true
}));

// --- IN-MEMORY DATA & CONFIG ---
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = crypto.randomBytes(32); // AES-256 Key
const IV = crypto.randomBytes(16); // Initialization Vector
// HMAC Key for Digital Signatures (Simulating Private Key for signing)
const SIGNING_SECRET = crypto.randomBytes(64).toString('hex');

// Users
// Roles: 3=COLONEL, 2=SERGEANT, 1=SOLDIER
const users = [];

// Initialize simple users for demo (passwords will be hashed on startup)
const demoUsers = [
    { username: 'colonel', password: 'password123', role: 3, roleName: 'COLONEL' },
    { username: 'sergeant', password: 'password123', role: 2, roleName: 'SERGEANT' },
    { username: 'soldier', password: 'password123', role: 1, roleName: 'SOLDIER' }
];

(async () => {
    for (const u of demoUsers) {
        const hashedPassword = await bcrypt.hash(u.password, 10);
        users.push({ ...u, password: hashedPassword, otp: null });
    }
    console.log('Demo users initialized');
})();

// Top Secret Intel (Encrypted in storage)
const secretIntel = "OPERATION DEEP STRIKE: LAUNCH CODES 8822-9911-0033";
let encryptedVault = null;

// Encrypt Intel on startup
const encryptIntel = () => {
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    let encrypted = cipher.update(secretIntel, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    encryptedVault = encrypted; // This is what is "stored"
};
encryptIntel();


// --- HELPER FUNCTIONS ---

// Bell-LaPadula Model Check
// No Read Up (Simple Role Check here: User Level >= Required Level)
const checkClearance = (userRole, requiredRole) => {
    return userRole >= requiredRole;
};

// Generate 6-digit OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// --- MIDDLEWARE ---

const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'Access Denied' });

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ error: 'Invalid Token' });
    }
};

const requireRole = (roleLevel) => {
    return (req, res, next) => {
        if (req.user.role < roleLevel) { // No Read Up
            return res.status(403).json({ error: 'Insufficient Clearance Level' });
        }
        next();
    };
};


// --- ROUTES ---

// 1. Authentication (Phase 1: U/P)
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: 'Invalid password' });

    // Phase 2: Generate OTP
    const otp = generateOTP();
    user.otp = otp; // Store in memory
    console.log(`[OTP] Generated for ${username}: ${otp}`); // Log for demo purposes so user can see it

    res.json({ message: 'Credentials valid. Enter OTP sent to device.', step: '2FA' });
});

// 2. Authentication (Phase 2: OTP)
app.post('/api/verify-otp', (req, res) => {
    const { username, otp } = req.body;
    const user = users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: 'User not found' });

    if (user.otp !== otp) {
        return res.status(400).json({ error: 'Invalid Code' });
    }

    // Clear OTP
    user.otp = null;

    // Create Session Token
    const token = jwt.sign({ username: user.username, role: user.role, roleName: user.roleName }, JWT_SECRET, { expiresIn: '1h' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax' }); // Lax for localhost dev

    res.json({
        message: 'Login Successful',
        user: { username: user.username, role: user.role, roleName: user.roleName }
    });
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out' });
});

// 3. User Info & QR Code
app.get('/api/me', verifyToken, async (req, res) => {
    // Generate QR Code for ID
    // QR Content: Base64 Encoded (Identity Data)
    const identityString = JSON.stringify({
        id: req.user.username,
        role: req.user.roleName,
        clearance: req.user.role
    });
    const base64Identity = Buffer.from(identityString).toString('base64');

    try {
        const qrCodeUrl = await QRCode.toDataURL(base64Identity);
        res.json({ user: req.user, qrCode: qrCodeUrl });
    } catch (err) {
        res.status(500).json({ error: 'QR Generation Failed' });
    }
});

// 4. Secure Vault (Encryption/Decryption) - Only COLONEL (Lvl 3)
app.get('/api/vault', verifyToken, requireRole(3), (req, res) => {
    // Return the encrypted string AND the key/iv simulation for frontend decryption
    // In a real scenario, you wouldn't send the key, you'd decrypt on server.
    // BUT the requirement says: "Include a function to decrypt this on the frontend using a simulated Key Exchange."

    res.json({
        encryptedData: encryptedVault,
        key: ENCRYPTION_KEY.toString('hex'), // Simulating key exchange
        iv: IV.toString('hex')
    });
});

// 5. Logistics - SERGEANT (Lvl 2+)
app.get('/api/logistics', verifyToken, requireRole(2), (req, res) => {
    res.json({
        data: [
            { id: 1, item: 'M4 Carbine', quantity: 500, status: 'In Stock' },
            { id: 2, item: 'Humvee', quantity: 12, status: 'Maintenance' },
            { id: 3, item: 'Rations', quantity: 10000, status: 'Low' }
        ]
    });
});

// 6. Integrity (Digital Signatures)
app.post('/api/sign', verifyToken, requireRole(3), (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    // Hash the message
    const hash = crypto.createHash('sha256').update(message).digest('hex');

    // Sign the hash (HMAC simulation of RSA signing)
    const signature = crypto.createHmac('sha256', SIGNING_SECRET).update(hash).digest('hex');

    res.json({
        message,
        hash,
        signature
    });
});

// 7. Verify Signature (Public Access/All Roles)
app.post('/api/verify', verifyToken, (req, res) => {
    const { message, signature } = req.body;

    // 1. Re-hash message
    const hash = crypto.createHash('sha256').update(message).digest('hex');

    // 2. Re-create signature
    const expectedSignature = crypto.createHmac('sha256', SIGNING_SECRET).update(hash).digest('hex');

    if (signature === expectedSignature) {
        res.json({ valid: true, status: 'Integrity Configuration Confirmed. Signature Valid.' });
    } else {
        res.json({ valid: false, status: 'WARNING: TAMPERING DETECTED. Signature Invalid.' });
    }
});


app.listen(PORT, () => {
    console.log(`Command Center Server running on port ${PORT}`);
});
