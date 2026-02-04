require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const QRCode = require('qrcode');
const crypto = require('crypto');
const mongoose = require('mongoose');
const forge = require('node-forge');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174'],
    credentials: true
}));

// --- DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vanguard_mongo')
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true }, // Added email field
    password: { type: String, required: true },
    role: { type: Number, required: true, default: 1 }, // 1=Soldier, 2=Sergeant, 3=Colonel
    roleName: { type: String, required: true, default: 'SOLDIER' },
    otp: { type: String, default: null },
    publicKey: { type: String, default: null }, // RSA Public Key
    privateKey: { type: String, default: null } // RSA Private Key (Stored for easier UX)
});

const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
    sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    senderName: { type: String, required: true }, // Cached for display

    // Hybrid Encryption Payloads
    encryptedContent: { type: String, required: true }, // AES-256 Encrypted Body
    encryptedKey: { type: String, required: true },     // RSA Encrypted AES Key
    salt: { type: String, required: true },             // Salt for AES Key Derivation
    iv: { type: String, required: true },               // AES IV

    timestamp: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', MessageSchema);



// --- SEEDING ---
const seedUsers = async () => {
    try {
        const count = await User.countDocuments();
        if (count === 0) {
            console.log('Seeding Database...');
            const pwhash = await bcrypt.hash('password123', 10);
            const vishalHash = await bcrypt.hash('karthikvishal', 10);

            const usersToSeed = [
                // Requested Colonel
                { username: 'vishal', email: 'karthikvishal1506@gmail.com', password: vishalHash, role: 3, roleName: 'COLONEL' },
                // 3 Colonels
                { username: 'colonel', email: 'colonel@vanguard.mil', password: pwhash, role: 3, roleName: 'COLONEL' },
                { username: 'colonel_sheppard', email: 'sheppard@vanguard.mil', password: pwhash, role: 3, roleName: 'COLONEL' },
                { username: 'colonel_oneill', email: 'oneill@vanguard.mil', password: pwhash, role: 3, roleName: 'COLONEL' },
                // 4 Sergeants
                { username: 'sergeant', email: 'sergeant@vanguard.mil', password: pwhash, role: 2, roleName: 'SERGEANT' },
                { username: 'sergeant_carter', email: 'carter@vanguard.mil', password: pwhash, role: 2, roleName: 'SERGEANT' },
                { username: 'sergeant_tealc', email: 'tealc@vanguard.mil', password: pwhash, role: 2, roleName: 'SERGEANT' },
                { username: 'sergeant_jackson', email: 'jackson@vanguard.mil', password: pwhash, role: 2, roleName: 'SERGEANT' },
                // Default Soldier
                { username: 'soldier', email: 'soldier@vanguard.mil', password: pwhash, role: 1, roleName: 'SOLDIER' }
            ];

            await User.insertMany(usersToSeed);
            console.log('Database Seeded!');
        }
    } catch (err) {
        console.error('Seeding Error:', err);
    }
};
seedUsers();


// --- CRYPTO CONFIG ---
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const ENCRYPTION_KEY = crypto.randomBytes(32);
const IV = crypto.randomBytes(16);
const SIGNING_SECRET = crypto.randomBytes(64).toString('hex');

// Top Secret Intel
const secretIntel = "OPERATION DEEP STRIKE: LAUNCH CODES 8822-9911-0033";
let encryptedVault = null;

const encryptIntel = () => {
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
    let encrypted = cipher.update(secretIntel, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    encryptedVault = encrypted; // This is what is "stored"
};
encryptIntel();


// --- EMAIL CONFIG ---
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const sendEmail = async (to, otp) => {
    try {
        await transporter.sendMail({
            from: 'VANGUARD COMMAND <no-reply@vanguard.mil>',
            to: to,
            subject: 'SECURE AUTHENTICATION TOKEN',
            text: `COMMAND ALERT\n\nYOUR 2FA CODE IS: ${otp}\n\nTHIS MESSAGE WILL SELF-DESTRUCT IN 5 MINUTES.`
        });
        console.log(`[EMAIL] SENT TO ${to}`);
        return true;
    } catch (err) {
        console.error('[EMAIL ERROR]', err);
        return false;
    }
};


// --- HELPERS ---
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

const getRoleName = (role) => {
    if (role === 3) return 'COLONEL';
    if (role === 2) return 'SERGEANT';
    return 'SOLDIER';
}

const generateKeyPair = () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    return {
        publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
    };
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
        if (req.user.role < roleLevel) {
            return res.status(403).json({ error: 'Insufficient Clearance Level' });
        }
        next();
    };
};

// --- ROUTES ---

// 1. Authentication
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const validPass = await bcrypt.compare(password, user.password);
        if (!validPass) return res.status(400).json({ error: 'Invalid password' });

        const otp = generateOTP();
        user.otp = otp;
        await user.save();

        await sendEmail(user.email, otp);
        console.log(`[OTP] Generated for ${username}: ${otp}`);

        res.json({ message: 'Credentials valid. Secure token sent to secure email channel.', step: '2FA' });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/verify-otp', async (req, res) => {
    const { username, otp } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ error: 'User not found' });

        if (user.otp !== otp) {
            return res.status(400).json({ error: 'Invalid Code' });
        }

        user.otp = null;
        await user.save();



        const token = jwt.sign({ id: user._id, username: user.username, role: user.role, roleName: user.roleName }, JWT_SECRET, { expiresIn: '10m' });


        res.cookie('token', token, { httpOnly: true, sameSite: 'lax' });

        res.json({
            message: 'Login Successful',
            user: { username: user.username, role: user.role, roleName: user.roleName }
        });
    } catch (err) {
        res.status(500).json({ error: 'Server Error' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out' });
});

// 2. Registration (New features)
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    try {
        const existing = await User.findOne({ username });
        if (existing) return res.status(400).json({ error: 'Username taken' });

        const existingEmail = await User.findOne({ email });
        if (existingEmail) return res.status(400).json({ error: 'Email already registered' });

        const hashedPassword = await bcrypt.hash(password, 10);

        // Generate Keys for new user
        const keys = generateKeyPair();

        // Default role is 1 (Soldier)
        const newUser = new User({
            username,
            email,
            password: hashedPassword,
            role: 1,
            roleName: 'SOLDIER',
            publicKey: keys.publicKey,
            privateKey: keys.privateKey
        });
        await newUser.save();
        res.json({ message: 'Registration Successful. Please Login.' });
    } catch (err) {
        res.status(500).json({ error: 'Registration Failed' });
    }
});

// 3. Personnel Management (Colonel Only)
app.get('/api/users', verifyToken, requireRole(3), async (req, res) => {
    try {
        // Return all users except self? Or all users?
        // Let's return all users for the dashboard list
        const users = await User.find({}, 'username role roleName');
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: 'Fetch Failed' });
    }
});

// Promote/Demote
app.patch('/api/users/:id/role', verifyToken, requireRole(3), async (req, res) => {
    const { role } = req.body; // New role level
    const targetUserId = req.params.id;

    if (![1, 2].includes(role)) {
        return res.status(400).json({ error: 'Invalid Role Assignment. Can only set Soldier(1) or Sergeant(2).' });
    }

    try {
        const targetUser = await User.findById(targetUserId);
        if (!targetUser) return res.status(404).json({ error: 'User not found' });

        if (targetUser.role === 3) {
            return res.status(403).json({ error: 'Cannot modify rank of a fellow Colonel.' });
        }

        targetUser.role = role;
        targetUser.roleName = getRoleName(role);
        await targetUser.save();

        res.json({ message: `User promoted/demoted to ${targetUser.roleName}` });
    } catch (err) {
        res.status(500).json({ error: 'Update Failed' });
    }
});

// --- SECURE MESSAGING ROUTES ---

// Upload Public Key
app.post('/api/keys', verifyToken, async (req, res) => {
    const { publicKey, privateKey } = req.body;
    if (!publicKey) return res.status(400).json({ error: 'Public Key Missing' });

    try {
        const updates = { publicKey };
        if (privateKey) updates.privateKey = privateKey;

        await User.findByIdAndUpdate(req.user.id, updates);
        res.json({ message: 'Keys Registered' });
    } catch (err) {
        res.status(500).json({ error: 'Key Upload Failed' });
    }
});

// Get My Keys (For auto-login/sync)
app.get('/api/users/me/keys', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({
            publicKey: user.publicKey,
            privateKey: user.privateKey
        });
    } catch (err) {
        res.status(500).json({ error: 'Fetch Failed' });
    }
});

// Get Recipient Public Key (Colonel/Sergeant only)
app.get('/api/users/public-key/:id', verifyToken, requireRole(2), async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({ publicKey: user.publicKey, username: user.username });
    } catch (err) {
        res.status(500).json({ error: 'Fetch Failed' });
    }
});

// Send Message
app.post('/api/messages', verifyToken, requireRole(2), async (req, res) => {
    const { recipientId, encryptedContent, encryptedKey, salt, iv } = req.body;

    try {
        const newMessage = new Message({
            sender: req.user.id,
            senderName: req.user.username,
            recipient: recipientId,
            encryptedContent,
            encryptedKey,
            salt,
            iv
        });
        await newMessage.save();
        res.json({ message: 'Transmission Sent' });
    } catch (err) {
        console.error('Send Error:', err);
        res.status(500).json({ error: 'Transmission Failed' });
    }
});

// Get Inbox
app.get('/api/messages', verifyToken, requireRole(2), async (req, res) => {
    try {
        const messages = await Message.find({ recipient: req.user.id })
            .sort({ timestamp: -1 })
            .limit(50);
        res.json({ messages });
    } catch (err) {
        res.status(500).json({ error: 'Inbox Retrieval Failed' });
    }
});

// Get Eligible Recipients (exclude self, include only Colonels(3) and Sergeants(2))
app.get('/api/recipients', verifyToken, requireRole(2), async (req, res) => {
    try {
        const recipients = await User.find({
            _id: { $ne: req.user.id },
            role: { $in: [2, 3] }
        }, 'username roleName');
        res.json({ recipients });
    } catch (err) {
        res.status(500).json({ error: 'Recipient List Failed' });
    }
});

// 4. Feature Routes
app.get('/api/me', verifyToken, async (req, res) => {
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

app.get('/api/vault', verifyToken, requireRole(3), (req, res) => {
    res.json({
        encryptedData: encryptedVault,
        key: ENCRYPTION_KEY.toString('hex'),
        iv: IV.toString('hex')
    });
});

app.get('/api/logistics', verifyToken, requireRole(2), (req, res) => {
    res.json({
        data: [
            { id: 1, item: 'M4 Carbine', quantity: 500, status: 'In Stock' },
            { id: 2, item: 'Humvee', quantity: 12, status: 'Maintenance' },
            { id: 3, item: 'Rations', quantity: 10000, status: 'Low' }
        ]
    });
});

app.post('/api/sign', verifyToken, requireRole(3), (req, res) => {
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });
    const hash = crypto.createHash('sha256').update(message).digest('hex');
    const signature = crypto.createHmac('sha256', SIGNING_SECRET).update(hash).digest('hex');
    res.json({ message, hash, signature });
});

app.post('/api/verify', verifyToken, (req, res) => {
    const { message, signature } = req.body;
    const hash = crypto.createHash('sha256').update(message).digest('hex');
    const expectedSignature = crypto.createHmac('sha256', SIGNING_SECRET).update(hash).digest('hex');

    if (signature === expectedSignature) {
        res.json({ valid: true, status: 'Integrity Configuration Confirmed. Signature Valid.' });
    } else {
        res.json({ valid: false, status: 'WARNING: TAMPERING DETECTED. Signature Invalid.' });
    }
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Command Center Server running on port ${PORT}`);
    });
}

module.exports = app;
