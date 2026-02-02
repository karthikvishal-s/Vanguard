require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const forge = require('node-forge');

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: Number, required: true, default: 1 },
    roleName: { type: String, required: true, default: 'SOLDIER' },
    otp: { type: String, default: null },
    publicKey: { type: String, default: null },
    privateKey: { type: String, default: null }
});

const User = mongoose.model('User', UserSchema);

const generateKeyPair = () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    return {
        publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
    };
};

const resetDatabase = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vanguard_mongo');
        console.log('Connected to MongoDB');

        // CLEAR EXISTING USERS
        await User.deleteMany({});
        console.log('All existing users deleted.');

        // PREPARE DATA
        const pwhash = await bcrypt.hash('password123', 10);
        const vishalHash = await bcrypt.hash('karthikvishal', 10);

        console.log('Generating RSA Keys for massive user base... this might take a moment...');

        const baseUsers = [
            { username: 'vishal', password: vishalHash, role: 3, roleName: 'COLONEL' },
            { username: 'colonel', password: pwhash, role: 3, roleName: 'COLONEL' },
            { username: 'colonel_sheppard', password: pwhash, role: 3, roleName: 'COLONEL' },
            { username: 'colonel_oneill', password: pwhash, role: 3, roleName: 'COLONEL' },
            { username: 'sergeant', password: pwhash, role: 2, roleName: 'SERGEANT' },
            { username: 'sergeant_carter', password: pwhash, role: 2, roleName: 'SERGEANT' },
            { username: 'sergeant_tealc', password: pwhash, role: 2, roleName: 'SERGEANT' },
            { username: 'sergeant_jackson', password: pwhash, role: 2, roleName: 'SERGEANT' },
            { username: 'soldier', password: pwhash, role: 1, roleName: 'SOLDIER' }
        ];

        const usersToSeed = baseUsers.map(user => {
            const keys = generateKeyPair();
            return {
                ...user,
                publicKey: keys.publicKey,
                privateKey: keys.privateKey
            };
        });

        // INSERT
        await User.insertMany(usersToSeed);
        console.log('Database successfully re-seeded with RSA keys!');
        console.log('You can now login as "vishal" with password "karthikvishal".');

        mongoose.disconnect();
    } catch (err) {
        console.error('Reset Error:', err);
        process.exit(1);
    }
};

resetDatabase();
