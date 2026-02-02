require('dotenv').config();
const mongoose = require('mongoose');
const forge = require('node-forge');

const UserSchema = new mongoose.Schema({
    username: String,
    publicKey: String,
    privateKey: String
});
const User = mongoose.model('User', UserSchema);

const generateKeyPair = () => {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
    return {
        publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
        privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
    };
};

async function repair() {
    try {
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vanguard_mongo');

        const users = await User.find({
            $or: [{ publicKey: null }, { privateKey: null }]
        });

        console.log(`Found ${users.length} users needing key repair.`);

        for (const user of users) {
            console.log(`Generating keys for user: ${user.username}...`);
            const keys = generateKeyPair();
            user.publicKey = keys.publicKey;
            user.privateKey = keys.privateKey;
            await user.save();
            console.log(`> Fixed ${user.username}`);
        }

        console.log('Repair Complete.');
        mongoose.disconnect();
    } catch (e) {
        console.error(e);
    }
}
repair();
