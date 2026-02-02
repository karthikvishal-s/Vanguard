require('dotenv').config();
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: String,
    publicKey: String,
    privateKey: String
});
const User = mongoose.model('User', UserSchema);

async function check() {
    try {
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vanguard_mongo');
        const users = await User.find({}, 'username publicKey privateKey');

        console.log('--- USER KEY AUDIT ---');
        users.forEach(u => {
            const hasPub = !!u.publicKey;
            const hasPriv = !!u.privateKey;
            console.log(`User: ${u.username.padEnd(15)} | PubKey: ${hasPub} | PrivKey: ${hasPriv}`);
        });
        mongoose.disconnect();
    } catch (e) {
        console.error(e);
    }
}
check();
