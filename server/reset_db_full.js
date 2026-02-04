require('dotenv').config();
const mongoose = require('mongoose');

const resetDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/vanguard_mongo');
        console.log('Connected to MongoDB...');

        await mongoose.connection.dropDatabase();
        console.log('Database Dropped!');

        await mongoose.connection.close();
        console.log('Connection Closed.');
    } catch (err) {
        console.error('Error:', err);
    }
};

resetDB();
