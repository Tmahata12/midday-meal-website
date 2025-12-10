// Create Default Admin User Script
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// MongoDB Connection
const MONGODB_URI = 'mongodb+srv://tmahata0100_db_user:sjI4p9mBZucFQ7kY@cluster0.jbqjbsg.mongodb.net/rhs_mdm?retryWrites=true&w=majority&appName=Cluster0';

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'teacher', 'viewer'], default: 'viewer' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    phone: String,
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

async function createDefaultAdmin() {
    try {
        console.log('🔌 Connecting to MongoDB...');
        await mongoose.connect(MONGODB_URI);
        console.log('✅ Connected to MongoDB!');

        // Check if admin exists
        const existingAdmin = await User.findOne({ email: 'admin@ramnagarhs.edu' });

        if (existingAdmin) {
            console.log('ℹ️  Admin user already exists!');
            console.log('📧 Email: admin@ramnagarhs.edu');
            console.log('🔑 Password: (existing password)');
        } else {
            // Create new admin
            const hashedPassword = await bcrypt.hash('admin123', 10);
            
            const admin = await User.create({
                name: 'Admin',
                email: 'admin@ramnagarhs.edu',
                password: hashedPassword,
                role: 'admin',
                status: 'active',
                phone: '',
                createdAt: new Date()
            });

            console.log('✅ Default admin user created successfully!');
            console.log('');
            console.log('📧 Email: admin@ramnagarhs.edu');
            console.log('🔑 Password: admin123');
            console.log('');
            console.log('⚠️  Please change the password after first login!');
        }

        await mongoose.connection.close();
        console.log('');
        console.log('✅ Done! You can now start the server with: npm start');
        process.exit(0);

    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

// Run the function
createDefaultAdmin();
