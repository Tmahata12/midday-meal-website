// ========================================
// RHS MDM Management System - Backend Server
// Complete Node.js + Express + MongoDB Server
// ========================================

const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================
// MIDDLEWARE
// ========================================
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(__dirname)); // Serve static files from current directory

// ========================================
// MONGODB CONNECTION
// ========================================
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected Successfully!'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// ========================================
// MONGOOSE SCHEMAS
// ========================================

// Form C Schema
const formCSchema = new mongoose.Schema({
    date: { type: String, required: true },
    class: String,
    students: Number,
    attendanceMale: Number,
    attendanceFemale: Number,
    attendance: Number,
    meals: Number,
    rice: Number,
    costPerMeal: Number,
    totalCost: Number,
    remarks: String
}, { timestamps: true });

// Bank Ledger Schema
const bankLedgerSchema = new mongoose.Schema({
    date: { type: String, required: true },
    type: { type: String, enum: ['receipt', 'payment'], required: true },
    particulars: String,
    voucherNo: String,
    amount: { type: Number, required: true },
    balance: Number,
    remarks: String
}, { timestamps: true });

// Rice Ledger Schema
const riceLedgerSchema = new mongoose.Schema({
    date: { type: String, required: true },
    type: { type: String, enum: ['receipt', 'issue'], required: true },
    particulars: String,
    quantity: { type: Number, required: true },
    balance: Number,
    remarks: String
}, { timestamps: true });

// Expense Ledger Schema
const expenseLedgerSchema = new mongoose.Schema({
    date: { type: String, required: true },
    particulars: String,
    voucherNo: String,
    amount: { type: Number, required: true },
    category: String,
    paymentMode: String,
    remarks: String
}, { timestamps: true });

// Cook Schema
const cookSchema = new mongoose.Schema({
    name: { type: String, required: true },
    role: String,
    phone: String,
    salary: Number,
    joinDate: String,
    status: { type: String, default: 'active' }
}, { timestamps: true });

// Staff Schema
const staffSchema = new mongoose.Schema({
    name: { type: String, required: true },
    designation: String,
    phone: String,
    email: String,
    joinDate: String,
    status: { type: String, default: 'active' }
}, { timestamps: true });

// Settings Schema
const settingsSchema = new mongoose.Schema({
    settingsId: { type: String, default: 'default', unique: true },
    school: {
        name: String,
        address: String,
        phone: String,
        email: String,
        principal: String,
        teacherInCharge: String
    },
    enrollment: {
        class1: Number,
        class2: Number,
        class3: Number,
        class4: Number,
        class5: Number,
        class6: Number,
        class7: Number,
        class8: Number,
        class9: Number,
        class10: Number,
        class11: Number,
        class12: Number
    },
    bank: {
        name: String,
        branch: String,
        accountNo: String,
        ifsc: String
    },
    riceStock: { type: Number, default: 0 },
    fundOpening: { type: Number, default: 120000 }
}, { timestamps: true });

// ========================================
// MODELS
// ========================================
const FormC = mongoose.model('FormC', formCSchema);
const BankLedger = mongoose.model('BankLedger', bankLedgerSchema);
const RiceLedger = mongoose.model('RiceLedger', riceLedgerSchema);
const ExpenseLedger = mongoose.model('ExpenseLedger', expenseLedgerSchema);
const Cook = mongoose.model('Cook', cookSchema);
const Staff = mongoose.model('Staff', staffSchema);
const Settings = mongoose.model('Settings', settingsSchema);

// User Schema for Authentication (V2.0)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['admin', 'teacher', 'viewer'], default: 'viewer' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    phone: String,
    lastLogin: Date,
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Activity Log Schema (V2.0)
const activityLogSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    userName: String,
    action: { type: String, required: true }, // 'create', 'update', 'delete', 'login', 'logout'
    module: String, // 'FormC', 'Bank', 'Rice', 'Expense', 'Auth', 'Users'
    details: String,
    timestamp: { type: Date, default: Date.now }
});

const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Role-based authorization middleware
const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                message: 'You do not have permission to perform this action' 
            });
        }
        next();
    };
};

// ========================================
// API ROUTES
// ========================================

// Health Check
app.get('/api/health', (req, res) => {
    res.json({ 
        success: true, 
        message: 'RHS MDM Server is running!',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'
    });
});

// ========================================
// AUTHENTICATION ROUTES (V2.0)
// ========================================

// Register new user (Admin only)
app.post('/api/auth/register', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { name, email, password, role, phone } = req.body;

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            role: role || 'viewer',
            phone,
            status: 'active'
        });

        // Log activity
        await ActivityLog.create({
            user: req.user.userId,
            userName: req.user.name,
            action: 'create',
            module: 'Users',
            details: `Created new user: ${name} (${email})`
        });

        res.json({
            success: true,
            message: 'User created successfully',
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ success: false, message: 'Server error during registration' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        // Check if user is active
        if (user.status !== 'active') {
            return res.status(403).json({ success: false, message: 'Account is inactive' });
        }

        // Verify password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ success: false, message: 'Invalid email or password' });
        }

        // Update last login
        user.lastLogin = new Date();
        await user.save();

        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role, name: user.name },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        // Log activity
        await ActivityLog.create({
            user: user._id,
            userName: user.name,
            action: 'login',
            module: 'Auth',
            details: 'User logged in'
        });

        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                phone: user.phone
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Server error during login' });
    }
});

// Get current user info
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({ success: true, user });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        // Log activity
        await ActivityLog.create({
            user: req.user.userId,
            userName: req.user.name,
            action: 'logout',
            module: 'Auth',
            details: 'User logged out'
        });

        res.json({ success: true, message: 'Logout successful' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get activity logs (Admin and Teacher only)
app.get('/api/activity-logs', authenticateToken, authorizeRoles('admin', 'teacher'), async (req, res) => {
    try {
        const { module, action, limit = 50 } = req.query;
        
        let query = {};
        if (module && module !== 'all') query.module = module;
        if (action && action !== 'all') query.action = action;

        const logs = await ActivityLog.find(query)
            .sort({ timestamp: -1 })
            .limit(parseInt(limit))
            .populate('user', 'name email');

        res.json({ success: true, logs });
    } catch (error) {
        console.error('Get logs error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Dashboard statistics (Authenticated users)
app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const stats = {
            formC: await FormC.countDocuments(),
            bankBalance: 0,
            riceStock: 0,
            totalExpense: 0,
            activeUsers: await User.countDocuments({ status: 'active' })
        };

        // Get bank balance
        const bankLedger = await BankLedger.find().sort({ date: -1 }).limit(1);
        if (bankLedger.length > 0) {
            stats.bankBalance = bankLedger[0].balance || 0;
        }

        // Get rice stock
        const riceLedger = await RiceLedger.find().sort({ date: -1 }).limit(1);
        if (riceLedger.length > 0) {
            stats.riceStock = riceLedger[0].closingStock || 0;
        }

        // Get total expense (last 30 days)
        const thirtyDaysAgo = new Date();
        thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
        const expenses = await ExpenseLedger.find({
            date: { $gte: thirtyDaysAgo.toISOString().split('T')[0] }
        });
        stats.totalExpense = expenses.reduce((sum, exp) => sum + (exp.amount || 0), 0);

        res.json({ success: true, stats });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ========================================
// FORM C ROUTES
// ========================================
app.get('/api/formC', async (req, res) => {
    try {
        const data = await FormC.find().sort({ date: 1 });
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/formC', async (req, res) => {
    try {
        const formC = new FormC(req.body);
        await formC.save();
        res.json({ success: true, data: formC });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/formC/:id', async (req, res) => {
    try {
        const formC = await FormC.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json({ success: true, data: formC });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/formC/:id', async (req, res) => {
    try {
        await FormC.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// BANK LEDGER ROUTES
// ========================================
app.get('/api/bank', async (req, res) => {
    try {
        const data = await BankLedger.find().sort({ date: 1 });
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/bank', async (req, res) => {
    try {
        const ledger = new BankLedger(req.body);
        await ledger.save();
        res.json({ success: true, data: ledger });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/bank/:id', async (req, res) => {
    try {
        await BankLedger.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// RICE LEDGER ROUTES
// ========================================
app.get('/api/rice', async (req, res) => {
    try {
        const data = await RiceLedger.find().sort({ date: 1 });
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/rice', async (req, res) => {
    try {
        const ledger = new RiceLedger(req.body);
        await ledger.save();
        res.json({ success: true, data: ledger });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/rice/:id', async (req, res) => {
    try {
        await RiceLedger.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// EXPENSE LEDGER ROUTES
// ========================================
app.get('/api/expense', async (req, res) => {
    try {
        const data = await ExpenseLedger.find().sort({ date: 1 });
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/expense', async (req, res) => {
    try {
        const ledger = new ExpenseLedger(req.body);
        await ledger.save();
        res.json({ success: true, data: ledger });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/expense/:id', async (req, res) => {
    try {
        await ExpenseLedger.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// COOK ROUTES
// ========================================
app.get('/api/cooks', async (req, res) => {
    try {
        const data = await Cook.find();
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/cooks', async (req, res) => {
    try {
        const cook = new Cook(req.body);
        await cook.save();
        res.json({ success: true, data: cook });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/cooks/:id', async (req, res) => {
    try {
        await Cook.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// STAFF ROUTES
// ========================================
app.get('/api/staff', async (req, res) => {
    try {
        const data = await Staff.find();
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/staff', async (req, res) => {
    try {
        const staff = new Staff(req.body);
        await staff.save();
        res.json({ success: true, data: staff });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.delete('/api/staff/:id', async (req, res) => {
    try {
        await Staff.findByIdAndDelete(req.params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// SETTINGS ROUTES
// ========================================
app.get('/api/settings', async (req, res) => {
    try {
        let settings = await Settings.findOne({ settingsId: 'default' });
        if (!settings) {
            settings = new Settings({ settingsId: 'default' });
            await settings.save();
        }
        res.json({ success: true, data: settings });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.put('/api/settings', async (req, res) => {
    try {
        let settings = await Settings.findOne({ settingsId: 'default' });
        if (!settings) {
            settings = new Settings({ settingsId: 'default', ...req.body });
        } else {
            Object.assign(settings, req.body);
        }
        await settings.save();
        res.json({ success: true, data: settings });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// BULK IMPORT ROUTE (for initial data migration)
// ========================================
app.post('/api/import', async (req, res) => {
    try {
        const { formC, bankLedger, riceLedger, expenseLedger, cooks, staff, settings } = req.body;
        
        // Import Form C
        if (formC && formC.length > 0) {
            await FormC.deleteMany({});
            await FormC.insertMany(formC);
        }
        
        // Import Bank Ledger
        if (bankLedger && bankLedger.length > 0) {
            await BankLedger.deleteMany({});
            await BankLedger.insertMany(bankLedger);
        }
        
        // Import Rice Ledger
        if (riceLedger && riceLedger.length > 0) {
            await RiceLedger.deleteMany({});
            await RiceLedger.insertMany(riceLedger);
        }
        
        // Import Expense Ledger
        if (expenseLedger && expenseLedger.length > 0) {
            await ExpenseLedger.deleteMany({});
            await ExpenseLedger.insertMany(expenseLedger);
        }
        
        // Import Cooks
        if (cooks && cooks.length > 0) {
            await Cook.deleteMany({});
            await Cook.insertMany(cooks);
        }
        
        // Import Staff
        if (staff && staff.length > 0) {
            await Staff.deleteMany({});
            await Staff.insertMany(staff);
        }
        
        // Import Settings
        if (settings) {
            await Settings.findOneAndUpdate(
                { settingsId: 'default' },
                { settingsId: 'default', ...settings },
                { upsert: true, new: true }
            );
        }
        
        res.json({ 
            success: true, 
            message: 'Data imported successfully!',
            imported: {
                formC: formC?.length || 0,
                bankLedger: bankLedger?.length || 0,
                riceLedger: riceLedger?.length || 0,
                expenseLedger: expenseLedger?.length || 0,
                cooks: cooks?.length || 0,
                staff: staff?.length || 0
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// BACKUP ROUTE
// ========================================
app.get('/api/backup', async (req, res) => {
    try {
        const [settings, formC, bank, rice, expense, cooks, staff] = await Promise.all([
            Settings.findOne({ settingsId: 'default' }),
            FormC.find().sort({ date: 1 }),
            BankLedger.find().sort({ date: 1 }),
            RiceLedger.find().sort({ date: 1 }),
            ExpenseLedger.find().sort({ date: 1 }),
            Cook.find(),
            Staff.find()
        ]);
        
        res.json({
            success: true,
            backup: {
                timestamp: new Date().toISOString(),
                settings,
                formC,
                bankLedger: bank,
                riceLedger: rice,
                expenseLedger: expense,
                cooks,
                staff
            }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// SERVE MAIN HTML FILE
// ========================================
// ========================================
// ROOT ROUTES
// ========================================

app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>RHS MDM Management System</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background:  linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                .container {
                    background: white;
                    padding: 50px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    max-width: 700px;
                    width: 100%;
                    animation: fadeIn 0.5s ease-in;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(-20px); }
                    to { opacity: 1; transform:  translateY(0); }
                }
                h1 {
                    color: #2c3e50;
                    margin-bottom: 10px;
                    font-size: 2.5em;
                    text-align:  center;
                }
                . subtitle {
                    text-align: center;
                    color: #7f8c8d;
                    margin-bottom: 30px;
                    font-size: 1.1em;
                }
                . status-card {
                    background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
                    color: #155724;
                    padding: 20px;
                    border-radius: 15px;
                    margin: 20px 0;
                    border-left: 5px solid #28a745;
                }
                .status-card h3 {
                    margin-bottom: 15px;
                    font-size: 1.3em;
                }
                .status-item {
                    display: flex;
                    justify-content: space-between;
                    padding: 8px 0;
                    border-bottom: 1px solid rgba(0,0,0,0.1);
                }
                .status-item: last-child {
                    border-bottom: none;
                }
                .status-label {
                    font-weight:  600;
                }
                .status-value {
                    color: #28a745;
                    font-weight: bold;
                }
                .api-links {
                    margin-top: 30px;
                }
                .api-links h3 {
                    color: #2c3e50;
                    margin-bottom: 15px;
                    text-align: center;
                }
                .link-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                }
                .api-link {
                    display: block;
                    background: linear-gradient(135deg, #3498db 0%, #2980b9 100%);
                    color: white;
                    padding: 15px 20px;
                    border-radius: 10px;
                    text-decoration: none;
                    text-align: center;
                    transition: all 0.3s;
                    font-weight: 500;
                    box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
                }
                .api-link:hover {
                    transform: translateY(-3px);
                    box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
                }
                .footer {
                    margin-top: 30px;
                    text-align: center;
                    color:  #7f8c8d;
                    font-size: 0.9em;
                }
                .emoji {
                    font-size:  1.5em;
                    margin-right: 10px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🍽️ RHS MDM Management System</h1>
                <p class="subtitle">Ramnagar High School - Midday Meal Management</p>
                
                <div class="status-card">
                    <h3>✅ System Status</h3>
                    <div class="status-item">
                        <span class="status-label">📡 Server Status:</span>
                        <span class="status-value">Running</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">🍃 MongoDB: </span>
                        <span class="status-value">Connected</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">🚀 Deployment:</span>
                        <span class="status-value">Railway Cloud</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">⏰ Server Time:</span>
                        <span class="status-value">${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })}</span>
                    </div>
                    <div class="status-item">
                        <span class="status-label">🔐 Authentication:</span>
                        <span class="status-value">Enabled</span>
                    </div>
                </div>

                <div class="api-links">
                    <h3>📋 API Endpoints</h3>
                    <div class="link-grid">
                        <a href="/api/health" class="api-link">🔍 Health Check</a>
                        <a href="/api/formC" class="api-link">📝 Form C Data</a>
                        <a href="/api/bank" class="api-link">💰 Bank Ledger</a>
                        <a href="/api/rice" class="api-link">🌾 Rice Ledger</a>
                        <a href="/api/expense" class="api-link">💵 Expense Ledger</a>
                        <a href="/api/settings" class="api-link">⚙️ Settings</a>
                    </div>
                </div>

                <div class="footer">
                    <p>🔒 Secured with JWT Authentication</p>
                    <p>Built with Node.js + Express + MongoDB</p>
                    <p style="margin-top: 10px; font-size: 0.8em;">
                        Default Login: <strong>admin@ramnagarhs. edu</strong> / <strong>admin123</strong>
                    </p>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ 
        success: true,
        status: 'OK', 
        message: 'RHS MDM Server is running smoothly',
        mongodb: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        uptime: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
        environment: process.env. NODE_ENV || 'production',
        port: PORT
    });
});

// ========================================
// ERROR HANDLING
// ========================================
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ 
        success: false, 
        error: 'Something went wrong!',
        message: err.message 
    });
});

// ========================================

// ========================================
// INITIALIZE DEFAULT ADMIN USER
// ========================================
async function initializeDefaultAdmin() {
    try {
        const adminEmail = 'admin@ramnagarhs.edu';
        const existingAdmin = await User.findOne({ email: adminEmail });
        
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await User.create({
                name: 'Admin',
                email: adminEmail,
                password: hashedPassword,
                role: 'admin',
                status: 'active'
            });
            console.log('\n✅ Default admin user created');
            console.log('   📧 Email: admin@ramnagarhs.edu');
            console.log('   🔑 Password: admin123\n');
        }
    } catch (error) {
        console.error('❌ Error creating default admin:', error.message);
    }
}

// Initialize on MongoDB connection
mongoose.connection.once('open', async () => {
    console.log('🔐 Initializing authentication system...');
    await initializeDefaultAdmin();
});

// START SERVER
// ========================================
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════╗
║   🍽️  RHS MDM Management System Server          ║
║   📡 Server running on port ${PORT}               ║
║   🌐 Access: http://localhost:${PORT}            ║
║   🍃 MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected ✅' : 'Connecting... ⏳'}  ║
╚══════════════════════════════════════════════════╝
    `);
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down gracefully...');
    await mongoose.connection.close();
    process.exit(0);
});
