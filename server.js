// ========================================
// RHS MDM Management System - Backend Server
// ========================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8080;

// ========================================
// MIDDLEWARE
// ========================================
app.use(cors());
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// ========================================
// MONGODB CONNECTION
// ========================================
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser:  true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB Connected'))
.catch(err => console.error('MongoDB Error:', err));

// ========================================
// SCHEMAS
// ========================================

const formCSchema = new mongoose.Schema({
    date: String,
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

const bankLedgerSchema = new mongoose.Schema({
    date: String,
    type: String,
    particulars: String,
    voucherNo: String,
    amount: Number,
    balance: Number,
    remarks: String
}, { timestamps: true });

const riceLedgerSchema = new mongoose. Schema({
    date: String,
    type: String,
    particulars: String,
    quantity: Number,
    balance: Number,
    remarks: String
}, { timestamps: true });

const expenseLedgerSchema = new mongoose.Schema({
    date: String,
    particulars: String,
    voucherNo: String,
    amount: Number,
    category: String,
    paymentMode: String,
    remarks: String
}, { timestamps: true });

const cookSchema = new mongoose.Schema({
    name: String,
    role: String,
    phone: String,
    salary: Number,
    joinDate: String,
    status:  { type: String, default: 'active' }
}, { timestamps:  true });

const staffSchema = new mongoose.Schema({
    name: String,
    designation: String,
    phone: String,
    email: String,
    joinDate:  String,
    status: { type: String, default: 'active' }
}, { timestamps: true });

const settingsSchema = new mongoose.Schema({
    settingsId: { type: String, default: 'default', unique: true },
    school: {
        name: String,
        address: String,
        phone:  String,
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

const userSchema = new mongoose.Schema({
    name: { type:  String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role:  { type: String, enum: ['admin', 'teacher', 'viewer'], default: 'viewer' },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    phone: String,
    lastLogin: Date
}, { timestamps: true });

const activityLogSchema = new mongoose.Schema({
    user: { type: mongoose.Schema. Types.ObjectId, ref: 'User' },
    userName: String,
    action: String,
    module: String,
    details: String,
    timestamp: { type: Date, default: Date. now }
});

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
const User = mongoose.model('User', userSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// ========================================
// AUTH MIDDLEWARE
// ========================================
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Token required' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'secret', (err, user) => {
        if (err) return res.status(403).json({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
};

const authorizeRoles = (...roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ success: false, message: 'Permission denied' });
        }
        next();
    };
};

// ========================================
// AUTH ROUTES
// ========================================

app.post('/api/auth/register', authenticateToken, authorizeRoles('admin'), async (req, res) => {
    try {
        const { name, email, password, role, phone } = req.body;
        
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ success: false, message: 'User exists' });
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ name, email, password: hashedPassword, role, phone, status: 'active' });
        
        await ActivityLog.create({
            user: req.user. userId,
            userName: req.user.name,
            action: 'create',
            module: 'Users',
            details: 'Created user:  ' + name
        });
        
        res.json({ success: true, message: 'User created', user:  { id: user._id, name, email, role } });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req. body;
        
        const user = await User.findOne({ email });
        if (!user) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        
        if (user.status !== 'active') return res.status(403).json({ success: false, message: 'Account inactive' });
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });
        
        user.lastLogin = new Date();
        await user.save();
        
        const token = jwt.sign(
            { userId: user._id, email: user.email, role: user.role, name: user.name },
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '7d' }
        );
        
        await ActivityLog.create({ user: user._id, userName: user.name, action: 'login', module: 'Auth', details: 'User login' });
        
        res. json({ success: true, token, user: { id: user._id, name: user.name, email, role:  user.role, phone: user.phone } });
    } catch (error) {
        res.status(500).json({ success: false, message: error. message });
    }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user. userId).select('-password');
        if (!user) return res.status(404).json({ success: false, message: 'User not found' });
        res.json({ success: true, user });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        await ActivityLog.create({ user: req.user.userId, userName: req.user.name, action: 'logout', module: 'Auth', details: 'User logout' });
        res.json({ success: true, message: 'Logged out' });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/activity-logs', authenticateToken, authorizeRoles('admin', 'teacher'), async (req, res) => {
    try {
        const { module, action, limit = 50 } = req.query;
        let query = {};
        if (module && module !== 'all') query.module = module;
        if (action && action !== 'all') query.action = action;
        
        const logs = await ActivityLog.find(query).sort({ timestamp: -1 }).limit(parseInt(limit)).populate('user', 'name email');
        res.json({ success: true, logs });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.get('/api/dashboard/stats', authenticateToken, async (req, res) => {
    try {
        const stats = {
            formC: await FormC.countDocuments(),
            bankBalance: 0,
            riceStock: 0,
            totalExpense: 0,
            activeUsers: await User.countDocuments({ status: 'active' })
        };
        
        const bank = await BankLedger. find().sort({ date: -1 }).limit(1);
        if (bank.length > 0) stats.bankBalance = bank[0]. balance || 0;
        
        const rice = await RiceLedger.find().sort({ date: -1 }).limit(1);
        if (rice.length > 0) stats.riceStock = rice[0].balance || 0;
        
        const thirtyDays = new Date();
        thirtyDays.setDate(thirtyDays.getDate() - 30);
        const expenses = await ExpenseLedger.find({ date: { $gte: thirtyDays. toISOString().split('T')[0] } });
        stats.totalExpense = expenses.reduce((sum, exp) => sum + (exp.amount || 0), 0);
        
        res. json({ success: true, stats });
    } catch (error) {
        res.status(500).json({ success: false, message:  error.message });
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
        const formC = new FormC(req. body);
        await formC. save();
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
        res.status(500).json({ success: false, error:  error.message });
    }
});

// ========================================
// BANK ROUTES
// ========================================
app. get('/api/bank', async (req, res) => {
    try {
        const data = await BankLedger. find().sort({ date: 1 });
        res.json({ success: true, data });
    } catch (error) {
        res.status(500).json({ success: false, error: error. message });
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
// RICE ROUTES
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
        res.status(500).json({ success: false, error:  error.message });
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
// EXPENSE ROUTES
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
        await ExpenseLedger.findByIdAndDelete(req.params. id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// COOK ROUTES
// ========================================
app. get('/api/cooks', async (req, res) => {
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
        res.status(500).json({ success: false, error:  error.message });
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
        await Staff. findByIdAndDelete(req. params.id);
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error. message });
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
            settings = new Settings({ settingsId: 'default', ... req.body });
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
// IMPORT ROUTE
// ========================================
app. post('/api/import', async (req, res) => {
    try {
        const { formC, bankLedger, riceLedger, expenseLedger, cooks, staff, settings } = req.body;
        
        if (formC && formC.length > 0) {
            await FormC.deleteMany({});
            await FormC.insertMany(formC);
        }
        if (bankLedger && bankLedger.length > 0) {
            await BankLedger.deleteMany({});
            await BankLedger.insertMany(bankLedger);
        }
        if (riceLedger && riceLedger. length > 0) {
            await RiceLedger.deleteMany({});
            await RiceLedger.insertMany(riceLedger);
        }
        if (expenseLedger && expenseLedger.length > 0) {
            await ExpenseLedger.deleteMany({});
            await ExpenseLedger.insertMany(expenseLedger);
        }
        if (cooks && cooks.length > 0) {
            await Cook.deleteMany({});
            await Cook.insertMany(cooks);
        }
        if (staff && staff.length > 0) {
            await Staff.deleteMany({});
            await Staff.insertMany(staff);
        }
        if (settings) {
            await Settings.findOneAndUpdate({ settingsId: 'default' }, { settingsId: 'default', ...settings }, { upsert: true });
        }
        
        res.json({ 
            success: true, 
            message: 'Imported successfully',
            imported: {
                formC: formC?. length || 0,
                bankLedger: bankLedger?.length || 0,
                riceLedger: riceLedger?. length || 0,
                expenseLedger: expenseLedger?.length || 0,
                cooks: cooks?. length || 0,
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
        const [settings, formC, bank, rice, expense, cooks, staff] = await Promise. all([
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
            backup: { timestamp: new Date().toISOString(), settings, formC, bankLedger:  bank, riceLedger: rice, expenseLedger: expense, cooks, staff }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ========================================
// ROOT ROUTE
// ========================================
app.get('/', (req, res) => {
    res.send('<! DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RHS MDM</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background: linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display: flex;justify-content:center;align-items:center;padding: 20px}. container{background:#fff;padding:40px;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,. 3);max-width:600px;width:100%}h1{color:#2c3e50;text-align:center;margin-bottom:20px}p{text-align:center;color:#7f8c8d;margin: 10px 0}. status{background:#d4edda;padding:15px;border-radius:10px;margin:20px 0;color:#155724}. status p{margin:8px 0}a{display:block;background:#3498db;color:#fff;padding:12px;margin:8px 0;text-align:center;text-decoration:none;border-radius:8px;transition:. 3s}a:hover{background:#2980b9;transform:translateY(-2px)}.footer{margin-top:20px;font-size:. 85em;color:#7f8c8d;text-align:center}</style></head><body><div class="container"><h1>🍽️ RHS MDM System</h1><p>Ramnagar High School - Midday Meal Management</p><div class="status"><p>✅ Server:  Running</p><p>📡 Port: ' + PORT + '</p><p>🍃 MongoDB: Connected</p><p>⏰ ' + new Date().toLocaleString('en-IN',{timeZone:'Asia/Kolkata'}) + '</p></div><a href="/api/health">🔍 Health Check</a><a href="/api/formC">📝 Form C Data</a><a href="/api/bank">💰 Bank Ledger</a><a href="/api/rice">🌾 Rice Ledger</a><a href="/api/expense">💵 Expense Ledger</a><a href="/api/settings">⚙️ Settings</a><div class="footer"><p>🔒 JWT Authentication Enabled</p><p>Default:  admin@ramnagarhs.edu / admin123</p></div></div></body></html>');
});

app.get('/api/health', (req, res) => {
    res.json({ 
        success: true,
        status: 'OK',
        message: 'Server running',
        mongodb: mongoose.connection.readyState === 1 ? 'Connected' :  'Disconnected',
        port: PORT,
        timestamp: new Date().toISOString()
    });
});

// ========================================
// ERROR HANDLER
// ========================================
app. use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ success: false, error: 'Server error', message: err.message });
});

// ========================================
// INIT ADMIN
// ========================================
async function initAdmin() {
    try {
        const email = 'admin@ramnagarhs.edu';
        const existing = await User.findOne({ email });
        if (!existing) {
            const hash = await bcrypt.hash('admin123', 10);
            await User.create({ name: 'Admin', email, password: hash, role: 'admin', status: 'active' });
            console.log('Admin created:  admin@ramnagarhs.edu / admin123');
        }
    } catch (error) {
        console.error('Admin init error:', error. message);
    }
}

mongoose.connection.once('open', () => {
    console.log('Initializing admin...');
    initAdmin();
});

// ========================================
// START SERVER
// ========================================
app.listen(PORT, () => {
    console.log('RHS MDM Server started on port', PORT);
}).on('error', (err) => {
    console.error('Server error:', err);
    process.exit(1);
});

process.on('SIGINT', async () => {
    console.log('Shutting down.. .');
    await mongoose.connection. close();
    process.exit(0);
});
