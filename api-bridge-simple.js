// MongoDB API Bridge - Simple Version
// Add: <script src="api-bridge-simple.js"></script> before </body>

// Auto-detect API URL based on environment
const API = window.location.hostname === 'localhost' 
    ? "http://localhost:3000/api" 
    : `${window.location.protocol}//${window.location.host}/api`;

let syncing = false;

console.log("🚀 Starting MongoDB Bridge...");
console.log("📡 API Endpoint:", API);

// Save original localStorage
const oldSet = localStorage.setItem.bind(localStorage);
const oldGet = localStorage.getItem.bind(localStorage);

// API call helper with authentication
async function callAPI(path, method, data) {
    try {
        // Get auth token
        const token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
        
        const headers = {"Content-Type": "application/json"};
        
        // Add auth header if token exists
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }
        
        const res = await fetch(API + path, {
            method: method || "GET",
            headers: headers,
            body: data ? JSON.stringify(data) : null
        });
        
        // Check for authentication errors
        if (res.status === 401) {
            // Unauthorized - redirect to login
            console.log('⚠️ Authentication required - redirecting to login');
            window.location.href = 'login.html';
            return null;
        }
        
        return await res.json();
    } catch(e) {
        console.error("API Error:", e);
        return null;
    }
}

// Sync to MongoDB
async function syncToMongo(dataStr) {
    if (syncing) return;
    syncing = true;
    
    try {
        const d = JSON.parse(dataStr);
        await callAPI("/import", "POST", {
            formC: d.formC || [],
            bankLedger: d.bankLedger || [],
            riceLedger: d.riceLedger || [],
            expenseLedger: d.expenseLedger || [],
            cooks: d.cooks || [],
            staff: d.staff || [],
            settings: {
                school: d.school || {},
                enrollment: d.enrollment || {},
                bank: d.bank || {},
                riceStock: d.riceOpeningStock || 0,
                fundOpening: d.fundOpening || 120000
            }
        });
        console.log("✅ Synced to MongoDB");
    } catch(e) {
        console.error("❌ Sync error:", e);
    }
    
    syncing = false;
}

// Load from MongoDB
async function loadFromMongo() {
    try {
        const [settings, formC, bank, rice, expense, cooks, staff] = await Promise.all([
            callAPI("/settings"),
            callAPI("/formC"),
            callAPI("/bank"),
            callAPI("/rice"),
            callAPI("/expense"),
            callAPI("/cooks"),
            callAPI("/staff")
        ]);
        
        const data = {};
        
        if (settings && settings.success) {
            data.school = settings.data.school || {};
            data.enrollment = settings.data.enrollment || {};
            data.bank = settings.data.bank || {};
            data.riceOpeningStock = settings.data.riceStock || 0;
            data.fundOpening = settings.data.fundOpening || 120000;
        }
        
        data.formC = (formC && formC.success) ? formC.data : [];
        data.bankLedger = (bank && bank.success) ? bank.data : [];
        data.riceLedger = (rice && rice.success) ? rice.data : [];
        data.expenseLedger = (expense && expense.success) ? expense.data : [];
        data.cooks = (cooks && cooks.success) ? cooks.data : [];
        data.staff = (staff && staff.success) ? staff.data : [];
        
        syncing = true;
        oldSet("mdmData", JSON.stringify(data));
        syncing = false;
        
        console.log("✅ Loaded from MongoDB");
        
        if (location.hash !== "#loaded") {
            location.hash = "loaded";
            location.reload();
        }
    } catch(e) {
        console.error("❌ Load error:", e);
    }
}

// Override localStorage.setItem
localStorage.setItem = function(key, value) {
    oldSet(key, value);
    if (key === "mdmData" && !syncing) {
        syncToMongo(value);
    }
};

// Auto-sync every 30 seconds
setInterval(function() {
    const data = oldGet("mdmData");
    if (data && !syncing) {
        syncToMongo(data);
    }
}, 30000);

// Initialize
console.log("🍃 MongoDB API Bridge activated!");
console.log("📊 Auto-sync enabled");
loadFromMongo();
