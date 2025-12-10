// RHS MDM System - Health Check Script
// Run this to verify your setup is correct
// Usage: node test-setup.js

const fs = require('fs');
const path = require('path');

console.log('🔍 RHS MDM System - Setup Verification\n');
console.log('═'.repeat(50));

let errors = 0;
let warnings = 0;

// Check 1: Required Files
console.log('\n📁 Checking Required Files...');
const requiredFiles = [
    'server.js',
    'package.json',
    'RHS_MDM_MONGODB_READY.html',
    'api-bridge-simple.js'
];

requiredFiles.forEach(file => {
    if (fs.existsSync(file)) {
        console.log(`  ✅ ${file}`);
    } else {
        console.log(`  ❌ ${file} - MISSING!`);
        errors++;
    }
});

// Check 2: .env file
console.log('\n🔐 Checking Environment Configuration...');
if (fs.existsSync('.env')) {
    console.log('  ✅ .env file exists');
    
    const envContent = fs.readFileSync('.env', 'utf8');
    
    if (envContent.includes('MONGODB_URI=')) {
        if (envContent.includes('your_username') || envContent.includes('your_password')) {
            console.log('  ⚠️  WARNING: .env file contains placeholder values!');
            console.log('     Please update with actual MongoDB credentials');
            warnings++;
        } else {
            console.log('  ✅ MONGODB_URI configured');
        }
    } else {
        console.log('  ❌ MONGODB_URI not found in .env');
        errors++;
    }
} else {
    console.log('  ⚠️  .env file not found');
    console.log('     Copy .env.example to .env and configure it');
    warnings++;
}

// Check 3: node_modules
console.log('\n📦 Checking Dependencies...');
if (fs.existsSync('node_modules')) {
    console.log('  ✅ node_modules folder exists');
    
    const requiredPackages = ['express', 'mongoose', 'cors', 'dotenv', 'body-parser'];
    let allInstalled = true;
    
    requiredPackages.forEach(pkg => {
        if (fs.existsSync(`node_modules/${pkg}`)) {
            console.log(`  ✅ ${pkg} installed`);
        } else {
            console.log(`  ❌ ${pkg} NOT installed`);
            allInstalled = false;
            errors++;
        }
    });
    
    if (!allInstalled) {
        console.log('\n  💡 Run: npm install');
    }
} else {
    console.log('  ❌ node_modules not found');
    console.log('     Run: npm install');
    errors++;
}

// Check 4: Port availability (if .env exists)
console.log('\n🔌 Checking Port Configuration...');
if (fs.existsSync('.env')) {
    const envContent = fs.readFileSync('.env', 'utf8');
    const portMatch = envContent.match(/PORT=(\d+)/);
    
    if (portMatch) {
        const port = portMatch[1];
        console.log(`  ✅ PORT configured: ${port}`);
    } else {
        console.log('  ⚠️  PORT not configured in .env (will use default 3000)');
        warnings++;
    }
}

// Check 5: JavaScript Files
console.log('\n📜 Checking JavaScript Modules...');
const jsFiles = [
    'activity-logger.js',
    'advanced-export.js',
    'backup-system.js',
    'enhanced-formc-system.js',
    'formc-dashboard.js'
];

jsFiles.forEach(file => {
    if (fs.existsSync(file)) {
        console.log(`  ✅ ${file}`);
    } else {
        console.log(`  ⚠️  ${file} - Not found (optional)`);
    }
});

// Summary
console.log('\n' + '═'.repeat(50));
console.log('\n📊 Summary:');
console.log(`  Errors: ${errors}`);
console.log(`  Warnings: ${warnings}`);

if (errors === 0 && warnings === 0) {
    console.log('\n✅ Everything looks good! You can start the server.');
    console.log('   Run: npm start\n');
} else if (errors === 0) {
    console.log('\n⚠️  Some warnings found, but you can proceed.');
    console.log('   Address the warnings for best results.');
    console.log('   Run: npm start\n');
} else {
    console.log('\n❌ Please fix the errors before starting the server.\n');
}

console.log('═'.repeat(50));
console.log('\n💡 Next Steps:');
console.log('   1. Fix any errors shown above');
console.log('   2. Configure .env with MongoDB credentials');
console.log('   3. Run: npm install (if needed)');
console.log('   4. Run: npm start');
console.log('   5. Test: http://localhost:3000/api/health\n');
