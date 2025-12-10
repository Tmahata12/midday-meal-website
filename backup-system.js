// ========== AUTOMATIC BACKUP SYSTEM ==========
// Add this to api-bridge-simple.js or create separate backup.js

const BACKUP_CONFIG = {
    autoBackup: true,
    backupInterval: 24 * 60 * 60 * 1000, // 24 hours
    backupLocation: 'localStorage', // or send to email/download
    maxBackups: 7 // Keep last 7 backups
};

// Automatic Backup Function
async function createBackup() {
    try {
        console.log('🔄 Creating backup...');
        
        const mdmData = localStorage.getItem('mdmData');
        if (!mdmData) {
            console.log('⚠️ No data to backup');
            return;
        }
        
        const backup = {
            timestamp: new Date().toISOString(),
            date: new Date().toLocaleDateString('en-IN'),
            time: new Date().toLocaleTimeString('en-IN'),
            data: mdmData,
            version: '1.0'
        };
        
        // Get existing backups
        const backupsStr = localStorage.getItem('mdm_backups');
        const backups = backupsStr ? JSON.parse(backupsStr) : [];
        
        // Add new backup
        backups.push(backup);
        
        // Keep only last N backups
        if (backups.length > BACKUP_CONFIG.maxBackups) {
            backups.shift(); // Remove oldest
        }
        
        // Save backups
        localStorage.setItem('mdm_backups', JSON.stringify(backups));
        
        console.log(`✅ Backup created successfully! Total backups: ${backups.length}`);
        
        // Also download as file
        downloadBackup(backup);
        
    } catch (error) {
        console.error('❌ Backup error:', error);
    }
}

// Download Backup as JSON File
function downloadBackup(backup) {
    const filename = `MDM_Backup_${backup.date.replace(/\//g, '-')}_${backup.time.replace(/:/g, '-')}.json`;
    const blob = new Blob([JSON.stringify(backup, null, 2)], {type: 'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
    console.log(`📥 Backup downloaded: ${filename}`);
}

// Restore from Backup
async function restoreBackup(backupIndex) {
    try {
        const backupsStr = localStorage.getItem('mdm_backups');
        if (!backupsStr) {
            alert('No backups found!');
            return;
        }
        
        const backups = JSON.parse(backupsStr);
        if (backupIndex >= backups.length) {
            alert('Invalid backup index!');
            return;
        }
        
        const backup = backups[backupIndex];
        
        if (confirm(`Restore backup from ${backup.date} ${backup.time}?`)) {
            localStorage.setItem('mdmData', backup.data);
            console.log('✅ Backup restored successfully!');
            alert('Backup restored! Page will reload.');
            location.reload();
        }
    } catch (error) {
        console.error('❌ Restore error:', error);
        alert('Failed to restore backup!');
    }
}

// List All Backups
function listBackups() {
    const backupsStr = localStorage.getItem('mdm_backups');
    if (!backupsStr) {
        console.log('No backups found');
        return [];
    }
    
    const backups = JSON.parse(backupsStr);
    console.log('📋 Available Backups:');
    backups.forEach((backup, index) => {
        console.log(`${index}: ${backup.date} ${backup.time}`);
    });
    return backups;
}

// Initialize Backup System
if (BACKUP_CONFIG.autoBackup) {
    // Create backup on page load
    setTimeout(createBackup, 5000); // After 5 seconds
    
    // Create backup every 24 hours
    setInterval(createBackup, BACKUP_CONFIG.backupInterval);
    
    console.log('🛡️ Automatic backup system enabled');
}

// Export functions for use
window.MDMBackup = {
    create: createBackup,
    restore: restoreBackup,
    list: listBackups,
    download: downloadBackup
};

// Usage in console:
// MDMBackup.create() - Create backup now
// MDMBackup.list() - See all backups
// MDMBackup.restore(0) - Restore first backup
