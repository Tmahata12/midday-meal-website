// ========== USER ACTIVITY LOG SYSTEM ==========
// Track all important actions in the system

const ActivityLogger = {
    logs: [],
    maxLogs: 500, // Keep last 500 activities
    
    // Log an activity
    log(action, details) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            date: new Date().toLocaleDateString('en-IN'),
            time: new Date().toLocaleTimeString('en-IN'),
            user: 'admin', // Get from current user
            action: action,
            details: details || {}
        };
        
        // Get existing logs
        const logsStr = localStorage.getItem('mdm_activity_logs');
        this.logs = logsStr ? JSON.parse(logsStr) : [];
        
        // Add new log
        this.logs.push(logEntry);
        
        // Keep only last N logs
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(-this.maxLogs);
        }
        
        // Save logs
        localStorage.setItem('mdm_activity_logs', JSON.stringify(this.logs));
        
        console.log('📝 Activity logged:', action);
    },
    
    // Get logs by date
    getByDate(date) {
        const logsStr = localStorage.getItem('mdm_activity_logs');
        if (!logsStr) return [];
        
        const logs = JSON.parse(logsStr);
        return logs.filter(log => log.date === date);
    },
    
    // Get logs by action
    getByAction(action) {
        const logsStr = localStorage.getItem('mdm_activity_logs');
        if (!logsStr) return [];
        
        const logs = JSON.parse(logsStr);
        return logs.filter(log => log.action === action);
    },
    
    // Get recent logs
    getRecent(count = 10) {
        const logsStr = localStorage.getItem('mdm_activity_logs');
        if (!logsStr) return [];
        
        const logs = JSON.parse(logsStr);
        return logs.slice(-count).reverse();
    },
    
    // Export logs as CSV
    exportCSV() {
        const logsStr = localStorage.getItem('mdm_activity_logs');
        if (!logsStr) {
            alert('No logs to export!');
            return;
        }
        
        const logs = JSON.parse(logsStr);
        
        // Create CSV content
        let csv = 'Date,Time,User,Action,Details\n';
        logs.forEach(log => {
            const details = JSON.stringify(log.details).replace(/"/g, '""');
            csv += `"${log.date}","${log.time}","${log.user}","${log.action}","${details}"\n`;
        });
        
        // Download CSV
        const blob = new Blob([csv], {type: 'text/csv'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Activity_Log_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        
        console.log('📥 Activity log exported');
    },
    
    // Clear old logs
    clearOldLogs(daysToKeep = 90) {
        const logsStr = localStorage.getItem('mdm_activity_logs');
        if (!logsStr) return;
        
        const logs = JSON.parse(logsStr);
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);
        
        const filteredLogs = logs.filter(log => {
            const logDate = new Date(log.timestamp);
            return logDate >= cutoffDate;
        });
        
        localStorage.setItem('mdm_activity_logs', JSON.stringify(filteredLogs));
        console.log(`🗑️ Cleared logs older than ${daysToKeep} days`);
    }
};

// Intercept important actions and log them
// Add this after your existing code

// Override original functions to add logging
const originalSetItem = localStorage.setItem;
localStorage.setItem = function(key, value) {
    if (key === 'mdmData') {
        try {
            const data = JSON.parse(value);
            // Log based on what changed
            ActivityLogger.log('DATA_UPDATED', {
                formCCount: data.formC?.length || 0,
                bankCount: data.bankLedger?.length || 0,
                riceCount: data.riceLedger?.length || 0
            });
        } catch (e) {}
    }
    return originalSetItem.call(this, key, value);
};

// Export for global use
window.ActivityLogger = ActivityLogger;

// Usage examples:
// ActivityLogger.log('FORM_C_ADDED', {class: 'V', students: 75});
// ActivityLogger.log('BANK_TRANSACTION', {amount: 5000, type: 'credit'});
// ActivityLogger.log('SETTINGS_UPDATED', {field: 'school.name'});
// ActivityLogger.getRecent(20) - Get last 20 activities
// ActivityLogger.exportCSV() - Download activity log
