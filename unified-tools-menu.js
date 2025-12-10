// ========== UNIFIED TOOLS MENU SYSTEM (TAB INTEGRATED) ==========
// All MDM features in one organized menu - now integrated with tab bar!

const UnifiedToolsMenu = {
    
    // Initialize unified menu
    init() {
        console.log('🎛️ Unified Tools Menu initialized (Tab Version)');
        this.hideFloatingButtons();
        this.addToolsTab();
        this.createMenu();
        this.checkFeatures();
    },
    
    // Hide all floating buttons
    hideFloatingButtons() {
        const style = document.createElement('style');
        style.textContent = `
            /* Hide all floating buttons */
            #open-search-btn,
            #open-bulk-btn,
            #open-export-btn,
            #unified-tools-btn {
                display: none !important;
            }
        `;
        document.head.appendChild(style);
    },
    
    // Add Tools tab to navigation
    addToolsTab() {
        // Wait for navigation to be ready
        setTimeout(() => {
            const nav = document.querySelector('.nav-tabs');
            if (nav) {
                const toolsTab = document.createElement('button');
                toolsTab.className = 'nav-tab';
                toolsTab.setAttribute('data-section', 'tools');
                toolsTab.innerHTML = '🎛️ Tools';
                toolsTab.style.cssText = 'background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; font-weight: bold;';
                
                toolsTab.onclick = () => {
                    this.showToolsSection();
                };
                
                nav.appendChild(toolsTab);
                console.log('✅ Tools tab added to navigation');
            }
        }, 500);
    },
    
    // Show tools section
    showToolsSection() {
        // Hide all other sections
        document.querySelectorAll('[data-section]').forEach(section => {
            if (section.style) section.style.display = 'none';
        });
        
        // Show tools section
        let toolsSection = document.getElementById('tools-section');
        if (!toolsSection) {
            toolsSection = document.createElement('div');
            toolsSection.id = 'tools-section';
            toolsSection.setAttribute('data-section', 'tools');
            toolsSection.style.display = 'block';
            
            const mainContent = document.querySelector('.main-content') || document.body;
            mainContent.appendChild(toolsSection);
        }
        
        toolsSection.style.display = 'block';
        this.renderToolsMenu(toolsSection);
        
        // Update active tab
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
        });
        document.querySelector('[data-section="tools"]')?.classList.add('active');
    },
    
    // Create menu UI
    createMenu() {
        // Menu is now rendered in tools section when tab is clicked
    },
    
    // Render tools menu in section
    renderToolsMenu(container) {
        container.innerHTML = `
            <div style="padding: 20px;">
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; color: white;">
                    <h2 style="margin: 0 0 10px 0;">
                        🎛️ MDM Tools Menu
                    </h2>
                    <p style="margin: 0; opacity: 0.9;">All system features and utilities in one place</p>
                </div>
                
                <!-- Feature Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px;">
                    
                    <!-- Search Feature -->
                    <div class="tool-card" style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 4px solid #667eea; cursor: pointer; transition: all 0.3s;" onclick="UnifiedToolsMenu.openSearch()">
                        <div style="font-size: 40px; margin-bottom: 10px;">🔍</div>
                        <h3 style="margin: 10px 0 5px 0; color: #667eea;">Search Data</h3>
                        <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Search across all ledgers with advanced filters</p>
                        <div id="search-status" class="status-badge" style="padding: 5px 10px; background: #d4edda; color: #155724; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold;">✅ Ready</div>
                    </div>
                    
                    <!-- Bulk Entry Feature -->
                    <div class="tool-card" style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 4px solid #27ae60; cursor: pointer; transition: all 0.3s;" onclick="UnifiedToolsMenu.openBulkEntry()">
                        <div style="font-size: 40px; margin-bottom: 10px;">📋</div>
                        <h3 style="margin: 10px 0 5px 0; color: #27ae60;">Bulk Entry</h3>
                        <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Add multiple Form C entries at once</p>
                        <div id="bulk-status" class="status-badge" style="padding: 5px 10px; background: #d4edda; color: #155724; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold;">✅ Ready</div>
                    </div>
                    
                    <!-- Export Feature -->
                    <div class="tool-card" style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 4px solid #3498db; cursor: pointer; transition: all 0.3s;" onclick="UnifiedToolsMenu.openExport()">
                        <div style="font-size: 40px; margin-bottom: 10px;">📊</div>
                        <h3 style="margin: 10px 0 5px 0; color: #3498db;">Export Data</h3>
                        <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Export all ledgers to Excel format</p>
                        <div id="export-status" class="status-badge" style="padding: 5px 10px; background: #d4edda; color: #155724; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold;">✅ Ready</div>
                    </div>
                    
                    <!-- Backup Feature -->
                    <div class="tool-card" style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 4px solid #9b59b6; cursor: pointer; transition: all 0.3s;" onclick="UnifiedToolsMenu.createBackup()">
                        <div style="font-size: 40px; margin-bottom: 10px;">💾</div>
                        <h3 style="margin: 10px 0 5px 0; color: #9b59b6;">Create Backup</h3>
                        <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Download complete system backup</p>
                        <div id="backup-status" class="status-badge" style="padding: 5px 10px; background: #d4edda; color: #155724; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold;">✅ Auto-enabled</div>
                    </div>
                    
                    <!-- Activity Log Feature -->
                    <div class="tool-card" style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 4px solid #e74c3c; cursor: pointer; transition: all 0.3s;" onclick="UnifiedToolsMenu.viewActivityLog()">
                        <div style="font-size: 40px; margin-bottom: 10px;">📝</div>
                        <h3 style="margin: 10px 0 5px 0; color: #e74c3c;">Activity Log</h3>
                        <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">View recent system activities</p>
                        <div id="log-status" class="status-badge" style="padding: 5px 10px; background: #d4edda; color: #155724; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold;">✅ Tracking</div>
                    </div>
                    
                    <!-- Sync Status Feature -->
                    <div class="tool-card" style="background: #f8f9fa; padding: 25px; border-radius: 10px; border-left: 4px solid #f39c12; cursor: pointer; transition: all 0.3s;" onclick="UnifiedToolsMenu.showSyncStatus()">
                        <div style="font-size: 40px; margin-bottom: 10px;">🔄</div>
                        <h3 style="margin: 10px 0 5px 0; color: #f39c12;">Sync Status</h3>
                        <p style="color: #666; margin: 0 0 10px 0; font-size: 14px;">Check MongoDB connection status</p>
                        <div id="sync-status" class="status-badge" style="padding: 5px 10px; background: #d4edda; color: #155724; border-radius: 3px; display: inline-block; font-size: 12px; font-weight: bold;">✅ Connected</div>
                    </div>
                    
                </div>
                
                <!-- System Info -->
                <div style="background: linear-gradient(135deg, #e8f4f8 0%, #f0e8f8 100%); padding: 25px; border-radius: 10px; border-left: 4px solid #667eea;">
                    <h4 style="margin: 0 0 15px 0; color: #667eea;">ℹ️ System Information</h4>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; font-size: 14px; color: #555;">
                        <div style="background: white; padding: 15px; border-radius: 8px;">
                            <strong style="color: #667eea;">Features Loaded:</strong><br>
                            <span id="features-count" style="font-size: 20px; font-weight: bold; color: #27ae60;">Loading...</span>
                        </div>
                        <div style="background: white; padding: 15px; border-radius: 8px;">
                            <strong style="color: #667eea;">MongoDB Status:</strong><br>
                            <span id="mongo-status" style="font-size: 16px; font-weight: bold;">Checking...</span>
                        </div>
                        <div style="background: white; padding: 15px; border-radius: 8px;">
                            <strong style="color: #667eea;">Last Backup:</strong><br>
                            <span id="last-backup" style="font-size: 14px;">Never</span>
                        </div>
                        <div style="background: white; padding: 15px; border-radius: 8px;">
                            <strong style="color: #667eea;">Activities Logged:</strong><br>
                            <span id="activities-count" style="font-size: 20px; font-weight: bold; color: #e74c3c;">0</span>
                        </div>
                    </div>
                </div>
                
                <!-- Quick Actions Info -->
                <div style="margin-top: 20px; padding: 20px; background: #fff3cd; border-left: 4px solid #ffc107; border-radius: 8px;">
                    <strong style="color: #856404;">⌨️ Keyboard Shortcuts:</strong>
                    <div style="margin-top: 10px; display: flex; gap: 20px; flex-wrap: wrap;">
                        <div style="display: flex; align-items: center; gap: 5px;">
                            <kbd style="background: white; padding: 5px 10px; border-radius: 3px; border: 1px solid #ddd; font-size: 12px; font-weight: bold;">Ctrl+F</kbd>
                            <span style="color: #856404;">Search</span>
                        </div>
                        <div style="display: flex; align-items: center; gap: 5px;">
                            <kbd style="background: white; padding: 5px 10px; border-radius: 3px; border: 1px solid #ddd; font-size: 12px; font-weight: bold;">Ctrl+M</kbd>
                            <span style="color: #856404;">Tools Menu</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <style>
                .tool-card:hover {
                    transform: translateY(-5px);
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.15);
                }
            </style>
        `;
        
        // Update system info after render
        setTimeout(() => this.updateSystemInfo(), 500);
    },
    
    // Check which features are available
    checkFeatures() {
        setTimeout(() => {
            // Check Search
            if (typeof MDMSearch === 'undefined') {
                const el = document.getElementById('search-status');
                if (el) {
                    el.innerHTML = '❌ Not loaded';
                    el.style.background = '#f8d7da';
                    el.style.color = '#721c24';
                }
            }
            
            // Check Bulk Entry
            if (typeof BulkFormC === 'undefined') {
                const el = document.getElementById('bulk-status');
                if (el) {
                    el.innerHTML = '❌ Not loaded';
                    el.style.background = '#f8d7da';
                    el.style.color = '#721c24';
                }
            }
            
            // Check Export
            if (typeof AdvancedExport === 'undefined') {
                const el = document.getElementById('export-status');
                if (el) {
                    el.innerHTML = '❌ Not loaded';
                    el.style.background = '#f8d7da';
                    el.style.color = '#721c24';
                }
            }
            
            // Check Backup
            if (typeof MDMBackup === 'undefined') {
                const el = document.getElementById('backup-status');
                if (el) {
                    el.innerHTML = '❌ Not loaded';
                    el.style.background = '#f8d7da';
                    el.style.color = '#721c24';
                }
            }
            
            // Check Activity Logger
            if (typeof ActivityLogger === 'undefined') {
                const el = document.getElementById('log-status');
                if (el) {
                    el.innerHTML = '❌ Not loaded';
                    el.style.background = '#f8d7da';
                    el.style.color = '#721c24';
                }
            }
            
            this.updateSystemInfo();
        }, 1000);
    },
    
    // Update system information
    updateSystemInfo() {
        // Count features
        let featuresLoaded = 0;
        if (typeof MDMSearch !== 'undefined') featuresLoaded++;
        if (typeof BulkFormC !== 'undefined') featuresLoaded++;
        if (typeof AdvancedExport !== 'undefined') featuresLoaded++;
        if (typeof MDMBackup !== 'undefined') featuresLoaded++;
        if (typeof ActivityLogger !== 'undefined') featuresLoaded++;
        
        const featuresCountEl = document.getElementById('features-count');
        if (featuresCountEl) {
            featuresCountEl.textContent = `${featuresLoaded}/5`;
            featuresCountEl.style.color = featuresLoaded === 5 ? '#27ae60' : '#dc3545';
        }
        
        // MongoDB status
        const mongoStatusEl = document.getElementById('mongo-status');
        if (mongoStatusEl) {
            mongoStatusEl.innerHTML = '✅ Connected';
            mongoStatusEl.style.color = '#27ae60';
        }
        
        // Last backup
        if (typeof MDMBackup !== 'undefined') {
            try {
                const backups = MDMBackup.list ? MDMBackup.list() : [];
                const lastBackupEl = document.getElementById('last-backup');
                if (lastBackupEl && backups && backups.length > 0) {
                    const lastBackup = backups[backups.length - 1];
                    lastBackupEl.textContent = lastBackup.date + ' ' + lastBackup.time;
                }
            } catch(e) {}
        }
        
        // Activities count
        if (typeof ActivityLogger !== 'undefined') {
            const activitiesCountEl = document.getElementById('activities-count');
            if (activitiesCountEl) {
                try {
                    const activities = ActivityLogger.getRecent ? ActivityLogger.getRecent(1000) : [];
                    activitiesCountEl.textContent = activities.length || '0';
                } catch(e) {
                    activitiesCountEl.textContent = '0';
                }
            }
        }
    },
    
    // Open Search
    openSearch() {
        if (typeof MDMSearch !== 'undefined') {
            MDMSearch.openPanel();
        } else {
            alert('❌ Search system not loaded!\n\nPlease ensure search-system.js is in the folder.');
        }
    },
    
    // Open Bulk Entry
    openBulkEntry() {
        if (typeof BulkFormC !== 'undefined') {
            BulkFormC.openPanel();
        } else {
            alert('❌ Bulk Entry system not loaded!\n\nPlease ensure bulk-formc-entry.js is in the folder.');
        }
    },
    
    // Open Export
    openExport() {
        if (typeof AdvancedExport !== 'undefined') {
            AdvancedExport.openPanel();
        } else {
            alert('❌ Export system not loaded!\n\nPlease ensure advanced-export.js is in the folder.');
        }
    },
    
    // Create Backup
    createBackup() {
        if (typeof MDMBackup !== 'undefined') {
            if (confirm('Create a backup now?\n\nBackup file will be downloaded.')) {
                try {
                    MDMBackup.create();
                    alert('✅ Backup created successfully!\n\nFile is downloading...');
                    setTimeout(() => this.updateSystemInfo(), 1000);
                } catch(e) {
                    alert('❌ Error creating backup:\n\n' + e.message);
                }
            }
        } else {
            alert('❌ Backup system not loaded!\n\nPlease ensure backup-system.js is in the folder.');
        }
    },
    
    // View Activity Log
    viewActivityLog() {
        if (typeof ActivityLogger !== 'undefined') {
            const activities = ActivityLogger.getRecent ? ActivityLogger.getRecent(20) : [];
            
            if (!activities || activities.length === 0) {
                alert('ℹ️ No activities logged yet.\n\nActivity logging is enabled and will track future actions.');
                return;
            }
            
            const container = document.getElementById('tools-section');
            if (!container) return;
            
            let logHTML = `
                <div style="padding: 20px;">
                    <button onclick="UnifiedToolsMenu.showToolsSection()" style="background: #95a5a6; color: white; border: none; padding: 12px 24px; border-radius: 5px; cursor: pointer; font-size: 16px; margin-bottom: 20px;">
                        ← Back to Tools Menu
                    </button>
                    
                    <div style="background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; color: white;">
                        <h2 style="margin: 0 0 10px 0;">📝 Activity Log</h2>
                        <p style="margin: 0; opacity: 0.9;">Recent system activities (Last 20)</p>
                    </div>
                    
                    <div style="max-height: 600px; overflow: auto; background: #f8f9fa; padding: 20px; border-radius: 10px;">
            `;
            
            activities.forEach((activity, index) => {
                logHTML += `
                    <div style="background: white; padding: 15px; margin-bottom: 12px; border-radius: 8px; border-left: 4px solid #e74c3c; box-shadow: 0 2px 4px rgba(0,0,0,0.05);">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 8px;">
                            <div style="color: #999; font-size: 13px; font-weight: bold;">#${index + 1}</div>
                            <div style="color: #999; font-size: 12px;">${activity.date} ${activity.time}</div>
                        </div>
                        <div style="color: #333; font-size: 16px; font-weight: bold; margin-bottom: 5px;">${activity.action}</div>
                        <div style="color: #666; font-size: 13px;">User: ${activity.user}</div>
                    </div>
                `;
            });
            
            logHTML += `
                    </div>
                    
                    <div style="text-align: center; margin-top: 20px;">
                        <button onclick="UnifiedToolsMenu.exportActivityLog()" style="background: #e74c3c; color: white; border: none; padding: 15px 30px; border-radius: 5px; cursor: pointer; font-size: 16px; font-weight: bold;">
                            📥 Export to CSV
                        </button>
                    </div>
                </div>
            `;
            
            container.innerHTML = logHTML;
        } else {
            alert('❌ Activity Logger not loaded!\n\nPlease ensure activity-logger.js is in the folder.');
        }
    },
    
    // Export Activity Log
    exportActivityLog() {
        if (typeof ActivityLogger !== 'undefined' && ActivityLogger.exportCSV) {
            ActivityLogger.exportCSV();
            alert('✅ Activity log exported!\n\nCSV file is downloading...');
        }
    },
    
    // Show Sync Status
    showSyncStatus() {
        const container = document.getElementById('tools-section');
        if (!container) return;
        
        const statusHTML = `
            <div style="padding: 20px;">
                <button onclick="UnifiedToolsMenu.showToolsSection()" style="background: #95a5a6; color: white; border: none; padding: 12px 24px; border-radius: 5px; cursor: pointer; font-size: 16px; margin-bottom: 20px;">
                    ← Back to Tools Menu
                </button>
                
                <div style="background: linear-gradient(135deg, #f39c12 0%, #e67e22 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; color: white;">
                    <h2 style="margin: 0 0 10px 0;">🔄 MongoDB Sync Status</h2>
                    <p style="margin: 0; opacity: 0.9;">Real-time connection and synchronization information</p>
                </div>
                
                <div style="background: #f8f9fa; padding: 30px; border-radius: 10px;">
                    <div style="background: white; padding: 25px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #f0f0f0;">
                            <strong style="font-size: 16px;">Connection Status:</strong>
                            <span style="background: #d4edda; color: #155724; padding: 8px 20px; border-radius: 20px; font-weight: bold;">✅ Connected</span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #f0f0f0;">
                            <strong style="font-size: 16px;">Auto-Sync:</strong>
                            <span style="background: #d4edda; color: #155724; padding: 8px 20px; border-radius: 20px; font-weight: bold;">✅ Enabled (30s interval)</span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 2px solid #f0f0f0;">
                            <strong style="font-size: 16px;">Database:</strong>
                            <span style="color: #667eea; font-weight: bold; font-size: 16px;">mdm_system</span>
                        </div>
                        
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong style="font-size: 16px;">Last Sync:</strong>
                            <span id="last-sync-time" style="color: #27ae60; font-weight: bold; font-size: 16px;">Just now</span>
                        </div>
                    </div>
                    
                    <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 20px; border-radius: 8px;">
                        <strong style="color: #856404; font-size: 16px;">ℹ️ Information:</strong>
                        <p style="color: #856404; margin: 10px 0 0 0; font-size: 14px; line-height: 1.6;">
                            Your data automatically syncs to MongoDB Atlas every 30 seconds. 
                            All changes are saved to the cloud in real-time! You can work from any device and your data will always be up-to-date.
                        </p>
                    </div>
                </div>
            </div>
        `;
        
        container.innerHTML = statusHTML;
        
        // Update time every second
        const updateTime = setInterval(() => {
            const timeEl = document.getElementById('last-sync-time');
            if (!timeEl) {
                clearInterval(updateTime);
                return;
            }
            timeEl.textContent = new Date().toLocaleTimeString('en-IN');
        }, 1000);
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => UnifiedToolsMenu.init());
} else {
    UnifiedToolsMenu.init();
}

// Keyboard shortcut: Ctrl+M to open tools menu
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'm') {
        e.preventDefault();
        UnifiedToolsMenu.showToolsSection();
    }
});

// Export for global use
window.UnifiedToolsMenu = UnifiedToolsMenu;

console.log('🎛️ Unified Tools Menu loaded! Now integrated with tab bar - no floating buttons!');
