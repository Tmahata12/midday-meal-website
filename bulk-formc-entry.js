// ========== BULK FORM C ENTRY SYSTEM ==========
// Add multiple Form C entries at once + Excel Import/Export

const BulkFormC = {
    
    // Initialize bulk entry system
    init() {
        console.log('📋 Bulk Form C Entry system initialized');
        this.addBulkEntryUI();
        this.setupEventListeners();
    },
    
    // Add bulk entry interface
    addBulkEntryUI() {
        const bulkHTML = `
            <div id="bulk-formc-panel" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:99999; overflow:auto;">
                <div style="max-width:1400px; margin:30px auto; background:white; border-radius:10px; padding:30px;">
                    <!-- Header -->
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:30px;">
                        <h2 style="margin:0; color:#667eea;">
                            📋 Bulk Form C Entry
                        </h2>
                        <button onclick="BulkFormC.closePanel()" style="background:#e74c3c; color:white; border:none; padding:10px 20px; border-radius:5px; cursor:pointer; font-size:16px;">
                            ✕ Close
                        </button>
                    </div>
                    
                    <!-- Options -->
                    <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:20px; margin-bottom:30px;">
                        <button onclick="BulkFormC.showManualEntry()" style="padding:30px; background:#27ae60; color:white; border:none; border-radius:10px; cursor:pointer; font-size:16px;">
                            <div style="font-size:40px; margin-bottom:10px;">✏️</div>
                            <div style="font-weight:bold; margin-bottom:5px;">Manual Bulk Entry</div>
                            <div style="font-size:14px; opacity:0.9;">Add multiple days manually</div>
                        </button>
                        
                        <button onclick="BulkFormC.showExcelImport()" style="padding:30px; background:#3498db; color:white; border:none; border-radius:10px; cursor:pointer; font-size:16px;">
                            <div style="font-size:40px; margin-bottom:10px;">📥</div>
                            <div style="font-weight:bold; margin-bottom:5px;">Import from Excel</div>
                            <div style="font-size:14px; opacity:0.9;">Upload Excel file with entries</div>
                        </button>
                        
                        <button onclick="BulkFormC.showCopyMonth()" style="padding:30px; background:#9b59b6; color:white; border:none; border-radius:10px; cursor:pointer; font-size:16px;">
                            <div style="font-size:40px; margin-bottom:10px;">📅</div>
                            <div style="font-weight:bold; margin-bottom:5px;">Copy Previous Month</div>
                            <div style="font-size:14px; opacity:0.9;">Copy & adjust last month</div>
                        </button>
                    </div>
                    
                    <!-- Content Area -->
                    <div id="bulk-content-area"></div>
                </div>
            </div>
            
            <!-- Bulk Entry Button (Always Visible) -->
            <button id="open-bulk-btn" onclick="BulkFormC.openPanel()" style="position:fixed; bottom:100px; right:30px; background:#27ae60; color:white; border:none; padding:15px 25px; border-radius:50px; cursor:pointer; font-size:16px; box-shadow:0 4px 12px rgba(0,0,0,0.3); z-index:9999; display:none;">
                📋 Bulk Entry
            </button>
        `;
        
        document.body.insertAdjacentHTML('beforeend', bulkHTML);
        
        // Show button only on Form C page
        this.checkCurrentPage();
    },
    
    // Check if on Form C page
    checkCurrentPage() {
        const interval = setInterval(() => {
            const formCSection = document.querySelector('[data-section="formC"]');
            const bulkBtn = document.getElementById('open-bulk-btn');
            if (formCSection && formCSection.style.display !== 'none') {
                bulkBtn.style.display = 'block';
            } else {
                bulkBtn.style.display = 'none';
            }
        }, 1000);
    },
    
    // Setup event listeners
    setupEventListeners() {
        // File upload handling will be added dynamically
    },
    
    // Open panel
    openPanel() {
        document.getElementById('bulk-formc-panel').style.display = 'block';
    },
    
    // Close panel
    closePanel() {
        document.getElementById('bulk-formc-panel').style.display = 'none';
    },
    
    // Show manual bulk entry form
    showManualEntry() {
        const contentArea = document.getElementById('bulk-content-area');
        
        const today = new Date();
        const firstDay = new Date(today.getFullYear(), today.getMonth(), 1);
        const lastDay = new Date(today.getFullYear(), today.getMonth() + 1, 0);
        
        contentArea.innerHTML = `
            <div style="background:#f8f9fa; padding:30px; border-radius:10px;">
                <h3 style="margin-top:0; color:#667eea;">📝 Manual Bulk Entry</h3>
                
                <!-- Date Range -->
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px;">
                    <div>
                        <label style="display:block; margin-bottom:5px; font-weight:bold;">Start Date:</label>
                        <input type="date" id="bulk-start-date" value="${firstDay.toISOString().split('T')[0]}" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                    </div>
                    <div>
                        <label style="display:block; margin-bottom:5px; font-weight:bold;">End Date:</label>
                        <input type="date" id="bulk-end-date" value="${lastDay.toISOString().split('T')[0]}" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                    </div>
                </div>
                
                <!-- Default Values -->
                <div style="background:white; padding:20px; border-radius:8px; margin-bottom:20px;">
                    <h4 style="margin-top:0;">Default Values (will apply to all days):</h4>
                    
                    <div style="display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:15px; margin-bottom:15px;">
                        <div>
                            <label style="display:block; margin-bottom:5px;">Class V MT:</label>
                            <input type="number" id="bulk-mtV" value="75" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                        <div>
                            <label style="display:block; margin-bottom:5px;">Class VI MT:</label>
                            <input type="number" id="bulk-mtVI" value="95" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                        <div>
                            <label style="display:block; margin-bottom:5px;">Class VII MT:</label>
                            <input type="number" id="bulk-mtVII" value="95" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                        <div>
                            <label style="display:block; margin-bottom:5px;">Class VIII MT:</label>
                            <input type="number" id="bulk-mtVIII" value="85" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                    </div>
                    
                    <div style="display:grid; grid-template-columns:2fr 1fr 1fr; gap:15px;">
                        <div>
                            <label style="display:block; margin-bottom:5px;">Menu:</label>
                            <input type="text" id="bulk-menu" value="Rice, Dal, Egg Curry" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                        <div>
                            <label style="display:block; margin-bottom:5px;">Rice (kg):</label>
                            <input type="number" id="bulk-rice" value="48.65" step="0.01" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                        <div>
                            <label style="display:block; margin-bottom:5px;">Cost (₹):</label>
                            <input type="number" id="bulk-cost" value="3500" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px;">
                        </div>
                    </div>
                </div>
                
                <!-- Options -->
                <div style="margin-bottom:20px;">
                    <label style="display:flex; align-items:center; cursor:pointer;">
                        <input type="checkbox" id="skip-sundays" checked style="margin-right:10px; width:20px; height:20px;">
                        <span style="font-weight:bold;">Skip Sundays automatically</span>
                    </label>
                    <label style="display:flex; align-items:center; cursor:pointer; margin-top:10px;">
                        <input type="checkbox" id="skip-holidays" style="margin-right:10px; width:20px; height:20px;">
                        <span style="font-weight:bold;">Skip holidays (enter dates below if checked)</span>
                    </label>
                    <input type="text" id="holiday-dates" placeholder="e.g., 2025-11-15, 2025-11-20" style="width:100%; padding:10px; border:1px solid #ddd; border-radius:5px; margin-top:10px; display:none;">
                </div>
                
                <!-- Generate Button -->
                <div style="text-align:center;">
                    <button onclick="BulkFormC.generateEntries()" style="background:#27ae60; color:white; border:none; padding:15px 40px; border-radius:5px; cursor:pointer; font-size:18px; font-weight:bold;">
                        ✨ Generate Entries
                    </button>
                </div>
                
                <!-- Preview Area -->
                <div id="bulk-preview" style="margin-top:30px; display:none;">
                    <h4>📋 Preview (will create <span id="entry-count">0</span> entries):</h4>
                    <div id="preview-list" style="max-height:400px; overflow:auto; background:white; padding:20px; border-radius:8px;"></div>
                    <div style="text-align:center; margin-top:20px;">
                        <button onclick="BulkFormC.saveBulkEntries()" style="background:#667eea; color:white; border:none; padding:15px 40px; border-radius:5px; cursor:pointer; font-size:18px; font-weight:bold;">
                            💾 Save All Entries
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Show/hide holiday input
        document.getElementById('skip-holidays').addEventListener('change', (e) => {
            document.getElementById('holiday-dates').style.display = e.target.checked ? 'block' : 'none';
        });
    },
    
    // Generate entries
    generateEntries() {
        const startDate = new Date(document.getElementById('bulk-start-date').value);
        const endDate = new Date(document.getElementById('bulk-end-date').value);
        const skipSundays = document.getElementById('skip-sundays').checked;
        const skipHolidays = document.getElementById('skip-holidays').checked;
        const holidayDates = skipHolidays ? document.getElementById('holiday-dates').value.split(',').map(d => d.trim()) : [];
        
        const mtV = parseInt(document.getElementById('bulk-mtV').value) || 0;
        const mtVI = parseInt(document.getElementById('bulk-mtVI').value) || 0;
        const mtVII = parseInt(document.getElementById('bulk-mtVII').value) || 0;
        const mtVIII = parseInt(document.getElementById('bulk-mtVIII').value) || 0;
        const menu = document.getElementById('bulk-menu').value;
        const rice = parseFloat(document.getElementById('bulk-rice').value) || 0;
        const cost = parseFloat(document.getElementById('bulk-cost').value) || 0;
        
        this.bulkEntries = [];
        
        for (let d = new Date(startDate); d <= endDate; d.setDate(d.getDate() + 1)) {
            const dateStr = d.toISOString().split('T')[0];
            
            // Skip Sundays
            if (skipSundays && d.getDay() === 0) continue;
            
            // Skip holidays
            if (holidayDates.includes(dateStr)) continue;
            
            this.bulkEntries.push({
                date: dateStr,
                mtV, mtVI, mtVII, mtVIII,
                menu, rice, cost
            });
        }
        
        this.showPreview();
    },
    
    // Show preview
    showPreview() {
        document.getElementById('bulk-preview').style.display = 'block';
        document.getElementById('entry-count').textContent = this.bulkEntries.length;
        
        let previewHTML = '<table style="width:100%; border-collapse:collapse;">';
        previewHTML += '<thead><tr style="background:#667eea; color:white;"><th style="padding:10px; border:1px solid #ddd;">Date</th><th>V</th><th>VI</th><th>VII</th><th>VIII</th><th>Total</th><th>Menu</th><th>Rice(kg)</th><th>Cost(₹)</th></tr></thead>';
        previewHTML += '<tbody>';
        
        this.bulkEntries.forEach(entry => {
            const total = entry.mtV + entry.mtVI + entry.mtVII + entry.mtVIII;
            const day = new Date(entry.date).toLocaleDateString('en-IN', {weekday: 'short'});
            previewHTML += `
                <tr style="border-bottom:1px solid #eee;">
                    <td style="padding:10px; border:1px solid #ddd;">${entry.date} (${day})</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtV}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtVI}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtVII}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtVIII}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center; font-weight:bold;">${total}</td>
                    <td style="padding:10px; border:1px solid #ddd;">${entry.menu}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.rice}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.cost}</td>
                </tr>
            `;
        });
        
        previewHTML += '</tbody></table>';
        document.getElementById('preview-list').innerHTML = previewHTML;
        
        // Scroll to preview
        document.getElementById('bulk-preview').scrollIntoView({behavior: 'smooth'});
    },
    
    // Save bulk entries
    saveBulkEntries() {
        if (!this.bulkEntries || this.bulkEntries.length === 0) {
            alert('No entries to save!');
            return;
        }
        
        if (!confirm(`Save ${this.bulkEntries.length} Form C entries?`)) {
            return;
        }
        
        // Get existing data
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        if (!mdmData.formC) mdmData.formC = [];
        
        // Add new entries (check for duplicates)
        let added = 0;
        let skipped = 0;
        
        this.bulkEntries.forEach(entry => {
            const exists = mdmData.formC.some(e => e.date === entry.date);
            if (!exists) {
                mdmData.formC.push(entry);
                added++;
            } else {
                skipped++;
            }
        });
        
        // Sort by date
        mdmData.formC.sort((a, b) => a.date.localeCompare(b.date));
        
        // Save
        localStorage.setItem('mdmData', JSON.stringify(mdmData));
        
        alert(`✅ Success!\n\nAdded: ${added} entries\nSkipped (duplicates): ${skipped} entries\n\nPage will reload to show new data.`);
        
        console.log(`✅ Bulk Form C: Added ${added}, Skipped ${skipped}`);
        
        // Close and reload
        this.closePanel();
        setTimeout(() => location.reload(), 500);
    },
    
    // Show Excel import
    showExcelImport() {
        const contentArea = document.getElementById('bulk-content-area');
        
        contentArea.innerHTML = `
            <div style="background:#f8f9fa; padding:30px; border-radius:10px;">
                <h3 style="margin-top:0; color:#667eea;">📥 Import from Excel</h3>
                
                <!-- Instructions -->
                <div style="background:#fff3cd; padding:20px; border-radius:8px; margin-bottom:20px; border-left:4px solid #ffc107;">
                    <h4 style="margin-top:0;">📋 Excel Format Required:</h4>
                    <p style="margin:10px 0;">Your Excel file should have these columns (exact names):</p>
                    <div style="background:white; padding:15px; border-radius:5px; font-family:monospace; margin:10px 0;">
                        Date | Class V | Class VI | Class VII | Class VIII | Menu | Rice(kg) | Cost(₹)
                    </div>
                    <p style="margin:10px 0;">Example:</p>
                    <div style="background:white; padding:15px; border-radius:5px; font-family:monospace; font-size:12px;">
                        2025-11-01 | 75 | 95 | 95 | 85 | Rice, Dal, Egg | 48.65 | 3500
                    </div>
                </div>
                
                <!-- Download Template -->
                <div style="text-align:center; margin-bottom:20px;">
                    <button onclick="BulkFormC.downloadTemplate()" style="background:#3498db; color:white; border:none; padding:12px 30px; border-radius:5px; cursor:pointer; font-size:16px;">
                        📥 Download Excel Template
                    </button>
                    <p style="margin-top:10px; color:#666; font-size:14px;">Fill this template and upload back</p>
                </div>
                
                <!-- Upload Area -->
                <div style="border:2px dashed #667eea; border-radius:10px; padding:40px; text-align:center; background:white;">
                    <div style="font-size:60px; margin-bottom:15px;">📂</div>
                    <h4>Upload Excel File</h4>
                    <input type="file" id="excel-file-input" accept=".xlsx,.xls,.csv" style="display:none;">
                    <button onclick="document.getElementById('excel-file-input').click()" style="background:#27ae60; color:white; border:none; padding:15px 40px; border-radius:5px; cursor:pointer; font-size:16px; margin-top:10px;">
                        Choose File
                    </button>
                    <p style="margin-top:15px; color:#666;">Supported: Excel (.xlsx, .xls) or CSV (.csv)</p>
                </div>
                
                <!-- Preview Area -->
                <div id="import-preview" style="margin-top:30px; display:none;">
                    <h4>📋 Preview:</h4>
                    <div id="import-preview-list" style="max-height:400px; overflow:auto; background:white; padding:20px; border-radius:8px;"></div>
                    <div style="text-align:center; margin-top:20px;">
                        <button onclick="BulkFormC.saveImportedEntries()" style="background:#667eea; color:white; border:none; padding:15px 40px; border-radius:5px; cursor:pointer; font-size:18px; font-weight:bold;">
                            💾 Import All Entries
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Setup file upload handler
        document.getElementById('excel-file-input').addEventListener('change', (e) => {
            this.handleExcelUpload(e.target.files[0]);
        });
    },
    
    // Download Excel template
    downloadTemplate() {
        const csv = `Date,Class V,Class VI,Class VII,Class VIII,Menu,Rice(kg),Cost(₹)
2025-11-01,75,95,95,85,"Rice, Dal, Egg Curry",48.65,3500
2025-11-02,75,95,95,85,"Rice, Dal, Veg",48.65,3500
2025-11-04,75,95,95,85,"Rice, Dal, Chicken",48.65,3500`;
        
        const blob = new Blob([csv], {type: 'text/csv'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'FormC_Template.csv';
        a.click();
        URL.revokeObjectURL(url);
        
        console.log('📥 Template downloaded');
    },
    
    // Handle Excel upload
    handleExcelUpload(file) {
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target.result;
            this.parseCSV(text);
        };
        reader.readAsText(file);
    },
    
    // Parse CSV
    parseCSV(text) {
        const lines = text.trim().split('\n');
        const headers = lines[0].split(',').map(h => h.trim().replace(/"/g, ''));
        
        this.importedEntries = [];
        
        for (let i = 1; i < lines.length; i++) {
            const values = lines[i].split(',').map(v => v.trim().replace(/"/g, ''));
            
            if (values.length < 8) continue;
            
            this.importedEntries.push({
                date: values[0],
                mtV: parseInt(values[1]) || 0,
                mtVI: parseInt(values[2]) || 0,
                mtVII: parseInt(values[3]) || 0,
                mtVIII: parseInt(values[4]) || 0,
                menu: values[5],
                rice: parseFloat(values[6]) || 0,
                cost: parseFloat(values[7]) || 0
            });
        }
        
        this.showImportPreview();
    },
    
    // Show import preview
    showImportPreview() {
        document.getElementById('import-preview').style.display = 'block';
        
        let previewHTML = `<p>Found ${this.importedEntries.length} entries</p>`;
        previewHTML += '<table style="width:100%; border-collapse:collapse;">';
        previewHTML += '<thead><tr style="background:#667eea; color:white;"><th style="padding:10px; border:1px solid #ddd;">Date</th><th>V</th><th>VI</th><th>VII</th><th>VIII</th><th>Total</th><th>Menu</th><th>Rice</th><th>Cost</th></tr></thead>';
        previewHTML += '<tbody>';
        
        this.importedEntries.forEach(entry => {
            const total = entry.mtV + entry.mtVI + entry.mtVII + entry.mtVIII;
            previewHTML += `
                <tr style="border-bottom:1px solid #eee;">
                    <td style="padding:10px; border:1px solid #ddd;">${entry.date}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtV}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtVI}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtVII}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.mtVIII}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center; font-weight:bold;">${total}</td>
                    <td style="padding:10px; border:1px solid #ddd;">${entry.menu}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.rice}</td>
                    <td style="padding:10px; border:1px solid #ddd; text-align:center;">${entry.cost}</td>
                </tr>
            `;
        });
        
        previewHTML += '</tbody></table>';
        document.getElementById('import-preview-list').innerHTML = previewHTML;
    },
    
    // Save imported entries
    saveImportedEntries() {
        this.bulkEntries = this.importedEntries;
        this.saveBulkEntries();
    },
    
    // Show copy previous month
    showCopyMonth() {
        const contentArea = document.getElementById('bulk-content-area');
        
        const today = new Date();
        const lastMonth = new Date(today.getFullYear(), today.getMonth() - 1, 1);
        const lastMonthName = lastMonth.toLocaleDateString('en-IN', {month: 'long', year: 'numeric'});
        
        contentArea.innerHTML = `
            <div style="background:#f8f9fa; padding:30px; border-radius:10px;">
                <h3 style="margin-top:0; color:#667eea;">📅 Copy Previous Month</h3>
                
                <div style="background:#d4edda; padding:20px; border-radius:8px; margin-bottom:20px; border-left:4px solid #28a745;">
                    <h4 style="margin-top:0;">ℹ️ How it works:</h4>
                    <p style="margin:5px 0;">1. Select which month to copy from</p>
                    <p style="margin:5px 0;">2. Select which month to copy to</p>
                    <p style="margin:5px 0;">3. Dates will be adjusted automatically</p>
                    <p style="margin:5px 0;">4. You can edit values before saving</p>
                </div>
                
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px;">
                    <div>
                        <label style="display:block; margin-bottom:5px; font-weight:bold;">Copy From Month:</label>
                        <select id="copy-from-month" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            ${this.getMonthOptions()}
                        </select>
                    </div>
                    <div>
                        <label style="display:block; margin-bottom:5px; font-weight:bold;">Copy To Month:</label>
                        <select id="copy-to-month" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            ${this.getMonthOptions(true)}
                        </select>
                    </div>
                </div>
                
                <div style="text-align:center;">
                    <button onclick="BulkFormC.copyPreviousMonth()" style="background:#9b59b6; color:white; border:none; padding:15px 40px; border-radius:5px; cursor:pointer; font-size:18px; font-weight:bold;">
                        📋 Copy Entries
                    </button>
                </div>
                
                <div id="copy-preview" style="margin-top:30px; display:none;"></div>
            </div>
        `;
    },
    
    // Get month options
    getMonthOptions(futureOnly = false) {
        let html = '';
        const today = new Date();
        
        for (let i = futureOnly ? 0 : -6; i <= (futureOnly ? 6 : 0); i++) {
            const date = new Date(today.getFullYear(), today.getMonth() + i, 1);
            const value = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
            const text = date.toLocaleDateString('en-IN', {month: 'long', year: 'numeric'});
            html += `<option value="${value}" ${i === (futureOnly ? 1 : -1) ? 'selected' : ''}>${text}</option>`;
        }
        
        return html;
    },
    
    // Copy previous month
    copyPreviousMonth() {
        const fromMonth = document.getElementById('copy-from-month').value;
        const toMonth = document.getElementById('copy-to-month').value;
        
        // Get existing data
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        if (!mdmData.formC) mdmData.formC = [];
        
        // Filter entries from source month
        const sourceEntries = mdmData.formC.filter(entry => entry.date.startsWith(fromMonth));
        
        if (sourceEntries.length === 0) {
            alert(`No entries found for ${fromMonth}!`);
            return;
        }
        
        // Create new entries for target month
        this.bulkEntries = sourceEntries.map(entry => {
            const oldDate = new Date(entry.date);
            const day = oldDate.getDate();
            const [year, month] = toMonth.split('-');
            const newDate = new Date(parseInt(year), parseInt(month) - 1, day);
            
            return {
                date: newDate.toISOString().split('T')[0],
                mtV: entry.mtV,
                mtVI: entry.mtVI,
                mtVII: entry.mtVII,
                mtVIII: entry.mtVIII,
                menu: entry.menu,
                rice: entry.rice,
                cost: entry.cost
            };
        });
        
        this.showPreview();
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => BulkFormC.init());
} else {
    BulkFormC.init();
}

// Export for global use
window.BulkFormC = BulkFormC;

console.log('📋 Bulk Form C Entry system loaded!');
