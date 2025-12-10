// ============================================
// ENHANCED FORM C SYSTEM - COMPLETE PACKAGE
// All 10+ Improvements Integrated
// ============================================

const EnhancedFormC = {
    // Configuration
    config: {
        classStrengths: {
            V: { total: 50, cpPercent: 96, mtPercent: 94 },
            VI: { total: 45, cpPercent: 96, mtPercent: 94 },
            VII: { total: 42, cpPercent: 96, mtPercent: 94 },
            VIII: { total: 40, cpPercent: 96, mtPercent: 94 }
        },
        holidays: [],
        templates: {},
        validationRules: {
            maxDeviation: 30, // % deviation warning
            minAttendance: 50, // % minimum
            maxRicePerStudent: 0.15 // kg
        }
    },

    // Initialize system
    init: function() {
        console.log('🚀 Initializing Enhanced Form C System...');
        
        // Initialize current view date for calendar navigation
        this.currentViewDate = new Date();
        
        this.loadConfig();
        this.setupEventListeners();
        this.renderCalendarView();
        this.updateStats();
        this.checkDuplicates();
        console.log('✅ Enhanced Form C System Ready!');
    },

    // ============================================
    // FEATURE 1: EXCEL UPLOAD
    // ============================================
    
    uploadExcel: function() {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = '.xlsx, .xls, .csv';
        input.onchange = (e) => this.handleExcelFile(e.target.files[0]);
        input.click();
    },

    handleExcelFile: async function(file) {
        if (!file) return;
        
        this.showLoading('Reading Excel file...');
        
        try {
            const reader = new FileReader();
            reader.onload = (e) => {
                try {
                    const data = new Uint8Array(e.target.result);
                    const workbook = XLSX.read(data, { type: 'array' });
                    const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
                    const jsonData = XLSX.utils.sheet_to_json(firstSheet);
                    
                    this.previewExcelData(jsonData);
                } catch (error) {
                    this.hideLoading();
                    this.showToast('Error reading Excel file: ' + error.message, 'error');
                }
            };
            reader.readAsArrayBuffer(file);
        } catch (error) {
            this.hideLoading();
            this.showToast('Error uploading file: ' + error.message, 'error');
        }
    },

    previewExcelData: function(data) {
        this.hideLoading();
        
        if (!data || data.length === 0) {
            this.showToast('No data found in Excel file', 'error');
            return;
        }

        // Validate and map columns
        const mappedData = this.mapExcelColumns(data);
        const validation = this.validateExcelData(mappedData);

        // Show preview modal
        this.showExcelPreview(mappedData, validation);
    },

    mapExcelColumns: function(data) {
        // Try to auto-detect columns
        const mapped = [];
        
        for (let row of data) {
            const entry = {
                date: this.findColumn(row, ['date', 'তারিখ', 'Date', 'DATE']),
                cpV: this.findColumn(row, ['Class V CP', 'CP V', 'Class-V-CP', 'cpV']),
                mtV: this.findColumn(row, ['Class V MT', 'MT V', 'Class-V-MT', 'mtV']),
                cpVI: this.findColumn(row, ['Class VI CP', 'CP VI', 'Class-VI-CP', 'cpVI']),
                mtVI: this.findColumn(row, ['Class VI MT', 'MT VI', 'Class-VI-MT', 'mtVI']),
                cpVII: this.findColumn(row, ['Class VII CP', 'CP VII', 'Class-VII-CP', 'cpVII']),
                mtVII: this.findColumn(row, ['Class VII MT', 'MT VII', 'Class-VII-MT', 'mtVII']),
                cpVIII: this.findColumn(row, ['Class VIII CP', 'CP VIII', 'Class-VIII-CP', 'cpVIII']),
                mtVIII: this.findColumn(row, ['Class VIII MT', 'MT VIII', 'Class-VIII-MT', 'mtVIII']),
                rice: this.findColumn(row, ['Rice', 'Rice(Kg)', 'রাইস', 'rice']),
                cost: this.findColumn(row, ['Cost', 'Cost(₹)', 'খরচ', 'cost']),
                menu: this.findColumn(row, ['Menu', 'menu', 'মেনু'])
            };
            
            if (entry.date) {
                mapped.push(entry);
            }
        }
        
        return mapped;
    },

    findColumn: function(row, possibleNames) {
        for (let name of possibleNames) {
            if (row[name] !== undefined && row[name] !== null && row[name] !== '') {
                return row[name];
            }
        }
        return null;
    },

    validateExcelData: function(data) {
        const validation = {
            valid: [],
            errors: [],
            warnings: [],
            duplicates: []
        };

        const existingDates = this.getExistingDates();
        const seenDates = new Set();

        for (let i = 0; i < data.length; i++) {
            const entry = data[i];
            const rowNum = i + 2; // Excel row number (1 = header)

            // Validate date
            const dateStr = this.parseExcelDate(entry.date);
            if (!dateStr) {
                validation.errors.push(`Row ${rowNum}: Invalid date "${entry.date}"`);
                continue;
            }

            // Check duplicate in Excel
            if (seenDates.has(dateStr)) {
                validation.errors.push(`Row ${rowNum}: Duplicate date in Excel - ${dateStr}`);
                continue;
            }
            seenDates.add(dateStr);

            // Check duplicate in system
            if (existingDates.includes(dateStr)) {
                validation.duplicates.push(`Row ${rowNum}: Date ${dateStr} already exists in system`);
            }

            // Validate numbers
            const numbers = [entry.cpV, entry.mtV, entry.cpVI, entry.mtVI, 
                           entry.cpVII, entry.mtVII, entry.cpVIII, entry.mtVIII];
            
            let hasError = false;
            for (let num of numbers) {
                if (num !== null && (isNaN(num) || num < 0)) {
                    validation.errors.push(`Row ${rowNum}: Invalid number "${num}"`);
                    hasError = true;
                    break;
                }
            }

            if (!hasError) {
                validation.valid.push({ ...entry, dateStr, rowNum });
            }
        }

        return validation;
    },

    parseExcelDate: function(dateValue) {
        if (!dateValue) return null;

        // If already in dd-mm-yyyy format
        if (typeof dateValue === 'string' && /^\d{2}-\d{2}-\d{4}$/.test(dateValue)) {
            return dateValue;
        }

        // If Excel serial number
        if (typeof dateValue === 'number') {
            const date = XLSX.SSF.parse_date_code(dateValue);
            return `${String(date.d).padStart(2, '0')}-${String(date.m).padStart(2, '0')}-${date.y}`;
        }

        // Try to parse other formats
        try {
            const date = new Date(dateValue);
            if (!isNaN(date)) {
                const d = String(date.getDate()).padStart(2, '0');
                const m = String(date.getMonth() + 1).padStart(2, '0');
                const y = date.getFullYear();
                return `${d}-${m}-${y}`;
            }
        } catch (e) {
            // Failed to parse
        }

        return null;
    },

    showExcelPreview: function(data, validation) {
        const modal = document.createElement('div');
        modal.className = 'excel-preview-modal';
        modal.innerHTML = `
            <div class="excel-preview-content">
                <div class="excel-preview-header">
                    <h2>📊 Excel Import Preview</h2>
                    <button onclick="EnhancedFormC.closeExcelPreview()" class="close-btn">✕</button>
                </div>
                
                <div class="excel-preview-stats">
                    <div class="stat-box stat-success">
                        <div class="stat-number">${validation.valid.length}</div>
                        <div class="stat-label">✅ Valid Entries</div>
                    </div>
                    <div class="stat-box stat-error">
                        <div class="stat-number">${validation.errors.length}</div>
                        <div class="stat-label">❌ Errors</div>
                    </div>
                    <div class="stat-box stat-warning">
                        <div class="stat-number">${validation.duplicates.length}</div>
                        <div class="stat-label">⚠️ Duplicates</div>
                    </div>
                </div>

                ${validation.errors.length > 0 ? `
                    <div class="excel-errors">
                        <h3>❌ Errors Found:</h3>
                        <ul>${validation.errors.map(e => `<li>${e}</li>`).join('')}</ul>
                    </div>
                ` : ''}

                ${validation.duplicates.length > 0 ? `
                    <div class="excel-warnings">
                        <h3>⚠️ Duplicate Dates:</h3>
                        <ul>${validation.duplicates.map(e => `<li>${e}</li>`).join('')}</ul>
                        <p style="margin-top: 10px; font-size: 13px; color: #666;">
                            These entries will overwrite existing data if you proceed.
                        </p>
                    </div>
                ` : ''}

                ${validation.valid.length > 0 ? `
                    <div class="excel-preview-table">
                        <h3>Preview Valid Entries (First 10):</h3>
                        <table>
                            <thead>
                                <tr>
                                    <th>Date</th>
                                    <th>V-CP</th>
                                    <th>V-MT</th>
                                    <th>VI-CP</th>
                                    <th>VI-MT</th>
                                    <th>VII-CP</th>
                                    <th>VII-MT</th>
                                    <th>VIII-CP</th>
                                    <th>VIII-MT</th>
                                    <th>Rice</th>
                                    <th>Cost</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${validation.valid.slice(0, 10).map(entry => `
                                    <tr>
                                        <td>${entry.dateStr}</td>
                                        <td>${entry.cpV || 0}</td>
                                        <td>${entry.mtV || 0}</td>
                                        <td>${entry.cpVI || 0}</td>
                                        <td>${entry.mtVI || 0}</td>
                                        <td>${entry.cpVII || 0}</td>
                                        <td>${entry.mtVII || 0}</td>
                                        <td>${entry.cpVIII || 0}</td>
                                        <td>${entry.mtVIII || 0}</td>
                                        <td>${entry.rice || 0}</td>
                                        <td>${entry.cost || 0}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                        ${validation.valid.length > 10 ? `<p style="text-align: center; color: #666; margin-top: 10px;">...and ${validation.valid.length - 10} more entries</p>` : ''}
                    </div>
                ` : ''}

                <div class="excel-preview-actions">
                    ${validation.valid.length > 0 ? `
                        <button onclick="EnhancedFormC.importExcelData()" class="btn-import">
                            📥 Import ${validation.valid.length} Entries
                        </button>
                    ` : ''}
                    <button onclick="EnhancedFormC.closeExcelPreview()" class="btn-cancel">
                        Cancel
                    </button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        this.currentExcelData = validation.valid;
    },

    importExcelData: async function() {
        if (!this.currentExcelData || this.currentExcelData.length === 0) return;

        this.showLoading(`Importing ${this.currentExcelData.length} entries...`);

        let imported = 0;
        let failed = 0;

        for (let entry of this.currentExcelData) {
            try {
                const formCEntry = {
                    date: entry.dateStr,
                    cpV: parseInt(entry.cpV) || 0,
                    mtV: parseInt(entry.mtV) || 0,
                    cpVI: parseInt(entry.cpVI) || 0,
                    mtVI: parseInt(entry.mtVI) || 0,
                    cpVII: parseInt(entry.cpVII) || 0,
                    mtVII: parseInt(entry.mtVII) || 0,
                    cpVIII: parseInt(entry.cpVIII) || 0,
                    mtVIII: parseInt(entry.mtVIII) || 0,
                    totalCPVI: (parseInt(entry.cpVI) || 0) + (parseInt(entry.cpVII) || 0) + (parseInt(entry.cpVIII) || 0),
                    totalMTVI: (parseInt(entry.mtVI) || 0) + (parseInt(entry.mtVII) || 0) + (parseInt(entry.mtVIII) || 0),
                    rice: parseFloat(entry.rice) || 0,
                    cost: parseFloat(entry.cost) || 0,
                    menu: entry.menu || 'Rice + Dal + Vegetable + Ban'
                };

                // Save to formCData (new system)
                const existingData = JSON.parse(localStorage.getItem('formCData') || '[]');
                const filtered = existingData.filter(e => e.date !== entry.dateStr);
                filtered.push(formCEntry);
                localStorage.setItem('formCData', JSON.stringify(filtered));

                // ALSO save to mdmData.formC (old system for reports)
                const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
                if (!mdmData.formC) mdmData.formC = [];
                
                // Remove duplicate if exists
                mdmData.formC = mdmData.formC.filter(e => e.date !== entry.dateStr);
                mdmData.formC.push(formCEntry);
                
                localStorage.setItem('mdmData', JSON.stringify(mdmData));
                
                imported++;

            } catch (error) {
                console.error('Failed to import entry:', entry, error);
                failed++;
            }
        }

        this.hideLoading();
        this.closeExcelPreview();

        if (imported > 0) {
            this.showToast(`✅ Successfully imported ${imported} entries!${failed > 0 ? ` (${failed} failed)` : ''}`, 'success');
            
            // CRITICAL: Reload data from localStorage into memory
            if (typeof loadAllData === 'function') {
                loadAllData();
            }
            
            // Auto-navigate calendar to first imported date's month
            if (this.currentExcelData.length > 0) {
                const firstDate = this.currentExcelData[0].dateStr;
                const [day, month, year] = firstDate.split('-');
                this.currentViewDate = new Date(parseInt(year), parseInt(month) - 1, parseInt(day));
                console.log('📅 Auto-navigating to:', this.getMonthName(parseInt(month) - 1), year);
            }
            
            // Refresh all displays
            if (typeof loadFormCTable === 'function') {
                loadFormCTable();
            }
            if (typeof refreshAllTables === 'function') {
                refreshAllTables();
            }
            this.renderCalendarView();
            this.updateStats();
            
            // Trigger save to ensure persistence
            if (typeof saveAllData === 'function') {
                saveAllData();
            }
        } else {
            this.showToast('❌ Failed to import data', 'error');
        }
    },

    closeExcelPreview: function() {
        const modal = document.querySelector('.excel-preview-modal');
        if (modal) modal.remove();
        this.currentExcelData = null;
    },

    downloadExcelTemplate: function() {
        const template = [
            {
                'Date': '01-12-2024',
                'Class V CP': 48,
                'Class V MT': 47,
                'Class VI CP': 43,
                'Class VI MT': 42,
                'Class VII CP': 40,
                'Class VII MT': 39,
                'Class VIII CP': 38,
                'Class VIII MT': 37,
                'Rice(Kg)': 20.5,
                'Cost(₹)': 2340,
                'Menu': 'Rice + Dal + Vegetable + Ban'
            },
            {
                'Date': '02-12-2024',
                'Class V CP': 47,
                'Class V MT': 46,
                'Class VI CP': 42,
                'Class VI MT': 41,
                'Class VII CP': 39,
                'Class VII MT': 38,
                'Class VIII CP': 37,
                'Class VIII MT': 36,
                'Rice(Kg)': 19.8,
                'Cost(₹)': 2280,
                'Menu': 'Rice + Dal + Potato + Fish'
            }
        ];

        const ws = XLSX.utils.json_to_sheet(template);
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'Form C Template');
        XLSX.writeFile(wb, 'FormC_Template.xlsx');

        this.showToast('📥 Template downloaded! Fill it and upload.', 'success');
    },

    // ============================================
    // FEATURE 2: AUTO-CALCULATE DEFAULTS
    // ============================================

    autoFillDefaults: function() {
        const config = this.config.classStrengths;
        
        // Class V
        document.getElementById('cpV').value = Math.round(config.V.total * config.V.cpPercent / 100);
        document.getElementById('mtV').value = Math.round(config.V.total * config.V.mtPercent / 100);
        
        // Class VI
        document.getElementById('cpVI').value = Math.round(config.VI.total * config.VI.cpPercent / 100);
        document.getElementById('mtVI').value = Math.round(config.VI.total * config.VI.mtPercent / 100);
        
        // Class VII
        document.getElementById('cpVII').value = Math.round(config.VII.total * config.VII.cpPercent / 100);
        document.getElementById('mtVII').value = Math.round(config.VII.total * config.VII.mtPercent / 100);
        
        // Class VIII
        document.getElementById('cpVIII').value = Math.round(config.VIII.total * config.VIII.cpPercent / 100);
        document.getElementById('mtVIII').value = Math.round(config.VIII.total * config.VIII.mtPercent / 100);

        // Trigger calculation
        if (typeof calculateFormC === 'function') {
            calculateFormC();
        }

        this.showToast('✅ Auto-filled with default values!', 'success');
    },

    openClassStrengthSettings: function() {
        const modal = document.createElement('div');
        modal.className = 'settings-modal';
        modal.innerHTML = `
            <div class="settings-content">
                <h2>⚙️ Class Strength Settings</h2>
                <p style="color: #666; margin-bottom: 20px;">Set default class strengths for auto-fill</p>
                
                ${Object.keys(this.config.classStrengths).map(cls => `
                    <div class="settings-row">
                        <label>Class ${cls} Total Students:</label>
                        <input type="number" id="strength_${cls}" value="${this.config.classStrengths[cls].total}" min="0" max="100">
                    </div>
                    <div class="settings-row">
                        <label>Class ${cls} CP %:</label>
                        <input type="number" id="cp_${cls}" value="${this.config.classStrengths[cls].cpPercent}" min="0" max="100">
                    </div>
                    <div class="settings-row">
                        <label>Class ${cls} MT %:</label>
                        <input type="number" id="mt_${cls}" value="${this.config.classStrengths[cls].mtPercent}" min="0" max="100">
                    </div>
                    <hr style="margin: 15px 0;">
                `).join('')}
                
                <div class="settings-actions">
                    <button onclick="EnhancedFormC.saveClassStrengths()" class="btn-save">💾 Save</button>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn-cancel">Cancel</button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    },

    saveClassStrengths: function() {
        for (let cls of Object.keys(this.config.classStrengths)) {
            this.config.classStrengths[cls].total = parseInt(document.getElementById(`strength_${cls}`).value) || 0;
            this.config.classStrengths[cls].cpPercent = parseInt(document.getElementById(`cp_${cls}`).value) || 96;
            this.config.classStrengths[cls].mtPercent = parseInt(document.getElementById(`mt_${cls}`).value) || 94;
        }
        
        localStorage.setItem('formC_classStrengths', JSON.stringify(this.config.classStrengths));
        this.showToast('✅ Settings saved!', 'success');
        
        const modal = document.querySelector('.settings-modal');
        if (modal) modal.remove();
    },

    // Continue in Part 2...
};

// Export for use
window.EnhancedFormC = EnhancedFormC;
// ============================================
// ENHANCED FORM C SYSTEM - PART 2
// Continuing from Part 1...
// ============================================

// Add these methods to EnhancedFormC object

Object.assign(EnhancedFormC, {

    // ============================================
    // FEATURE 3: DUPLICATE DATE WARNING
    // ============================================

    checkDuplicates: function() {
        const dateInput = document.getElementById('cpDate');
        if (!dateInput) return;

        dateInput.addEventListener('blur', () => {
            const date = dateInput.value;
            if (!date || !/^\d{2}-\d{2}-\d{4}$/.test(date)) return;

            const existing = this.getExistingDates();
            if (existing.includes(date)) {
                this.showDuplicateWarning(date);
            }
        });
    },

    getExistingDates: function() {
        const data = JSON.parse(localStorage.getItem('formCData') || '[]');
        return data.map(entry => entry.date);
    },

    showDuplicateWarning: function(date) {
        const modal = document.createElement('div');
        modal.className = 'duplicate-warning-modal';
        modal.innerHTML = `
            <div class="duplicate-warning-content">
                <div class="warning-icon">⚠️</div>
                <h2>Duplicate Date Detected!</h2>
                <p>An entry for <strong>${date}</strong> already exists.</p>
                <p style="color: #666; font-size: 14px;">What would you like to do?</p>
                
                <div class="duplicate-actions">
                    <button onclick="EnhancedFormC.editExistingEntry('${date}')" class="btn-edit">
                        📝 Edit Existing Entry
                    </button>
                    <button onclick="EnhancedFormC.overwriteEntry('${date}')" class="btn-overwrite">
                        🔄 Overwrite
                    </button>
                    <button onclick="EnhancedFormC.clearFormAndClose()" class="btn-cancel">
                        Cancel
                    </button>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
    },

    editExistingEntry: function(date) {
        const data = JSON.parse(localStorage.getItem('formCData') || '[]');
        const entry = data.find(e => e.date === date);
        
        if (entry) {
            // Fill form with existing data
            document.getElementById('cpDate').value = entry.date;
            document.getElementById('cpV').value = entry.cpV;
            document.getElementById('mtV').value = entry.mtV;
            document.getElementById('cpVI').value = entry.cpVI;
            document.getElementById('mtVI').value = entry.mtVI;
            document.getElementById('cpVII').value = entry.cpVII;
            document.getElementById('mtVII').value = entry.mtVII;
            document.getElementById('cpVIII').value = entry.cpVIII;
            document.getElementById('mtVIII').value = entry.mtVIII;
            document.getElementById('formCMenu').value = entry.menu || 'Rice + Dal + Vegetable + Ban';
            
            if (typeof calculateFormC === 'function') {
                calculateFormC();
            }
            
            this.showToast('📝 Editing existing entry for ' + date, 'info');
        }
        
        const modal = document.querySelector('.duplicate-warning-modal');
        if (modal) modal.remove();
    },

    overwriteEntry: function(date) {
        this.allowOverwrite = date;
        this.showToast('⚠️ Next save will overwrite ' + date, 'warning');
        
        const modal = document.querySelector('.duplicate-warning-modal');
        if (modal) modal.remove();
    },

    clearFormAndClose: function() {
        if (typeof clearFormC === 'function') {
            clearFormC();
        }
        
        const modal = document.querySelector('.duplicate-warning-modal');
        if (modal) modal.remove();
    },

    // ============================================
    // FEATURE 4: COLOR-CODED VALIDATION
    // ============================================

    setupValidation: function() {
        const inputs = ['cpV', 'mtV', 'cpVI', 'mtVI', 'cpVII', 'mtVII', 'cpVIII', 'mtVIII'];
        
        inputs.forEach(id => {
            const input = document.getElementById(id);
            if (input) {
                input.addEventListener('input', () => this.validateField(input));
                input.addEventListener('blur', () => this.validateField(input));
            }
        });

        // Validate date
        const dateInput = document.getElementById('cpDate');
        if (dateInput) {
            dateInput.addEventListener('blur', () => this.validateDateField(dateInput));
        }
    },

    validateField: function(input) {
        const value = parseInt(input.value);
        const fieldId = input.id;
        
        // Get class from field ID
        const classMatch = fieldId.match(/(V|VI|VII|VIII)/);
        if (!classMatch) return;
        
        const cls = classMatch[1];
        const strength = this.config.classStrengths[cls];
        
        if (!strength) return;

        // Remove existing validation classes
        input.classList.remove('valid', 'warning', 'error');

        if (isNaN(value) || value < 0) {
            input.classList.add('error');
            input.title = 'Invalid number';
            return;
        }

        if (value === 0) {
            input.classList.add('warning');
            input.title = 'Zero value - check if correct';
            return;
        }

        if (value > strength.total) {
            input.classList.add('error');
            input.title = `Exceeds class strength (${strength.total})`;
            return;
        }

        // Check if unusually low
        const expectedMin = Math.floor(strength.total * this.config.validationRules.minAttendance / 100);
        if (value < expectedMin) {
            input.classList.add('warning');
            input.title = `Unusually low (expected min: ${expectedMin})`;
            return;
        }

        // Valid
        input.classList.add('valid');
        input.title = 'Valid';
    },

    validateDateField: function(input) {
        const value = input.value;
        input.classList.remove('valid', 'error');

        if (!value || !/^\d{2}-\d{2}-\d{4}$/.test(value)) {
            input.classList.add('error');
            input.title = 'Invalid date format (dd-mm-yyyy)';
            return;
        }

        input.classList.add('valid');
        input.title = 'Valid date';
    },

    // ============================================
    // FEATURE 5: CALENDAR VIEW
    // ============================================

    renderCalendarView: function() {
        const container = document.getElementById('formCCalendarView');
        if (!container) return;

        // Use currentViewDate for display (allows navigation)
        const viewDate = this.currentViewDate || new Date();
        const year = viewDate.getFullYear();
        const month = viewDate.getMonth();
        
        // Get current actual date for "today" highlighting
        const now = new Date();
        const currentYear = now.getFullYear();
        const currentMonth = now.getMonth();
        const currentDay = now.getDate();

        const firstDay = new Date(year, month, 1).getDay();
        const daysInMonth = new Date(year, month + 1, 0).getDate();

        const existingDates = this.getExistingDates();
        const holidays = this.config.holidays;
        
        console.log('📅 Rendering calendar:', { year, month: month + 1, existingDates: existingDates.length });

        let html = `
            <div class="calendar-header">
                <button onclick="EnhancedFormC.changeMonth(-1)" class="calendar-nav" title="Previous Month">◀</button>
                <h3>${this.getMonthName(month)} ${year}</h3>
                <button onclick="EnhancedFormC.goToToday()" class="calendar-nav" title="Go to Current Month" style="margin: 0 5px; padding: 4px 10px; font-size: 11px;">📅 Today</button>
                <button onclick="EnhancedFormC.changeMonth(1)" class="calendar-nav" title="Next Month">▶</button>
            </div>
            <div class="calendar-grid">
                <div class="calendar-day-header">Sun</div>
                <div class="calendar-day-header">Mon</div>
                <div class="calendar-day-header">Tue</div>
                <div class="calendar-day-header">Wed</div>
                <div class="calendar-day-header">Thu</div>
                <div class="calendar-day-header">Fri</div>
                <div class="calendar-day-header">Sat</div>
        `;

        // Empty cells for first week
        for (let i = 0; i < firstDay; i++) {
            html += '<div class="calendar-day calendar-day-empty"></div>';
        }

        // Days
        for (let day = 1; day <= daysInMonth; day++) {
            const dateStr = `${String(day).padStart(2, '0')}-${String(month + 1).padStart(2, '0')}-${year}`;
            const isToday = (day === currentDay && month === currentMonth && year === currentYear);
            const hasEntry = existingDates.includes(dateStr);
            const dayOfWeek = (firstDay + day - 1) % 7;
            const isSunday = dayOfWeek === 0;
            const isHoliday = holidays.includes(dateStr) || isSunday;
            
            let classes = ['calendar-day'];
            if (isToday) classes.push('calendar-today');
            if (hasEntry) classes.push('calendar-has-entry');
            if (isHoliday) classes.push('calendar-holiday');
            
            html += `
                <div class="${classes.join(' ')}" onclick="EnhancedFormC.selectDate('${dateStr}')" title="${dateStr}${hasEntry ? ' (Has Entry)' : ''}">
                    <span class="calendar-day-number">${day}</span>
                    ${hasEntry ? '<span class="calendar-indicator">✅</span>' : ''}
                    ${isHoliday && !hasEntry ? '<span class="calendar-indicator">🔒</span>' : ''}
                </div>
            `;
        }

        html += '</div>';
        html += `
            <div class="calendar-legend">
                <span><span class="legend-box legend-today"></span> Today</span>
                <span><span class="legend-box legend-entry"></span> Entered</span>
                <span><span class="legend-box legend-holiday"></span> Holiday</span>
            </div>
        `;

        container.innerHTML = html;
    },

    getMonthName: function(month) {
        const names = ['January', 'February', 'March', 'April', 'May', 'June',
                      'July', 'August', 'September', 'October', 'November', 'December'];
        return names[month];
    },

    changeMonth: function(delta) {
        // Initialize if not already done
        if (!this.currentViewDate) {
            this.currentViewDate = new Date();
        }
        
        // Change month
        this.currentViewDate.setMonth(this.currentViewDate.getMonth() + delta);
        
        console.log('📅 Navigating to:', this.getMonthName(this.currentViewDate.getMonth()), this.currentViewDate.getFullYear());
        
        // Re-render calendar with new month
        this.renderCalendarView();
        
        // Show feedback
        const monthName = this.getMonthName(this.currentViewDate.getMonth());
        const year = this.currentViewDate.getFullYear();
        this.showToast(`📅 Viewing ${monthName} ${year}`, 'info');
    },
    
    goToToday: function() {
        // Reset to current date
        this.currentViewDate = new Date();
        
        console.log('📅 Navigating to today:', this.currentViewDate);
        
        // Re-render calendar
        this.renderCalendarView();
        
        const monthName = this.getMonthName(this.currentViewDate.getMonth());
        const year = this.currentViewDate.getFullYear();
        this.showToast(`📅 Back to ${monthName} ${year}`, 'info');
    },

    selectDate: function(dateStr) {
        document.getElementById('cpDate').value = dateStr;
        this.editExistingEntry(dateStr);
        
        // Scroll to form
        document.getElementById('form-c').scrollIntoView({ behavior: 'smooth' });
    },

    // ============================================
    // FEATURE 6: COPY WEEK PATTERN
    // ============================================

    copyLastWeek: function() {
        const data = JSON.parse(localStorage.getItem('formCData') || '[]');
        if (data.length === 0) {
            this.showToast('No previous data to copy', 'error');
            return;
        }

        // Get last 6 entries (excluding Sundays)
        const lastWeek = data.slice(-6);
        
        const modal = document.createElement('div');
        modal.className = 'copy-week-modal';
        modal.innerHTML = `
            <div class="copy-week-content">
                <h2>📋 Copy Last Week Pattern</h2>
                <p>Copy the last ${lastWeek.length} entries to new dates?</p>
                
                <div class="copy-week-preview">
                    <table>
                        <thead>
                            <tr>
                                <th>From Date</th>
                                <th>→</th>
                                <th>To Date (New)</th>
                            </tr>
                        </thead>
                        <tbody id="copyWeekPreview">
                        </tbody>
                    </table>
                </div>
                
                <p style="font-size: 13px; color: #666; margin-top: 10px;">
                    You can edit the new dates before copying.
                </p>
                
                <div class="copy-week-actions">
                    <button onclick="EnhancedFormC.executeCopyWeek()" class="btn-copy">
                        📋 Copy Week
                    </button>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn-cancel">
                        Cancel
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Generate date mappings
        this.generateWeekCopyDates(lastWeek);
    },

    generateWeekCopyDates: function(entries) {
        const preview = document.getElementById('copyWeekPreview');
        if (!preview) return;

        const today = new Date();
        let html = '';
        
        entries.forEach((entry, i) => {
            // Calculate new date (7 days forward from entry date)
            const [d, m, y] = entry.date.split('-').map(Number);
            const oldDate = new Date(y, m - 1, d);
            const newDate = new Date(oldDate);
            newDate.setDate(newDate.getDate() + 7);
            
            const newDateStr = `${String(newDate.getDate()).padStart(2, '0')}-${String(newDate.getMonth() + 1).padStart(2, '0')}-${newDate.getFullYear()}`;
            
            html += `
                <tr>
                    <td>${entry.date}</td>
                    <td>→</td>
                    <td>
                        <input type="text" value="${newDateStr}" 
                               id="newDate_${i}" 
                               placeholder="dd-mm-yyyy"
                               style="width: 120px; padding: 5px; text-align: center;">
                    </td>
                </tr>
            `;
        });
        
        preview.innerHTML = html;
        this.weekCopyData = entries;
    },

    executeCopyWeek: function() {
        if (!this.weekCopyData) return;

        const existingData = JSON.parse(localStorage.getItem('formCData') || '[]');
        let copied = 0;

        this.weekCopyData.forEach((entry, i) => {
            const newDateInput = document.getElementById(`newDate_${i}`);
            if (!newDateInput) return;

            const newDate = newDateInput.value;
            if (!/^\d{2}-\d{2}-\d{4}$/.test(newDate)) return;

            // Create new entry
            const newEntry = {
                ...entry,
                date: newDate
            };

            // Check if date already exists
            const existingIndex = existingData.findIndex(e => e.date === newDate);
            if (existingIndex >= 0) {
                existingData[existingIndex] = newEntry;
            } else {
                existingData.push(newEntry);
            }
            
            copied++;
        });

        localStorage.setItem('formCData', JSON.stringify(existingData));
        
        const modal = document.querySelector('.copy-week-modal');
        if (modal) modal.remove();

        this.showToast(`✅ Copied ${copied} entries!`, 'success');
        
        // Refresh display
        if (typeof loadFormCTable === 'function') {
            loadFormCTable();
        }
        this.renderCalendarView();
        this.updateStats();
    },

    // ============================================
    // FEATURE 7: ENTRY STATS WIDGET
    // ============================================

    updateStats: function() {
        const container = document.getElementById('formCStatsWidget');
        if (!container) return;

        const data = JSON.parse(localStorage.getItem('formCData') || '[]');
        const now = new Date();
        const currentMonth = now.getMonth();
        const currentYear = now.getFullYear();

        // Filter current month
        const monthData = data.filter(entry => {
            const [d, m, y] = entry.date.split('-').map(Number);
            return m - 1 === currentMonth && y === currentYear;
        });

        if (monthData.length === 0) {
            container.innerHTML = `
                <div class="stats-widget-empty">
                    <p>📊 No entries for this month yet</p>
                </div>
            `;
            return;
        }

        // Calculate stats
        const totalStudents = monthData.reduce((sum, e) => sum + (e.totalCPVI || 0), 0);
        const avgStudents = Math.round(totalStudents / monthData.length);
        const totalRice = monthData.reduce((sum, e) => sum + (parseFloat(e.rice) || 0), 0);
        const totalCost = monthData.reduce((sum, e) => sum + (parseFloat(e.cost) || 0), 0);

        const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
        const progress = Math.round((monthData.length / daysInMonth) * 100);

        container.innerHTML = `
            <div class="stats-widget-header">
                <h3>📊 ${this.getMonthName(currentMonth)} Stats</h3>
            </div>
            <div class="stats-widget-grid">
                <div class="stat-item">
                    <div class="stat-value">${monthData.length}</div>
                    <div class="stat-label">Days Entered</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${avgStudents}</div>
                    <div class="stat-label">Avg Students</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">${totalRice.toFixed(1)}</div>
                    <div class="stat-label">Total Rice (kg)</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">₹${totalCost.toLocaleString()}</div>
                    <div class="stat-label">Total Cost</div>
                </div>
            </div>
            <div class="stats-progress">
                <div class="progress-label">Month Progress: ${progress}%</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: ${progress}%"></div>
                </div>
                <div class="progress-text">${monthData.length} / ${daysInMonth} days</div>
            </div>
        `;
    },

    // Continue in Part 3...
});
// ============================================
// ENHANCED FORM C SYSTEM - PART 3
// Templates, Holidays, Utilities
// ============================================

Object.assign(EnhancedFormC, {

    // ============================================
    // FEATURE 8: QUICK TEMPLATES
    // ============================================

    openTemplatesModal: function() {
        const templates = this.config.templates;
        
        const modal = document.createElement('div');
        modal.className = 'templates-modal';
        modal.innerHTML = `
            <div class="templates-content">
                <h2>⚡ Quick Templates</h2>
                <p style="color: #666;">Save and load common entry patterns</p>
                
                <div class="templates-grid">
                    ${Object.keys(templates).length > 0 ? `
                        ${Object.entries(templates).map(([name, template]) => `
                            <div class="template-card">
                                <h4>${name}</h4>
                                <p>VI-VIII: ${template.totalCPVI} students</p>
                                <p>Rice: ${template.rice}kg | ₹${template.cost}</p>
                                <div class="template-actions">
                                    <button onclick="EnhancedFormC.applyTemplate('${name}')" class="btn-apply">Apply</button>
                                    <button onclick="EnhancedFormC.deleteTemplate('${name}')" class="btn-delete">Delete</button>
                                </div>
                            </div>
                        `).join('')}
                    ` : `
                        <p style="text-align: center; color: #999; padding: 20px;">
                            No templates saved yet. Fill form and click "Save as Template" below.
                        </p>
                    `}
                </div>
                
                <div class="templates-form">
                    <h3>Create New Template</h3>
                    <input type="text" id="templateName" placeholder="Template name (e.g., Normal Day)" 
                           style="width: 100%; padding: 10px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button onclick="EnhancedFormC.saveCurrentAsTemplate()" class="btn-save">
                        💾 Save Current Form as Template
                    </button>
                </div>
                
                <div class="templates-actions">
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn-cancel">
                        Close
                    </button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    },

    saveCurrentAsTemplate: function() {
        const name = document.getElementById('templateName').value.trim();
        if (!name) {
            this.showToast('Please enter template name', 'error');
            return;
        }

        const template = {
            cpV: parseInt(document.getElementById('cpV').value) || 0,
            mtV: parseInt(document.getElementById('mtV').value) || 0,
            cpVI: parseInt(document.getElementById('cpVI').value) || 0,
            mtVI: parseInt(document.getElementById('mtVI').value) || 0,
            cpVII: parseInt(document.getElementById('cpVII').value) || 0,
            mtVII: parseInt(document.getElementById('mtVII').value) || 0,
            cpVIII: parseInt(document.getElementById('cpVIII').value) || 0,
            mtVIII: parseInt(document.getElementById('mtVIII').value) || 0,
            totalCPVI: parseInt(document.getElementById('totalCPVI').textContent) || 0,
            totalMTVI: parseInt(document.getElementById('totalMTVI').textContent) || 0,
            rice: parseFloat(document.getElementById('totalRice').textContent) || 0,
            cost: parseFloat(document.getElementById('totalCost').textContent) || 0,
            menu: document.getElementById('formCMenu').value
        };

        this.config.templates[name] = template;
        localStorage.setItem('formC_templates', JSON.stringify(this.config.templates));
        
        this.showToast(`✅ Template "${name}" saved!`, 'success');
        
        // Refresh modal
        const modal = document.querySelector('.templates-modal');
        if (modal) modal.remove();
        this.openTemplatesModal();
    },

    applyTemplate: function(name) {
        const template = this.config.templates[name];
        if (!template) return;

        // Fill form
        document.getElementById('cpV').value = template.cpV;
        document.getElementById('mtV').value = template.mtV;
        document.getElementById('cpVI').value = template.cpVI;
        document.getElementById('mtVI').value = template.mtVI;
        document.getElementById('cpVII').value = template.cpVII;
        document.getElementById('mtVII').value = template.mtVII;
        document.getElementById('cpVIII').value = template.cpVIII;
        document.getElementById('mtVIII').value = template.mtVIII;
        document.getElementById('formCMenu').value = template.menu;

        // Trigger calculation
        if (typeof calculateFormC === 'function') {
            calculateFormC();
        }

        this.showToast(`✅ Applied template "${name}"`, 'success');
        
        const modal = document.querySelector('.templates-modal');
        if (modal) modal.remove();
    },

    deleteTemplate: function(name) {
        if (!confirm(`Delete template "${name}"?`)) return;

        delete this.config.templates[name];
        localStorage.setItem('formC_templates', JSON.stringify(this.config.templates));
        
        this.showToast(`🗑️ Template "${name}" deleted`, 'success');
        
        // Refresh modal
        const modal = document.querySelector('.templates-modal');
        if (modal) modal.remove();
        this.openTemplatesModal();
    },

    // ============================================
    // FEATURE 9: HOLIDAY MANAGEMENT
    // ============================================

    openHolidayManager: function() {
        const modal = document.createElement('div');
        modal.className = 'holiday-modal';
        modal.innerHTML = `
            <div class="holiday-content">
                <h2>📅 Holiday Management</h2>
                <p style="color: #666;">Mark holidays to skip entry (Sundays auto-marked)</p>
                
                <div class="holiday-list">
                    <h3>Marked Holidays:</h3>
                    ${this.config.holidays.length > 0 ? `
                        <ul>
                            ${this.config.holidays.map(date => `
                                <li>
                                    ${date}
                                    <button onclick="EnhancedFormC.removeHoliday('${date}')" class="btn-remove-small">✕</button>
                                </li>
                            `).join('')}
                        </ul>
                    ` : `
                        <p style="color: #999;">No holidays marked yet</p>
                    `}
                </div>
                
                <div class="holiday-form">
                    <h3>Add Holiday:</h3>
                    <input type="text" id="holidayDate" placeholder="dd-mm-yyyy" 
                           style="width: 150px; padding: 8px; margin-right: 10px; border: 1px solid #ddd; border-radius: 5px;">
                    <button onclick="EnhancedFormC.addHoliday()" class="btn-add">
                        ➕ Add
                    </button>
                </div>
                
                <div class="holiday-quick">
                    <h3>Quick Add Common Holidays:</h3>
                    <button onclick="EnhancedFormC.addCommonHolidays('2024')" class="btn-quick">
                        Add 2024 National Holidays
                    </button>
                    <button onclick="EnhancedFormC.addCommonHolidays('2025')" class="btn-quick">
                        Add 2025 National Holidays
                    </button>
                </div>
                
                <div class="holiday-actions">
                    <button onclick="EnhancedFormC.saveHolidays()" class="btn-save">💾 Save</button>
                    <button onclick="this.parentElement.parentElement.parentElement.remove()" class="btn-cancel">Close</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
    },

    addHoliday: function() {
        const input = document.getElementById('holidayDate');
        const date = input.value.trim();
        
        if (!date || !/^\d{2}-\d{2}-\d{4}$/.test(date)) {
            this.showToast('Invalid date format', 'error');
            return;
        }

        if (this.config.holidays.includes(date)) {
            this.showToast('Holiday already added', 'warning');
            return;
        }

        this.config.holidays.push(date);
        this.config.holidays.sort();
        
        input.value = '';
        
        // Refresh modal
        const modal = document.querySelector('.holiday-modal');
        if (modal) modal.remove();
        this.openHolidayManager();
    },

    removeHoliday: function(date) {
        this.config.holidays = this.config.holidays.filter(d => d !== date);
        
        // Refresh modal
        const modal = document.querySelector('.holiday-modal');
        if (modal) modal.remove();
        this.openHolidayManager();
    },

    addCommonHolidays: function(year) {
        // Common Indian National Holidays
        const holidays = [
            `26-01-${year}`, // Republic Day
            `15-08-${year}`, // Independence Day
            `02-10-${year}`, // Gandhi Jayanti
            `25-12-${year}`  // Christmas
        ];

        let added = 0;
        holidays.forEach(date => {
            if (!this.config.holidays.includes(date)) {
                this.config.holidays.push(date);
                added++;
            }
        });

        this.config.holidays.sort();
        
        this.showToast(`Added ${added} holidays for ${year}`, 'success');
        
        // Refresh modal
        const modal = document.querySelector('.holiday-modal');
        if (modal) modal.remove();
        this.openHolidayManager();
    },

    saveHolidays: function() {
        localStorage.setItem('formC_holidays', JSON.stringify(this.config.holidays));
        this.showToast('✅ Holidays saved!', 'success');
        
        const modal = document.querySelector('.holiday-modal');
        if (modal) modal.remove();
        
        // Refresh calendar
        this.renderCalendarView();
    },

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    loadConfig: function() {
        // Load class strengths
        const savedStrengths = localStorage.getItem('formC_classStrengths');
        if (savedStrengths) {
            this.config.classStrengths = JSON.parse(savedStrengths);
        }

        // Load templates
        const savedTemplates = localStorage.getItem('formC_templates');
        if (savedTemplates) {
            this.config.templates = JSON.parse(savedTemplates);
        }

        // Load holidays
        const savedHolidays = localStorage.getItem('formC_holidays');
        if (savedHolidays) {
            this.config.holidays = JSON.parse(savedHolidays);
        }
    },

    setupEventListeners: function() {
        // Setup validation on inputs
        this.setupValidation();
        
        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            // Ctrl+E: Excel upload
            if (e.ctrlKey && e.key === 'e') {
                e.preventDefault();
                this.uploadExcel();
            }
            
            // Ctrl+T: Templates
            if (e.ctrlKey && e.key === 't') {
                e.preventDefault();
                this.openTemplatesModal();
            }
            
            // Ctrl+A: Auto-fill
            if (e.ctrlKey && e.key === 'a' && e.target.tagName !== 'INPUT') {
                e.preventDefault();
                this.autoFillDefaults();
            }
        });
    },

    showLoading: function(message = 'Loading...') {
        let loader = document.getElementById('enhancedLoader');
        if (!loader) {
            loader = document.createElement('div');
            loader.id = 'enhancedLoader';
            loader.className = 'enhanced-loader';
            document.body.appendChild(loader);
        }
        
        loader.innerHTML = `
            <div class="loader-content">
                <div class="loader-spinner"></div>
                <p>${message}</p>
            </div>
        `;
        loader.style.display = 'flex';
    },

    hideLoading: function() {
        const loader = document.getElementById('enhancedLoader');
        if (loader) {
            loader.style.display = 'none';
        }
    },

    showToast: function(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `enhanced-toast enhanced-toast-${type}`;
        
        const icon = {
            'success': '✅',
            'error': '❌',
            'warning': '⚠️',
            'info': 'ℹ️'
        }[type] || 'ℹ️';
        
        toast.innerHTML = `
            <span class="toast-icon">${icon}</span>
            <span class="toast-message">${message}</span>
        `;
        
        document.body.appendChild(toast);
        
        // Show
        setTimeout(() => toast.classList.add('show'), 10);
        
        // Hide and remove
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    // ============================================
    // EXPORT FUNCTIONS FOR EXTERNAL USE
    // ============================================

    getEnhancedEntryData: function() {
        // Get all form data with validation
        const data = {
            date: document.getElementById('cpDate').value,
            cpV: parseInt(document.getElementById('cpV').value) || 0,
            mtV: parseInt(document.getElementById('mtV').value) || 0,
            cpVI: parseInt(document.getElementById('cpVI').value) || 0,
            mtVI: parseInt(document.getElementById('mtVI').value) || 0,
            cpVII: parseInt(document.getElementById('cpVII').value) || 0,
            mtVII: parseInt(document.getElementById('mtVII').value) || 0,
            cpVIII: parseInt(document.getElementById('cpVIII').value) || 0,
            mtVIII: parseInt(document.getElementById('mtVIII').value) || 0,
            totalCPVI: (parseInt(document.getElementById('cpVI').value) || 0) + 
                      (parseInt(document.getElementById('cpVII').value) || 0) + 
                      (parseInt(document.getElementById('cpVIII').value) || 0),
            totalMTVI: (parseInt(document.getElementById('mtVI').value) || 0) + 
                      (parseInt(document.getElementById('mtVII').value) || 0) + 
                      (parseInt(document.getElementById('mtVIII').value) || 0),
            rice: parseFloat(document.getElementById('totalRice').textContent) || 0,
            cost: parseFloat(document.getElementById('totalCost').textContent) || 0,
            menu: document.getElementById('formCMenu').value
        };

        return data;
    },

    validateEntryData: function(data) {
        const errors = [];

        if (!data.date || !/^\d{2}-\d{2}-\d{4}$/.test(data.date)) {
            errors.push('Invalid date format');
        }

        if (data.totalCPVI === 0 && data.totalMTVI === 0) {
            errors.push('No students entered');
        }

        if (data.rice === 0 || data.cost === 0) {
            errors.push('Rice or cost is zero');
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    }
});

// Initialize on page load (faster loading)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        // Quick initialization for better performance
        setTimeout(() => {
            if (window.location.hash === '#form-c' || document.getElementById('formCTable')) {
                EnhancedFormC.init();
            }
        }, 200);
    });
} else {
    setTimeout(() => {
        if (window.location.hash === '#form-c' || document.getElementById('formCTable')) {
            EnhancedFormC.init();
        }
    }, 200);
}

console.log('✅ Enhanced Form C System Loaded!');
