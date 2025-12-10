// ========== ADVANCED SEARCH & FILTER SYSTEM ==========
// Add this script to enable powerful search across all data

const MDMSearch = {
    // Initialize search system
    init() {
        console.log('🔍 Search system initialized');
        this.addSearchUI();
        this.setupEventListeners();
    },
    
    // Add search interface to page
    addSearchUI() {
        const searchHTML = `
            <div id="mdm-search-panel" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:99999; overflow:auto;">
                <div style="max-width:1200px; margin:50px auto; background:white; border-radius:10px; padding:30px;">
                    <!-- Header -->
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:30px;">
                        <h2 style="margin:0; color:#667eea;">
                            🔍 Advanced Search & Filter
                        </h2>
                        <button onclick="MDMSearch.closePanel()" style="background:#e74c3c; color:white; border:none; padding:10px 20px; border-radius:5px; cursor:pointer; font-size:16px;">
                            ✕ Close
                        </button>
                    </div>
                    
                    <!-- Search Tabs -->
                    <div style="display:flex; gap:10px; margin-bottom:20px; border-bottom:2px solid #eee; padding-bottom:10px;">
                        <button class="search-tab active" data-tab="formC" style="padding:10px 20px; border:none; background:#667eea; color:white; border-radius:5px 5px 0 0; cursor:pointer;">
                            📋 Form C
                        </button>
                        <button class="search-tab" data-tab="bank" style="padding:10px 20px; border:none; background:#ddd; color:#333; border-radius:5px 5px 0 0; cursor:pointer;">
                            💰 Bank
                        </button>
                        <button class="search-tab" data-tab="rice" style="padding:10px 20px; border:none; background:#ddd; color:#333; border-radius:5px 5px 0 0; cursor:pointer;">
                            🌾 Rice
                        </button>
                        <button class="search-tab" data-tab="expense" style="padding:10px 20px; border:none; background:#ddd; color:#333; border-radius:5px 5px 0 0; cursor:pointer;">
                            💵 Expense
                        </button>
                        <button class="search-tab" data-tab="all" style="padding:10px 20px; border:none; background:#ddd; color:#333; border-radius:5px 5px 0 0; cursor:pointer;">
                            🔍 Search All
                        </button>
                    </div>
                    
                    <!-- Search Form -->
                    <div style="background:#f8f9fa; padding:20px; border-radius:8px; margin-bottom:20px;">
                        <!-- Text Search -->
                        <div style="margin-bottom:15px;">
                            <label style="display:block; margin-bottom:5px; font-weight:bold;">🔎 Search Text:</label>
                            <input type="text" id="search-text" placeholder="Search by any field..." style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px; font-size:16px;">
                        </div>
                        
                        <!-- Date Range -->
                        <div style="display:grid; grid-template-columns:1fr 1fr; gap:15px; margin-bottom:15px;">
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">📅 From Date:</label>
                                <input type="date" id="search-from-date" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            </div>
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">📅 To Date:</label>
                                <input type="date" id="search-to-date" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            </div>
                        </div>
                        
                        <!-- Additional Filters (Form C specific) -->
                        <div id="formC-filters" style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:15px; margin-bottom:15px;">
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">🎓 Class:</label>
                                <select id="search-class" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                                    <option value="">All Classes</option>
                                    <option value="V">Class V</option>
                                    <option value="VI">Class VI</option>
                                    <option value="VII">Class VII</option>
                                    <option value="VIII">Class VIII</option>
                                </select>
                            </div>
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">👥 Min Students:</label>
                                <input type="number" id="search-min-students" placeholder="Minimum" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            </div>
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">👥 Max Students:</label>
                                <input type="number" id="search-max-students" placeholder="Maximum" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            </div>
                        </div>
                        
                        <!-- Amount Range (Bank/Expense) -->
                        <div id="amount-filters" style="display:none; grid-template-columns:1fr 1fr; gap:15px; margin-bottom:15px;">
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">💰 Min Amount:</label>
                                <input type="number" id="search-min-amount" placeholder="Minimum" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            </div>
                            <div>
                                <label style="display:block; margin-bottom:5px; font-weight:bold;">💰 Max Amount:</label>
                                <input type="number" id="search-max-amount" placeholder="Maximum" style="width:100%; padding:12px; border:1px solid #ddd; border-radius:5px;">
                            </div>
                        </div>
                        
                        <!-- Search Buttons -->
                        <div style="display:flex; gap:10px;">
                            <button onclick="MDMSearch.performSearch()" style="flex:1; background:#27ae60; color:white; border:none; padding:15px; border-radius:5px; cursor:pointer; font-size:16px; font-weight:bold;">
                                🔍 Search
                            </button>
                            <button onclick="MDMSearch.clearFilters()" style="background:#95a5a6; color:white; border:none; padding:15px 30px; border-radius:5px; cursor:pointer; font-size:16px;">
                                🗑️ Clear
                            </button>
                        </div>
                    </div>
                    
                    <!-- Results -->
                    <div id="search-results" style="max-height:500px; overflow:auto;">
                        <div style="text-align:center; padding:50px; color:#999;">
                            Enter search criteria and click Search
                        </div>
                    </div>
                    
                    <!-- Export Results -->
                    <div id="export-section" style="display:none; margin-top:20px; text-align:right;">
                        <button onclick="MDMSearch.exportResults()" style="background:#3498db; color:white; border:none; padding:12px 30px; border-radius:5px; cursor:pointer; font-size:16px;">
                            📥 Export Results to Excel
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Search Button (Always Visible) -->
            <button id="open-search-btn" onclick="MDMSearch.openPanel()" style="position:fixed; bottom:30px; right:30px; background:#667eea; color:white; border:none; padding:15px 25px; border-radius:50px; cursor:pointer; font-size:18px; box-shadow:0 4px 12px rgba(0,0,0,0.3); z-index:9999;">
                🔍 Search Data
            </button>
        `;
        
        document.body.insertAdjacentHTML('beforeend', searchHTML);
    },
    
    // Setup event listeners
    setupEventListeners() {
        // Tab switching
        document.querySelectorAll('.search-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const tabName = e.target.dataset.tab;
                this.switchTab(tabName);
            });
        });
        
        // Enter key to search
        document.getElementById('search-text')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.performSearch();
        });
    },
    
    // Switch search tab
    switchTab(tabName) {
        // Update active tab
        document.querySelectorAll('.search-tab').forEach(tab => {
            if (tab.dataset.tab === tabName) {
                tab.style.background = '#667eea';
                tab.style.color = 'white';
                tab.classList.add('active');
            } else {
                tab.style.background = '#ddd';
                tab.style.color = '#333';
                tab.classList.remove('active');
            }
        });
        
        // Show/hide relevant filters
        const formCFilters = document.getElementById('formC-filters');
        const amountFilters = document.getElementById('amount-filters');
        
        if (tabName === 'formC') {
            formCFilters.style.display = 'grid';
            amountFilters.style.display = 'none';
        } else if (tabName === 'bank' || tabName === 'expense') {
            formCFilters.style.display = 'none';
            amountFilters.style.display = 'grid';
        } else {
            formCFilters.style.display = 'none';
            amountFilters.style.display = 'none';
        }
        
        this.currentTab = tabName;
    },
    
    // Open search panel
    openPanel() {
        document.getElementById('mdm-search-panel').style.display = 'block';
        if (!this.currentTab) this.switchTab('formC');
    },
    
    // Close search panel
    closePanel() {
        document.getElementById('mdm-search-panel').style.display = 'none';
    },
    
    // Perform search
    performSearch() {
        const searchText = document.getElementById('search-text').value.toLowerCase();
        const fromDate = document.getElementById('search-from-date').value;
        const toDate = document.getElementById('search-to-date').value;
        const searchClass = document.getElementById('search-class').value;
        const minStudents = document.getElementById('search-min-students').value;
        const maxStudents = document.getElementById('search-max-students').value;
        const minAmount = document.getElementById('search-min-amount').value;
        const maxAmount = document.getElementById('search-max-amount').value;
        
        // Get data
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        let results = [];
        
        // Search based on active tab
        const tab = this.currentTab || 'formC';
        
        if (tab === 'formC' || tab === 'all') {
            results = results.concat(this.searchFormC(mdmData.formC || [], {
                searchText, fromDate, toDate, searchClass, minStudents, maxStudents
            }));
        }
        
        if (tab === 'bank' || tab === 'all') {
            results = results.concat(this.searchBank(mdmData.bankLedger || [], {
                searchText, fromDate, toDate, minAmount, maxAmount
            }));
        }
        
        if (tab === 'rice' || tab === 'all') {
            results = results.concat(this.searchRice(mdmData.riceLedger || [], {
                searchText, fromDate, toDate
            }));
        }
        
        if (tab === 'expense' || tab === 'all') {
            results = results.concat(this.searchExpense(mdmData.expenseLedger || [], {
                searchText, fromDate, toDate, minAmount, maxAmount
            }));
        }
        
        this.displayResults(results);
        
        console.log(`🔍 Found ${results.length} results`);
    },
    
    // Search Form C entries
    searchFormC(data, filters) {
        return data.filter(entry => {
            // Text search
            if (filters.searchText) {
                const searchableText = `${entry.date} ${entry.menu || ''} ${entry.mtV} ${entry.mtVI} ${entry.mtVII} ${entry.mtVIII}`.toLowerCase();
                if (!searchableText.includes(filters.searchText)) return false;
            }
            
            // Date range
            if (filters.fromDate && entry.date < filters.fromDate) return false;
            if (filters.toDate && entry.date > filters.toDate) return false;
            
            // Class filter (check if any class matches)
            if (filters.searchClass) {
                const classKey = `mt${filters.searchClass}`;
                if (!entry[classKey]) return false;
            }
            
            // Student count range
            const totalStudents = (entry.mtV || 0) + (entry.mtVI || 0) + (entry.mtVII || 0) + (entry.mtVIII || 0);
            if (filters.minStudents && totalStudents < parseInt(filters.minStudents)) return false;
            if (filters.maxStudents && totalStudents > parseInt(filters.maxStudents)) return false;
            
            return true;
        }).map(entry => ({
            type: 'Form C',
            ...entry,
            display: `📋 ${entry.date} - ${(entry.mtV || 0) + (entry.mtVI || 0) + (entry.mtVII || 0) + (entry.mtVIII || 0)} students - ${entry.menu || 'N/A'}`
        }));
    },
    
    // Search Bank entries
    searchBank(data, filters) {
        return data.filter(entry => {
            // Text search
            if (filters.searchText) {
                const searchableText = `${entry.date} ${entry.particulars || ''} ${entry.voucherNo || ''} ${entry.amount}`.toLowerCase();
                if (!searchableText.includes(filters.searchText)) return false;
            }
            
            // Date range
            if (filters.fromDate && entry.date < filters.fromDate) return false;
            if (filters.toDate && entry.date > filters.toDate) return false;
            
            // Amount range
            if (filters.minAmount && entry.amount < parseFloat(filters.minAmount)) return false;
            if (filters.maxAmount && entry.amount > parseFloat(filters.maxAmount)) return false;
            
            return true;
        }).map(entry => ({
            type: 'Bank',
            ...entry,
            display: `💰 ${entry.date} - ₹${entry.amount} - ${entry.particulars || 'N/A'}`
        }));
    },
    
    // Search Rice entries
    searchRice(data, filters) {
        return data.filter(entry => {
            // Text search
            if (filters.searchText) {
                const searchableText = `${entry.date} ${entry.supplier || ''} ${entry.quantity}`.toLowerCase();
                if (!searchableText.includes(filters.searchText)) return false;
            }
            
            // Date range
            if (filters.fromDate && entry.date < filters.fromDate) return false;
            if (filters.toDate && entry.date > filters.toDate) return false;
            
            return true;
        }).map(entry => ({
            type: 'Rice',
            ...entry,
            display: `🌾 ${entry.date} - ${entry.quantity}kg - ${entry.supplier || 'N/A'}`
        }));
    },
    
    // Search Expense entries
    searchExpense(data, filters) {
        return data.filter(entry => {
            // Text search
            if (filters.searchText) {
                const searchableText = `${entry.date} ${entry.particulars || ''} ${entry.amount}`.toLowerCase();
                if (!searchableText.includes(filters.searchText)) return false;
            }
            
            // Date range
            if (filters.fromDate && entry.date < filters.fromDate) return false;
            if (filters.toDate && entry.date > filters.toDate) return false;
            
            // Amount range
            if (filters.minAmount && entry.amount < parseFloat(filters.minAmount)) return false;
            if (filters.maxAmount && entry.amount > parseFloat(filters.maxAmount)) return false;
            
            return true;
        }).map(entry => ({
            type: 'Expense',
            ...entry,
            display: `💵 ${entry.date} - ₹${entry.amount} - ${entry.particulars || 'N/A'}`
        }));
    },
    
    // Display results
    displayResults(results) {
        const resultsDiv = document.getElementById('search-results');
        const exportSection = document.getElementById('export-section');
        
        if (results.length === 0) {
            resultsDiv.innerHTML = `
                <div style="text-align:center; padding:50px; color:#999;">
                    <h3>No results found</h3>
                    <p>Try adjusting your search criteria</p>
                </div>
            `;
            exportSection.style.display = 'none';
            return;
        }
        
        this.searchResults = results; // Store for export
        
        let html = `
            <div style="background:#e8f5e9; padding:15px; border-radius:5px; margin-bottom:15px;">
                <strong>✅ Found ${results.length} results</strong>
            </div>
            <div style="max-height:400px; overflow:auto;">
        `;
        
        results.forEach((result, index) => {
            html += `
                <div style="background:white; padding:15px; margin-bottom:10px; border-radius:5px; border-left:4px solid #667eea;">
                    <div style="font-weight:bold; color:#667eea; margin-bottom:5px;">
                        ${result.type} Entry #${index + 1}
                    </div>
                    <div style="color:#555;">
                        ${result.display}
                    </div>
                    <div style="margin-top:10px; font-size:12px; color:#999;">
                        ${JSON.stringify(result, null, 2).substring(0, 200)}...
                    </div>
                </div>
            `;
        });
        
        html += '</div>';
        resultsDiv.innerHTML = html;
        exportSection.style.display = 'block';
    },
    
    // Export results
    exportResults() {
        if (!this.searchResults || this.searchResults.length === 0) {
            alert('No results to export!');
            return;
        }
        
        // Create CSV
        let csv = 'Type,Date,Details,Amount\n';
        this.searchResults.forEach(result => {
            const type = result.type;
            const date = result.date || '';
            const details = (result.particulars || result.menu || result.supplier || '').replace(/,/g, ';');
            const amount = result.amount || '';
            csv += `"${type}","${date}","${details}","${amount}"\n`;
        });
        
        // Download
        const blob = new Blob([csv], {type: 'text/csv'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `Search_Results_${new Date().toISOString().split('T')[0]}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        
        console.log('📥 Search results exported');
    },
    
    // Clear filters
    clearFilters() {
        document.getElementById('search-text').value = '';
        document.getElementById('search-from-date').value = '';
        document.getElementById('search-to-date').value = '';
        document.getElementById('search-class').value = '';
        document.getElementById('search-min-students').value = '';
        document.getElementById('search-max-students').value = '';
        document.getElementById('search-min-amount').value = '';
        document.getElementById('search-max-amount').value = '';
        
        document.getElementById('search-results').innerHTML = `
            <div style="text-align:center; padding:50px; color:#999;">
                Enter search criteria and click Search
            </div>
        `;
        document.getElementById('export-section').style.display = 'none';
        
        console.log('🗑️ Filters cleared');
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => MDMSearch.init());
} else {
    MDMSearch.init();
}

// Export for global use
window.MDMSearch = MDMSearch;

// Keyboard shortcut: Ctrl+F to open search
document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'f') {
        e.preventDefault();
        MDMSearch.openPanel();
    }
});

console.log('🔍 Advanced Search System loaded! Press Ctrl+F or click floating button');
