// ========== ADVANCED EXCEL EXPORT SYSTEM ==========
// Export all ledgers to Excel with professional formatting

const AdvancedExport = {
    
    // Initialize export system
    init() {
        console.log('📊 Advanced Export system initialized');
        this.addExportUI();
    },
    
    // Add export interface
    addExportUI() {
        const exportHTML = `
            <div id="advanced-export-panel" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.8); z-index:99999; overflow:auto;">
                <div style="max-width:1200px; margin:50px auto; background:white; border-radius:10px; padding:30px;">
                    <!-- Header -->
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:30px;">
                        <h2 style="margin:0; color:#667eea;">
                            📊 Advanced Data Export
                        </h2>
                        <button onclick="AdvancedExport.closePanel()" style="background:#e74c3c; color:white; border:none; padding:10px 20px; border-radius:5px; cursor:pointer; font-size:16px;">
                            ✕ Close
                        </button>
                    </div>
                    
                    <!-- Export Options Grid -->
                    <div style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:30px;">
                        <!-- Form C Export -->
                        <div style="background:#e8f5e9; padding:25px; border-radius:10px; border-left:4px solid #27ae60;">
                            <h3 style="margin-top:0; color:#27ae60;">📋 Form C Ledger</h3>
                            <p style="color:#666; margin-bottom:20px;">Complete attendance & meal records</p>
                            <div style="display:flex; gap:10px;">
                                <button onclick="AdvancedExport.exportFormC('month')" style="flex:1; background:#27ae60; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    This Month
                                </button>
                                <button onclick="AdvancedExport.exportFormC('all')" style="flex:1; background:#27ae60; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    All Data
                                </button>
                            </div>
                        </div>
                        
                        <!-- Bank Ledger Export -->
                        <div style="background:#e3f2fd; padding:25px; border-radius:10px; border-left:4px solid #2196f3;">
                            <h3 style="margin-top:0; color:#2196f3;">💰 Bank Ledger</h3>
                            <p style="color:#666; margin-bottom:20px;">All financial transactions</p>
                            <div style="display:flex; gap:10px;">
                                <button onclick="AdvancedExport.exportBank('month')" style="flex:1; background:#2196f3; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    This Month
                                </button>
                                <button onclick="AdvancedExport.exportBank('all')" style="flex:1; background:#2196f3; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    All Data
                                </button>
                            </div>
                        </div>
                        
                        <!-- Rice Ledger Export -->
                        <div style="background:#fff9c4; padding:25px; border-radius:10px; border-left:4px solid #ffc107;">
                            <h3 style="margin-top:0; color:#f57c00;">🌾 Rice Ledger</h3>
                            <p style="color:#666; margin-bottom:20px;">Rice stock & consumption</p>
                            <div style="display:flex; gap:10px;">
                                <button onclick="AdvancedExport.exportRice('month')" style="flex:1; background:#ffc107; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    This Month
                                </button>
                                <button onclick="AdvancedExport.exportRice('all')" style="flex:1; background:#ffc107; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    All Data
                                </button>
                            </div>
                        </div>
                        
                        <!-- Expense Ledger Export -->
                        <div style="background:#fce4ec; padding:25px; border-radius:10px; border-left:4px solid #e91e63;">
                            <h3 style="margin-top:0; color:#e91e63;">💵 Expense Ledger</h3>
                            <p style="color:#666; margin-bottom:20px;">All expense records</p>
                            <div style="display:flex; gap:10px;">
                                <button onclick="AdvancedExport.exportExpense('month')" style="flex:1; background:#e91e63; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    This Month
                                </button>
                                <button onclick="AdvancedExport.exportExpense('all')" style="flex:1; background:#e91e63; color:white; border:none; padding:12px; border-radius:5px; cursor:pointer;">
                                    All Data
                                </button>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Special Exports -->
                    <div style="background:#f5f5f5; padding:25px; border-radius:10px; margin-bottom:20px;">
                        <h3 style="margin-top:0; color:#667eea;">🎯 Special Exports</h3>
                        
                        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:15px;">
                            <button onclick="AdvancedExport.exportAll()" style="background:#667eea; color:white; border:none; padding:15px; border-radius:5px; cursor:pointer; font-weight:bold;">
                                📦 All Data (Complete)
                            </button>
                            <button onclick="AdvancedExport.exportMonthlyReport()" style="background:#9c27b0; color:white; border:none; padding:15px; border-radius:5px; cursor:pointer; font-weight:bold;">
                                📈 Monthly Report
                            </button>
                            <button onclick="AdvancedExport.exportCustomRange()" style="background:#ff5722; color:white; border:none; padding:15px; border-radius:5px; cursor:pointer; font-weight:bold;">
                                🗓️ Custom Date Range
                            </button>
                        </div>
                    </div>
                    
                    <!-- Export Format Options -->
                    <div style="background:#fff; padding:20px; border:1px solid #ddd; border-radius:10px;">
                        <h4 style="margin-top:0;">⚙️ Export Settings</h4>
                        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:15px;">
                            <label style="display:flex; align-items:center; cursor:pointer;">
                                <input type="checkbox" id="include-summary" checked style="margin-right:10px; width:20px; height:20px;">
                                <span>Include Summary</span>
                            </label>
                            <label style="display:flex; align-items:center; cursor:pointer;">
                                <input type="checkbox" id="include-charts" checked style="margin-right:10px; width:20px; height:20px;">
                                <span>Include Charts</span>
                            </label>
                            <label style="display:flex; align-items:center; cursor:pointer;">
                                <input type="checkbox" id="print-friendly" checked style="margin-right:10px; width:20px; height:20px;">
                                <span>Print-Friendly Format</span>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Export Button (Always Visible) -->
            <button id="open-export-btn" onclick="AdvancedExport.openPanel()" style="position:fixed; bottom:170px; right:30px; background:#667eea; color:white; border:none; padding:15px 25px; border-radius:50px; cursor:pointer; font-size:16px; box-shadow:0 4px 12px rgba(0,0,0,0.3); z-index:9999;">
                📊 Export Data
            </button>
        `;
        
        document.body.insertAdjacentHTML('beforeend', exportHTML);
    },
    
    // Open panel
    openPanel() {
        document.getElementById('advanced-export-panel').style.display = 'block';
    },
    
    // Close panel
    closePanel() {
        document.getElementById('advanced-export-panel').style.display = 'none';
    },
    
    // Get current month data filter
    getCurrentMonthFilter() {
        const now = new Date();
        return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
    },
    
    // Export Form C
    exportFormC(range) {
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        let data = mdmData.formC || [];
        
        if (range === 'month') {
            const currentMonth = this.getCurrentMonthFilter();
            data = data.filter(entry => entry.date.startsWith(currentMonth));
        }
        
        if (data.length === 0) {
            alert('No data to export!');
            return;
        }
        
        // Create CSV with headers
        let csv = 'Date,Day,Class V MT,Class VI MT,Class VII MT,Class VIII MT,Total Students,Menu,Rice Consumed (kg),Total Cost (₹)\n';
        
        let totalStudents = 0;
        let totalRice = 0;
        let totalCost = 0;
        
        data.forEach(entry => {
            const date = new Date(entry.date);
            const day = date.toLocaleDateString('en-IN', {weekday: 'long'});
            const total = (entry.mtV || 0) + (entry.mtVI || 0) + (entry.mtVII || 0) + (entry.mtVIII || 0);
            
            totalStudents += total;
            totalRice += entry.rice || 0;
            totalCost += entry.cost || 0;
            
            csv += `${entry.date},${day},${entry.mtV || 0},${entry.mtVI || 0},${entry.mtVII || 0},${entry.mtVIII || 0},${total},"${entry.menu || ''}",${entry.rice || 0},${entry.cost || 0}\n`;
        });
        
        // Add summary
        csv += `\nSUMMARY,,,,,,${totalStudents},Total:,${totalRice.toFixed(2)},${totalCost.toFixed(2)}\n`;
        csv += `,,,,,,Entries: ${data.length},Avg/Day:,${(totalRice/data.length).toFixed(2)},${(totalCost/data.length).toFixed(2)}\n`;
        
        this.downloadCSV(csv, `FormC_${range === 'month' ? 'ThisMonth' : 'AllData'}_${new Date().toISOString().split('T')[0]}.csv`);
        
        console.log(`📥 Form C exported: ${data.length} entries`);
    },
    
    // Export Bank Ledger
    exportBank(range) {
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        let data = mdmData.bankLedger || [];
        
        if (range === 'month') {
            const currentMonth = this.getCurrentMonthFilter();
            data = data.filter(entry => entry.date.startsWith(currentMonth));
        }
        
        if (data.length === 0) {
            alert('No data to export!');
            return;
        }
        
        // Create CSV
        let csv = 'Date,Voucher No,Particulars,Debit (₹),Credit (₹),Balance (₹)\n';
        
        let totalDebit = 0;
        let totalCredit = 0;
        
        data.forEach(entry => {
            const debit = entry.type === 'debit' ? entry.amount : '';
            const credit = entry.type === 'credit' ? entry.amount : '';
            
            if (entry.type === 'debit') totalDebit += entry.amount;
            if (entry.type === 'credit') totalCredit += entry.amount;
            
            csv += `${entry.date},"${entry.voucherNo || ''}","${entry.particulars || ''}",${debit},${credit},${entry.balance || 0}\n`;
        });
        
        // Add summary
        csv += `\nSUMMARY,,,${totalDebit.toFixed(2)},${totalCredit.toFixed(2)},\n`;
        csv += `Entries: ${data.length},,,Net:,${(totalCredit - totalDebit).toFixed(2)},\n`;
        
        this.downloadCSV(csv, `BankLedger_${range === 'month' ? 'ThisMonth' : 'AllData'}_${new Date().toISOString().split('T')[0]}.csv`);
        
        console.log(`📥 Bank Ledger exported: ${data.length} entries`);
    },
    
    // Export Rice Ledger
    exportRice(range) {
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        let data = mdmData.riceLedger || [];
        
        if (range === 'month') {
            const currentMonth = this.getCurrentMonthFilter();
            data = data.filter(entry => entry.date.startsWith(currentMonth));
        }
        
        if (data.length === 0) {
            alert('No data to export!');
            return;
        }
        
        // Create CSV
        let csv = 'Date,Type,Supplier/Purpose,Quantity (kg),Rate (₹/kg),Amount (₹),Balance (kg)\n';
        
        let totalReceived = 0;
        let totalConsumed = 0;
        let totalAmount = 0;
        
        data.forEach(entry => {
            const qty = entry.quantity || 0;
            const rate = entry.rate || 0;
            const amount = entry.amount || (qty * rate);
            
            if (entry.type === 'received') totalReceived += qty;
            if (entry.type === 'consumed') totalConsumed += qty;
            totalAmount += amount;
            
            csv += `${entry.date},"${entry.type}","${entry.supplier || entry.purpose || ''}",${qty},${rate},${amount},${entry.balance || 0}\n`;
        });
        
        // Add summary
        csv += `\nSUMMARY,,,Received: ${totalReceived.toFixed(2)},,,\n`;
        csv += `,,,Consumed: ${totalConsumed.toFixed(2)},,,\n`;
        csv += `,,,Total Amount:,${totalAmount.toFixed(2)},,\n`;
        csv += `,,,Entries: ${data.length},,,\n`;
        
        this.downloadCSV(csv, `RiceLedger_${range === 'month' ? 'ThisMonth' : 'AllData'}_${new Date().toISOString().split('T')[0]}.csv`);
        
        console.log(`📥 Rice Ledger exported: ${data.length} entries`);
    },
    
    // Export Expense Ledger
    exportExpense(range) {
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        let data = mdmData.expenseLedger || [];
        
        if (range === 'month') {
            const currentMonth = this.getCurrentMonthFilter();
            data = data.filter(entry => entry.date.startsWith(currentMonth));
        }
        
        if (data.length === 0) {
            alert('No data to export!');
            return;
        }
        
        // Create CSV
        let csv = 'Date,Voucher No,Particulars,Category,Amount (₹),Payment Mode,Remarks\n';
        
        let totalAmount = 0;
        const categoryTotals = {};
        
        data.forEach(entry => {
            totalAmount += entry.amount || 0;
            
            const category = entry.category || 'Other';
            categoryTotals[category] = (categoryTotals[category] || 0) + (entry.amount || 0);
            
            csv += `${entry.date},"${entry.voucherNo || ''}","${entry.particulars || ''}","${category}",${entry.amount || 0},"${entry.paymentMode || ''}","${entry.remarks || ''}"\n`;
        });
        
        // Add summary
        csv += `\nSUMMARY,,,,${totalAmount.toFixed(2)},,\n`;
        csv += `Entries: ${data.length},,,,,,\n`;
        csv += `\nCATEGORY BREAKDOWN,,,,,, \n`;
        Object.entries(categoryTotals).forEach(([cat, amt]) => {
            csv += `${cat},,,,${amt.toFixed(2)},,\n`;
        });
        
        this.downloadCSV(csv, `ExpenseLedger_${range === 'month' ? 'ThisMonth' : 'AllData'}_${new Date().toISOString().split('T')[0]}.csv`);
        
        console.log(`📥 Expense Ledger exported: ${data.length} entries`);
    },
    
    // Export All Data
    exportAll() {
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        
        // Create comprehensive export
        let csv = '========== RAMNAGAR HIGH SCHOOL - COMPLETE MDM DATA ==========\n';
        csv += `Export Date: ${new Date().toLocaleString('en-IN')}\n\n`;
        
        // School Info
        csv += '========== SCHOOL INFORMATION ==========\n';
        csv += `School Name:,"${mdmData.school?.name || 'N/A'}"\n`;
        csv += `DISE Code:,"${mdmData.school?.dise || 'N/A'}"\n`;
        csv += `Block:,"${mdmData.school?.block || 'N/A'}"\n`;
        csv += `District:,"${mdmData.school?.district || 'N/A'}"\n`;
        csv += `Total Enrollment:,${(mdmData.enrollment?.V || 0) + (mdmData.enrollment?.VI || 0) + (mdmData.enrollment?.VII || 0) + (mdmData.enrollment?.VIII || 0)}\n\n`;
        
        // Form C Summary
        csv += '========== FORM C ENTRIES ==========\n';
        csv += `Total Entries:,${mdmData.formC?.length || 0}\n\n`;
        
        // Bank Summary
        csv += '========== BANK LEDGER ==========\n';
        csv += `Total Transactions:,${mdmData.bankLedger?.length || 0}\n`;
        const bankBalance = mdmData.bankLedger?.[mdmData.bankLedger.length - 1]?.balance || 0;
        csv += `Current Balance:,₹${bankBalance}\n\n`;
        
        // Rice Summary
        csv += '========== RICE STOCK ==========\n';
        csv += `Total Entries:,${mdmData.riceLedger?.length || 0}\n`;
        const riceBalance = mdmData.riceLedger?.[mdmData.riceLedger.length - 1]?.balance || 0;
        csv += `Current Stock:,${riceBalance} kg\n\n`;
        
        // Expense Summary
        csv += '========== EXPENSES ==========\n';
        csv += `Total Entries:,${mdmData.expenseLedger?.length || 0}\n`;
        const totalExpense = (mdmData.expenseLedger || []).reduce((sum, e) => sum + (e.amount || 0), 0);
        csv += `Total Amount:,₹${totalExpense.toFixed(2)}\n\n`;
        
        csv += '========== END OF SUMMARY ==========\n';
        csv += '\nFor detailed ledgers, please export individual reports.\n';
        
        this.downloadCSV(csv, `MDM_Complete_Summary_${new Date().toISOString().split('T')[0]}.csv`);
        
        // Also export individual files
        if (confirm('Summary exported! Do you want to export all individual ledgers as well?')) {
            setTimeout(() => this.exportFormC('all'), 500);
            setTimeout(() => this.exportBank('all'), 1000);
            setTimeout(() => this.exportRice('all'), 1500);
            setTimeout(() => this.exportExpense('all'), 2000);
        }
        
        console.log('📥 Complete data exported');
    },
    
    // Export Monthly Report
    exportMonthlyReport() {
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        const currentMonth = this.getCurrentMonthFilter();
        const [year, month] = currentMonth.split('-');
        const monthName = new Date(parseInt(year), parseInt(month) - 1).toLocaleDateString('en-IN', {month: 'long', year: 'numeric'});
        
        // Filter data for current month
        const formC = (mdmData.formC || []).filter(e => e.date.startsWith(currentMonth));
        const bank = (mdmData.bankLedger || []).filter(e => e.date.startsWith(currentMonth));
        const rice = (mdmData.riceLedger || []).filter(e => e.date.startsWith(currentMonth));
        const expense = (mdmData.expenseLedger || []).filter(e => e.date.startsWith(currentMonth));
        
        // Create comprehensive monthly report
        let csv = `========== MONTHLY REPORT - ${monthName.toUpperCase()} ==========\n`;
        csv += `School: ${mdmData.school?.name || 'Ramnagar High School'}\n`;
        csv += `Generated: ${new Date().toLocaleString('en-IN')}\n\n`;
        
        // Attendance Summary
        csv += '========== ATTENDANCE SUMMARY ==========\n';
        const totalDays = formC.length;
        const totalStudents = formC.reduce((sum, e) => sum + (e.mtV || 0) + (e.mtVI || 0) + (e.mtVII || 0) + (e.mtVIII || 0), 0);
        const avgStudents = totalDays > 0 ? (totalStudents / totalDays).toFixed(2) : 0;
        
        csv += `Working Days:,${totalDays}\n`;
        csv += `Total Meals Served:,${totalStudents}\n`;
        csv += `Average Students/Day:,${avgStudents}\n\n`;
        
        // Financial Summary
        csv += '========== FINANCIAL SUMMARY ==========\n';
        const totalIncome = bank.filter(e => e.type === 'credit').reduce((sum, e) => sum + (e.amount || 0), 0);
        const totalExpenditure = bank.filter(e => e.type === 'debit').reduce((sum, e) => sum + (e.amount || 0), 0);
        const totalExpenseAmt = expense.reduce((sum, e) => sum + (e.amount || 0), 0);
        
        csv += `Income:,₹${totalIncome.toFixed(2)}\n`;
        csv += `Expenditure (Bank):,₹${totalExpenditure.toFixed(2)}\n`;
        csv += `Expenses Recorded:,₹${totalExpenseAmt.toFixed(2)}\n`;
        csv += `Balance:,₹${(totalIncome - totalExpenditure).toFixed(2)}\n\n`;
        
        // Rice Summary
        csv += '========== RICE STOCK SUMMARY ==========\n';
        const riceReceived = rice.filter(e => e.type === 'received').reduce((sum, e) => sum + (e.quantity || 0), 0);
        const riceConsumed = rice.filter(e => e.type === 'consumed').reduce((sum, e) => sum + (e.quantity || 0), 0);
        
        csv += `Received:,${riceReceived.toFixed(2)} kg\n`;
        csv += `Consumed:,${riceConsumed.toFixed(2)} kg\n`;
        csv += `Net:,${(riceReceived - riceConsumed).toFixed(2)} kg\n\n`;
        
        csv += '========== END OF MONTHLY REPORT ==========\n';
        
        this.downloadCSV(csv, `Monthly_Report_${monthName.replace(' ', '_')}_${new Date().toISOString().split('T')[0]}.csv`);
        
        console.log(`📥 Monthly report exported: ${monthName}`);
    },
    
    // Export Custom Date Range
    exportCustomRange() {
        const startDate = prompt('Enter start date (YYYY-MM-DD):');
        const endDate = prompt('Enter end date (YYYY-MM-DD):');
        
        if (!startDate || !endDate) {
            alert('Date range required!');
            return;
        }
        
        const mdmData = JSON.parse(localStorage.getItem('mdmData') || '{}');
        
        // Filter all data by date range
        const formC = (mdmData.formC || []).filter(e => e.date >= startDate && e.date <= endDate);
        const bank = (mdmData.bankLedger || []).filter(e => e.date >= startDate && e.date <= endDate);
        const rice = (mdmData.riceLedger || []).filter(e => e.date >= startDate && e.date <= endDate);
        const expense = (mdmData.expenseLedger || []).filter(e => e.date >= startDate && e.date <= endDate);
        
        let csv = `========== CUSTOM REPORT: ${startDate} to ${endDate} ==========\n\n`;
        csv += `Form C Entries:,${formC.length}\n`;
        csv += `Bank Transactions:,${bank.length}\n`;
        csv += `Rice Transactions:,${rice.length}\n`;
        csv += `Expense Entries:,${expense.length}\n\n`;
        csv += '========== END OF SUMMARY ==========\n';
        
        this.downloadCSV(csv, `Custom_Range_${startDate}_to_${endDate}.csv`);
        
        if (confirm('Export individual ledgers for this date range?')) {
            // Export detailed data for date range (would need separate functions)
            alert('Individual ledgers for custom range - coming soon! For now, use monthly reports.');
        }
        
        console.log(`📥 Custom range exported: ${startDate} to ${endDate}`);
    },
    
    // Download CSV
    downloadCSV(content, filename) {
        const blob = new Blob([content], {type: 'text/csv;charset=utf-8;'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        
        // Show success message
        this.showSuccess(`✅ Exported: ${filename}`);
    },
    
    // Show success message
    showSuccess(message) {
        const div = document.createElement('div');
        div.textContent = message;
        div.style.cssText = 'position:fixed; bottom:30px; left:50%; transform:translateX(-50%); background:#27ae60; color:white; padding:15px 30px; border-radius:5px; z-index:999999; box-shadow:0 4px 12px rgba(0,0,0,0.3);';
        document.body.appendChild(div);
        
        setTimeout(() => div.remove(), 3000);
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => AdvancedExport.init());
} else {
    AdvancedExport.init();
}

// Export for global use
window.AdvancedExport = AdvancedExport;

console.log('📊 Advanced Export system loaded!');
