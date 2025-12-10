// ============================================
// AT A GLANCE DASHBOARD - FORM C
// Shows totals, uploads, and quick stats
// ============================================

const FormCDashboard = {
    
    // Initialize dashboard
    init: function() {
        this.renderDashboard();
        this.updateDashboard();
        
        // Update every 15 seconds (reduced frequency for better performance)
        setInterval(() => this.updateDashboard(), 15000);
    },

    // Render dashboard HTML
    renderDashboard: function() {
        const container = document.getElementById('formCAtAGlance');
        if (!container) return;

        container.innerHTML = `
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        border-radius: 15px; padding: 25px; margin-bottom: 25px; 
                        box-shadow: 0 10px 40px rgba(102, 126, 234, 0.3);">
                
                <!-- Header -->
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2 style="color: white; margin: 0; display: flex; align-items: center; gap: 10px;">
                        👁️ AT A GLANCE
                        <span style="font-size: 14px; background: rgba(255,255,255,0.2); 
                                     padding: 4px 12px; border-radius: 20px; font-weight: normal;">
                            Real-time Overview
                        </span>
                    </h2>
                    <button onclick="FormCDashboard.updateDashboard()" 
                            style="background: rgba(255,255,255,0.2); color: white; border: none; 
                                   padding: 8px 16px; border-radius: 20px; cursor: pointer; 
                                   font-weight: 600; transition: all 0.3s;"
                            onmouseover="this.style.background='rgba(255,255,255,0.3)'"
                            onmouseout="this.style.background='rgba(255,255,255,0.2)'">
                        🔄 Refresh
                    </button>
                </div>

                <!-- Main Grid -->
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
                            gap: 20px;">
                    
                    <!-- Today's Summary -->
                    <div style="background: rgba(255,255,255,0.95); border-radius: 12px; padding: 20px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h3 style="color: #667eea; margin: 0; font-size: 16px;">📅 TODAY</h3>
                            <span id="todayDate" style="color: #666; font-size: 13px; font-weight: 600;">--</span>
                        </div>
                        <div id="todaySummary" style="color: #333;">
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Status:</span>
                                <strong id="todayStatus" style="color: #666; font-size: 14px;">Loading...</strong>
                            </div>
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Students:</span>
                                <strong id="todayStudents" style="color: #667eea; font-size: 18px;">--</strong>
                            </div>
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Rice:</span>
                                <strong id="todayRice" style="color: #28a745; font-size: 16px;">-- kg</strong>
                            </div>
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Cost:</span>
                                <strong id="todayCost" style="color: #dc3545; font-size: 16px;">₹--</strong>
                            </div>
                        </div>
                    </div>

                    <!-- This Month Summary -->
                    <div style="background: rgba(255,255,255,0.95); border-radius: 12px; padding: 20px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                            <h3 style="color: #764ba2; margin: 0; font-size: 16px;">📊 THIS MONTH</h3>
                            <span id="monthName" style="color: #666; font-size: 13px; font-weight: 600;">--</span>
                        </div>
                        <div id="monthSummary" style="color: #333;">
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Days Entered:</span>
                                <strong id="monthDays" style="color: #764ba2; font-size: 18px;">--</strong>
                                <span style="color: #999; font-size: 12px;">/30</span>
                            </div>
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Avg Students:</span>
                                <strong id="monthAvgStudents" style="color: #667eea; font-size: 16px;">--</strong>
                            </div>
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Total Rice:</span>
                                <strong id="monthTotalRice" style="color: #28a745; font-size: 16px;">-- kg</strong>
                            </div>
                            <div style="margin: 8px 0;">
                                <span style="color: #666; font-size: 13px;">Total Cost:</span>
                                <strong id="monthTotalCost" style="color: #dc3545; font-size: 16px;">₹--</strong>
                            </div>
                        </div>
                    </div>

                    <!-- Quick Actions & Stats -->
                    <div style="background: rgba(255,255,255,0.95); border-radius: 12px; padding: 20px;">
                        <h3 style="color: #28a745; margin: 0 0 15px 0; font-size: 16px;">⚡ QUICK STATS</h3>
                        <div id="quickStats" style="color: #333;">
                            <div style="margin: 8px 0; padding: 8px; background: #f0f8ff; border-radius: 6px;">
                                <span style="color: #666; font-size: 13px;">Last Entry:</span>
                                <strong id="lastEntryDate" style="color: #0066cc; font-size: 14px;">--</strong>
                            </div>
                            <div style="margin: 8px 0; padding: 8px; background: #f0fff4; border-radius: 6px;">
                                <span style="color: #666; font-size: 13px;">Total Entries:</span>
                                <strong id="totalEntries" style="color: #28a745; font-size: 14px;">--</strong>
                            </div>
                            <div style="margin: 8px 0; padding: 8px; background: #fff9e6; border-radius: 6px;">
                                <span style="color: #666; font-size: 13px;">Excel Uploads:</span>
                                <strong id="excelUploads" style="color: #ffc107; font-size: 14px;">--</strong>
                            </div>
                            <div style="margin: 8px 0; padding: 8px; background: #f8f9fa; border-radius: 6px;">
                                <span style="color: #666; font-size: 13px;">Completion:</span>
                                <strong id="completionRate" style="color: #6c757d; font-size: 14px;">--%</strong>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Activity -->
                    <div style="background: rgba(255,255,255,0.95); border-radius: 12px; padding: 20px;">
                        <h3 style="color: #dc3545; margin: 0 0 15px 0; font-size: 16px;">🔔 RECENT ACTIVITY</h3>
                        <div id="recentActivity" style="color: #333; font-size: 13px; line-height: 1.8;">
                            <div style="color: #999;">Loading...</div>
                        </div>
                    </div>

                </div>

                <!-- Progress Bar -->
                <div style="margin-top: 20px; background: rgba(255,255,255,0.95); 
                            border-radius: 12px; padding: 15px;">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                        <span style="color: #667eea; font-weight: 600; font-size: 14px;">
                            📈 Monthly Progress
                        </span>
                        <span id="progressText" style="color: #666; font-size: 14px; font-weight: 600;">
                            0%
                        </span>
                    </div>
                    <div style="width: 100%; height: 30px; background: #e0e0e0; 
                                border-radius: 15px; overflow: hidden; position: relative;">
                        <div id="progressBar" 
                             style="height: 100%; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); 
                                    width: 0%; transition: width 0.5s ease; display: flex; 
                                    align-items: center; justify-content: center; color: white; 
                                    font-weight: 600; font-size: 13px;">
                        </div>
                    </div>
                </div>

            </div>
        `;
    },

    // Update dashboard with real data
    updateDashboard: function() {
        const data = JSON.parse(localStorage.getItem('formCData') || '[]');
        const now = new Date();
        const currentMonth = now.getMonth();
        const currentYear = now.getFullYear();

        // Today's date
        const today = `${String(now.getDate()).padStart(2, '0')}-${String(now.getMonth() + 1).padStart(2, '0')}-${now.getFullYear()}`;
        
        // Update today's date display
        const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
        document.getElementById('todayDate').textContent = `${now.getDate()} ${monthNames[now.getMonth()]} ${now.getFullYear()}`;
        document.getElementById('monthName').textContent = `${monthNames[now.getMonth()]} ${now.getFullYear()}`;

        // Today's data
        const todayEntry = data.find(e => e.date === today);
        if (todayEntry) {
            document.getElementById('todayStatus').textContent = '✅ Entered';
            document.getElementById('todayStatus').style.color = '#28a745';
            document.getElementById('todayStudents').textContent = todayEntry.totalCPVI || 0;
            document.getElementById('todayRice').textContent = (todayEntry.rice || 0) + ' kg';
            document.getElementById('todayCost').textContent = '₹' + (todayEntry.cost || 0).toLocaleString();
        } else {
            document.getElementById('todayStatus').textContent = '❌ Not Entered';
            document.getElementById('todayStatus').style.color = '#dc3545';
            document.getElementById('todayStudents').textContent = '0';
            document.getElementById('todayRice').textContent = '0 kg';
            document.getElementById('todayCost').textContent = '₹0';
        }

        // This month's data
        const monthData = data.filter(entry => {
            const [d, m, y] = entry.date.split('-').map(Number);
            return m - 1 === currentMonth && y === currentYear;
        });

        const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
        const totalStudents = monthData.reduce((sum, e) => sum + (e.totalCPVI || 0), 0);
        const avgStudents = monthData.length > 0 ? Math.round(totalStudents / monthData.length) : 0;
        const totalRice = monthData.reduce((sum, e) => sum + (parseFloat(e.rice) || 0), 0);
        const totalCost = monthData.reduce((sum, e) => sum + (parseFloat(e.cost) || 0), 0);
        const completion = Math.round((monthData.length / daysInMonth) * 100);

        document.getElementById('monthDays').textContent = monthData.length;
        document.getElementById('monthAvgStudents').textContent = avgStudents;
        document.getElementById('monthTotalRice').textContent = totalRice.toFixed(1) + ' kg';
        document.getElementById('monthTotalCost').textContent = '₹' + totalCost.toLocaleString();

        // Quick stats
        const lastEntry = data.length > 0 ? data[data.length - 1].date : 'None';
        document.getElementById('lastEntryDate').textContent = lastEntry;
        document.getElementById('totalEntries').textContent = data.length;
        
        // Excel uploads (track from activity log)
        const excelUploads = parseInt(localStorage.getItem('formC_excelUploads') || '0');
        document.getElementById('excelUploads').textContent = excelUploads + ' times';
        
        document.getElementById('completionRate').textContent = completion + '%';

        // Progress bar
        document.getElementById('progressText').textContent = `${monthData.length} / ${daysInMonth} days (${completion}%)`;
        document.getElementById('progressBar').style.width = completion + '%';
        document.getElementById('progressBar').textContent = completion + '%';

        // Recent activity
        this.updateRecentActivity(data);
    },

    updateRecentActivity: function(data) {
        const container = document.getElementById('recentActivity');
        if (!container) return;

        const recent = data.slice(-5).reverse(); // Last 5 entries

        if (recent.length === 0) {
            container.innerHTML = '<div style="color: #999;">No entries yet</div>';
            return;
        }

        let html = '';
        recent.forEach((entry, i) => {
            const icon = i === 0 ? '🆕' : '📝';
            const color = i === 0 ? '#28a745' : '#666';
            html += `
                <div style="padding: 6px 0; border-bottom: ${i < recent.length - 1 ? '1px solid #f0f0f0' : 'none'};">
                    <span style="color: ${color};">${icon}</span>
                    <strong style="color: ${color};">${entry.date}</strong>
                    <span style="color: #999; font-size: 12px;">
                        - ${entry.totalCPVI || 0} students, ${entry.rice || 0}kg
                    </span>
                </div>
            `;
        });

        container.innerHTML = html;
    },

    // Track Excel upload
    trackExcelUpload: function() {
        const count = parseInt(localStorage.getItem('formC_excelUploads') || '0');
        localStorage.setItem('formC_excelUploads', count + 1);
        this.updateDashboard();
    }
};

// Initialize on page load
// Initialize on page load (faster loading - reduced delay)
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        setTimeout(() => {
            if (window.location.hash === '#form-c' || document.getElementById('formCAtAGlance')) {
                FormCDashboard.init();
            }
        }, 300);
    });
} else {
    setTimeout(() => {
        if (window.location.hash === '#form-c' || document.getElementById('formCAtAGlance')) {
            FormCDashboard.init();
        }
    }, 300);
}

// Export
window.FormCDashboard = FormCDashboard;

// Hook into existing Excel upload to track
if (window.EnhancedFormC) {
    const originalImport = EnhancedFormC.importExcelData;
    EnhancedFormC.importExcelData = function() {
        const result = originalImport.call(this);
        FormCDashboard.trackExcelUpload();
        return result;
    };
}

console.log('✅ Form C Dashboard Loaded!');
