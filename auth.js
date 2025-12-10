// ========================================
// RHS MDM System V2.0 - Authentication Module
// Handles user authentication, token management, and authorization
// ========================================

class AuthManager {
    constructor() {
        this.API_URL = window.location.hostname === 'localhost' 
            ? 'http://localhost:3000/api' 
            : `${window.location.protocol}//${window.location.host}/api`;
        
        this.token = null;
        this.user = null;
        this.initialized = false;
    }

    // Initialize authentication
    async init() {
        if (this.initialized) return;

        // Get token from storage
        this.token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
        
        if (this.token) {
            try {
                // Verify token and get user info
                const response = await fetch(`${this.API_URL}/auth/me`, {
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                });

                const data = await response.json();

                if (data.success) {
                    this.user = data.user;
                    this.initialized = true;
                    
                    // Update stored user info
                    const storage = localStorage.getItem('authToken') ? localStorage : sessionStorage;
                    storage.setItem('user', JSON.stringify(this.user));
                    
                    return true;
                } else {
                    this.clearAuth();
                    return false;
                }
            } catch (error) {
                console.error('Auth init error:', error);
                this.clearAuth();
                return false;
            }
        } else {
            return false;
        }
    }

    // Check if user is authenticated
    isAuthenticated() {
        return this.token !== null && this.user !== null;
    }

    // Get current user
    getUser() {
        if (!this.user) {
            // Try to get from storage
            const userStr = localStorage.getItem('user') || sessionStorage.getItem('user');
            if (userStr) {
                try {
                    this.user = JSON.parse(userStr);
                } catch (e) {
                    console.error('Error parsing user data:', e);
                }
            }
        }
        return this.user;
    }

    // Get auth token
    getToken() {
        if (!this.token) {
            this.token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
        }
        return this.token;
    }

    // Check if user has specific role
    hasRole(role) {
        return this.user && this.user.role === role;
    }

    // Check if user has any of the specified roles
    hasAnyRole(...roles) {
        return this.user && roles.includes(this.user.role);
    }

    // Check if user is admin
    isAdmin() {
        return this.hasRole('admin');
    }

    // Check if user is teacher
    isTeacher() {
        return this.hasRole('teacher');
    }

    // Check if user is viewer
    isViewer() {
        return this.hasRole('viewer');
    }

    // Login
    async login(email, password, remember = false) {
        try {
            const response = await fetch(`${this.API_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (data.success) {
                this.token = data.token;
                this.user = data.user;

                // Store in appropriate storage
                const storage = remember ? localStorage : sessionStorage;
                storage.setItem('authToken', this.token);
                storage.setItem('user', JSON.stringify(this.user));

                this.initialized = true;
                return { success: true, user: this.user };
            } else {
                return { success: false, error: data.error };
            }
        } catch (error) {
            console.error('Login error:', error);
            return { success: false, error: 'Network error. Please try again.' };
        }
    }

    // Logout
    async logout() {
        try {
            if (this.token) {
                await fetch(`${this.API_URL}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    }
                });
            }
        } catch (error) {
            console.error('Logout error:', error);
        } finally {
            this.clearAuth();
            window.location.href = 'login.html';
        }
    }

    // Clear authentication data
    clearAuth() {
        this.token = null;
        this.user = null;
        this.initialized = false;
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        sessionStorage.removeItem('authToken');
        sessionStorage.removeItem('user');
    }

    // Make authenticated API call
    async apiCall(endpoint, options = {}) {
        const token = this.getToken();
        
        if (!token) {
            throw new Error('Not authenticated');
        }

        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            }
        };

        const mergedOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(`${this.API_URL}${endpoint}`, mergedOptions);
            const data = await response.json();

            // Check for authentication errors
            if (response.status === 401) {
                this.clearAuth();
                window.location.href = 'login.html';
                throw new Error('Session expired. Please login again.');
            }

            return data;
        } catch (error) {
            console.error('API call error:', error);
            throw error;
        }
    }

    // Change password
    async changePassword(currentPassword, newPassword) {
        try {
            const data = await this.apiCall('/auth/change-password', {
                method: 'POST',
                body: JSON.stringify({ currentPassword, newPassword })
            });

            return data;
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // Forgot password
    async forgotPassword(email) {
        try {
            const response = await fetch(`${this.API_URL}/auth/forgot-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email })
            });

            return await response.json();
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // Reset password
    async resetPassword(token, newPassword) {
        try {
            const response = await fetch(`${this.API_URL}/auth/reset-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ token, newPassword })
            });

            return await response.json();
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    // Require authentication (call this on protected pages)
    async requireAuth(requiredRoles = []) {
        const isAuth = await this.init();
        
        if (!isAuth) {
            window.location.href = 'login.html';
            return false;
        }

        // Check role if specified
        if (requiredRoles.length > 0 && !this.hasAnyRole(...requiredRoles)) {
            alert('আপনার এই পেজে প্রবেশের অনুমতি নেই।');
            window.location.href = 'index.html';
            return false;
        }

        return true;
    }

    // Update UI based on user role
    updateUIForRole() {
        const user = this.getUser();
        if (!user) return;

        // Hide admin-only elements for non-admins
        if (!this.isAdmin()) {
            document.querySelectorAll('.admin-only').forEach(el => {
                el.style.display = 'none';
            });
        }

        // Hide teacher-only elements for viewers
        if (this.isViewer()) {
            document.querySelectorAll('.teacher-only, .admin-only').forEach(el => {
                el.style.display = 'none';
            });
        }

        // Show user info
        document.querySelectorAll('.user-name').forEach(el => {
            el.textContent = user.name;
        });

        document.querySelectorAll('.user-email').forEach(el => {
            el.textContent = user.email;
        });

        document.querySelectorAll('.user-role').forEach(el => {
            const roleText = {
                'admin': 'অ্যাডমিন',
                'teacher': 'শিক্ষক',
                'viewer': 'দর্শক'
            };
            el.textContent = roleText[user.role] || user.role;
        });
    }

    // Show/hide loading overlay
    showLoading(show = true) {
        let overlay = document.getElementById('authLoadingOverlay');
        
        if (!overlay && show) {
            overlay = document.createElement('div');
            overlay.id = 'authLoadingOverlay';
            overlay.innerHTML = `
                <style>
                    #authLoadingOverlay {
                        position: fixed;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: rgba(0, 0, 0, 0.7);
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        z-index: 99999;
                    }
                    .auth-spinner {
                        width: 50px;
                        height: 50px;
                        border: 5px solid rgba(255, 255, 255, 0.3);
                        border-top-color: white;
                        border-radius: 50%;
                        animation: authSpin 1s linear infinite;
                    }
                    @keyframes authSpin {
                        to { transform: rotate(360deg); }
                    }
                </style>
                <div class="auth-spinner"></div>
            `;
            document.body.appendChild(overlay);
        } else if (overlay) {
            overlay.style.display = show ? 'flex' : 'none';
        }
    }

    // Format date for display
    formatDate(date) {
        if (!date) return '';
        const d = new Date(date);
        return d.toLocaleDateString('bn-BD', { 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    // Show notification
    showNotification(message, type = 'info') {
        // Create notification element if it doesn't exist
        let container = document.getElementById('authNotificationContainer');
        
        if (!container) {
            container = document.createElement('div');
            container.id = 'authNotificationContainer';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 999999;
                max-width: 400px;
            `;
            document.body.appendChild(container);
        }

        const notification = document.createElement('div');
        const colors = {
            success: '#4caf50',
            error: '#f44336',
            warning: '#ff9800',
            info: '#2196f3'
        };

        notification.style.cssText = `
            background: ${colors[type] || colors.info};
            color: white;
            padding: 16px 20px;
            border-radius: 8px;
            margin-bottom: 10px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
            animation: slideInRight 0.3s ease-out;
            cursor: pointer;
        `;

        notification.innerHTML = `
            <style>
                @keyframes slideInRight {
                    from {
                        opacity: 0;
                        transform: translateX(100%);
                    }
                    to {
                        opacity: 1;
                        transform: translateX(0);
                    }
                }
            </style>
            <strong>${message}</strong>
        `;

        container.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideInRight 0.3s ease-out reverse';
            setTimeout(() => notification.remove(), 300);
        }, 5000);

        // Remove on click
        notification.addEventListener('click', () => {
            notification.style.animation = 'slideInRight 0.3s ease-out reverse';
            setTimeout(() => notification.remove(), 300);
        });
    }
}

// Create global auth manager instance
window.authManager = new AuthManager();

// Convenience methods
window.requireAuth = (roles) => authManager.requireAuth(roles);
window.logout = () => authManager.logout();
window.apiCall = (endpoint, options) => authManager.apiCall(endpoint, options);

// Auto-initialize on page load
document.addEventListener('DOMContentLoaded', async () => {
    // Don't initialize on login page
    if (window.location.pathname.includes('login.html')) {
        return;
    }

    console.log('🔐 Initializing authentication...');
    
    const isAuth = await authManager.init();
    
    if (isAuth) {
        console.log('✅ User authenticated:', authManager.getUser().name);
        authManager.updateUIForRole();
    } else {
        console.log('⚠️ Not authenticated, redirecting to login...');
        window.location.href = 'login.html';
    }
});

console.log('✅ Auth module loaded');
