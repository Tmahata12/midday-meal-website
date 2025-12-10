// ========================================
// FORGOT PASSWORD SYSTEM
// Simple & Secure Password Recovery
// ========================================

const ForgotPasswordSystem = {
    
    // Initialize the system
    init() {
        this.createForgotPasswordUI();
        this.setupSecurityQuestions();
        console.log('🔐 Forgot Password System initialized');
    },
    
    // Default security questions
    securityQuestions: [
        "আপনার প্রিয় শিক্ষকের নাম কি?",
        "আপনার জন্ম স্থান কোথায়?",
        "আপনার প্রথম স্কুলের নাম কি?",
        "আপনার প্রিয় বইয়ের নাম কি?",
        "আপনার মায়ের মেয়ের নাম কি?"
    ],
    
    // Setup security questions for current user
    setupSecurityQuestions() {
        // Check if security questions are already set
        const existingQ = localStorage.getItem('mdm_security_question');
        if (!existingQ) {
            // Set default for admin
            localStorage.setItem('mdm_security_question', this.securityQuestions[0]);
            localStorage.setItem('mdm_security_answer', 'admin'); // Default answer
            console.log('✅ Default security question set');
        }
    },
    
    // Create Forgot Password UI
    createForgotPasswordUI() {
        const forgotHTML = `
            <!-- Forgot Password Modal -->
            <div id="forgot-password-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); z-index: 99999; overflow: auto;">
                <div style="max-width: 500px; margin: 50px auto; background: white; border-radius: 15px; padding: 40px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3); position: relative; animation: slideIn 0.3s ease;">
                    
                    <!-- Close Button -->
                    <button onclick="ForgotPasswordSystem.closeForgotModal()" style="position: absolute; top: 15px; right: 15px; background: #e74c3c; color: white; border: none; width: 35px; height: 35px; border-radius: 50%; cursor: pointer; font-size: 20px; font-weight: bold;">×</button>
                    
                    <!-- Header -->
                    <div style="text-align: center; margin-bottom: 30px;">
                        <div style="font-size: 50px; margin-bottom: 10px;">🔐</div>
                        <h2 style="margin: 0; color: #667eea;">Password Recovery</h2>
                        <p style="color: #666; margin-top: 5px; font-size: 14px;">Answer your security question to reset password</p>
                    </div>
                    
                    <!-- Step 1: Verify Username -->
                    <div id="verify-username-step" style="display: block;">
                        <div style="background: #e3f2fd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #2196f3;">
                            <strong style="color: #1976d2;">Step 1: Verify Your Username</strong>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600; color: #333;">Username:</label>
                            <input type="text" id="forgot-username" placeholder="Enter your username" style="width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 14px;">
                        </div>
                        
                        <button onclick="ForgotPasswordSystem.verifyUsername()" style="width: 100%; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 20px;">
                            Next →
                        </button>
                    </div>
                    
                    <!-- Step 2: Answer Security Question -->
                    <div id="security-question-step" style="display: none;">
                        <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #ffc107;">
                            <strong style="color: #856404;">Step 2: Answer Security Question</strong>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600; color: #333;">Security Question:</label>
                            <div id="security-question-text" style="background: #f8f9fa; padding: 12px; border-radius: 8px; border: 2px solid #667eea; color: #667eea; font-weight: 600;"></div>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600; color: #333;">Your Answer:</label>
                            <input type="text" id="security-answer" placeholder="Type your answer" style="width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 14px;">
                        </div>
                        
                        <div style="display: flex; gap: 10px; margin-top: 20px;">
                            <button onclick="ForgotPasswordSystem.backToUsername()" style="flex: 1; padding: 15px; background: #95a5a6; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer;">
                                ← Back
                            </button>
                            <button onclick="ForgotPasswordSystem.verifyAnswer()" style="flex: 2; padding: 15px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer;">
                                Verify
                            </button>
                        </div>
                    </div>
                    
                    <!-- Step 3: Reset Password -->
                    <div id="reset-password-step" style="display: none;">
                        <div style="background: #d4edda; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #28a745;">
                            <strong style="color: #155724;">✅ Verified! Step 3: Set New Password</strong>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600; color: #333;">New Password:</label>
                            <input type="password" id="new-password" placeholder="Enter new password" style="width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 14px;">
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 600; color: #333;">Confirm Password:</label>
                            <input type="password" id="confirm-password" placeholder="Re-enter new password" style="width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px; font-size: 14px;">
                        </div>
                        
                        <div style="background: #fff3cd; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-size: 13px; color: #856404;">
                            <strong>💡 Tip:</strong> Use a strong password with letters, numbers and symbols
                        </div>
                        
                        <button onclick="ForgotPasswordSystem.resetPassword()" style="width: 100%; padding: 15px; background: linear-gradient(135deg, #28a745 0%, #20c997 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer;">
                            Reset Password 🔒
                        </button>
                    </div>
                    
                </div>
            </div>
            
            <style>
                @keyframes slideIn {
                    from {
                        opacity: 0;
                        transform: translateY(-50px);
                    }
                    to {
                        opacity: 1;
                        transform: translateY(0);
                    }
                }
                
                #forgot-password-modal input:focus {
                    outline: none;
                    border-color: #667eea;
                    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
                }
                
                #forgot-password-modal button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
                    transition: all 0.3s;
                }
                
                #forgot-password-modal button:active {
                    transform: translateY(0);
                }
            </style>
        `;
        
        // Add to body
        document.body.insertAdjacentHTML('beforeend', forgotHTML);
    },
    
    // Open forgot password modal
    openForgotModal() {
        document.getElementById('forgot-password-modal').style.display = 'block';
        document.getElementById('forgot-username').focus();
        // Reset to step 1
        this.showStep('verify-username-step');
    },
    
    // Close forgot password modal
    closeForgotModal() {
        document.getElementById('forgot-password-modal').style.display = 'none';
        // Clear inputs
        document.getElementById('forgot-username').value = '';
        document.getElementById('security-answer').value = '';
        document.getElementById('new-password').value = '';
        document.getElementById('confirm-password').value = '';
    },
    
    // Show specific step
    showStep(stepId) {
        ['verify-username-step', 'security-question-step', 'reset-password-step'].forEach(id => {
            document.getElementById(id).style.display = 'none';
        });
        document.getElementById(stepId).style.display = 'block';
    },
    
    // Verify username
    verifyUsername() {
        const username = document.getElementById('forgot-username').value.trim();
        
        if (!username) {
            alert('❌ Please enter your username!');
            return;
        }
        
        // Get stored username from settings
        const storedUsername = localStorage.getItem('mdm_username') || 'admin';
        
        if (username !== storedUsername) {
            alert('❌ Username not found!\n\nPlease enter correct username.');
            return;
        }
        
        // Load security question
        const question = localStorage.getItem('mdm_security_question') || this.securityQuestions[0];
        document.getElementById('security-question-text').textContent = question;
        
        // Move to step 2
        this.showStep('security-question-step');
        document.getElementById('security-answer').focus();
    },
    
    // Back to username step
    backToUsername() {
        this.showStep('verify-username-step');
    },
    
    // Verify security answer
    verifyAnswer() {
        const answer = document.getElementById('security-answer').value.trim().toLowerCase();
        
        if (!answer) {
            alert('❌ Please enter your answer!');
            return;
        }
        
        // Get stored answer
        const storedAnswer = (localStorage.getItem('mdm_security_answer') || 'admin').toLowerCase();
        
        if (answer !== storedAnswer) {
            alert('❌ Incorrect answer!\n\nPlease try again.');
            document.getElementById('security-answer').value = '';
            document.getElementById('security-answer').focus();
            return;
        }
        
        // Correct answer! Move to step 3
        this.showStep('reset-password-step');
        document.getElementById('new-password').focus();
    },
    
    // Reset password
    resetPassword() {
        const newPassword = document.getElementById('new-password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        
        if (!newPassword || !confirmPassword) {
            alert('❌ Please fill in both password fields!');
            return;
        }
        
        if (newPassword.length < 6) {
            alert('❌ Password must be at least 6 characters long!');
            return;
        }
        
        if (newPassword !== confirmPassword) {
            alert('❌ Passwords do not match!\n\nPlease re-enter carefully.');
            return;
        }
        
        // Save new password
        localStorage.setItem('mdm_password', newPassword);
        
        // Success!
        alert('✅ Password Reset Successful!\n\nYour new password has been saved.\n\nYou can now login with your new password.');
        
        // Close modal
        this.closeForgotModal();
        
        // Log activity
        if (typeof ActivityLogger !== 'undefined') {
            ActivityLogger.log('Password reset via security question');
        }
    },
    
    // Change security question (for settings page)
    changeSecurityQuestion() {
        const modal = `
            <div id="change-security-modal" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); z-index: 99999; display: flex; align-items: center; justify-content: center;">
                <div style="background: white; padding: 40px; border-radius: 15px; max-width: 500px; width: 90%;">
                    <h3 style="margin-top: 0; color: #667eea;">🔐 Change Security Question</h3>
                    
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">Select Question:</label>
                        <select id="new-security-question" style="width: 100%; padding: 10px; border: 2px solid #ddd; border-radius: 8px;">
                            ${this.securityQuestions.map(q => `<option value="${q}">${q}</option>`).join('')}
                        </select>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 600;">Your Answer:</label>
                        <input type="text" id="new-security-answer" placeholder="Enter your answer" style="width: 100%; padding: 10px; border: 2px solid #ddd; border-radius: 8px;">
                    </div>
                    
                    <div style="background: #fff3cd; padding: 15px; border-radius: 8px; margin-bottom: 20px; font-size: 13px;">
                        <strong>⚠️ Important:</strong> Remember your answer! You'll need it to reset your password if you forget it.
                    </div>
                    
                    <div style="display: flex; gap: 10px;">
                        <button onclick="document.getElementById('change-security-modal').remove()" style="flex: 1; padding: 12px; background: #95a5a6; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: bold;">
                            Cancel
                        </button>
                        <button onclick="ForgotPasswordSystem.saveSecurityQuestion()" style="flex: 1; padding: 12px; background: #667eea; color: white; border: none; border-radius: 8px; cursor: pointer; font-weight: bold;">
                            Save
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', modal);
        
        // Set current question
        const currentQ = localStorage.getItem('mdm_security_question');
        if (currentQ) {
            document.getElementById('new-security-question').value = currentQ;
        }
    },
    
    // Save security question
    saveSecurityQuestion() {
        const question = document.getElementById('new-security-question').value;
        const answer = document.getElementById('new-security-answer').value.trim();
        
        if (!answer) {
            alert('❌ Please enter an answer!');
            return;
        }
        
        localStorage.setItem('mdm_security_question', question);
        localStorage.setItem('mdm_security_answer', answer);
        
        alert('✅ Security question updated successfully!');
        document.getElementById('change-security-modal').remove();
        
        // Log activity
        if (typeof ActivityLogger !== 'undefined') {
            ActivityLogger.log('Security question changed');
        }
    }
};

// Initialize on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => ForgotPasswordSystem.init());
} else {
    ForgotPasswordSystem.init();
}

// Export for global use
window.ForgotPasswordSystem = ForgotPasswordSystem;

console.log('🔐 Forgot Password System loaded! Use ForgotPasswordSystem.openForgotModal() to test');
