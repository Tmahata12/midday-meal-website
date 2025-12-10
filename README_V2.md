# 🍽️ RHS MDM Management System - Version 2.0

## 🎯 **Complete Enterprise-Grade School Meal Management System**

**Ramnagar High School Mid-Day Meal Management System Version 2.0** - A comprehensive, secure, cloud-based solution with authentication, activity tracking, automated backups, and advanced analytics.

---

## 🆕 **What's New in Version 2.0**

### 🔐 **Security & Authentication**
- ✅ **User Authentication System** - JWT token-based secure login
- ✅ **Role-Based Access Control** - Admin, Teacher, and Viewer roles
- ✅ **Password Recovery** - Forgot password with email reset
- ✅ **Session Management** - Remember me functionality
- ✅ **Secure Password Hashing** - bcrypt encryption
- ✅ **Auto Logout** - Session timeout protection

### 📊 **Activity Tracking & Audit**
- ✅ **Complete Activity Logging** - Track all system changes
- ✅ **User Action History** - Who changed what and when
- ✅ **Audit Trail** - Complete change history with old/new values
- ✅ **Search & Filter Logs** - Filter by user, module, action, date

### 💾 **Automated Backup System**
- ✅ **Daily Automatic Backups** - Scheduled at 11:59 PM
- ✅ **Manual Backup Option** - On-demand backup anytime
- ✅ **Backup History** - Track all backups with metadata
- ✅ **Email Notifications** - Backup completion alerts

### 🔔 **Notification System**
- ✅ **Email Notifications** - Automated email alerts
- ✅ **Low Stock Alerts** - Rice stock warnings
- ✅ **System Notifications** - Important system events
- ✅ **User Notifications** - Personal alerts and reminders

### 🎨 **Enhanced User Interface**
- ✅ **Professional Dashboard** - Real-time statistics and charts
- ✅ **User Management Interface** - Easy user administration
- ✅ **Activity Logs Viewer** - Beautiful log viewing interface
- ✅ **Responsive Design** - Works on all devices

### 🛡️ **Advanced Security**
- ✅ **Helmet Security Headers** - XSS, clickjacking protection
- ✅ **Rate Limiting** - Prevent brute force attacks
- ✅ **CORS Configuration** - Secure cross-origin requests
- ✅ **Input Validation** - Server-side data validation
- ✅ **Compression** - Gzip compression for performance

### 📈 **Analytics & Reporting**
- ✅ **Dashboard Statistics** - Real-time data visualization
- ✅ **Chart.js Integration** - Beautiful charts and graphs
- ✅ **Attendance Trends** - Visual attendance analytics
- ✅ **Expense Analysis** - Monthly expense tracking

---

## 📋 **Table of Contents**
1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [User Roles & Permissions](#user-roles--permissions)
5. [Features](#features)
6. [API Documentation](#api-documentation)
7. [Deployment](#deployment)
8. [Troubleshooting](#troubleshooting)
9. [Security Best Practices](#security-best-practices)

---

## 💻 **System Requirements**

### For Local Development:
- **Node.js** 14.0 or higher
- **npm** 6.0 or higher
- **MongoDB Atlas** account (FREE tier)
- **Modern Browser** (Chrome, Firefox, Safari, Edge)
- **Email Account** (Gmail recommended for notifications)

### For Production (cPanel):
- **cPanel** with Node.js support
- **SSH access** (recommended)
- **MongoDB Atlas** cluster
- **SSL Certificate** (recommended)

---

## 🚀 **Installation**

### Step 1: Extract Files
```bash
unzip rhs_mdm_v2.zip
cd mdm_system_v2
```

### Step 2: Install Dependencies
```bash
npm install
```

**Dependencies installed:**
- express (Web framework)
- mongoose (MongoDB ODM)
- bcryptjs (Password hashing)
- jsonwebtoken (JWT authentication)
- nodemailer (Email notifications)
- node-cron (Scheduled tasks)
- helmet (Security headers)
- express-rate-limit (Rate limiting)
- compression (Gzip compression)
- cors (Cross-origin resource sharing)
- dotenv (Environment variables)

### Step 3: MongoDB Atlas Setup

1. **Create Account**
   - Go to https://www.mongodb.com/cloud/atlas
   - Sign up (FREE - no credit card required)

2. **Create Cluster**
   - Select FREE tier (M0)
   - Choose region (Mumbai for India)
   - Cluster name: `rhs-mdm-cluster`
   - Wait 3-5 minutes

3. **Create Database User**
   - Go to "Database Access"
   - Add new user
   - Username: `rhs_admin`
   - Password: Create strong password
   - Role: Atlas admin

4. **Whitelist IP**
   - Go to "Network Access"
   - Add IP: `0.0.0.0/0` (Allow from anywhere)

5. **Get Connection String**
   - Click "Connect" on cluster
   - Choose "Connect Your Application"
   - Copy connection string
   - Replace `<password>` with actual password
   - Add `/rhs_mdm` database name

**Example:**
```
mongodb+srv://rhs_admin:YourPassword123@rhs-mdm-cluster.xxxxx.mongodb.net/rhs_mdm?retryWrites=true&w=majority
```

### Step 4: Environment Configuration

```bash
# Copy example file
cp .env.example .env

# Edit .env file
nano .env
```

**Required Configuration (.env file):**
```env
# MongoDB Connection
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/rhs_mdm

# Server Port
PORT=3000

# JWT Secret (generate random key)
JWT_SECRET=your_random_secret_key_here

# Email Configuration (Optional)
EMAIL_SERVICE=gmail
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your_app_password

# Frontend URL
FRONTEND_URL=http://localhost:3000
```

**Generate JWT Secret:**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Step 5: Gmail App Password (for Email Notifications)

1. Enable 2-Factor Authentication on Gmail
2. Go to: https://myaccount.google.com/apppasswords
3. Generate App Password
4. Use this password in `.env` file

### Step 6: Start Server

```bash
# Development mode (auto-restart)
npm run dev

# Production mode
npm start

# Test setup
npm test
```

**You should see:**
```
╔══════════════════════════════════════════════════════════╗
║   🍽️  RHS MDM Management System - Version 2.0          ║
║   📡 Server running on port 3000                         ║
║   🌐 Access: http://localhost:3000                       ║
║   🍃 MongoDB: Connected ✅                               ║
║                                                          ║
║   🔐 Authentication: Enabled                            ║
║   📊 Activity Logging: Enabled                          ║
║   💾 Auto Backup: Scheduled (11:59 PM daily)           ║
║   🔔 Notifications: Enabled                             ║
║   🛡️  Security: Enhanced                                ║
╚══════════════════════════════════════════════════════════╝
```

### Step 7: First Login

**Default Admin Credentials:**
- **Email:** `admin@ramnagarhs.edu`
- **Password:** `admin123`

⚠️ **IMPORTANT:** Change the default password immediately after first login!

### Step 8: Access Application

```
http://localhost:3000/login.html
```

---

## ⚙️ **Configuration**

### Environment Variables (.env)

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGODB_URI` | ✅ Yes | MongoDB Atlas connection string |
| `PORT` | ✅ Yes | Server port (default: 3000) |
| `NODE_ENV` | ❌ No | Environment (development/production) |
| `JWT_SECRET` | ✅ Yes | Secret key for JWT tokens |
| `EMAIL_SERVICE` | ❌ No | Email service (gmail/outlook/yahoo) |
| `EMAIL_USER` | ❌ No | Email address for notifications |
| `EMAIL_PASSWORD` | ❌ No | Email password/app password |
| `FRONTEND_URL` | ❌ No | Frontend URL for password reset links |

---

## 👥 **User Roles & Permissions**

### 🔴 **Admin** (অ্যাডমিন)
**Full System Access**
- ✅ View all data
- ✅ Create, Edit, Delete all records
- ✅ Manage users (create, edit, delete)
- ✅ View activity logs
- ✅ Access all reports
- ✅ Change system settings
- ✅ Create manual backups
- ✅ Send notifications

### 🟡 **Teacher** (শিক্ষক)
**Data Entry & Viewing**
- ✅ View all data
- ✅ Create new records (Form C, Bank, Rice, Expense)
- ✅ Edit records
- ❌ Delete records
- ❌ User management
- ✅ View activity logs (limited)
- ✅ Access reports
- ❌ Change system settings

### 🟢 **Viewer** (দর্শক)
**Read-Only Access**
- ✅ View all data
- ❌ Create records
- ❌ Edit records
- ❌ Delete records
- ❌ User management
- ❌ Activity logs
- ✅ View reports
- ❌ Change settings

---

## 🎯 **Features**

### 1. **Authentication System**
- Secure login with JWT tokens
- Password recovery via email
- Remember me functionality
- Auto-logout on inactivity
- Session management

### 2. **Dashboard**
- Real-time statistics
- Interactive charts (Chart.js)
- Quick action buttons
- Recent activity feed
- Role-based content

### 3. **Form C Management**
- Daily attendance entry
- Male/Female breakdown
- Automatic calculations
- Class-wise tracking
- Monthly summaries

### 4. **Bank Ledger**
- Receipt/Payment tracking
- Running balance
- Voucher management
- Transaction history
- Monthly reports

### 5. **Rice Ledger**
- Stock receipt tracking
- Daily issue tracking
- Running balance
- Low stock alerts
- Consumption analysis

### 6. **Expense Ledger**
- Categorized expenses
- Payment mode tracking
- Monthly summaries
- Budget analysis
- Voucher management

### 7. **User Management** (Admin Only)
- Create/Edit/Delete users
- Role assignment
- Status management
- Last login tracking
- Activity monitoring

### 8. **Activity Logs**
- Complete audit trail
- Filter by module/action/user
- Change history
- Export logs
- Search functionality

### 9. **Automated Backups**
- Daily automatic backups
- Manual backup option
- Backup history
- Email notifications
- One-click restore

### 10. **Reporting System**
- 6 Excel formats
- PDF export
- Monthly summaries
- Class-wise breakdowns
- Custom date ranges

---

## 🔌 **API Documentation**

### Authentication Endpoints

#### Login
```
POST /api/auth/login
Body: { email, password }
Response: { success, token, user }
```

#### Register (Admin only)
```
POST /api/auth/register
Headers: Authorization: Bearer <token>
Body: { name, email, password, role, phone }
Response: { success, user }
```

#### Get Current User
```
GET /api/auth/me
Headers: Authorization: Bearer <token>
Response: { success, user }
```

#### Change Password
```
POST /api/auth/change-password
Headers: Authorization: Bearer <token>
Body: { currentPassword, newPassword }
Response: { success, message }
```

#### Forgot Password
```
POST /api/auth/forgot-password
Body: { email }
Response: { success, message }
```

#### Reset Password
```
POST /api/auth/reset-password
Body: { token, newPassword }
Response: { success, message }
```

### Data Endpoints

All data endpoints require authentication (Bearer token).

#### Form C
```
GET    /api/formC           - Get all Form C entries
POST   /api/formC           - Create new entry (Admin/Teacher)
PUT    /api/formC/:id       - Update entry (Admin/Teacher)
DELETE /api/formC/:id       - Delete entry (Admin)
```

#### Bank Ledger
```
GET    /api/bank            - Get all bank transactions
POST   /api/bank            - Create transaction (Admin/Teacher)
DELETE /api/bank/:id        - Delete transaction (Admin)
```

#### Rice Ledger
```
GET    /api/rice            - Get all rice transactions
POST   /api/rice            - Create transaction (Admin/Teacher)
DELETE /api/rice/:id        - Delete transaction (Admin)
```

#### Expense Ledger
```
GET    /api/expense         - Get all expenses
POST   /api/expense         - Create expense (Admin/Teacher)
DELETE /api/expense/:id     - Delete expense (Admin)
```

### Admin Endpoints

#### User Management
```
GET    /api/users           - Get all users (Admin)
PUT    /api/users/:id       - Update user (Admin)
DELETE /api/users/:id       - Delete user (Admin)
```

#### Activity Logs
```
GET    /api/activity-logs   - Get activity logs (Admin/Teacher)
Query: ?module=formC&action=create&limit=100
```

#### Notifications
```
GET    /api/notifications   - Get my notifications
PUT    /api/notifications/:id/read - Mark as read
POST   /api/notifications   - Create notification (Admin)
```

#### Backup
```
GET    /api/backup          - Create manual backup (Admin)
GET    /api/backups         - Get backup history (Admin)
```

#### Dashboard Statistics
```
GET    /api/dashboard/stats - Get dashboard statistics
Response: { users, formCEntries, bankBalance, riceStock, etc. }
```

---

## 🌐 **Deployment (cPanel)**

### Method 1: cPanel File Manager

1. **Upload Files**
   - Login to cPanel
   - File Manager → public_html
   - Upload `rhs_mdm_v2.zip`
   - Extract

2. **Setup Node.js App**
   - cPanel → Setup Node.js App
   - Create Application:
     - Node.js Version: 14+
     - Application Root: `/home/username/public_html/mdm_system_v2`
     - Application URL: Your domain
     - Startup File: `server.js`

3. **Environment Variables**
   - Add all variables from `.env.example`
   - `MONGODB_URI`, `JWT_SECRET`, etc.

4. **Install Dependencies**
   - Click "Run NPM Install"
   - Wait for completion

5. **Start Application**
   - Click "Start App"
   - Status should show "Running"

### Method 2: SSH (Advanced)

```bash
# Upload files
scp -r mdm_system_v2 username@yourdomain.com:~/public_html/

# SSH into server
ssh username@yourdomain.com

# Navigate to folder
cd ~/public_html/mdm_system_v2

# Install dependencies
npm install --production

# Create .env file
nano .env
# Paste your configuration

# Start with PM2
pm2 start server.js --name rhs-mdm-v2
pm2 save
pm2 startup
```

### Testing Deployment

1. **Health Check**
```
https://yourdomain.com/api/health
```

2. **Login Page**
```
https://yourdomain.com/login.html
```

3. **Dashboard**
```
https://yourdomain.com/dashboard.html
```

---

## 🔧 **Troubleshooting**

### Issue: "MongoDB connection failed"
**Solution:**
- Verify connection string in `.env`
- Check MongoDB cluster is running
- Confirm IP whitelist (0.0.0.0/0)
- Test credentials

### Issue: "Invalid token / Authentication failed"
**Solution:**
- Clear browser cookies/localStorage
- Check JWT_SECRET is set
- Verify token expiry (7 days)
- Re-login

### Issue: "Email notifications not working"
**Solution:**
- Check EMAIL_USER and EMAIL_PASSWORD
- Use App Password for Gmail
- Verify email service is correct
- Check spam folder

### Issue: "Application won't start"
**Solution:**
- Run `npm test` to check setup
- Verify all dependencies installed
- Check PORT is not in use
- Review error logs

### Issue: "Can't create/edit/delete records"
**Solution:**
- Check user role and permissions
- Verify authentication token
- Check network connection
- Review activity logs

---

## 🛡️ **Security Best Practices**

### 1. **Password Security**
- ✅ Change default admin password immediately
- ✅ Use strong passwords (12+ characters)
- ✅ Enable password recovery email
- ✅ Regular password updates

### 2. **Environment Security**
- ✅ Never commit `.env` file to Git
- ✅ Use strong JWT_SECRET
- ✅ Rotate secrets regularly
- ✅ Limit .env file permissions

### 3. **Server Security**
- ✅ Enable HTTPS/SSL
- ✅ Keep Node.js updated
- ✅ Regular security audits
- ✅ Monitor access logs

### 4. **Database Security**
- ✅ Use specific IP whitelist when possible
- ✅ Strong MongoDB passwords
- ✅ Enable encryption at rest
- ✅ Regular backups

### 5. **Application Security**
- ✅ Input validation enabled
- ✅ Rate limiting active
- ✅ Helmet security headers
- ✅ CORS properly configured

---

## 📞 **Support & Contact**

- **School:** Ramnagar High School
- **Email:** support@ramnagarhs.edu
- **Documentation:** README.md
- **Issues:** Create issue in repository

---

## 📜 **License**

Copyright © 2024 Ramnagar High School  
All rights reserved.

---

## 🎉 **Version History**

### Version 2.0.0 (December 2024)
- ✅ Complete authentication system
- ✅ Role-based access control
- ✅ Activity logging and audit trail
- ✅ Automated daily backups
- ✅ Email notifications
- ✅ Enhanced security (Helmet, Rate limiting)
- ✅ Professional dashboard with charts
- ✅ User management interface
- ✅ Activity logs viewer
- ✅ Password recovery system

### Version 1.0.0 (November 2024)
- ✅ Basic CRUD operations
- ✅ MongoDB cloud integration
- ✅ Form C, Bank, Rice, Expense ledgers
- ✅ Real-time sync
- ✅ Excel reports

---

**Last Updated:** December 2024  
**Current Version:** 2.0.0  
**Status:** ✅ Production Ready

---

## 🚀 **Quick Start Checklist**

- [ ] Node.js installed (v14+)
- [ ] MongoDB Atlas cluster created
- [ ] Database user created
- [ ] IP whitelist configured
- [ ] Files extracted
- [ ] Dependencies installed (`npm install`)
- [ ] `.env` file configured
- [ ] JWT secret generated
- [ ] Email configured (optional)
- [ ] Server started (`npm start`)
- [ ] Health check passed
- [ ] Admin password changed
- [ ] First user created
- [ ] Backups scheduled
- [ ] SSL enabled (production)

**Congratulations! Your RHS MDM System V2.0 is ready! 🎉**
