// PM2 Ecosystem Configuration
// Use this for production deployment with PM2
// 
// Installation:
// npm install -g pm2
//
// Usage:
// pm2 start ecosystem.config.js
// pm2 save
// pm2 startup

module.exports = {
  apps: [{
    name: 'rhs-mdm-system',
    script: './server.js',
    
    // Instances
    instances: 1,
    exec_mode: 'fork',
    
    // Environment
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    },
    
    // Logs
    error_file: './logs/error.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    merge_logs: true,
    
    // Auto restart
    watch: false,
    max_memory_restart: '500M',
    
    // Restart settings
    autorestart: true,
    max_restarts: 10,
    min_uptime: '10s',
    
    // Advanced features
    kill_timeout: 5000,
    wait_ready: true,
    listen_timeout: 10000
  }]
};
