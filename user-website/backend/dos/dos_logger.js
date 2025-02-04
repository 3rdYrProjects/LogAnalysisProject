const fs = require('fs');
const path = require('path');
const MAX_REQUESTS = 100;
const TIME_WINDOW = 10 * 1000; // 10 seconds
const LOG_FILE_PATH = path.join(__dirname, '../../log-analysis-dashboard/logs/dos-logs.json');

// Store request timestamps per IP
const requestLog = {};

// Detect DoS attacks in real-time
const detectDoS = (ip) => {
    const now = Date.now();

    if (!requestLog[ip]) {
        requestLog[ip] = [];
    }

    requestLog[ip].push(now);
    requestLog[ip] = requestLog[ip].filter(timestamp => now - timestamp <= TIME_WINDOW);

    if (requestLog[ip].length > MAX_REQUESTS) {
        console.log(`⚠️ DoS attack detected from IP: ${ip}`);
        recordDoSLog(ip);
    }
};

// Record detected DoS attack to a log file
const recordDoSLog = (ip) => {
    const log = {
        ip,
        timestamp: new Date().toISOString(),
        message: 'Possible DoS attack detected'
    };

    fs.readFile(LOG_FILE_PATH, 'utf8', (err, data) => {
        let logs = [];
        if (!err) {
            logs = JSON.parse(data);
        }

        logs.push(log);

        fs.writeFile(LOG_FILE_PATH, JSON.stringify(logs, null, 2), (err) => {
            if (err) {
                console.error('Error writing DoS logs:', err);
            }
        });
    });
};

module.exports = { detectDoS };