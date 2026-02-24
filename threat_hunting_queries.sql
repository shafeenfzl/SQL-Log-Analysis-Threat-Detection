/* =============================================================================
PROJECT: Enterprise Log Analysis & Threat Detection
DESCRIPTION: Simulating enterprise authentication logs and using SQL to 
             proactively hunt for brute-force attacks and password spraying.
=============================================================================
*/

-- ==========================================
-- STEP 1: SCHEMA SETUP
-- ==========================================

-- Create the Users Table (Employee Directory)
CREATE TABLE users (
    user_id INTEGER PRIMARY KEY,
    username TEXT,
    department TEXT
);

-- Create the Authentication Logs Table (Event Log)
CREATE TABLE auth_logs (
    log_id INTEGER PRIMARY KEY,
    user_id INTEGER,
    event_time DATETIME,
    ip_address TEXT,
    action TEXT,
    FOREIGN KEY(user_id) REFERENCES users(user_id)
);

-- ==========================================
-- STEP 2: DATA SIMULATION
-- ==========================================

-- Insert simulated Employees
INSERT INTO users (user_id, username, department) VALUES
(1, 'alice_admin', 'IT'),
(2, 'bob_sales', 'Sales'),
(3, 'carol_hr', 'HR'),
(4, 'dave_finance', 'Finance');

-- Insert simulated Authentication Logs (Normal Activity + Anomalies)
INSERT INTO auth_logs (user_id, event_time, ip_address, action) VALUES
-- Normal morning logins
(1, '2026-02-24 08:00:00', '192.168.1.50', 'Success'),
(2, '2026-02-24 08:15:00', '192.168.1.51', 'Success'),
(3, '2026-02-24 08:30:00', '192.168.1.52', 'Success'),

-- ANOMALY 1: Brute Force Attempt (Admin account, external IP)
(1, '2026-02-24 09:01:00', '203.0.113.45', 'Failed'),
(1, '2026-02-24 09:01:05', '203.0.113.45', 'Failed'),
(1, '2026-02-24 09:01:12', '203.0.113.45', 'Failed'),
(1, '2026-02-24 09:01:18', '203.0.113.45', 'Failed'),
(1, '2026-02-24 09:01:25', '203.0.113.45', 'Failed'),

-- ANOMALY 2: Password Spraying (External IP hitting multiple accounts)
(2, '2026-02-24 10:00:00', '198.51.100.22', 'Failed'),
(3, '2026-02-24 10:00:05', '198.51.100.22', 'Failed'),
(4, '2026-02-24 10:00:10', '198.51.100.22', 'Failed');

-- ==========================================
-- STEP 3: THREAT HUNTING QUERIES
-- ==========================================

-- Query 1: Detect Brute Force Attacks
-- Identifies users experiencing >3 failed logins from a single IP
SELECT 
    u.username, 
    u.department, 
    a.ip_address, 
    COUNT(a.action) as failed_attempts
FROM users u
JOIN auth_logs a ON u.user_id = a.user_id
WHERE a.action = 'Failed'
GROUP BY u.username, u.department, a.ip_address
HAVING failed_attempts > 3;

-- Query 2: Detect Password Spraying
-- Identifies a single IP targeting multiple distinct user accounts
SELECT 
    a.ip_address, 
    COUNT(DISTINCT a.user_id) as targeted_accounts,
    COUNT(a.action) as total_failed_attempts
FROM auth_logs a
WHERE a.action = 'Failed'
GROUP BY a.ip_address
HAVING targeted_accounts > 1;
