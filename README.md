# SQL-Log-Analysis-Threat-Detection

## Objective
The goal of this project is to demonstrate proactive threat hunting and log analysis capabilities using SQL. By simulating an enterprise environment, I correlated disjointed user and event tables to detect anomalous authentication behaviors, specifically focusing on brute-force attacks and password spraying.

## Scenario
In a typical managed services or Security Operations Center (SOC) environment, analysts are tasked with triaging massive amounts of authentication logs. This project involves creating a mock database of employee directories and authentication logs, and engineering SQL queries to automatically flag malicious external IP addresses targeting internal accounts.

## Database Structure
The project utilizes a SQLite relational database with two primary tables connected via a One-to-Many relationship using the `user_id` as the foreign key.



* **`users` table**: Contains employee directory information (`user_id`, `username`, `department`).
* **`auth_logs` table**: Contains the authentication events (`log_id`, `user_id`, `event_time`, `ip_address`, `action`).

## Threat Detection Queries & Analysis

### 1. Detecting Brute-Force Attacks
A brute-force attack typically originates from a single IP address attempting to guess the password of a single account multiple times. This query joins the user and log tables to identify accounts with more than 3 failed attempts from the same IP.

```sql
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

```

* **Result:** Successfully detected the `alice_admin` account (IT Department) being targeted by external IP `203.0.113.45` with 5 failed attempts in under a minute.

### 2. Detecting Password Spraying

Password spraying is a stealthier attack where a single IP address attempts to log into multiple *different* accounts using a few common passwords to avoid triggering standard account lockouts. This query pivots to group by the IP address and counts the distinct user accounts targeted.

```sql
SELECT 
    a.ip_address, 
    COUNT(DISTINCT a.user_id) as targeted_accounts,
    COUNT(a.action) as total_failed_attempts
FROM auth_logs a
WHERE a.action = 'Failed'
GROUP BY a.ip_address
HAVING targeted_accounts > 1;

```

* **Result:** Successfully identified malicious IP `198.51.100.22` attempting to compromise 3 distinct user accounts across the Sales, HR, and Finance departments.
