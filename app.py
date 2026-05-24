import sqlite3
import hashlib
import csv
import sys
from flask import Flask, render_template, request, redirect, url_for, session
from loguru import logger  # Modern enterprise logging engine

app = Flask(__name__)
app.secret_key = 'super_secret_cybersecurity_token'

# =====================================================================
# ENTERPRISE LOGGING CONFIGURATION (Structured JSON Logs)
# =====================================================================
# Remove the default terminal logger
logger.remove()

# 1. Keep a clean, colorful logger for the local developer console
logger.add(sys.stderr, format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{message}</cyan>")

# 2. Create a production-grade, structured JSON file for Security Ops / Tableau
logger.add(
    "app_security.json", 
    serialize=True,  # This forces the output to be structured JSON
    rotation="10 MB", # Automatically archives and splits files when they get big
    retention="90 days" # Retention compliance window
)

# =====================================================================
# SECURE DATABASE INITIALIZATION & CRYPTOGRAPHY
# =====================================================================

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def sync_database_to_csv():
    try:
        with sqlite3.connect('clinic.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM web_audit_logs ORDER BY log_id DESC")
            with open("security_logs.csv", "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Log Id", "Timestamp", "Username", "Role", "Status", "Message"])
                writer.writerows(cursor.fetchall())
    except Exception as e:
        logger.error(f"CSV Sync Failure: {e}")

def init_hardened_db():
    conn = sqlite3.connect('clinic.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_secure TEXT,
            assigned_role TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS web_audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
            username TEXT,
            role TEXT,
            status TEXT,
            message TEXT
        )
    ''')
    
    cursor.execute("SELECT COUNT(*) FROM system_users")
    if cursor.fetchone()[0] == 0:
        users_to_provision = [
            ('nush', hash_password('SkinCare2026!'), 'Esthetician'),
            ('alex', hash_password('FrontDeskPass123'), 'FrontDesk'),
            ('it_admin', hash_password('ZeroZeroTrust99!'), 'Admin')
        ]
        cursor.executemany('''
            INSERT INTO system_users (username, password_secure, assigned_role)
            VALUES (?, ?, ?)
        ''', users_to_provision)
        
    conn.commit()
    conn.close()
    sync_database_to_csv()

# =====================================================================
# FLASK WEB ROUTING & SECURITY GATEWAYS
# =====================================================================

@app.route('/')
def home():
    return redirect(url_for('login_page'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        input_password = request.form['password']
        
        conn = sqlite3.connect('clinic.db')
        cursor = conn.cursor()
        
        # Check for account lockouts
        cursor.execute("SELECT status FROM web_audit_logs WHERE username = ? ORDER BY log_id DESC LIMIT 3", (username,))
        recent_attempts = cursor.fetchall()
        
        if len(recent_attempts) >= 3 and all(attempt[0] == 'DENIED' for attempt in recent_attempts):
            conn.close()
            # SEVERITY: CRITICAL - Active Lockout Enforced
            logger.critical(f"AUTHENTICATION BLOCK: Login restricted for user '{username}' due to consecutive failures.")
            return render_template('login.html', error="🚨 ACCOUNT LOCKED: Multiple login failures. Contact IT Security Office.")

        cursor.execute("SELECT password_secure, assigned_role FROM system_users WHERE username = ?", (username,))
        user_record = cursor.fetchone()
        
        if not user_record:
            action_msg = f"MALICIOUS PROBE: Access attempted with invalid username."
            cursor.execute('INSERT INTO web_audit_logs (username, role, status, message) VALUES (?, "UNKNOWN", "DENIED", ?)', (username, action_msg))
            conn.commit()
            conn.close()
            sync_database_to_csv()
            
            # SEVERITY: WARNING - Potential brute force probing usernames
            logger.warning(f"SECURITY EVENT: Non-existent user probe target='{username}' from ip={request.remote_addr}")
            return render_template('login.html', error="✕ Access Denied: Credentials invalid.")
            
        hashed_input = hash_password(input_password)
        if hashed_input == user_record[0]:
            session['username'] = username
            session['role'] = user_record[1]
            conn.close()
            
            # SEVERITY: INFO - Standard successful operation
            logger.info(f"ACCESS GRANTED: User '{username}' successfully authenticated. Role: {user_record[1]}")
            return redirect(url_for('dashboard_page'))
        else:
            action_msg = f"FAILED AUTHENTICATION: Incorrect password submitted."
            cursor.execute('INSERT INTO web_audit_logs (username, role, status, message) VALUES (?, ?, "DENIED", ?)', (username, user_record[1], action_msg))
            conn.commit()
            conn.close()
            sync_database_to_csv()
            
            # SEVERITY: WARNING - Incorrect password attempt
            logger.warning(f"AUTH FAILURE: Invalid password credentials for user '{username}'")
            return render_template('login.html', error="✕ Access Denied: Credentials invalid.")
        
    return render_template('login.html', error=None)

@app.route('/dashboard')
def dashboard_page():
    if 'username' not in session:
        logger.error(f"UNAUTHORIZED ACCESS ATTEMPT: Anonymous user redirected from /dashboard.")
        return redirect(url_for('login_page'))
        
    username = session['username']
    role = session['role']
    
    conn = sqlite3.connect('clinic.db')
    cursor = conn.cursor()
    
    if role == 'Esthetician':
        status = "SUCCESS"
        action_msg = "Authorized clinical chart data view initialization."
        logger.info(f"DATA READ: User '{username}' accessed clinical medical charts.")
    elif role == 'Admin':
        status = "SUCCESS"
        action_msg = "Administrator cleared. Loading security core terminal telemetry."
        logger.info(f"SYSTEM AUDIT: Admin '{username}' loaded security console logs.")
    else:
        status = "DENIED"
        action_msg = f"DATA POLICY ENFORCED: Account '{username}' restricted from parsing clinical charts."
        # SEVERITY: WARNING - Privilege escalation or horizontal boundary probe
        logger.warning(f"PRIVILEGE VIOLATION: User '{username}' (Role: {role}) attempted to access restricted charts.")
        
    cursor.execute('INSERT INTO web_audit_logs (username, role, status, message) VALUES (?, ?, ?, ?)', (username, role, status, action_msg))
    conn.commit()
    
    cursor.execute('SELECT timestamp FROM web_audit_logs WHERE username = ? AND status = "SUCCESS" ORDER BY log_id DESC LIMIT 1 OFFSET 1', (username,))
    last_login_row = cursor.fetchone()
    last_login = last_login_row[0] if last_login_row else "Initial infrastructure session recorded."
    
    cursor.execute("SELECT * FROM web_audit_logs ORDER BY log_id DESC LIMIT 5")
    live_logs = cursor.fetchall()
    conn.close()
    
    sync_database_to_csv()
    return render_template('dashboard.html', username=username, role=role, logs=live_logs, last_login=last_login)

@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    logger.info(f"SESSION END: User '{username}' logged out securely.")
    session.clear()
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    init_hardened_db()
    logger.info("SYSTEM INITIALIZATION: Hardened clinic server online and monitoring routes.")
    app.run(debug=True, port=8000)