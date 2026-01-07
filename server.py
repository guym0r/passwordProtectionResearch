from flask import Flask, jsonify, request, redirect
import json
import os
import sqlite3
import atexit
import argparse
import logging
from enum import Enum
from datetime import datetime
from server_utils.password_handlers import PASSWORD_HANDLERS
from server_utils.security_hooks import run_pre_login_hooks, run_post_login_hooks, init_security_hooks, enabled_security_hooks
from server_utils.captcha_hook import get_captcha_token
from server_utils.account_lockout_hook import reset_account_lockout

import pyotp

# Constants for database path
DB_FILE = "users.db"

app = Flask(__name__)

# Dictionary to track password verification state: {username: True}
PASSWORD_VERIFIED = {}

class UserCreationResult(Enum):
    USER_ALREADY_DEFINED = "USER_ALREADY_DEFINED"
    USER_CREATED = "USER_CREATED"

def cleanup_server():
    """Cleanup function to close database connection, log file, and remove database file"""
    # Close log file
    if 'LOG_FILE' in app.config and app.config['LOG_FILE']:
        app.config['LOG_FILE'].close()
    
    # Close database connection and remove database file
    if 'DB_CONN' in app.config:
        conn = app.config['DB_CONN']
        conn.close()
    
    if 'DB_PATH' in app.config:
        db_path = app.config['DB_PATH']
        if os.path.exists(db_path):
            os.remove(db_path)

def log_login_attempt(username, success):
    """Log login attempt to attempts.log file in JSON format"""
    # Check if logging is enabled
    logging_config = app.config['CONFIG']['LOGGING']
    if not logging_config['ENABLED']:
        return
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    group_seed = app.config['CONFIG']['GROUP_SEED']
    hashmode = app.config['CONFIG']['PASSWORD_HASH_TYPE']
    
    # Get list of enabled security hooks
    security_hooks_list = list(enabled_security_hooks.keys())
    
    log_entry = {
        'timestamp': timestamp,
        'group_seed': group_seed,
        'username': username,
        'login_result': success,
        'hashmode': hashmode,
        'security_features': security_hooks_list
    }
    
    app.config['LOG_FILE'].write(json.dumps(log_entry) + '\n')
    app.config['LOG_FILE'].flush()


def create_new_user(username, password, secret=None):
    """Create a new user with password hashing based on config"""
    conn = app.config['DB_CONN']
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        return UserCreationResult.USER_ALREADY_DEFINED, None
    
    # Get password hash type from config
    password_hash_type = app.config['CONFIG']['PASSWORD_HASH_TYPE']
    
    # Get handler tuple from dictionary
    if password_hash_type not in PASSWORD_HANDLERS:
        raise RuntimeError(f'Unknown password hash type: {password_hash_type}')
    
    prepare_handler, handler = PASSWORD_HANDLERS[password_hash_type]
    
    # Call prepare handler and get handler info (is_new_user=True for creating new user)
    handler_info = prepare_handler(True, app.config['CONFIG'])
    
    # Process password using handler
    hashed_password = handler(password, handler_info)
    
    # Only store secret if explicitly provided (no auto-generation)
    otp_secret = secret
    totp_uri = None
    
    # Generate TOTP URI only if secret is provided and TOTP is enabled
    if secret is not None:
        totp = pyotp.TOTP(secret)
        totp_config = app.config['CONFIG']['TOTP']
        issuer = totp_config['ISSUER']
        totp_uri = totp.provisioning_uri(username, issuer_name=issuer)

    # Insert new user
    cursor.execute('''
        INSERT INTO users (username, password, otp_secret)
        VALUES (?, ?, ?)
    ''', (username, hashed_password, otp_secret))
    
    conn.commit()
    
    return UserCreationResult.USER_CREATED, totp_uri

def init_server_data(config_file_path):
    """Initialize server: load config, initialize security hooks, create database and log file"""
    if not os.path.exists(config_file_path):
        raise RuntimeError(f"Config file not found: {config_file_path}")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)
    
    # Store config in app.config
    app.config['CONFIG'] = config_data
    
    # Initialize security hooks
    init_security_hooks(config_data)
    
    # Create SQLite database and keep connection open
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # This allows column access by name
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            otp_secret TEXT
        )
    ''')
    
    # Store database connection and path in app config (keep it open for server lifetime)
    # This must be done before calling create_new_user
    app.config['DB_CONN'] = conn
    app.config['DB_PATH'] = DB_FILE
    
    # Get log file name from config, only open if logging is enabled
    logging_config = config_data['LOGGING']
    if logging_config['ENABLED']:
        log_file_name = logging_config['FILE_NAME']
        log_file = open(log_file_name, 'a')
        app.config['LOG_FILE'] = log_file
    else:
        app.config['LOG_FILE'] = None

@app.route('/get_users', methods=['GET'])
def get_users():
    """Endpoint that returns the users as JSON from database, meant for debugging purposes"""
    conn = app.config['DB_CONN']
    cursor = conn.cursor()
    
    cursor.execute('SELECT username, password FROM users')
    rows = cursor.fetchall()
    
    # Convert rows to list of dictionaries
    users = [{'username': row['username'], 'password': row['password']} for row in rows]
    
    return jsonify({'users': users})

@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    # Get username and password from request
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    
    username = data.get('username')
    password = data.get('password')
    totp_secret = data.get('totp_secret')  # Optional TOTP secret
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Pass totp_secret only if provided
    result, totp_uri = create_new_user(username, password, secret=totp_secret)

    if result == UserCreationResult.USER_ALREADY_DEFINED:
        return jsonify({'error': 'Username already exists'}), 400
    
    response = {
        'message': 'User registered successfully',
        'username': username
    }
    
    # Add TOTP URI to response if TOTP is enabled
    if totp_uri:
        response['totp_uri'] = totp_uri
    
    return jsonify(response), 200

@app.route('/login', methods=['GET'])
def login():
    """Login endpoint - validates username and password"""
    # Get username and password from query parameters
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Get all request parameters (for hooks that need them, like captcha)
    request_params = dict(request.args)
    
    # Run pre-login security hooks
    allowed, error_msg = run_pre_login_hooks(username, password, app.config['CONFIG'], request_params)
    if not allowed:
        log_login_attempt(username, False)
        if error_msg:
            try:
                # Parse error_msg as JSON and return it
                error_json = json.loads(error_msg)
                return jsonify(error_json), 403
            except (json.JSONDecodeError, TypeError):
                # If not JSON, wrap in error format
                return jsonify({'error': error_msg}), 403
        else:
            return jsonify({'error': 'Login denied by security check'}), 403
    
    conn = app.config['DB_CONN']
    cursor = conn.cursor()
    
    # Look for the user in the database (including otp_secret)
    cursor.execute('SELECT username, password, otp_secret FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user:
        # Log failed login attempt (user not found)
        log_login_attempt(username, False)
        return jsonify({'error': 'Invalid username or password'}), 400
    
    # Get password hash type from config
    password_hash_type = app.config['CONFIG']['PASSWORD_HASH_TYPE']
    
    prepare_handler, handler = PASSWORD_HANDLERS[password_hash_type]
    
    # Get stored password
    stored_password = user['password']
    
    # Call prepare handler and get handler info (is_new_user=False for login)
    handler_info = prepare_handler(False, app.config['CONFIG'], stored_password=stored_password)
    
    # Process input password using handler
    hashed_password = handler(password, handler_info)
    
    # Compare with stored password
    success = hashed_password == stored_password
    
    # Run post-login security hooks
    allowed, error_msg = run_post_login_hooks(username, password, success, app.config['CONFIG'], request_params)
    if not allowed:
        log_login_attempt(username, False)
        if error_msg:
            try:
                # Parse error_msg as JSON and return it
                error_json = json.loads(error_msg)
                return jsonify(error_json), 403
            except (json.JSONDecodeError, TypeError):
                # If not JSON, wrap in error format
                return jsonify({'error': error_msg}), 403
        else:
            return jsonify({'error': 'Login denied by security check'}), 403
    
    # Log login attempt
    log_login_attempt(username, success)
    
    if success:
        # Check if user has TOTP configured
        otp_secret = user['otp_secret']
        if otp_secret:
            # User has TOTP configured - set password verified state and redirect to TOTP verification
            PASSWORD_VERIFIED[username] = True
            return redirect(f'/login_totp?username={username}', code=302)
        else:
            # No TOTP configured - login complete
            return jsonify({'message': 'Login successful', 'username': username}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 400

@app.route('/login_totp', methods=['GET'])
def login_totp():
    """TOTP login endpoint - verifies TOTP code"""
    # Get username and code from query parameters
    username = request.args.get('username')
    code = request.args.get('code')
    
    if not username or not code:
        return jsonify({'error': 'Username and code are required'}), 400
    
    # Check if password was verified first
    if not PASSWORD_VERIFIED.get(username):
        return jsonify({'error': 'Password verification required first. Please login with password.'}), 403
    # Clear password verified state on first attempt (single-use)
    PASSWORD_VERIFIED.pop(username, None)
    
    # Validate code is 6 digits
    if not code.isdigit() or len(code) != 6:
        return jsonify({'error': 'Code must be exactly 6 digits'}), 400
    
    conn = app.config['DB_CONN']
    cursor = conn.cursor()
    
    # Look for the user in the database and get their OTP secret
    cursor.execute('SELECT username, otp_secret FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    otp_secret = user['otp_secret']
    
    if not otp_secret:
        return jsonify({'error': 'User does not have TOTP configured'}), 400
    
    # Verify the TOTP code with time drift tolerance
    try:
        totp = pyotp.TOTP(otp_secret)
        # Get time window from config (default to 1, meaning ±1 time step tolerance)
        totp_config = app.config['CONFIG']['TOTP']
        time_window = totp_config['TIME_WINDOW']
        # Verify with time window tolerance (checks current time ± window time steps)
        is_valid = totp.verify(code, valid_window=time_window)
        
        if is_valid:
            return jsonify({'message': 'TOTP verification successful', 'username': username}), 200
        else:
            return jsonify({'error': 'Invalid TOTP code'}), 400
    except Exception as e:
        return jsonify({'error': f'TOTP verification failed: {str(e)}'}), 400

@app.route('/admin/get_captcha_token', methods=['GET'])
def admin_get_captcha_token():
    """Admin endpoint to get captcha token for a username"""
    # Get group_seed and username from query parameters
    group_seed = request.args.get('group_seed')
    username = request.args.get('username')
    
    if not group_seed or not username:
        return jsonify({'error': 'group_seed and username are required'}), 400
    
    # Verify group_seed matches config
    if group_seed != app.config['CONFIG']['GROUP_SEED']:
        return jsonify({'error': 'Invalid group_seed'}), 403
    
    # Get captcha token for the username
    captcha_token = get_captcha_token(username)
    
    if captcha_token is None:
        return jsonify({'error': 'No captcha token found for this username'}), 404
    
    return jsonify({'username': username, 'captcha_token': captcha_token}), 200

@app.route('/admin/unlock_user', methods=['GET'])
def admin_unlock_user():
    """Admin endpoint to unlock a user account"""
    # Get group_seed and username from query parameters
    group_seed = request.args.get('group_seed')
    username = request.args.get('username')
    
    if not group_seed or not username:
        return jsonify({'error': 'group_seed and username are required'}), 400
    
    # Verify group_seed matches config
    if group_seed != app.config['CONFIG']['GROUP_SEED']:
        return jsonify({'error': 'Invalid group_seed'}), 403
    
    # Reset account lockout for the user
    reset_account_lockout(username)
    
    return jsonify({'message': 'User account unlocked successfully', 'username': username}), 200


def start_server(config_file_path='server_config.json'):
    # Disable Flask/Werkzeug request logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    
    init_server_data(config_file_path)
    app.run(host='0.0.0.0', port=8000)
    
if __name__ == '__main__':
    # Register cleanup function when running directly
    atexit.register(cleanup_server)
    start_server()

