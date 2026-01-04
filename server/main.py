from flask import Flask, jsonify, request, redirect
import json
import os
import sqlite3
import atexit
from enum import Enum
from datetime import datetime
from password_handlers import PASSWORD_HANDLERS
from security_hooks import run_pre_login_hooks, run_post_login_hooks, init_security_hooks
from captcha_hook import get_captcha_token
import pyotp

app = Flask(__name__)

# Dictionary to track password verification state: {username: True}
PASSWORD_VERIFIED = {}

class UserCreationResult(Enum):
    USER_ALREADY_DEFINED = "USER_ALREADY_DEFINED"
    USER_CREATED = "USER_CREATED"

def close_db(conn, db_path):
    conn.close()
    if os.path.exists(db_path):
        os.remove(db_path)

def close_log_file():
    if 'LOG_FILE' in app.config:
        app.config['LOG_FILE'].close()

def log_login_attempt(username, success):
    """Log login attempt to attempts.log file in JSON format"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    group_seed = app.config['CONFIG']['GROUP_SEED']
    hashmode = app.config['CONFIG']['PASSWORD_HASH_TYPE']
    
    log_entry = {
        'timestamp': timestamp,
        'group_seed': group_seed,
        'username': username,
        'login_result': success,
        'hashmode': hashmode
    }
    
    # Write to the open log file as JSON (one line per entry)
    log_file = app.config.get('LOG_FILE')
    if log_file:
        log_file.write(json.dumps(log_entry) + '\n')
        log_file.flush()  # Ensure data is written immediately


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
        enabled_features = app.config['CONFIG'].get('ENABLED_SECURITY_FEATURES', [])
        if 'totp' in enabled_features:
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

def init_server_data():
    """Load users.json file, create SQLite database and save users data"""
    # Load config.json file
    config_file_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if not os.path.exists(config_file_path):
        raise RuntimeError(f"Config file not found: {config_file_path}")
    
    with open(config_file_path, 'r') as f:
        config_data = json.load(f)
    
    # Store config in app.config
    app.config['CONFIG'] = config_data
    
    # Initialize security hooks
    init_security_hooks(config_data)
    
    # Load users.json file
    users_file_path = os.path.join(os.path.dirname(__file__), 'users.json')
    with open(users_file_path, 'r') as f:
        users_data = json.load(f)
    
    # Create SQLite database and keep connection open
    db_path = os.path.join(os.path.dirname(__file__), 'users.db')
    conn = sqlite3.connect(db_path, check_same_thread=False)
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
    app.config['DB_PATH'] = db_path
    
    # Open attempts.log file and keep it open
    log_file_path = os.path.join(os.path.dirname(__file__), 'attempts.log')
    log_file = open(log_file_path, 'a')
    app.config['LOG_FILE'] = log_file
    
    # Register cleanup function to close log file on exit
    atexit.register(close_log_file)
    
    # Insert users data into database using create_new_user
    for user in users_data['users']:
        username = user['username']
        password = str(app.config['CONFIG']['GROUP_SEED']) if username == 'guy' else user['password']
        # Load secret from users.json
        user_secret = user['secret']
        result, _ = create_new_user(username, password, secret=user_secret)
        # Note: USER_ALREADY_DEFINED is expected for existing users during initialization
    
    # Set cleanup function to close connection and delete db file on exit
    atexit.register(lambda: close_db(conn, db_path))

@app.route('/get_users', methods=['GET'])
def get_users():
    """Endpoint that returns the users as JSON from database"""
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
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    result, totp_uri = create_new_user(username, password)
    
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
    
    # Get handler tuple from dictionary
    if password_hash_type not in PASSWORD_HANDLERS:
        raise RuntimeError(f'Unknown password hash type: {password_hash_type}')
    
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
    
    # Verify the TOTP code
    try:
        totp = pyotp.TOTP(otp_secret)
        is_valid = totp.verify(code)
        
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

def main():
    init_server_data()
    app.run(host='0.0.0.0', port=8000)
    
if __name__ == '__main__':
    main()

