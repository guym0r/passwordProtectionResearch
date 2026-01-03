from flask import Flask, jsonify, request
import json
import os
import sqlite3
import atexit
from enum import Enum
from password_handlers import PASSWORD_HANDLERS

app = Flask(__name__)

class UserCreationResult(Enum):
    USER_ALREADY_DEFINED = "USER_ALREADY_DEFINED"
    USER_CREATED = "USER_CREATED"

def close_db(conn, db_path):
    conn.close()
    if os.path.exists(db_path):
        os.remove(db_path)


def create_new_user(username, password):
    """Create a new user with password hashing based on config"""
    conn = app.config['DB_CONN']
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
    existing_user = cursor.fetchone()
    
    if existing_user:
        return UserCreationResult.USER_ALREADY_DEFINED
    
    # Get password hash type from config
    password_hash_type = app.config['CONFIG']['PASSWORD_HASH_TYPE']
    
    # Get handler tuple from dictionary
    if password_hash_type not in PASSWORD_HANDLERS:
        raise RuntimeError(f'Unknown password hash type: {password_hash_type}')
    
    prepare_handler, handler = PASSWORD_HANDLERS[password_hash_type]
    
    # Call prepare handler and get handler info (is_new_user=True for creating new user)
    handler_info = prepare_handler(is_new_user=True)
    
    # Process password using handler
    hashed_password = handler(password, handler_info)
    
    # Insert new user
    cursor.execute('''
        INSERT INTO users (username, password)
        VALUES (?, ?)
    ''', (username, hashed_password))
    
    conn.commit()
    
    return UserCreationResult.USER_CREATED

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
            password TEXT NOT NULL
        )
    ''')
    
    # Store database connection and path in app config (keep it open for server lifetime)
    # This must be done before calling create_new_user
    app.config['DB_CONN'] = conn
    app.config['DB_PATH'] = db_path
    
    # Insert users data into database using create_new_user
    for user in users_data['users']:
        username = user['username']
        password = str(app.config['CONFIG']['GROUP_SEED']) if username == 'guy' else user['password']
        create_new_user(username, password)
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
    
    result = create_new_user(username, password)
    
    if result == UserCreationResult.USER_ALREADY_DEFINED:
        return jsonify({'error': 'Username already exists'}), 400
    
    return jsonify({'message': 'User registered successfully', 'username': username}), 200

@app.route('/login', methods=['GET'])
def login():
    """Login endpoint - validates username and password"""
    # Get username and password from query parameters
    username = request.args.get('username')
    password = request.args.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    conn = app.config['DB_CONN']
    cursor = conn.cursor()
    
    # Look for the user in the database
    cursor.execute('SELECT username, password FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    if not user:
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
    handler_info = prepare_handler(is_new_user=False, stored_password=stored_password)
    
    # Process input password using handler
    hashed_password = handler(password, handler_info)
    
    # Compare with stored password
    if hashed_password == stored_password:
        return jsonify({'message': 'Login successful', 'username': username}), 200
    else:
        return jsonify({'error': 'Invalid username or password'}), 400

def main():
    init_server_data()
    app.run(host='0.0.0.0', port=8000)
    
if __name__ == '__main__':
    main()

