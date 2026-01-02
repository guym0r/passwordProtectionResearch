from flask import Flask, jsonify
import json
import os
import sqlite3
import atexit

app = Flask(__name__)

# Global variable to store config data
config = None

def close_db(conn, db_path):
    conn.close()
    if os.path.exists(db_path):
        os.remove(db_path)

def init_server_data():
    """Load users.json file, create SQLite database and save users data"""
    global config
    
    # Load config.json file
    config_file_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if not os.path.exists(config_file_path):
        raise RuntimeError(f"Config file not found: {config_file_path}")
    
    with open(config_file_path, 'r') as f:
        config = json.load(f)
    
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
    
    # Insert users data into database
    for user in users_data['users']:
        username = user['username']
        password = str(config['GROUP_SEED']) if username == 'guy' else user['password']
        cursor.execute('''
            INSERT OR REPLACE INTO users (username, password)
            VALUES (?, ?)
        ''', (username, password))
    
    conn.commit()
    
    # Store database connection and path in app config (keep it open for server lifetime)
    app.config['DB_CONN'] = conn
    app.config['DB_PATH'] = db_path
    
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

def main():
    init_server_data()
    app.run(host='0.0.0.0', port=8000)
    
if __name__ == '__main__':
    main()

