from flask import Flask, jsonify
import json
import os

app = Flask(__name__)

def init_server_data():
    """Load users.json file"""
    users_file_path = os.path.join(os.path.dirname(__file__), 'users.json')
    with open(users_file_path, 'r') as f:
        users_data = json.load(f)
    app.config['USERS_DATA'] = users_data

@app.route('/get_users', methods=['GET'])
def get_users():
    """Endpoint that returns the users as JSON"""
    return jsonify(app.config['USERS_DATA'])

def main():
    init_server_data()
    app.run(host='0.0.0.0', port=8000, debug=True)
    
if __name__ == '__main__':
    main()

