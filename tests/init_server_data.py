import json
import os
from client import register


def init_server_data():
    print("Initializing server data...")
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    users_file_path = os.path.join(script_dir, 'users.json')
    
    # Load users.json file
    with open(users_file_path, 'r') as f:
        users_data = json.load(f)
    
    # Dictionary to store results: username -> (password, otp_uri)
    result = {}
    
    # Register each user
    for user in users_data['users']:
        username = user['username']
        password = user['password']
        secret = user.get('secret', None)  # Get secret, will be None if not present or null
        
        response, status_code = register(username, password, totp_secret=secret)
        
        # Print result
        if status_code == 200:
            print(f"Registered user: {username}")
            otp_uri = response.get('totp_uri', None)
            if otp_uri:
                print(f"  TOTP URI: {otp_uri}")
            # Store in result dictionary
            result[username] = (password, otp_uri)
        else:
            print(f"Failed to register user: {username} - {response.get('error', 'Unknown error')}")
    
    return result


if __name__ == '__main__':
    init_server_data()

