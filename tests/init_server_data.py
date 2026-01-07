import json
import os
import random
import string
from .client import register


def init_server_data():
    print("Initializing server data...")
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    users_file_path = os.path.join(script_dir, 'users.json')
    
    # Load users.json file
    with open(users_file_path, 'r') as f:
        users_data = json.load(f)
    
    # Dictionary to store results: username -> (password, otp_uri, password_type)
    result = {}
    
    # Register each user from users.json
    for user in users_data['users']:
        username = user['username']
        password = user['password']
        secret = user.get('secret', None)  # Get secret, will be None if not present or null
        password_type = user['password_type']  # Get password_type, will be None if not present
        
        response, status_code = register(username, password, totp_secret=secret)
        
        # Print result
        if status_code == 200:
            otp_uri = response.get('totp_uri', None)
            result[username] = (password, otp_uri, password_type)
        else:
            print(f"Failed to register user: {username} - {response.get('error', 'Unknown error')}")
    
    return result


def add_random_users(users_data_dict, num_random_password_users=0, num_random_rockyou_passwords=0):
    """
    Add random users to the existing users_data dictionary.
    
    Args:
        users_data_dict: Dictionary from init_server_data: username -> (password, otp_uri, password_type)
        num_random_password_users: Number of users to create with random 10-character alphanumeric passwords
        num_random_rockyou_passwords: Number of users to create with passwords randomly selected from rockyou.txt
    
    Returns:
        Updated dictionary with random users added
    """
    result = users_data_dict.copy()
    
    # Generate random users with random passwords (12 character alphanumeric)
    for _ in range(num_random_password_users):
        # Generate random username (lowercase letters only, length 8-12)
        username_length = random.randint(8, 12)
        username = ''.join(random.choice(string.ascii_lowercase) for _ in range(username_length))
        
        # Generate random password (10 character alphanumeric)
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        
        response, status_code = register(username, password, totp_secret=None)
        
        if status_code == 200:
            otp_uri = response.get('totp_uri', None)
            result[username] = (password, otp_uri, 'hard')  # Random password users are medium
        else:
            print(f"Failed to register random user: {username} - {response.get('error', 'Unknown error')}")
    
    # Generate random users with passwords from rockyou.txt
    if num_random_rockyou_passwords > 0:
        # Read rockyou.txt
        script_dir = os.path.dirname(os.path.abspath(__file__))
        rockyou_file_path = os.path.join(script_dir, 'rockyou.txt')
        
        rockyou_passwords = []
        with open(rockyou_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if password:  # Skip empty lines
                    rockyou_passwords.append(password)
        
        # Randomly select passwords from rockyou.txt
        selected_passwords = random.sample(rockyou_passwords, min(num_random_rockyou_passwords, len(rockyou_passwords)))
        
        for password in selected_passwords:
            # Generate random username (lowercase letters only, length 8-12)
            username_length = random.randint(8, 12)
            username = ''.join(random.choice(string.ascii_lowercase) for _ in range(username_length))
            
            response, status_code = register(username, password, totp_secret=None)
            
            if status_code == 200:
                otp_uri = response.get('totp_uri', None)
                result[username] = (password, otp_uri, 'easy')  # Rockyou password users are easy
            else:
                print(f"Failed to register random rockyou user: {username} - {response.get('error', 'Unknown error')}")
    
    return result


if __name__ == '__main__':
    init_server_data()

