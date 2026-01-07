import os
import time
import pyotp
import requests
from urllib.parse import urlparse, parse_qs
from .client import login, login_totp, admin_get_captcha_token

# GROUP_SEED from server_config.json (hardcoded for tests)
GROUP_SEED = "206360893"

def start_test(users_dict, max_attempts, progress_counter=0, captcha_sleep_time=2):
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rockyou_file_path = os.path.join(script_dir, 'rockyou.txt')
    
    # Read up to max_attempts passwords from rockyou.txt
    passwords = []
    with open(rockyou_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= max_attempts:
                break
            password = line.strip()
            if password:  # Skip empty lines
                passwords.append(password)
    
    results = {}
    locked_users = set()
    password_attempt_count = 0
    total_sleep_time = 0
    
    # Try each password against all users
    for password in passwords:
        # Check if all users are locked
        if len(locked_users) == len(users_dict):
            print("All users are locked, stopping password spraying test")
            return results, total_sleep_time
        
        # Try this password against each user
        if progress_counter > 0 and password_attempt_count % progress_counter == 0:
            print(f"current password index to spray: {password_attempt_count}")
        password_attempt_count += 1
        
        for username, otp_uri in users_dict.items():
            # Skip users we've already found passwords for
            if username in results:
                continue
            
            # Skip locked users
            if username in locked_users:
                continue
            # Try to login with this password
            try:
                response, status_code, redirect_url = login(username, password)
                
                # Check if rate limit is exceeded
                if status_code == 403 and 'retry_after' in response:
                    retry_after = response.get('retry_after', 0)
                    if retry_after > 0:
                        print(f"Rate limit exceeded, continuing to next attempt...")
                    continue
                
                # Check if account is locked
                if status_code == 403 and isinstance(response, dict):
                    error_msg = response.get('error', '')
                    if 'Account is locked' in error_msg:
                        print(f"Account {username} is locked, adding to locked users list")
                        locked_users.add(username)
                        # Skip this user - don't add to results (failed to find password)
                        continue
                
                # Check if captcha is required
                if status_code == 403 and response.get('captcha_required'):
                    print(f"Captcha required for user {username}, simulate captcha by sleep for {captcha_sleep_time} seconds...")
                    time.sleep(captcha_sleep_time)
                    
                    # Get captcha token and retry login
                    captcha_response, captcha_status = admin_get_captcha_token(GROUP_SEED, username)
                    if captcha_status == 200:
                        captcha_token = captcha_response.get('captcha_token')
                        if captcha_token:
                            # Retry login with captcha token
                            response, status_code, redirect_url = login(username, password, captcha_token=captcha_token)
                    else:
                        print(f"Failed to get captcha token, continuing to next attempt...")
                        # Failed to get captcha token, continue to next attempt
                        continue
            except Exception as e:
                # Occurs sometimes when the server needs to clean up after a previous requests
                print(f"Got connection error in attempt {password_attempt_count}, waiting a second and continuing...")
                time.sleep(1)
                total_sleep_time += 1
                continue
            
            # Check if login was successful
            # Status 200 = success (no TOTP)
            if status_code == 200:
                results[username] = password
                continue
            elif status_code == 302:
                # Check if redirect is to TOTP endpoint
                if redirect_url and '/login_totp' in redirect_url:
                    # Password is correct, but TOTP is required
                    if otp_uri is None:
                        results[username] = password
                        continue
                    
                    # Extract secret from otp_uri
                    parsed = urlparse(otp_uri)
                    query_params = parse_qs(parsed.query)
                    otp_secret = query_params.get('secret', [None])[0]
                    
                    # Generate TOTP code from secret
                    totp = pyotp.TOTP(otp_secret)
                    code = totp.now()
                    
                    # Try to verify TOTP
                    totp_response, totp_status = login_totp(username, code)
                    results[username] = password
                    
                    if totp_status != 200:
                        print(f"Password found for {username} after {password_attempt_count} attempts, but TOTP verification failed, password: {password}")
                else:
                    # Redirect to something other than TOTP - treat as failed password guess
                    continue

        # If we've found passwords for all users, we can stop early
        if len(results) == len(users_dict):
            break

    return results, total_sleep_time

if __name__ == '__main__':
    # Example usage
    users = {'james': None}
    start_test(users, max_attempts=1000)

