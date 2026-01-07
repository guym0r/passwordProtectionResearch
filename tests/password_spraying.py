import os
import pyotp
from urllib.parse import urlparse, parse_qs
from .client import login, login_totp


def start_test(users_dict, max_attempts):
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rockyou_file_path = os.path.join(script_dir, 'rockyou.txt')
    
    # Read first 10000 passwords from rockyou.txt
    passwords = []
    with open(rockyou_file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= 10000:
                break
            password = line.strip()
            if password:  # Skip empty lines
                passwords.append(password)
    
    results = {}
    attempt_count = 0
    
    # Try each password against all users
    for password in passwords:
        # Try this password against each user
        for username, otp_uri in users_dict.items():
            # Skip users we've already found passwords for
            if username in results:
                continue
            if attempt_count >= max_attempts:
                return results
            
            attempt_count += 1
            # Try to login with this password
            response, status_code, redirect_url = login(username, password)
            
            # Check if login was successful
            # Status 200 = success (no TOTP)
            if status_code == 200:
                print(f"Password found for {username} after {attempt_count} attempts!")
                print(f"Password: {password}")
                results[username] = password
                continue
            elif status_code == 302:
                # Check if redirect is to TOTP endpoint
                if redirect_url and '/login_totp' in redirect_url:
                    # Password is correct, but TOTP is required
                    if otp_uri is None:
                        print(f"Password found for {username} after {attempt_count} attempts, but TOTP URI not provided!")
                        print(f"Password: {password}")
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
                    print(f"Password: {password}")
                    
                    if totp_status == 200:
                        print(f"TOTP verification successful!")
                    else:
                        # Password correct but TOTP failed - still consider password found
                        print(f"Password found for {username} after {attempt_count} attempts, but TOTP verification failed!")
                else:
                    # Redirect to something other than TOTP - treat as failed password guess
                    continue
            
            # Print progress every 100 attempts
            if attempt_count % 100 == 0:
                found_count = len(results)
                print(f"Attempted {attempt_count} login attempts... Found {found_count} password(s) so far...")
        
        # If we've found passwords for all users, we can stop early
        if len(results) == len(users_dict):
            print(f"Found passwords for all {len(users_dict)} users!")
            break

    return results

if __name__ == '__main__':
    # Example usage
    users = {'james': None}
    start_test(users, max_attempts=1000)

