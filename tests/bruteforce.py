import os
import time
import pyotp
from urllib.parse import urlparse, parse_qs
from .client import login, login_totp, admin_get_captcha_token

# GROUP_SEED from server_config.json (hardcoded for tests)
GROUP_SEED = "206360893"
CAPTCHA_SLEEP_TIME = 2

def start_test(username, max_tries, otp_uri=None, progress_counter=0):
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    rockyou_file_path = os.path.join(script_dir, 'rockyou.txt')
    
    attempt_count = 0
    total_sleep_time = 0
    
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
                return None, total_sleep_time
            
            # Try to login with this password
            try:
                response, status_code, redirect_url = login(username, password)
            except Exception as e:
                # Occurs sometimes when the server needs to clean up after a previous requests
                print(f"Got connection error in attempt {attempt_count}, waiting a second and continuing...")
                time.sleep(1)
                total_sleep_time += 1
                continue
            
            # Check if rate limit is exceeded
            if status_code == 403 and 'retry_after' in response:
                retry_after = response.get('retry_after', 0)
                if retry_after > 0:
                    print(f"Rate limit exceeded, waiting {retry_after} seconds...")
                    # + 1 second to be sure that the rate limit is not exceeded again
                    time.sleep(retry_after + 1)
                continue
            
            # Check if captcha is required
            if status_code == 403 and response.get('captcha_required'):
                time.sleep(CAPTCHA_SLEEP_TIME)
                # Get captcha token and retry login
                captcha_response, captcha_status = admin_get_captcha_token(GROUP_SEED, username)
                if captcha_status == 200:
                    captcha_token = captcha_response.get('captcha_token')
                    if captcha_token:
                        # Retry login with captcha token
                        response, status_code, redirect_url = login(username, password, captcha_token=captcha_token)
                else:
                    print(f"Failed to get captcha token, continuing to next password...")
                    # Failed to get captcha token, continue to next password
                    continue
            
            # Check if login was successful
            # Status 200 = success (no TOTP)
            if status_code == 200:
                return password, total_sleep_time
            elif status_code == 302:
                # Check if redirect is to TOTP endpoint
                if redirect_url and '/login_totp' in redirect_url:
                    # Password is correct, but TOTP is required
                    if otp_uri is None:
                        print(f"Password found after {attempt_count} attempts, but TOTP URI not provided, password: {password}")
                        return password, total_sleep_time  # Still return password as found
                    
                    # Extract secret from otp_uri
                    parsed = urlparse(otp_uri)
                    query_params = parse_qs(parsed.query)
                    otp_secret = query_params.get('secret', [None])[0]
                    
                    if otp_secret is None:
                        print(f"Password found after {attempt_count} attempts, but could not extract secret from TOTP URI, password: {password}")
                        return None, total_sleep_time
                    
                    # Generate TOTP code from secret
                    totp = pyotp.TOTP(otp_secret)
                    code = totp.now()
                    
                    # Try to verify TOTP
                    totp_response, totp_status = login_totp(username, code)
                    
                    if totp_status == 200:
                        return password, total_sleep_time
                    else:
                        # Password correct but TOTP failed - still consider password found
                        print(f"Password found after {attempt_count} attempts, but TOTP verification failed, password: {password}")
                        return password, total_sleep_time
                else:
                    # Redirect to something other than TOTP - treat as failed password guess
                    continue

            if progress_counter > 0 and attempt_count % progress_counter == 0:
                print(f"Attempt {attempt_count} of {max_tries}")
                
    return None, total_sleep_time

if __name__ == '__main__':
    start_test("monika", 10000)