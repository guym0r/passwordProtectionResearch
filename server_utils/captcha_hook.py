# Captcha security hook
import secrets
import string
import json

# Track failed login attempts and captcha tokens per user
# Format: {username: (attempt_count, captcha_token)}
# captcha_token is None if no token has been generated yet
CAPTCHA_DATA = {}

def captcha_feature(context):
    """
    Captcha security feature
    After threshold failed login attempts, requires captcha_token parameter
    """
    username = context['username']
    stage = context['stage']
    request_params = context['request_params']
    config = context['config']
    
    # Get CAPTCHA_THRESHOLD from config
    captcha_config = config['CAPTCHA']
    captcha_threshold = captcha_config['THRESHOLD']
    
    if stage == 'pre_login':
        # Check if user has reached the captcha threshold
        if username not in CAPTCHA_DATA:
            return True, ""
        
        num_failed_attempts, stored_token = CAPTCHA_DATA[username]
        
        if num_failed_attempts == 0:
            return True, ""
        
        if num_failed_attempts >= captcha_threshold:
            # User has reached threshold -> require captcha_token
            if 'captcha_token' not in request_params:
                error_json = json.dumps({
                    'error': 'Captcha token required',
                    'captcha_required': True
                })
                return False, error_json
            
            captcha_token = request_params['captcha_token']
            # Verify the token matches the stored token
            if stored_token is None:
                error_json = json.dumps({
                    'error': 'Invalid captcha token',
                    'captcha_required': True
                })
                return False, error_json
            
            if captcha_token != stored_token:
                error_json = json.dumps({
                    'error': 'Invalid captcha token',
                    'captcha_required': True
                })
                return False, error_json
        
        return True, ""
    
    elif stage == 'post_login':
        success = context['success']
        
        if success:
            # Clear failed attempts and captcha token on successful login
            if username in CAPTCHA_DATA:
                CAPTCHA_DATA[username] = (0, None)
        else:
            # Increment failed login attempts counter
            if username not in CAPTCHA_DATA:
                num_failed_attempts = 1
                stored_token = None
            else:
                num_failed_attempts, stored_token = CAPTCHA_DATA[username]
                num_failed_attempts += 1
            
            # If user reached threshold, generate a captcha token
            if num_failed_attempts >= captcha_threshold:
                # Generate random alphanumeric string of length 10
                captcha_token = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
                CAPTCHA_DATA[username] = (num_failed_attempts, captcha_token)
            else:
                CAPTCHA_DATA[username] = (num_failed_attempts, stored_token)
        
        return True, ""  # Always allow, we're just tracking
    
    return True, ""

def get_captcha_token(username):
    """
    Get the captcha token for a given username
    Returns the captcha token string if exists, None otherwise
    """
    if username not in CAPTCHA_DATA:
        return None
    
    _, captcha_token = CAPTCHA_DATA[username]
    return captcha_token

