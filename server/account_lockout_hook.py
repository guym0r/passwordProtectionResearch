# Account lockout security hook
import json

# Track failed login attempts per user
# Format: {username: number_of_failed_login_in_row}
ACCOUNT_LOCKOUT_DATA = {}

def account_lockout_feature(context):
    """
    Account lockout security feature
    Permanently locks account after threshold failed attempts (pre_login)
    Records failed attempts and locks account (post_login)
    """
    username = context['username']
    stage = context['stage']
    config = context['config']
    
    # Get account lockout configuration from config
    account_lockout_config = config['ACCOUNT_LOCKOUT']
    lockout_threshold = account_lockout_config['THRESHOLD']
    
    if stage == 'pre_login':
        """
        Pre-login account lockout check:
        1. Check if account is permanently locked
        2. If locked, deny login
        3. If not locked, allow login attempt
        """
        # Check if account is permanently locked (calculate from number of tries)
        if username in ACCOUNT_LOCKOUT_DATA:
            num_failed_attempts = ACCOUNT_LOCKOUT_DATA[username]
            if num_failed_attempts >= lockout_threshold:
                error_json = json.dumps({
                    'error': 'Account is locked due to too many failed login attempts. Talk to the admin to unlock it'
                })
                return False, error_json
        
        return True, ""
    
    elif stage == 'post_login':
        success = context['success']
        
        if success:
            # Clear failed attempts on successful login
            if username in ACCOUNT_LOCKOUT_DATA:
                ACCOUNT_LOCKOUT_DATA[username] = 0
        else:
            # Record failed login attempt
            if username not in ACCOUNT_LOCKOUT_DATA:
                # First failed attempt
                ACCOUNT_LOCKOUT_DATA[username] = 1
            else:
                # Increment consecutive failed attempts counter
                ACCOUNT_LOCKOUT_DATA[username] += 1
        
        return True, ""  # Always allow, we're just tracking
    
    return True, ""

def reset_account_lockout(username):
    """
    Reset the account lockout for a user (unlock account)
    Removes the user from ACCOUNT_LOCKOUT_DATA, effectively resetting failed attempts to 0
    """
    if username in ACCOUNT_LOCKOUT_DATA:
        ACCOUNT_LOCKOUT_DATA[username] = 0

