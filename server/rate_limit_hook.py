# Rate limiting security hook
from datetime import datetime

# Track failed login attempts per user
# Format: {username: (number_of_failed_login_in_row, last_failed_login_time)}
FAILED_LOGIN_ATTEMPTS = {}

def rate_limit_feature(context):
    """
    Rate limiting security feature
    Checks if user is locked due to too many failed attempts (pre_login)
    Records failed attempts (post_login)
    """
    username = context['username']
    stage = context['stage']
    config = context['config']
    
    # Get rate limit configuration from config (default to 5 attempts, 10 seconds)
    rate_limit_configs = config.get('RATE_LIMIT_CONFIG', [{'attempts': 5, 'lockout_seconds': 10}])
    
    if stage == 'pre_login':
        """
        Pre-login rate limiting check:
        1. If user has no failed attempts -> allow login
        2. Get number of consecutive failed attempts and last attempt time
        3. Find the applicable rate limit rule (highest threshold <= current attempts)
        4. Check if enough time has passed since last failed attempt
        """
        # No failed attempts recorded -> allow login
        if username not in FAILED_LOGIN_ATTEMPTS:
            return True
        
        num_failed_attempts, last_failed_time = FAILED_LOGIN_ATTEMPTS[username]
        now = datetime.now()
        seconds_since_last_attempt = (now - last_failed_time).total_seconds()
        
        # Find the applicable rate limit rule
        # We want the highest threshold that the user has reached
        # Example: If user has 7 attempts and configs are [5 attempts/10s, 10 attempts/30s]
        #          -> Use the 5 attempts/10s rule (highest threshold <= 7)
        applicable_rules = list(filter(lambda rule: rule['attempts'] <= num_failed_attempts, rate_limit_configs))
        # If user has fewer attempts than the minimum threshold, no rule applies -> allow login
        if not applicable_rules:
            return True
        
        applicable_rule = max(applicable_rules, key=lambda x: x['attempts'])
        
        # Check if lockout period has passed
        return seconds_since_last_attempt >= applicable_rule['lockout_seconds']
    
    elif stage == 'post_login':
        success = context['success']
        now = datetime.now()
        
        if success:
            # Clear failed attempts on successful login
            if username in FAILED_LOGIN_ATTEMPTS:
                del FAILED_LOGIN_ATTEMPTS[username]
        else:
            # Record failed login attempt
            if username not in FAILED_LOGIN_ATTEMPTS:
                # First failed attempt
                FAILED_LOGIN_ATTEMPTS[username] = (1, now)
            else:
                # Increment consecutive failed attempts counter
                num_failed_attempts, _ = FAILED_LOGIN_ATTEMPTS[username]
                FAILED_LOGIN_ATTEMPTS[username] = (num_failed_attempts + 1, now)
        
        return True  # Always allow, we're just tracking
    
    return True

