# Security hooks system for login endpoint

# Security features registry
# Each feature is a function that takes context dict and returns True (allow) or False (deny)
SECURITY_FEATURES = {}

def register_security_feature(name, feature_func):
    """Register a security feature"""
    SECURITY_FEATURES[name] = feature_func

def run_pre_login_hooks(username, password, config):
    """
    Run security hooks before password validation
    Returns (allowed, error_message)
    """
    enabled_features = config.get('ENABLED_SECURITY_FEATURES', [])
    
    context = {
        'username': username,
        'password': password,
        'config': config,
        'stage': 'pre_login'
    }
    
    for feature_name in enabled_features:
        if feature_name in SECURITY_FEATURES:
            feature_func = SECURITY_FEATURES[feature_name]
            try:
                result = feature_func(context)
                if not result:
                    return False, f'Security check failed: {feature_name}'
            except Exception as e:
                # If feature raises exception, deny login for safety
                return False, f'Security check error: {feature_name} - {str(e)}'
    
    return True, None

def run_post_login_hooks(username, password, success, config):
    """
    Run security hooks after password validation
    Returns (allowed, error_message)
    """
    enabled_features = config.get('ENABLED_SECURITY_FEATURES', [])
    
    context = {
        'username': username,
        'password': password,
        'success': success,
        'config': config,
        'stage': 'post_login'
    }
    
    for feature_name in enabled_features:
        if feature_name in SECURITY_FEATURES:
            feature_func = SECURITY_FEATURES[feature_name]
            try:
                result = feature_func(context)
                if not result:
                    return False, f'Security check failed: {feature_name}'
            except Exception as e:
                # If feature raises exception, deny login for safety
                return False, f'Security check error: {feature_name} - {str(e)}'
    
    return True, None

