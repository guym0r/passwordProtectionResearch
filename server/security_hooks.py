# Security hooks system for login endpoint
from rate_limit_hook import rate_limit_feature
from captcha_hook import captcha_feature
from account_lockout_hook import account_lockout_feature
from totp_hook import totp_feature

# Global hardcoded list of all available security features
ALL_SECURITY_FEATURES = {
    'rate_limit': rate_limit_feature,
    'captcha': captcha_feature,
    'account_lockout': account_lockout_feature,
    'totp': totp_feature
}

# List of enabled security hooks (populated by init_security_hooks)
enabled_security_hooks = {}

def init_security_hooks(config):
    """Initialize security hooks based on config"""
    global enabled_security_hooks
    
    config_enabled_features = config.get('ENABLED_SECURITY_FEATURES', [])
    
    for feature_name in ALL_SECURITY_FEATURES:
        if feature_name in config_enabled_features:
            enabled_security_hooks[feature_name] = (ALL_SECURITY_FEATURES[feature_name])

def run_pre_login_hooks(username, password, config, request_params=None):
    """
    Run security hooks before password validation
    Returns (allowed, error_message)
    """
    context = {
        'username': username,
        'password': password,
        'config': config,
        'stage': 'pre_login',
        'request_params': request_params or {}
    }
    
    for feature_name in enabled_security_hooks.keys():
        feature_func = enabled_security_hooks[feature_name]
        try:
            success, error_message = feature_func(context)
            if not success:
                # If error message is empty, use generic message
                if error_message:
                    return False, error_message
                else:
                    return False, f'Security check failed: {feature_name}'
        except Exception as e:
            # If feature raises exception, deny login for safety
            return False, f'Security check error: {feature_name} - {str(e)}'
    
    return True, ""

def run_post_login_hooks(username, password, success, config, request_params=None):
    """
    Run security hooks after password validation
    Returns (allowed, error_message)
    """
    context = {
        'username': username,
        'password': password,
        'success': success,
        'config': config,
        'stage': 'post_login',
        'request_params': request_params or {}
    }
    
    for feature_name in enabled_security_hooks.keys():
        feature_func = enabled_security_hooks[feature_name]
        try:
            success, error_message = feature_func(context)
            if not success:
                # If error message is empty, use generic message
                if error_message:
                    return False, error_message
                else:
                    return False, f'Security check failed: {feature_name}'
        except Exception as e:
            # If feature raises exception, deny login for safety
            return False, f'Security check error: {feature_name} - {str(e)}'
    
    return True, ""
