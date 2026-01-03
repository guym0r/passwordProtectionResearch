# Password hash handlers dictionary
import hashlib
import secrets

def prepare_plaintext_handler(is_new_user, stored_password=None, config=None):
    """Prepare function for plaintext handler - returns empty dict"""
    return {}

def plaintext_handler(password, handler_info):
    """Plaintext handler - returns password as-is"""
    return password

def prepare_sha256_salt_handler(is_new_user, stored_password=None, config=None):
    """Prepare function for sha256-salt handler"""
    handler_info = {}
    
    if is_new_user:
        # Generate random salt for new user
        salt = secrets.token_hex(16)  # 32 hex characters (16 bytes)
        handler_info['salt'] = salt
    else:
        # Extract salt from stored password (format: salt:hash)
        if stored_password and ':' in stored_password:
            salt, _ = stored_password.split(':', 1)
            handler_info['salt'] = salt
        else:
            raise ValueError('Invalid stored password format for sha256-salt')
    
    # Add pepper if USE_PEPPER is enabled
    if config and config.get('USE_PEPPER', False):
        handler_info['pepper'] = config.get('PEPPER', '')
    
    return handler_info

def sha256_salt_handler(password, handler_info):
    """SHA256 handler with salt - concatenates salt to password and hashes"""
    salt = handler_info['salt']
    pepper = handler_info.get('pepper', '')
    
    # Concatenate password + pepper + salt
    salted_password = password + pepper + salt
    
    # Hash with SHA256
    hash_obj = hashlib.sha256(salted_password.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    # Return salt:hash format
    return f"{salt}:{hash_hex}"

PASSWORD_HANDLERS = {
    'plaintext': (prepare_plaintext_handler, plaintext_handler),
    'sha256-salt': (prepare_sha256_salt_handler, sha256_salt_handler)
}

