# Password hash handlers dictionary
import hashlib
import secrets

def prepare_plaintext_handler(is_new_user, stored_password=None):
    """Prepare function for plaintext handler - returns empty dict"""
    return {}

def plaintext_handler(password, handler_info):
    """Plaintext handler - returns password as-is"""
    return password

def prepare_sha256_salt_handler(is_new_user, stored_password=None):
    """Prepare function for sha256-salt handler"""
    if is_new_user:
        # Generate random salt for new user
        salt = secrets.token_hex(16)  # 32 hex characters (16 bytes)
        return {'salt': salt}
    else:
        # Extract salt from stored password (format: salt:hash)
        if stored_password and ':' in stored_password:
            salt, _ = stored_password.split(':', 1)
            return {'salt': salt}
        else:
            raise ValueError('Invalid stored password format for sha256-salt')

def sha256_salt_handler(password, handler_info):
    """SHA256 handler with salt - concatenates salt to password and hashes"""
    salt = handler_info['salt']
    # Concatenate salt to password
    salted_password = password + salt
    # Hash with SHA256
    hash_obj = hashlib.sha256(salted_password.encode('utf-8'))
    hash_hex = hash_obj.hexdigest()
    # Return salt:hash format
    return f"{salt}:{hash_hex}"

PASSWORD_HANDLERS = {
    'plaintext': (prepare_plaintext_handler, plaintext_handler),
    'sha256-salt': (prepare_sha256_salt_handler, sha256_salt_handler)
}

