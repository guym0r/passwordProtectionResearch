# Password hash handlers dictionary
import hashlib
import secrets
import bcrypt
from argon2 import PasswordHasher

def prepare_plaintext_handler(is_new_user, config, stored_password=None):
    """Prepare function for plaintext handler - returns empty dict"""
    return {}

def plaintext_handler(password, handler_info):
    """Plaintext handler - returns password as-is"""
    return password

def prepare_sha256_salt_handler(is_new_user, config, stored_password=None):
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
    if config.get('USE_PEPPER', False):
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

def prepare_bcrypt_handler(is_new_user, config, stored_password=None):
    """Prepare function for bcrypt handler"""
    handler_info = {}
    
    if not is_new_user and stored_password:
        # For login, pass stored hash to handler for verification
        handler_info['stored_hash'] = stored_password
    
    # Add bcrypt cost from config (default to 12)
    handler_info['bcrypt_cost'] = config.get('BCRYPT_COST', 12)
    
    # Add pepper if USE_PEPPER is enabled
    if config.get('USE_PEPPER', False):
        handler_info['pepper'] = config.get('PEPPER', '')
    
    return handler_info

def bcrypt_handler(password, handler_info):
    """BCrypt handler with configurable cost"""
    stored_hash = handler_info.get('stored_hash')
    pepper = handler_info.get('pepper', '')
    bcrypt_cost = handler_info.get('bcrypt_cost', 12)
    
    # Add pepper to password if present
    password_with_pepper = password + pepper
    
    if stored_hash:
        # Verify password against stored hash
        if bcrypt.checkpw(password_with_pepper.encode('utf-8'), stored_hash.encode('utf-8')):
            return stored_hash  # Return stored hash if verification succeeds
        else:
            # Return something that won't match to trigger login failure
            return ''
    else:
        # Generate new hash with cost from config
        salt = bcrypt.gensalt(rounds=bcrypt_cost)
        hashed = bcrypt.hashpw(password_with_pepper.encode('utf-8'), salt)
        return hashed.decode('utf-8')

def prepare_argon2id_handler(is_new_user, config, stored_password=None):
    """Prepare function for Argon2id handler"""
    handler_info = {}
    
    if not is_new_user and stored_password:
        # For login, pass stored hash to handler for verification
        handler_info['stored_hash'] = stored_password
    
    # Add Argon2id parameters from config (with defaults)
    handler_info['time_cost'] = config.get('ARGON2ID_TIME_COST', 1)
    handler_info['memory_cost'] = config.get('ARGON2ID_MEMORY_COST', 65536)
    handler_info['parallelism'] = config.get('ARGON2ID_PARALLELISM', 1)
    handler_info['hash_len'] = config.get('ARGON2ID_HASH_LEN', 32)
    handler_info['salt_len'] = config.get('ARGON2ID_SALT_LEN', 16)
    
    # Add pepper if USE_PEPPER is enabled
    if config.get('USE_PEPPER', False):
        handler_info['pepper'] = config.get('PEPPER', '')
    
    return handler_info

def argon2id_handler(password, handler_info):
    """Argon2id handler with configurable parameters"""
    stored_hash = handler_info.get('stored_hash')
    pepper = handler_info.get('pepper', '')
    
    # Get Argon2id parameters from handler_info
    time_cost = handler_info.get('time_cost', 1)
    memory_cost = handler_info.get('memory_cost', 65536)
    parallelism = handler_info.get('parallelism', 1)
    hash_len = handler_info.get('hash_len', 32)
    salt_len = handler_info.get('salt_len', 16)
    
    # Add pepper to password if present
    password_with_pepper = password + pepper
    
    # Create PasswordHasher with Argon2id parameters from config
    ph = PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        salt_len=salt_len
    )
    
    if stored_hash:
        # Verify password against stored hash
        try:
            ph.verify(stored_hash, password_with_pepper)
            return stored_hash  # Return stored hash if verification succeeds
        except:
            # Return something that won't match to trigger login failure
            return ''
    else:
        # Generate new hash
        hashed = ph.hash(password_with_pepper)
        return hashed

PASSWORD_HANDLERS = {
    'plaintext': (prepare_plaintext_handler, plaintext_handler),
    'sha256-salt': (prepare_sha256_salt_handler, sha256_salt_handler),
    'bcrypt': (prepare_bcrypt_handler, bcrypt_handler),
    'argon2id': (prepare_argon2id_handler, argon2id_handler)
}

