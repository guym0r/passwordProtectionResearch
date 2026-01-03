# Password hash handlers dictionary

def plaintext_handler(password, config):
    """Plaintext handler - returns password as-is"""
    return password

PASSWORD_HANDLERS = {
    'plaintext': plaintext_handler
}

