def totp_feature(context):
    """
    TOTP security feature is implemented in the login endpoint itself,
    so this hook does nothing.
    """
    return True, ""