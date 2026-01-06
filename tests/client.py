import requests

# Default server URL
DEFAULT_BASE_URL = 'http://localhost:8000'


def get_users():
    response = requests.get(f'{DEFAULT_BASE_URL}/get_users')
    return response.json(), response.status_code


def register(username, password, totp_secret=None):
    data = {
        'username': username,
        'password': password
    }
    if totp_secret is not None:
        data['totp_secret'] = totp_secret
    
    response = requests.post(f'{DEFAULT_BASE_URL}/register', json=data)
    return response.json(), response.status_code


def login(username, password, captcha_token=None):
    params = {
        'username': username,
        'password': password
    }
    if captcha_token is not None:
        params['captcha_token'] = captcha_token
    
    response = requests.get(f'{DEFAULT_BASE_URL}/login', params=params, allow_redirects=False)
    
    # Check if redirect to TOTP endpoint
    if response.status_code == 302:
        redirect_url = response.headers.get('Location', '')
        return {}, response.status_code, redirect_url
    
    return response.json(), response.status_code, None


def login_totp(username, code):
    params = {
        'username': username,
        'code': code
    }
    
    response = requests.get(f'{DEFAULT_BASE_URL}/login_totp', params=params)
    return response.json(), response.status_code


def admin_get_captcha_token(group_seed, username):
    params = {
        'group_seed': group_seed,
        'username': username
    }
    
    response = requests.get(f'{DEFAULT_BASE_URL}/admin/get_captcha_token', params=params)
    return response.json(), response.status_code


def admin_unlock_user(group_seed, username):
    params = {
        'group_seed': group_seed,
        'username': username
    }
    
    response = requests.get(f'{DEFAULT_BASE_URL}/admin/unlock_user', params=params)
    return response.json(), response.status_code

