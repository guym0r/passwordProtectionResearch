import sys
import os
import json
import time
import atexit
import requests
from server import start_server, cleanup_server
from tests import init_server_data
from tests import bruteforce
from tests import password_spraying


def wait_for_server(max_wait=30):
    """Wait for server to be ready"""
    url = 'http://localhost:8000/get_users'
    for _ in range(max_wait):
        try:
            response = requests.get(url, timeout=1)
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(1)
    return False

def filter_users_with_otp(users_data):
    """
    Filter out users without otp_uri from users_data.
    
    Args:
        users_data: Dictionary mapping username -> (password, otp_uri, password_type)
    
    Returns:
        Filtered dictionary containing only users with otp_uri
    """
    filtered_data = {}
    for username, (password, otp_uri, password_type) in users_data.items():
        if otp_uri is not None and otp_uri != '':
            filtered_data[username] = (password, otp_uri, password_type)
    return filtered_data

def run_hash_to_time_test(users_data):
    print("=" * 50)
    print("Starting hash to time test...")
    username = 'maria'
    max_tries = 100
    start_time = time.time()
    result, sleep_time = bruteforce.start_test(username, max_tries, otp_uri=None)
    
    end_time = time.time()
    duration = end_time - start_time - sleep_time
    print(f"Hash to time test completed in {duration} seconds")
    print("=" * 50)

def print_bruteforce_test_summary(password_type_counts):
    print("bruteforce test summary:")
    for password_type in password_type_counts.keys():
        total_successful_duration = 0
        total_failed_duration = 0
        successful_attempts = 0
        failed_attempts = 0
        for duration, result in password_type_counts[password_type]:
            if result:
                successful_attempts += 1
                total_successful_duration += duration
            else:
                failed_attempts += 1
                total_failed_duration += duration
        if successful_attempts > 0 and failed_attempts > 0:
            print(f"{password_type} password type: Successful attempts: {successful_attempts}, Failed attempts: {failed_attempts}, average successful duration: {total_successful_duration / successful_attempts:.2f} seconds, average failed duration: {total_failed_duration / failed_attempts:.2f} seconds")
        elif successful_attempts > 0:
            print(f"{password_type} password type: Successful attempts: {successful_attempts}, Failed attempts: {failed_attempts}, average successful duration: {total_successful_duration / successful_attempts:.2f} seconds")
        elif failed_attempts > 0:
            print(f"{password_type} password type: Successful attempts: {successful_attempts}, Failed attempts: {failed_attempts}, average failed duration: {total_failed_duration / failed_attempts:.2f} seconds")
        else:
            print(f"{password_type} password type: No attempts recorded")

def run_bruteforce_test(users_data, max_attempts=50000, enable_otp=False, captcha_sleep_time=2):
    print("=" * 50)
    if enable_otp:
        users_data = filter_users_with_otp(users_data)
    print("Starting bruteforce test...")
    
    password_type_counts = {}
    for username in users_data.keys():
        otp_uri = users_data[username][1]
        password_type = users_data[username][2]
        start_time = time.time()
        result, sleep_time = bruteforce.start_test(username, max_attempts, otp_uri=otp_uri, progress_counter=1000, captcha_sleep_time=captcha_sleep_time)
        
        end_time = time.time()
        duration = end_time - start_time - sleep_time
        if password_type not in password_type_counts:
            password_type_counts[password_type] = []
        password_type_counts[password_type].append((duration, result))
        print(f"{username}: {password_type} password type: {duration} seconds, result: {result}")

    print_bruteforce_test_summary(password_type_counts)
    print("=" * 50)

def print_password_spraying_test_summary(users_data, found_results):
    print("password spraying test summary:")
    # Group users by password_type
    password_type_stats = {}
    
    # Initialize stats for each password type
    for username, (password, otp_uri, password_type) in users_data.items():
        if password_type not in password_type_stats:
            password_type_stats[password_type] = {'found': 0, 'total': 0}
        password_type_stats[password_type]['total'] += 1
        if username in found_results:
            password_type_stats[password_type]['found'] += 1
    
    # Print summary for each password type
    for password_type in sorted(password_type_stats.keys()):
        stats = password_type_stats[password_type]
        found = stats['found']
        total = stats['total']
        not_found = total - found
        found_percentage = (found / total * 100) if total > 0 else 0
        
        print(f"{password_type} password type: Found: {found}/{total} ({found_percentage:.1f}%), Not found: {not_found}/{total}")

def run_password_spraying_test(users_data, max_attempts=20, enable_otp=False, captcha_sleep_time=2):
    print("=" * 50)
    users_data = init_server_data.add_random_users(users_data, 1000, 1000)

    if enable_otp:
        users_data = filter_users_with_otp(users_data)
    
    print("Starting password spraying test...")
    users_dict = {username: otp_uri for username, (password, otp_uri, password_type) in users_data.items()}
    result, sleep_time = password_spraying.start_test(users_dict, max_attempts, progress_counter=4, captcha_sleep_time=captcha_sleep_time)
    if result:
        print(f"Password spraying test completed successfully!")
        print(f"Found passwords for {len(result)} users")
    
    print_password_spraying_test_summary(users_data, result if result else {})
    print("=" * 50)

def load_test_config(config_file='security_test_config.json'):
    """Load test configuration from JSON file"""
    if not os.path.exists(config_file):
        raise RuntimeError(f"Test config file not found: {config_file}")
    
    with open(config_file, 'r') as f:
        return json.load(f)

def build_server_command(enabled_features):
    """Build command line string for running server.py with enabled features"""
    cmd_parts = ['python3', 'server.py']
    
    if 'rate_limit' in enabled_features:
        cmd_parts.append('--enable-rate-limit')
    if 'captcha' in enabled_features:
        cmd_parts.append('--enable-captcha')
    if 'account_lockout' in enabled_features:
        cmd_parts.append('--enable-account-lockout')
    if 'totp' in enabled_features:
        cmd_parts.append('--enable-totp')
    
    return ' '.join(cmd_parts)

def main():
    print("Starting security tests...")
    
    # Load test configuration
    test_config = load_test_config()
    enabled_features = test_config['ENABLED_SECURITY_FEATURES']
    enable_otp = 'totp' in enabled_features
    test_type = test_config['TEST_TYPE']
    bruteforce_max_attempts = test_config['BRUTEFORCE_MAX_ATTEMPTS']
    max_password_spraying = test_config['MAX_PASSWORD_SPRAYING']
    captcha_sleep_time = test_config['CAPTCHA_SIMULATE_SLEEP_TIME']
    
    # Build and print server command
    server_cmd = build_server_command(enabled_features)
    print(f"\nServer command: {server_cmd}\n")
    
    # Register cleanup function with atexit as a safety net
    atexit.register(cleanup_server)
    
    if not wait_for_server():
        print("Error: Server failed to start within timeout period")
        return
    
    # Initialize test data (register users)
    print("Initializing test data...")
    users_data = init_server_data.init_server_data()


    # Run test based on TEST_TYPE
    if test_type == 'bruteforce':
        run_bruteforce_test(users_data, max_attempts=bruteforce_max_attempts, enable_otp=enable_otp, captcha_sleep_time=captcha_sleep_time)
    elif test_type == 'password_spraying':
        run_password_spraying_test(users_data, max_attempts=max_password_spraying, enable_otp=enable_otp, captcha_sleep_time=captcha_sleep_time)
    elif test_type == 'hash_to_time':
        run_hash_to_time_test(users_data)
    else:
        print(f"Unknown test type: {test_type}")
        print(f"Available test types: {test_config.get('AVAILABLE_TEST_TYPES', [])}")

    # Cleanup server resources
    print("Cleaning up server resources...")
    cleanup_server()
    print("Test finished.")


if __name__ == '__main__':
    main()

