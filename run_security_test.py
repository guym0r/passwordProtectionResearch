import sys
import os
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

def run_bruteforce_test(users_data, max_attempts=50000):
    print("=" * 50)
    # uncomment to run tests only on users with TOTP enabled
    users_data = filter_users_with_otp(users_data)
    print("Starting bruteforce test...")
    
    password_type_counts = {}
    for username in users_data.keys():
        otp_uri = users_data[username][1]
        password_type = users_data[username][2]
        start_time = time.time()
        result, sleep_time = bruteforce.start_test(username, max_attempts, otp_uri=otp_uri, progress_counter=1000)
        
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

def run_password_spraying_test(users_data, max_attempts=20):
    print("=" * 50)
    users_data = init_server_data.add_random_users(users_data, 1000, 1000)

    # uncomment to run tests only on users with TOTP enabled
    users_data = filter_users_with_otp(users_data)
    
    print("Starting password spraying test...")
    users_dict = {username: otp_uri for username, (password, otp_uri, password_type) in users_data.items()}
    result, sleep_time = password_spraying.start_test(users_dict, max_attempts, progress_counter=4)
    if result:
        print(f"Password spraying test completed successfully!")
        print(f"Found passwords for {len(result)} users")
    
    print_password_spraying_test_summary(users_data, result if result else {})
    print("=" * 50)

def main():
    print("Starting security tests...")
    
    # Register cleanup function with atexit as a safety net
    atexit.register(cleanup_server)
    
    if not wait_for_server():
        print("Error: Server failed to start within timeout period")
        return
    
    # Initialize test data (register users)
    print("Initializing test data...")
    users_data = init_server_data.init_server_data()

    # uncomment to run hash to time test
    # run_hash_to_time_test(users_data)

    # uncomment to run bruteforce test
    # run_bruteforce_test(users_data)
    
    # uncomment to run password spraying test
    # run_password_spraying_test(users_data)

    # Cleanup server resources
    print("Cleaning up server resources...")
    cleanup_server()
    print("Test finished.")


if __name__ == '__main__':
    main()

