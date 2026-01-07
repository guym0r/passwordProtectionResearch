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

def run_bruteforce_test(users_data):
    print("=" * 50)
    print("Starting bruteforce test...")
    for username in users_data.keys():
        max_tries = 50000
        otp_uri = users_data[username][1]
        password_type = users_data[username][2]
        start_time = time.time()
        result, sleep_time = bruteforce.start_test(username, max_tries, otp_uri=otp_uri, progress_counter=1000)
        
        end_time = time.time()
        duration = end_time - start_time - sleep_time
        print(f"Bruteforce test completed in {duration} seconds, password type: {password_type}, password found: {result}")
    print("=" * 50)

def run_password_spraying_test(users_data):
    print("=" * 50)
    print("Starting password spraying test...")
    max_tries = 50000
    users_dict = {username: otp_uri for username, (password, otp_uri, password_type) in users_data.items()}
    result, sleep_time = password_spraying.start_test(users_dict, max_tries)
    if result:
        print(f"Password spraying test completed successfully!")
        print(f"Found passwords for {len(result)} user(s):")
        for username, password in result.items():
            print(f"{username}: {password}")
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

    # run_hash_to_time_test(users_data)

    run_bruteforce_test(users_data)

    # run_password_spraying_test(users_data)

    # Cleanup server resources
    print("Cleaning up server resources...")
    cleanup_server()
    print("Test finished.")


if __name__ == '__main__':
    main()

