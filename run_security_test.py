import sys
import os
import time
import threading
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



def main():
    print("Starting security tests...")
    
    # Register cleanup function with atexit as a safety net
    atexit.register(cleanup_server)
    
    # Start server in a separate thread
    print("Starting server...")
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Wait for server to be ready
    print("Waiting for server to be ready...")
    if not wait_for_server():
        print("Error: Server failed to start within timeout period")
        return
    
    print("Server is ready!")
    
    # Initialize test data (register users)
    print("Initializing test data...")
    users_data = init_server_data.init_server_data()
    
    # Run bruteforce test
    print("Starting bruteforce test...")
    username = 'robert'
    max_tries = 50000
    otp_uri = users_data[username][1]
    result = bruteforce.start_test(username, max_tries, otp_uri=otp_uri)
    
    if result:
        print(f"Test completed successfully. Password found: {result}")
    else:
        print(f"Test completed. Password not found within {max_tries} attempts.")

    # Prepare users_dict for password spraying: username -> otp_uri
    users_dict = {username: otp_uri for username, (password, otp_uri) in users_data.items()}
    
    # Run password spraying test
    print("Starting password spraying test...")
    result = password_spraying.start_test(users_dict, max_tries)
    
    if result:
        print(f"Password spraying test completed successfully!")
        print(f"Found passwords for {len(result)} user(s):")
        for username, password in result.items():
            print(f"  {username}: {password}")
    else:
        print(f"Password spraying test completed. No passwords found within {max_tries} attempts.")
    
    # Cleanup server resources
    print("Cleaning up server resources...")
    cleanup_server()
    print("Test finished.")


if __name__ == '__main__':
    main()

