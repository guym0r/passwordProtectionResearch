import sys
import os
import time
import threading
import atexit
import requests
from server import start_server, cleanup_server
from tests import init_server_data
from tests import bruteforce


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
    max_tries = 10000
    otp_uri = users_data[username][1]  # otp_uri is the second element
    result = bruteforce.start_test(username, max_tries, otp_uri=otp_uri)
    
    if result:
        print(f"Test completed successfully. Password found: {result}")
    else:
        print(f"Test completed. Password not found within {max_tries} attempts.")
    
    # Cleanup server resources
    print("Cleaning up server resources...")
    cleanup_server()
    print("Test finished.")


if __name__ == '__main__':
    main()

