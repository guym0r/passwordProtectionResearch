# Password Protection Research

Research about password protection mechanisms agains brute force attack and password spraying attack.

## GROUP_SEED value - **`206360893`**

## Install Requirements

```bash
pip install -r requirements.txt
```

## Quick Explain, TLDR

To run the experiment, execute `python3 run_security_test.py`. It will:
1. Load the test configuration from `security_test_config.json`
2. Print the command line to run the server (run it in another terminal)
3. Wait for the server to be ready
4. Run the experiment automatically
5. Print the results when finished

**Note:** If you see `"Got connection error in attempt X, waiting a second and continuing..."`, don't worry - this occurs when the server has too many open connections and should resolve automatically within a maximum of 30 seconds.
## The Server

### Start Server

The server is a Flask application running on `http://localhost:8000`.
The server uses `server_utils/` directory for the following utilities:
* `password_handlers.py` - Hash passwords (with salt and pepper)
* `security_hooks.py` - Initialize and manage the following security hooks:
    * `rate_limit_hook.py` - Rate limit security feature
    * `captcha_hook.py` - CAPTCHA security feature
    * `account_lockout_hook.py` - Account lockout security feature
    * `totp_hook.py` - Placeholder hook, TOTP logic is in `server.py`

The server has the following endpoints:

**Authentication Endpoints:**
- `GET /get_users` - Get list of all registered users (for debugging)
- `POST /register` - Register a new user, body params: `username`, `password`, `totp_secret` (optional)
- `GET /login` - Login with username and password, query params: `username`, `password`, `captcha_token` (optional)
- `GET /login_totp` - Verify TOTP code after password authentication, query params: `username`, `code`

**Admin Endpoints:**
- `GET /admin/get_captcha_token` - Get CAPTCHA token (for testing), query params: `group_seed`, `username`
- `GET /admin/unlock_user` - Unlock a locked user account (locked from "account lockout" security feature), query params: `group_seed`, `username`

** Running the the server (all the configuration are from "server_config.json")
```bash
python3 server.py
```

The server stores user credentials in a database called `users.db` (which is deleted when the server shuts down).

### Configuration Brief

Configure the server via `server_config.json`:

**Password Hashing:**
- `PASSWORD_HASH_TYPE`: `"sha256-salt"`, `"bcrypt"`, or `"argon2id"`
- `USE_PEPPER`: Enable/disable pepper
- `PEPPER`: Pepper value

**Security Features:**
Enable features in server_config.json`:
```json
{
  "ENABLED_SECURITY_FEATURES": ["rate_limit", "captcha", "account_lockout", "totp"]
}
```

Or via CLI or config:
```bash
python3 server.py --enable-rate-limit --enable-captcha --enable-account-lockout --enable-totp
```

**Security Feature Configuration:**
- `RATE_LIMIT_CONFIG`: Array of `{"attempts": N, "lockout_seconds": M}` thresholds
- `CAPTCHA.THRESHOLD`: Number of failed attempts before CAPTCHA is required
- `ACCOUNT_LOCKOUT.THRESHOLD`: Number of failed attempts before account is locked
- `TOTP.ISSUER`: TOTP issuer name
- `TOTP.TIME_WINDOW`: TOTP time window

*** Simple API CLI test (after run python server.py):
### Register
``` bash
curl -X POST http://127.0.0.1:8000/register -H "Content-Type:application/json" -d '{"username":"jesika", "password": "GoodPassowrd"}'
```

### Login
``` bash
curl http://127.0.0.1:8000/login?username=jesika&password=GoodPassowrd
```

### Get Users
```bash
curl http://localhost:8000/get_users
```

## Running the Experiments

### Prerequisites

1. **Download rockyou.txt**

   Download the password dictionary from: [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
   
   Place it in: `tests/rockyou.txt`

2. **Configure Test**

   Edit `security_test_config.json`:
   ```json
   {
     "AVAILABLE_SECURITY_FEATURES": ["rate_limit", "captcha", "account_lockout", "totp"],
     "ENABLED_SECURITY_FEATURES": ["captcha", "rate_limit"],
     "AVAILABLE_TEST_TYPES": ["bruteforce", "password_spraying", "hash_to_time"],
     "TEST_TYPE": "bruteforce",
     "BRUTEFORCE_MAX_ATTEMPTS": 10000,
     "MAX_PASSWORD_SPRAYING": 20,
     "CAPTCHA_SIMULATE_SLEEP_TIME": 2
   }
   ```

   **Test types:**
   - `bruteforce`: Tests password strength against dictionary attacks for individual users
   - `password_spraying`: Tests multiple accounts with common passwords
   - `hash_to_time`: Measures password verification performance

   **Note:** If `"totp"` is in `ENABLED_SECURITY_FEATURES`, tests only run on users with TOTP enabled.

### Running Tests

**Important: Restart the server before every test to reset state.**

1. **Start the server** (in Terminal 1):
   ```bash
   python3 server.py
   ```

2. **Run the test suite** (in Terminal 2):
   ```bash
   python3 run_security_test.py
   ```

   The script will:
   - Load configuration from `security_test_config.json`
   - Print the recommended server command (based on enabled features)
   - Wait for server to be ready
   - Initialize test users from `tests/users.json`
   - Run the configured test type
   - Display test results and summaries

3. **Restart the server** before running the next test to ensure clean state:
   ```bash
   # Stop current server (Ctrl+C)
   # Start again
   python3 server.py
   ```

### Test Output

The test suite provides detailed output including:
- Server command recommendation
- Test progress (with progress counters)
- Results per user/password type
- Summary statistics:
  - **Bruteforce test**: Success/failure rates, average durations by password type
  - **Password spraying test**: Found/not found counts by password type

### Test Configuration Details

**security_test_config.json:**
- `ENABLED_SECURITY_FEATURES`: List of security features to enable during testing
- `TEST_TYPE`: Which test to run (`bruteforce`, `password_spraying`, or `hash_to_time`)
- `BRUTEFORCE_MAX_ATTEMPTS`: Maximum password attempts for bruteforce test
- `MAX_PASSWORD_SPRAYING`: Maximum passwords to try in password spraying test
- `CAPTCHA_SIMULATE_SLEEP_TIME`: Sleep time (seconds) when CAPTCHA is encountered

### Troubleshooting

**Connection Error:**
If you see `"Got connection error in attempt X, waiting a second and continuing"`, it's because the server has too many open connections/ports. This should resolve automatically within a maximum of 30 seconds as the server cleans up connections.

