# c:\Users\user\Downloads\Veil\verify.py

import asyncio
import json
import urllib.request
import websockets

HTTP_URL = "http://127.0.0.1:8080"
WS_URL = "ws://127.0.0.1:8080/api/v1/ws"

def make_http_post(path, data):
    url = f"{HTTP_URL}{path}"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Veil Verification Client"
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except Exception as e:
        print(f"Error calling POST {path}: {e}")
        raise e

async def verify_local_run():
    print("--- Starting Local Verification Script ---")

    import time
    username = f"alice_dev_{int(time.time())}"

    # 1. Registration Payload
    # 24-word recovery mnemonic
    mnemonic = " ".join(["word"] * 24)
    reg_data = {
        "username": username,
        "password": "SuperSecurePassword1234!",
        "recovery_mnemonic": mnemonic,
        "display_name": "Alice Dev",
        "device_name": "Local Test Device",
        "device_type": "desktop",
        "platform": "windows",
        "app_version": "1.0.0",
        "device_public_key": [1] * 32,
        "verification_fingerprint": "fingerprint_12345"
    }

    print(f"Sending registration request for user '{username}'...")
    status, reg_res = make_http_post("/api/v1/auth/register", reg_data)
    print(f"Registration Response status: {status}")
    print(f"User ID: {reg_res.get('user_id')}, Device ID: {reg_res.get('device_id')}")

    # 2. Login Payload
    login_data = {
        "identifier": username,
        "password": "SuperSecurePassword1234!",
        "device_name": "Local Test Device",
        "device_type": "desktop",
        "platform": "windows",
        "app_version": "1.0.0",
        "device_public_key": [1] * 32,
        "verification_fingerprint": "fingerprint_12345",
        "user_agent": "Python client verification script"
    }

    print("Sending login request...")
    status, login_res = make_http_post("/api/v1/auth/login", login_data)
    print(f"Login Response status: {status}")
    access_token = login_res.get("access_token")
    print(f"Access Token retrieved: {access_token[:15]}...")

    # 3. Establish WebSocket connection
    # We pass access_token as the Sec-WebSocket-Protocol header via subprotocols
    print(f"Connecting to WebSocket endpoint at {WS_URL}...")
    async with websockets.connect(WS_URL, subprotocols=[access_token]) as ws:
        print("WebSocket handshake succeeded! Connection established.")
        # Send a native ping frame
        print("Sending native Ping frame...")
        ping_waiter = await ws.ping()
        await ping_waiter
        print("Received native Pong frame back successfully!")

    print("\nVerification COMPLETE: Registration, Login, and WebSocket connectivity successfully validated!")

if __name__ == "__main__":
    asyncio.run(verify_local_run())
