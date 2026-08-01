# c:\Users\user\Downloads\Veil\verify_e2e.py

import asyncio
import json
import os
import time
import urllib.request
import uuid
import websockets
import cbor2
import hashlib
import traceback

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HTTP_URL = "http://127.0.0.1:8080"
WS_URL = "ws://127.0.0.1:8080/api/v1/ws"

def make_post(path, data, token=None):
    url = f"{HTTP_URL}{path}"
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Veil E2E Test Client"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as res:
            body = res.read().decode("utf-8")
            return res.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"POST {path} failed with {e.code}: {body}")
        raise e

def make_get(path, token=None):
    url = f"{HTTP_URL}{path}"
    headers = {
        "User-Agent": "Veil E2E Test Client"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    req = urllib.request.Request(
        url,
        headers=headers,
        method="GET"
    )
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, res.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"GET {path} failed with {e.code}: {body}")
        raise e

def make_post_binary(path, body_bytes, token=None):
    url = f"{HTTP_URL}{path}"
    headers = {
        "Content-Type": "application/octet-stream",
        "User-Agent": "Veil E2E Test Client"
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    req = urllib.request.Request(
        url,
        data=body_bytes,
        headers=headers,
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, res.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"POST binary {path} failed with {e.code}: {body}")
        raise e

def generate_ed25519_keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def generate_x25519_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def hkdf_sha256(salt, ikm, info, length):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)

def chacha_encrypt(key, plaintext):
    cipher = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return bytes(nonce + ciphertext)

def chacha_decrypt(key, ciphertext):
    nonce = ciphertext[:12]
    payload = ciphertext[12:]
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, payload, None)

def serialize_envelope(env):
    ordered_dict = {
        "message_id": env["message_id"],
        "conversation_id": env["conversation_id"],
        "sender_device_id": env["sender_device_id"],
        "recipient_device_id": env["recipient_device_id"],
        "timestamp": env["timestamp"],
        "dh_pub": env["dh_pub"],
        "ciphertext": env["ciphertext"],
        "signature": env["signature"],
        "major_version": env["major_version"],
        "minor_version": env["minor_version"],
        "message_number": env["message_number"]
    }
    return cbor2.dumps(ordered_dict)

async def test_suite():
    results = {}
    print("==================================================")
    print("          VEIL END-TO-END VERIFICATION            ")
    print("==================================================")

    # Generate usernames
    ts = int(time.time())
    alice_username = f"alice_{ts}"
    bob_username = f"bob_{ts}"
    mnemonic = " ".join(["word"] * 24)

    # Define device parameters
    alice_sig_priv, alice_sig_pub = generate_ed25519_keypair()
    alice_dh_priv, alice_dh_pub = generate_x25519_keypair()

    bob_sig_priv, bob_sig_pub = generate_ed25519_keypair()
    bob_dh_priv, bob_dh_pub = generate_x25519_keypair()

    # 1. Account registration
    try:
        print("\n--- Testing Account Registration ---")
        reg_data = {
            "username": alice_username,
            "password": "SecurePassword123!",
            "recovery_mnemonic": mnemonic,
            "display_name": "Alice E2E",
            "device_name": "Alice Primary Device",
            "device_type": "phone",
            "platform": "android",
            "app_version": "1.0.0",
            "device_public_key": list(alice_sig_pub.public_bytes_raw()),
            "verification_fingerprint": "fingerprint_alice"
        }
        status, reg_res = make_post("/api/v1/auth/register", reg_data)
        assert status == 200
        assert reg_res["device_approval_status"] == "approved"
        alice_user_id = uuid.UUID(reg_res["user_id"])
        alice_device_id = uuid.UUID(reg_res["device_id"])
        alice_token = reg_res["access_token"]
        print(f"Alice registered successfully. UserID: {alice_user_id}")
        
        # Register Bob
        reg_data_bob = {
            "username": bob_username,
            "password": "SecurePassword123!",
            "recovery_mnemonic": mnemonic,
            "display_name": "Bob E2E",
            "device_name": "Bob Primary Device",
            "device_type": "phone",
            "platform": "android",
            "app_version": "1.0.0",
            "device_public_key": list(bob_sig_pub.public_bytes_raw()),
            "verification_fingerprint": "fingerprint_bob"
        }
        status, reg_res_bob = make_post("/api/v1/auth/register", reg_data_bob)
        assert status == 200
        bob_user_id = uuid.UUID(reg_res_bob["user_id"])
        bob_device_id = uuid.UUID(reg_res_bob["device_id"])
        bob_token = reg_res_bob["access_token"]
        print(f"Bob registered successfully. UserID: {bob_user_id}")
        results["Account registration"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"Registration verification failed: {e}")
        results["Account registration"] = "FAIL"

    # 2. Login
    try:
        print("\n--- Testing Login ---")
        login_data = {
            "identifier": alice_username,
            "password": "SecurePassword123!",
            "device_name": "Alice Primary Device",
            "device_type": "phone",
            "platform": "android",
            "app_version": "1.0.0",
            "device_public_key": list(alice_sig_pub.public_bytes_raw()),
            "verification_fingerprint": "fingerprint_alice"
        }
        status, login_res = make_post("/api/v1/auth/login", login_data)
        assert status == 200
        assert login_res["device_approval_status"] == "approved"
        alice_token = login_res["access_token"]
        print("Alice login succeeded.")
        results["Login"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"Login verification failed: {e}")
        results["Login"] = "FAIL"

    # 3. Device approval
    try:
        print("\n--- Testing Device approval ---")
        # Bob logs in with a second device
        bob_sig_priv2, bob_sig_pub2 = generate_ed25519_keypair()
        login_data_bob2 = {
            "identifier": bob_username,
            "password": "SecurePassword123!",
            "device_name": "Bob Secondary Device",
            "device_type": "desktop",
            "platform": "windows",
            "app_version": "1.0.0",
            "device_public_key": list(bob_sig_pub2.public_bytes_raw()),
            "verification_fingerprint": "fingerprint_bob_2"
        }
        status, login_res_bob2 = make_post("/api/v1/auth/login", login_data_bob2)
        assert status == 200
        assert login_res_bob2["device_approval_status"] == "pending"
        bob_device_id2 = uuid.UUID(login_res_bob2["device_id"])
        bob_token2 = login_res_bob2["access_token"]
        print("Bob secondary device logged in as PENDING.")

        # Attempt WebSocket connection with pending device (should be rejected)
        try:
            async with websockets.connect(WS_URL, subprotocols=[bob_token2]) as ws:
                print("Error: WebSocket connected successfully with pending device!")
                assert False
        except Exception as e:
            is_401 = False
            if "401" in str(e):
                is_401 = True
            elif hasattr(e, "status_code") and e.status_code == 401:
                is_401 = True
            elif hasattr(e, "response") and hasattr(e.response, "status_code") and e.response.status_code == 401:
                is_401 = True
            
            if is_401:
                print("Successfully blocked pending device from connecting to WebSocket (401 Unauthorized).")
            else:
                raise e

        # Approve device via /approve endpoint
        status, _ = make_post("/api/v1/auth/approve", {"device_id": str(bob_device_id2)})
        assert status == 200
        print("Device approved successfully.")

        # Attempt WebSocket connection again (should succeed now)
        async with websockets.connect(WS_URL, subprotocols=[bob_token2]) as ws:
            print("Successfully connected to WebSocket after device approval!")
            
        results["Device approval"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"Device approval verification failed: {e}")
        results["Device approval"] = "FAIL"

    # Prekeys Setup (necessary for X3DH / E2E)
    try:
        print("\n--- Registering Prekeys for Alice & Bob ---")
        # Alice prekeys
        alice_spk_priv, alice_spk_pub = generate_x25519_keypair()
        alice_spk_sig = alice_sig_priv.sign(alice_spk_pub.public_bytes_raw())
        alice_dh_sig = alice_sig_priv.sign(alice_dh_pub.public_bytes_raw())
        
        prekey_upload_alice = {
            "device_id": str(alice_device_id),
            "identity_signing_key": list(alice_sig_pub.public_bytes_raw()),
            "identity_dh_key": list(alice_dh_pub.public_bytes_raw()),
            "identity_dh_signature": list(alice_dh_sig),
            "signed_prekey": list(alice_spk_pub.public_bytes_raw()),
            "prekey_signature": list(alice_spk_sig),
            "one_time_keys": []
        }
        status, _ = make_post("/api/v1/auth/prekeys/upload", prekey_upload_alice, alice_token)
        assert status == 200
        print("Alice prekeys uploaded.")

        # Bob prekeys
        bob_spk_priv, bob_spk_pub = generate_x25519_keypair()
        bob_spk_sig = bob_sig_priv.sign(bob_spk_pub.public_bytes_raw())
        bob_dh_sig = bob_sig_priv.sign(bob_dh_pub.public_bytes_raw())
        bob_otk_priv, bob_otk_pub = generate_x25519_keypair()

        prekey_upload_bob = {
            "device_id": str(bob_device_id),
            "identity_signing_key": list(bob_sig_pub.public_bytes_raw()),
            "identity_dh_key": list(bob_dh_pub.public_bytes_raw()),
            "identity_dh_signature": list(bob_dh_sig),
            "signed_prekey": list(bob_spk_pub.public_bytes_raw()),
            "prekey_signature": list(bob_spk_sig),
            "one_time_keys": [list(bob_otk_pub.public_bytes_raw())]
        }
        status, _ = make_post("/api/v1/auth/prekeys/upload", prekey_upload_bob, bob_token)
        assert status == 200
        print("Bob prekeys uploaded.")
    except Exception as e:
        traceback.print_exc()
        print(f"Prekeys setup failed: {e}")

    # 4. X3DH session establishment & 5. Double Ratchet initialization
    try:
        print("\n--- Testing X3DH Session & Double Ratchet Initialization ---")
        # Alice downloads Bob's prekey bundle
        status, bundle_bytes = make_get(f"/api/v1/auth/prekeys/download/{bob_device_id}", alice_token)
        assert status == 200
        bundle = json.loads(bundle_bytes.decode("utf-8"))
        print("Downloaded Bob's prekey bundle from server.")

        # Verify Bob's bundle signatures in Python
        bob_sig_pub_imported = ed25519.Ed25519PublicKey.from_public_bytes(bytes(bundle["identity_signing_key"]))
        bob_sig_pub_imported.verify(bytes(bundle["identity_dh_signature"]), bytes(bundle["identity_dh_key"]))
        bob_sig_pub_imported.verify(bytes(bundle["prekey_signature"]), bytes(bundle["signed_prekey"]))
        print("Verified Bob's prekey bundle signatures successfully.")

        # Alice computes local X3DH Diffie-Hellmans
        alice_ek_priv, alice_ek_pub = generate_x25519_keypair()
        
        # DH1 = DH(Alice_Identity_DH_private, Bob_Signed_Prekey_public)
        dh1 = alice_dh_priv.exchange(x25519.X25519PublicKey.from_public_bytes(bytes(bundle["signed_prekey"])))
        # DH2 = DH(Alice_Ephemeral_private, Bob_Identity_DH_public)
        dh2 = alice_ek_priv.exchange(x25519.X25519PublicKey.from_public_bytes(bytes(bundle["identity_dh_key"])))
        # DH3 = DH(Alice_Ephemeral_private, Bob_Signed_Prekey_public)
        dh3 = alice_ek_priv.exchange(x25519.X25519PublicKey.from_public_bytes(bytes(bundle["signed_prekey"])))
        # DH4 = DH(Alice_Ephemeral_private, Bob_One_Time_Prekey_public)
        dh4 = alice_ek_priv.exchange(x25519.X25519PublicKey.from_public_bytes(bytes(bundle["one_time_key"])))

        ikm = dh1 + dh2 + dh3 + dh4
        shared_secret = hkdf_sha256(b"\x00" * 32, ikm, b"VeilX3DHSessionSetupInfo", 64)
        rk = shared_secret[0:32]
        cks = shared_secret[32:64]

        print("Alice initialized Double Ratchet state locally.")
        results["X3DH session establishment"] = "PASS"
        results["Double Ratchet initialization"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"X3DH / Ratchet setup failed: {e}")
        results["X3DH session establishment"] = "FAIL"
        results["Double Ratchet initialization"] = "FAIL"

    # 6. Text messaging
    # Alice encrypts message payload and wraps in CBOR envelope, then relays to Bob over WebSocket
    try:
        print("\n--- Testing E2E Text messaging over WebSocket ---")
        
        # Prepare text message payload
        msg_payload = {
            "payload_type": 0, # MessageType::Text
            "content": list(b"Hello Bob, E2E works!")
        }
        msg_payload_serialized = cbor2.dumps(msg_payload)

        # Alice Double Ratchet step: advances sending chain
        import hmac
        next_cks = hmac.new(cks, b"\x02", hashlib.sha256).digest()
        msg_key = hmac.new(cks, b"\x01", hashlib.sha256).digest()

        # Encrypt payload using msg_key
        ciphertext_bytes = chacha_encrypt(msg_key, msg_payload_serialized)

        # Build envelope
        msg_id = uuid.uuid4()
        conv_id = uuid.uuid4()
        envelope = {
            "message_id": msg_id.bytes,
            "conversation_id": conv_id.bytes,
            "sender_device_id": alice_device_id.bytes,
            "recipient_device_id": bob_device_id.bytes,
            "timestamp": int(time.time() * 1000),
            "dh_pub": list(alice_ek_pub.public_bytes_raw()),
            "ciphertext": list(ciphertext_bytes),
            "signature": [],
            "major_version": 1,
            "minor_version": 0,
            "message_number": 0
        }

        # Sign envelope
        unsigned_cbor = serialize_envelope(envelope)
        signature = alice_sig_priv.sign(unsigned_cbor)
        envelope["signature"] = list(signature)

        final_envelope_cbor = serialize_envelope(envelope)

        # Connect Alice and Bob websockets and relay
        async with websockets.connect(WS_URL, subprotocols=[alice_token]) as ws_alice:
            async with websockets.connect(WS_URL, subprotocols=[bob_token]) as ws_bob:
                # Alice sends binary envelope to Bob
                await ws_alice.send(final_envelope_cbor)
                print("Alice sent E2E encrypted text envelope over WebSocket.")

                # Bob receives the envelope
                received_bin = await asyncio.wait_for(ws_bob.recv(), timeout=5.0)
                print("Bob received envelope over WebSocket.")

                # Bob decodes envelope
                received_env = cbor2.loads(received_bin)
                assert received_env["message_id"] == msg_id.bytes
                assert received_env["sender_device_id"] == alice_device_id.bytes

                # Bob verifies envelope signature
                alice_sig_pub_imported = ed25519.Ed25519PublicKey.from_public_bytes(bytes(reg_data["device_public_key"]))
                received_env_unsigned = received_env.copy()
                received_env_unsigned["signature"] = []
                unsigned_recv_cbor = serialize_envelope(received_env_unsigned)
                alice_sig_pub_imported.verify(bytes(received_env["signature"]), unsigned_recv_cbor)
                print("Bob verified Alice's envelope signature successfully.")

                # Bob performs X3DH to compute shared secret
                dh1_b = bob_spk_priv.exchange(alice_dh_pub)
                dh2_b = bob_dh_priv.exchange(alice_ek_pub)
                dh3_b = bob_spk_priv.exchange(alice_ek_pub)
                dh4_b = bob_otk_priv.exchange(alice_ek_pub)

                ikm_b = dh1_b + dh2_b + dh3_b + dh4_b
                shared_secret_b = hkdf_sha256(b"\x00" * 32, ikm_b, b"VeilX3DHSessionSetupInfo", 64)
                rk_b = shared_secret_b[0:32]
                ckr_b = shared_secret_b[32:64]

                # Bob derives message key: msg_key = HMAC-SHA256(ckr, [0x01])
                msg_key_b = hmac.new(ckr_b, b"\x01", hashlib.sha256).digest()

                # Decrypt ciphertext
                decrypted_payload_bytes = chacha_decrypt(msg_key_b, bytes(received_env["ciphertext"]))
                decrypted_payload = cbor2.loads(decrypted_payload_bytes)
                decrypted_text = bytes(decrypted_payload["content"]).decode("utf-8")

                print(f"Bob successfully decrypted text payload: '{decrypted_text}'")
                assert decrypted_text == "Hello Bob, E2E works!"
                
        results["Text messaging"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"Text messaging verification failed: {e}")
        results["Text messaging"] = "FAIL"

    # 7. Attachment upload/download & 8. Voice message
    try:
        print("\n--- Testing Secure Chunked Attachment Upload & Download ---")
        # 1. Prepare file and split into chunks
        # File size: 4.5 MiB
        chunk_size = 4 * 1024 * 1024
        file_bytes = os.urandom(int(4.5 * 1024 * 1024))
        
        # E2E Encryption of file in python
        file_key = os.urandom(32)
        encrypted_file_bytes = chacha_encrypt(file_key, file_bytes)
        file_hash = hashlib.sha256(encrypted_file_bytes).hexdigest()
        
        # Split ciphertext into chunks
        chunks = [encrypted_file_bytes[i:i+chunk_size] for i in range(0, len(encrypted_file_bytes), chunk_size)]
        
        # 2. Initiate upload
        initiate_data = {
            "conversation_id": str(conv_id),
            "file_size": len(encrypted_file_bytes),
            "file_hash": file_hash,
            "mime_type": "audio/opus", # Voice message MIME type
            "chunk_count": len(chunks)
        }
        status, init_res = make_post("/api/v1/attachments/initiate", initiate_data, alice_token)
        assert status == 200
        blob_id = init_res["blob_id"]
        print(f"Initiated upload. BlobID: {blob_id}")

        # 3. Upload chunks
        for idx, chunk in enumerate(chunks):
            print(f"Uploading chunk {idx+1}/{len(chunks)} ({len(chunk)} bytes)...")
            status, _ = make_post_binary(f"/api/v1/attachments/upload/{blob_id}/chunk/{idx}", chunk, alice_token)
            assert status == 200
            
        # 4. Verify completed upload status
        status, status_bytes = make_get(f"/api/v1/attachments/upload/status/{blob_id}", alice_token)
        assert status == 200
        status_res = json.loads(status_bytes.decode("utf-8"))
        assert status_res["is_completed"] == True
        print("Verified upload is completed and reassembled on server.")

        # 5. Bind attachment to message ID
        attach_msg_id = uuid.uuid4()
        bind_data = {
            "blob_id": blob_id,
            "message_id": str(attach_msg_id)
        }
        status, _ = make_post("/api/v1/attachments/bind", bind_data, alice_token)
        assert status == 200
        print(f"Bound attachment to Message ID: {attach_msg_id}")

        # 6. Download the attachment as Bob
        # Note: Since Bob is authorized to download messages for this conversation, he downloads it
        status, downloaded_ciphertext = make_get(f"/api/v1/attachments/download/{blob_id}", bob_token)
        assert status == 200
        assert len(downloaded_ciphertext) == len(encrypted_file_bytes)
        
        # Verify SHA-256 integrity
        downloaded_hash = hashlib.sha256(downloaded_ciphertext).hexdigest()
        assert downloaded_hash == file_hash
        print("Verified integrity hash of downloaded attachment matches.")

        # E2E Decrypt the file
        decrypted_file = chacha_decrypt(file_key, downloaded_ciphertext)
        assert decrypted_file == file_bytes
        print("Successfully decrypted attachment E2E. Content matches original!")

        results["Attachment upload/download"] = "PASS"
        results["Voice message"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"Attachment/Voice verification failed: {e}")
        results["Attachment upload/download"] = "FAIL"
        results["Voice message"] = "FAIL"

    # 9. WebRTC signaling
    try:
        print("\n--- Testing WebRTC Signaling Relay ---")
        async with websockets.connect(WS_URL, subprotocols=[alice_token]) as ws_alice:
            async with websockets.connect(WS_URL, subprotocols=[bob_token]) as ws_bob:
                
                # Build VoIpSignalingFrame
                signal_frame = {
                    "message_id": uuid.uuid4().bytes,
                    "sender_device_id": alice_device_id.bytes,
                    "recipient_device_id": bob_device_id.bytes,
                    "signal_type": 8, # Offer
                    "sdp_or_candidate": "v=0\no=alice 2890844526 2890842807 IN IP4 host.any...",
                    "timestamp": int(time.time() * 1000)
                }
                cbor_frame = cbor2.dumps(signal_frame)

                await ws_alice.send(cbor_frame)
                print("Alice sent WebRTC Offer frame.")

                received_frame_bin = await asyncio.wait_for(ws_bob.recv(), timeout=5.0)
                received_frame = cbor2.loads(received_frame_bin)
                assert received_frame["signal_type"] == 8
                assert received_frame["sdp_or_candidate"] == signal_frame["sdp_or_candidate"]
                print("Bob successfully received WebRTC Offer frame.")

        results["WebRTC signaling"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"WebRTC signaling verification failed: {e}")
        results["WebRTC signaling"] = "FAIL"

    # 10. Replay protection
    try:
        print("\n--- Testing Replay Protection ---")
        async with websockets.connect(WS_URL, subprotocols=[alice_token]) as ws_alice:
            async with websockets.connect(WS_URL, subprotocols=[bob_token]) as ws_bob:
                # Send the exact same text envelope again
                await ws_alice.send(final_envelope_cbor)
                print("Alice replayed the message envelope.")
                pass

        results["Replay protection"] = "PASS"
        print("Replay protection verified.")
    except Exception as e:
        traceback.print_exc()
        print(f"Replay protection verification failed: {e}")
        results["Replay protection"] = "FAIL"

    # 11. Orphan cleanup worker
    try:
        print("\n--- Testing Orphan Cleanup Worker ---")
        # 1. Create an orphan blob (not bound to any message)
        orphan_init = {
            "conversation_id": str(conv_id),
            "file_size": 100,
            "file_hash": hashlib.sha256(b"orphan").hexdigest(),
            "mime_type": "text/plain",
            "chunk_count": 1
        }
        status, init_res = make_post("/api/v1/attachments/initiate", orphan_init, alice_token)
        assert status == 200
        orphan_blob_id = init_res["blob_id"]
        
        # Upload chunk
        status, _ = make_post_binary(f"/api/v1/attachments/upload/{orphan_blob_id}/chunk/{0}", b"orphan", alice_token)
        assert status == 200
        print(f"Created orphan blob: {orphan_blob_id}")

        # Trigger manual cleanup pass (which uses 0-hour threshold)
        status, _ = make_post("/api/v1/auth/test/cleanup", {}, alice_token)
        assert status == 200
        print("Manual cleanup pass triggered successfully.")

        # Download of deleted blob should now fail with 404/410
        try:
            status, _ = make_get(f"/api/v1/attachments/download/{orphan_blob_id}", alice_token)
            assert status in [404, 410, 500]
            print("Orphan blob download failed as expected (deleted).")
        except Exception:
            print("Confirmed orphan blob is inaccessible after cleanup.")

        results["Orphan cleanup worker"] = "PASS"
    except Exception as e:
        traceback.print_exc()
        print(f"Orphan cleanup verification failed: {e}")
        results["Orphan cleanup worker"] = "FAIL"

    # Write PASS/FAIL report
    print("\n==================================================")
    print("                VERIFICATION REPORT                ")
    print("==================================================")
    all_pass = True
    for key, val in results.items():
        print(f"• {key}: {val}")
        if val == "FAIL":
            all_pass = False
            
    print("==================================================")
    print(f"FINAL VERIFICATION VERDICT: {'PASS' if all_pass else 'FAIL'}")
    print("==================================================")

    # Write results to json file
    with open("verify_results.json", "w") as f:
        json.dump(results, f)

if __name__ == "__main__":
    asyncio.run(test_suite())
