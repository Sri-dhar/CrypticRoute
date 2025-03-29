#!/usr/bin/env python3
import socket
import time
import hashlib

BROADCAST_ADDR = "255.255.255.255"
DISCOVERY_PORT = 60001  # Port receiver listens on for broadcasts
SENDER_REPLY_PORT = 60002 # Port *this* sender listens on for the reply
BUFFER_SIZE = 1024
LISTEN_TIMEOUT = 10 # seconds

# --- Key and Hash ---
# Use a simple key for this example. In real use, load from file/config.
SECRET_KEY = b"my-secret-udp-key-123"
KEY_HASH_ALGO = 'sha256'

def calculate_key_hash(key_data):
    hasher = hashlib.new(KEY_HASH_ALGO)
    hasher.update(key_data)
    return hasher.hexdigest()

MY_KEY_HASH = calculate_key_hash(SECRET_KEY)
# --------------------

MY_MESSAGE = f"PING:{MY_KEY_HASH}:{SENDER_REPLY_PORT}".encode('utf-8')

print(f"Sender starting...")
print(f"My Key Hash: {MY_KEY_HASH[:8]}...")
print(f"Will broadcast '{MY_MESSAGE.decode()}' to {BROADCAST_ADDR}:{DISCOVERY_PORT}")
print(f"Will listen for reply on port {SENDER_REPLY_PORT}")

sender_socket = None
try:
    # Create UDP socket
    sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Enable broadcasting mode
    sender_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # Bind to the reply port so we can receive the unicast reply
    sender_socket.bind(("", SENDER_REPLY_PORT))
    print(f"Socket bound to ('', {SENDER_REPLY_PORT}) for listening")

    # Send broadcast message
    sender_socket.sendto(MY_MESSAGE, (BROADCAST_ADDR, DISCOVERY_PORT))
    print("Broadcast 'PING' sent.")

    # Wait for reply
    print(f"Waiting for 'PONG' reply with matching hash for {LISTEN_TIMEOUT} seconds...")
    sender_socket.settimeout(LISTEN_TIMEOUT)

    try:
        data, addr = sender_socket.recvfrom(BUFFER_SIZE)
        reply_message = data.decode('utf-8')
        print(f"Received reply: '{reply_message}' from {addr}")

        if reply_message.startswith("PONG:"):
            try:
                # Extract hash from PONG message
                received_hash = reply_message.split(":")[1]

                # Verify the hash
                if received_hash == MY_KEY_HASH:
                    print(f"\n*** SUCCESS: Discovered Receiver at IP: {addr[0]} (Hash Matched!) ***")
                else:
                    print(f"\n--- FAILED: Received PONG but hash mismatch! ---")
                    print(f"    Expected: {MY_KEY_HASH[:8]}...")
                    print(f"    Received: {received_hash[:8]}...")

            except IndexError:
                 print(f"\n--- FAILED: Received PONG but couldn't parse hash ---")
        else:
            print(f"\n--- FAILED: Received unexpected reply format (not PONG:) ---")

    except socket.timeout:
        print(f"\n--- FAILED: No 'PONG' reply received within {LISTEN_TIMEOUT} seconds ---")
    except UnicodeDecodeError:
        print(f"\n--- FAILED: Received non-UTF8 reply ---")
    except Exception as e:
        print(f"\n--- ERROR receiving reply: {e} ---")

except OSError as e:
    print(f"\n--- ERROR setting up socket (binding/broadcast): {e} ---")
    print("    Check permissions (sudo?) or if port is in use.")
except Exception as e:
    print(f"\n--- UNEXPECTED ERROR: {e} ---")
finally:
    if sender_socket:
        sender_socket.close()
        print("Sender socket closed.")