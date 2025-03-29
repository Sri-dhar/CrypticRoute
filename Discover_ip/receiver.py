#!/usr/bin/env python3
import socket
import time
import hashlib

LISTEN_ADDR = "" # Listen on all interfaces
DISCOVERY_PORT = 60001 # Port to listen on for broadcasts
BUFFER_SIZE = 1024

# --- Key and Hash ---
# Must be the SAME key as the sender
SECRET_KEY = b"my-secret-udp-key-123"
KEY_HASH_ALGO = 'sha256'

def calculate_key_hash(key_data):
    hasher = hashlib.new(KEY_HASH_ALGO)
    hasher.update(key_data)
    return hasher.hexdigest()

MY_KEY_HASH = calculate_key_hash(SECRET_KEY)
# --------------------

# Prepare the reply message (including our hash)
MY_REPLY = f"PONG:{MY_KEY_HASH}".encode('utf-8')

print("Receiver starting...")
print(f"My Key Hash: {MY_KEY_HASH[:8]}...")
print(f"Listening for 'PING' broadcasts on port {DISCOVERY_PORT}")

receiver_socket = None
try:
    # Create UDP socket
    receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Allow reuse of address
    receiver_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to the discovery port
    receiver_socket.bind((LISTEN_ADDR, DISCOVERY_PORT))
    print(f"Socket bound to ('', {DISCOVERY_PORT})")

    while True:
        print("\nWaiting to receive broadcast...")
        try:
            # Wait for a broadcast packet
            data, addr = receiver_socket.recvfrom(BUFFER_SIZE)
            message = data.decode('utf-8')
            sender_ip = addr[0]
            print(f"Received message: '{message}' from {addr}")

            # Check if it's our expected PING format
            if message.startswith("PING:"):
                try:
                    # Parse the message: PING:<hash>:<port>
                    parts = message.split(":")
                    if len(parts) == 3:
                        received_hash = parts[1]
                        sender_reply_port_str = parts[2]
                        sender_reply_port = int(sender_reply_port_str)

                        print(f"  Parsed Ping: Hash={received_hash[:8]}..., ReplyPort={sender_reply_port}")

                        # *** Verify Key Hash ***
                        if received_hash == MY_KEY_HASH:
                            print(f"  Hash MATCHED!")
                            print(f"\n*** SUCCESS: Discovered Sender at IP: {sender_ip} ***")
                            print(f"    Sender wants reply on port: {sender_reply_port}")

                            # Send the PONG reply (containing our hash) directly back
                            print(f"Sending '{MY_REPLY.decode()}' reply to {sender_ip}:{sender_reply_port}...")
                            receiver_socket.sendto(MY_REPLY, (sender_ip, sender_reply_port))
                            print("Reply sent.")

                            # Optional: Exit after finding one sender
                            # break
                        else:
                            print(f"  Hash MISMATCH! Ignoring PING.")
                            print(f"    Expected: {MY_KEY_HASH[:8]}...")
                            print(f"    Received: {received_hash[:8]}...")
                    else:
                        print(f"  Ignoring: Invalid PING format (expected 3 parts separated by ':').")

                except ValueError:
                    print(f"  Ignoring: Could not parse reply port as integer from message '{message}'.")
                except IndexError:
                     print(f"  Ignoring: Could not parse message parts from '{message}'.")
                except OSError as e:
                     print(f"    Error sending reply to {sender_ip}:{sender_reply_port}. Error: {e}")
            else:
                print("    Ignoring: Message was not a valid 'PING:'.")

        except UnicodeDecodeError:
            print(f"    Ignoring: Received non-UTF-8 data from {addr}")
        except Exception as e:
            print(f"\n--- ERROR during receive/process loop: {e} ---")
            time.sleep(1) # Avoid busy-looping


except OSError as e:
    print(f"\n--- ERROR setting up socket (binding): {e} ---")
    print(f"    Check permissions (sudo?) or if port {DISCOVERY_PORT} is in use.")
except Exception as e:
    print(f"\n--- UNEXPECTED ERROR: {e} ---")
finally:
    if receiver_socket:
        receiver_socket.close()
        print("Receiver socket closed.")