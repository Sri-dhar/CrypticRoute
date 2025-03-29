
#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure, acknowledgment system, and IP discovery.
"""

import sys
import os
import argparse
import time
import hashlib
import binascii
import threading
import json
import datetime
import random
import socket # Added for UDP discovery
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, sniff, conf, send

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size in bytes
DISCOVERY_PORT = 54321 # UDP port for discovery (must match sender)
DISCOVERY_MAGIC_BEACON = b"CRYPTRT_DISC_v1:" # Magic bytes for discovery beacon
DISCOVERY_MAGIC_ACK = b"CRYPTRT_ACK_v1:"   # Magic bytes for discovery ack

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
total_chunks_expected = 0 # Learned from first valid data packet
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None  # Will store the discovered sender's IP
sender_port = None # Will store the sender's TCP source port (learned during handshake)
ack_sent_chunks = set()  # Keep track of chunks we've acknowledged
stop_sniffing_event = threading.Event() # Event to signal sniffing thread to stop

# Output directory structure
OUTPUT_DIR = "stealth_output"
SESSION_DIR = ""  # Will be set based on timestamp
LOGS_DIR = ""     # Will be set based on session dir
DATA_DIR = ""     # Will be set based on session dir
CHUNKS_DIR = ""   # Will be set based on session dir

# Debug log file
DEBUG_LOG = ""  # Will be set based on logs dir

def setup_directories():
    """Create organized directory structure for outputs."""
    global OUTPUT_DIR, SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG

    # Create main output directory if it doesn't exist
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # Create a timestamped session directory
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"receiver_session_{timestamp}")
    os.makedirs(SESSION_DIR)

    # Create subdirectories
    LOGS_DIR = os.path.join(SESSION_DIR, "logs")
    DATA_DIR = os.path.join(SESSION_DIR, "data")
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks")

    os.makedirs(LOGS_DIR)
    os.makedirs(DATA_DIR)
    os.makedirs(CHUNKS_DIR)

    # Create raw and cleaned chunks directories
    os.makedirs(os.path.join(CHUNKS_DIR, "raw"))
    os.makedirs(os.path.join(CHUNKS_DIR, "cleaned"))

    # Set debug log path
    DEBUG_LOG = os.path.join(LOGS_DIR, "receiver_debug.log")

    # Initialize debug log file here
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Receiver Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")


    # Create or update symlink to the latest session for convenience
    latest_link = os.path.join(OUTPUT_DIR, "receiver_latest")

    # More robust handling of existing symlink
    try:
        # Remove existing symlink if it exists
        if os.path.islink(latest_link):
            os.unlink(latest_link)
        # If it's a regular file or directory, rename it
        elif os.path.exists(latest_link):
            backup_name = f"{latest_link}_{int(time.time())}"
            os.rename(latest_link, backup_name)
            print(f"Renamed existing file to {backup_name}")

        # Create new symlink
        os.symlink(SESSION_DIR, latest_link)
        print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e:
        print(f"Warning: Could not create symlink: {e}")
        # Continue without the symlink - this is not critical

    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    # Ensure log file exists if setup_directories hasn't run when this is first called
    if not DEBUG_LOG:
        temp_log_path = "receiver_debug_early.log"
        with open(temp_log_path, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] [EARLY] {message}\n")
        return

    with open(DEBUG_LOG, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

# def listen_for_sender(key_hash_hex, discovery_port):
#     """Listens for the sender's UDP beacon and responds."""
#     key_hash = bytes.fromhex(key_hash_hex)
#     ack_payload = DISCOVERY_MAGIC_ACK + key_hash

#     print(f"[DISCOVERY] Listening for sender beacon on UDP port {discovery_port}...")
#     log_debug(f"[DISCOVERY] Listening for beacon. Key hash: {key_hash_hex}")

#     # Create UDP socket and bind
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     try:
#         sock.bind(('', discovery_port)) # Listen on all interfaces
#         log_debug(f"[DISCOVERY] Socket bound to port {discovery_port}")
#     except OSError as e:
#         print(f"[ERROR] Could not bind to UDP port {discovery_port}: {e}")
#         print("Check if another process is using the port.")
#         log_debug(f"[DISCOVERY] Failed to bind UDP socket: {e}")
#         sock.close()
#         return None

#     found_sender_ip = None
#     try:
#         while True: # Listen indefinitely until valid beacon received
#             try:
#                 data, addr = sock.recvfrom(1024) # Buffer size 1024 bytes
#                 sender_ip_candidate = addr[0]
#                 sender_comm_port = addr[1] # Sender's source port for UDP beacon
#                 log_debug(f"[DISCOVERY] Received UDP packet from {addr}: {data.hex()}")

#                 # Check if it's the beacon we expect
#                 if data.startswith(DISCOVERY_MAGIC_BEACON):
#                     received_hash = data[len(DISCOVERY_MAGIC_BEACON):]
#                     if received_hash == key_hash:
#                         found_sender_ip = sender_ip_candidate
#                         print(f"[DISCOVERY] Valid beacon received from {found_sender_ip}!")
#                         log_debug(f"[DISCOVERY] Valid beacon received from {found_sender_ip}:{sender_comm_port}. Sending ACK.")

#                         # Send ACK back to the sender's IP and originating port
#                         ack_target_addr = (found_sender_ip, discovery_port) # Send ACK to the discovery port sender listens on
#                         # Send multiple ACKs for reliability
#                         for i in range(5):
#                             print(f"[DISCOVERY] Sending ACK ({i+1}/5) to {ack_target_addr}...")
#                             log_debug(f"Sending discovery ACK {i+1}/5 to {ack_target_addr}")
#                             sock.sendto(ack_payload, ack_target_addr)
#                             time.sleep(0.1)

#                         print("[DISCOVERY] Acknowledgment sent. Discovery complete.")
#                         log_debug("[DISCOVERY] ACK sent. Discovery finished.")
#                         break # Exit the loop once sender is found and ACK'd
#                     else:
#                         log_debug(f"[DISCOVERY] Received beacon with mismatching hash from {addr}. Ignoring.")
#                 else:
#                      log_debug(f"[DISCOVERY] Received non-beacon UDP packet from {addr}. Ignoring.")

#             except Exception as e:
#                 log_debug(f"[DISCOVERY] Error receiving/processing UDP packet: {e}")
#                 time.sleep(0.1) # Avoid busy-looping on error

#     except KeyboardInterrupt:
#         print("\n[DISCOVERY] Discovery interrupted by user.")
#         log_debug("[DISCOVERY] Discovery interrupted by user.")
#     finally:
#         sock.close()
#         log_debug("[DISCOVERY] UDP socket closed.")

#     return found_sender_ip

def listen_for_sender(key_hash_hex, discovery_port):
    """Listens for the sender's UDP beacon and responds."""
    key_hash = bytes.fromhex(key_hash_hex)
    ack_payload = DISCOVERY_MAGIC_ACK + key_hash
    sock = None # Initialize

    print(f"[DISCOVERY] Listening for sender beacon on UDP port {discovery_port}...")
    log_debug(f"[DISCOVERY] Listening for beacon. Key hash: {key_hash_hex}")

    try:
        # Create UDP socket and bind
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('', discovery_port)) # Listen on all interfaces
            log_debug(f"[DISCOVERY] Receiver socket bound to port {discovery_port}")
        except OSError as e:
            print(f"[ERROR] Could not bind receiver to UDP port {discovery_port}: {e}")
            log_debug(f"[DISCOVERY] Failed to bind receiver UDP socket: {e}")
            if sock: sock.close()
            return None

        found_sender_ip = None
        sender_comm_port = None # Port the sender used for the beacon

        # Listen indefinitely until valid beacon received or interrupted
        while found_sender_ip is None:
            try:
                data, addr = sock.recvfrom(1024) # Buffer size 1024 bytes
                sender_ip_candidate = addr[0]
                sender_comm_port = addr[1] # Sender's source port for UDP beacon
                log_debug(f"[DISCOVERY] Received UDP packet from {addr}: {data.hex()}")

                # Check if it's the beacon we expect
                if data.startswith(DISCOVERY_MAGIC_BEACON):
                    received_hash = data[len(DISCOVERY_MAGIC_BEACON):]
                    if received_hash == key_hash:
                        found_sender_ip = sender_ip_candidate # Found it!
                        print(f"\n[DISCOVERY] Valid beacon received from {found_sender_ip} (port {sender_comm_port})!") # Added newline
                        log_debug(f"[DISCOVERY] Valid beacon received from {found_sender_ip}:{sender_comm_port}.")

                        # Determine target for ACK: Sender's IP, Discovery Port
                        ack_target_addr = (found_sender_ip, discovery_port)
                        # *** ADD DETAILED LOGGING HERE ***
                        log_debug(f"!!!!!! Preparing to send ACK payload {ack_payload.hex()} to TARGET: {ack_target_addr} !!!!!!!")
                        print(f"[DISCOVERY] Sending ACK back to {ack_target_addr}...")


                        # Send multiple ACKs for reliability
                        ack_send_count = 0
                        for i in range(5):
                            try:
                                bytes_sent = sock.sendto(ack_payload, ack_target_addr)
                                log_debug(f"Discovery ACK {i+1}/5 sent ({bytes_sent} bytes) to {ack_target_addr}")
                                ack_send_count += 1
                            except OSError as send_err:
                                log_debug(f"Error sending discovery ACK {i+1}/5 to {ack_target_addr}: {send_err}")
                                print(f"[DISCOVERY] Warning: Error sending ACK ({i+1}/5): {send_err}")
                            time.sleep(0.1)

                        if ack_send_count > 0:
                            print(f"[DISCOVERY] Sent {ack_send_count} ACKs. Discovery complete on receiver side.")
                            log_debug(f"Sent {ack_send_count} ACKs. Discovery finished.")
                        else:
                            print("[DISCOVERY] Error: Failed to send any ACKs.")
                            log_debug("Failed to send any discovery ACKs.")
                            # Should we abort? Maybe sender will retry beacon. Keep listening for now?
                            # For simplicity, let's break the inner loop but the outer 'return' handles it.
                            found_sender_ip = None # Reset so loop continues if needed, or exits function

                        # No need to break here, loop condition found_sender_ip is now set

                    else:
                        # Correct magic, wrong hash
                        log_debug(f"[DISCOVERY] Received beacon with mismatching hash from {addr}. Ignoring.")
                else:
                     # Wrong magic
                     log_debug(f"[DISCOVERY] Received non-beacon UDP packet from {addr}. Ignoring.")

            except socket.timeout:
                 # This shouldn't happen unless we set a timeout on the receiver socket
                 log_debug("[DISCOVERY] Receiver socket timed out (unexpected).")
                 continue # Continue listening
            except Exception as e:
                log_debug(f"[DISCOVERY] Error receiving/processing UDP packet: {e}")
                time.sleep(0.1) # Avoid busy-looping on error

    except KeyboardInterrupt:
        print("\n[DISCOVERY] Discovery listening interrupted by user.")
        log_debug("[DISCOVERY] Discovery listening interrupted by user.")
    except Exception as e:
         print(f"\n[DISCOVERY] An unexpected error occurred during receiver discovery: {e}")
         log_debug(f"[DISCOVERY] An unexpected error occurred during receiver discovery: {e}")
    finally:
        if sock:
            sock.close()
            log_debug("[DISCOVERY] Receiver discovery socket closed.")

    return found_sender_ip # Return the found IP or None

class SteganographyReceiver:
    """Simple steganography receiver using only TCP with acknowledgment."""

    def __init__(self):
        """Initialize the receiver."""
        # Initialize debug file for received chunks
        chunks_json = os.path.join(LOGS_DIR, "received_chunks.json")
        with open(chunks_json, "w") as f:
            f.write("{}")
        self.chunks_json_path = chunks_json

        # Use a random high port for our side of TCP connections (SYN-ACK source, Data ACK source)
        self.my_port = random.randint(10000, 60000)
        log_debug(f"Receiver initialized. Will use TCP source port {self.my_port} for ACKs.")


        # Create debug file for sent ACKs
        acks_json = os.path.join(LOGS_DIR, "sent_acks.json")
        with open(acks_json, "w") as f:
            f.write("{}")
        self.acks_json_path = acks_json
        self.sent_acks = {}

    def log_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        # Load existing file safely
        chunk_info = {}
        try:
            # Check if file exists and is not empty before loading
            if os.path.exists(self.chunks_json_path) and os.path.getsize(self.chunks_json_path) > 0:
                with open(self.chunks_json_path, "r") as f:
                    chunk_info = json.load(f)
        except json.JSONDecodeError:
            log_debug(f"Warning: Could not decode existing chunks JSON file '{self.chunks_json_path}'. Starting fresh.")
        except FileNotFoundError:
            pass # File doesn't exist yet, that's fine

        # Add this chunk
        chunk_info[str(seq_num)] = {
            "data": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }

        # Save back to file
        try:
            with open(self.chunks_json_path, "w") as f:
                json.dump(chunk_info, f, indent=2)
        except Exception as e:
            log_debug(f"Error writing to chunks JSON file: {e}")


        # Also save the raw chunk data
        try:
            chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:03d}.bin")
            with open(chunk_file, "wb") as f:
                f.write(data)
        except Exception as e:
             log_debug(f"Error writing raw chunk file for seq {seq_num}: {e}")


    def log_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks[str(seq_num)] = {
            "timestamp": time.time()
        }
        try:
            with open(self.acks_json_path, "w") as f:
                json.dump(self.sent_acks, f, indent=2)
        except Exception as e:
             log_debug(f"Error writing ACKs JSON file: {e}")

    def create_ack_packet(self, seq_num):
        """Create a TCP ACK packet for a specific data chunk sequence number."""
        global sender_ip, sender_port # Use discovered sender IP and learned sender TCP port

        if not sender_ip or not sender_port:
            log_debug("Cannot create data ACK - sender IP or TCP Port information missing")
            print("[ERROR] Cannot create data ACK - sender IP/Port unknown")
            return None

        # Create an ACK packet with special markers
        # Use a specific bit pattern in seq and ack fields
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port,
            dport=sender_port,
            seq=0x12345678,  # Fixed pattern to identify this as a Data ACK
            ack=seq_num,     # Use the ack field to specify which chunk we're acknowledging
            window=0xCAFE,   # Special window value for Data ACKs
            flags="A"        # ACK flag
        )
        log_debug(f"Created Data ACK packet for chunk {seq_num} to {sender_ip}:{sender_port}")
        return ack_packet

    def send_ack(self, seq_num):
        """Send an acknowledgment for a specific sequence number."""
        global ack_sent_chunks

        # Skip if we've already ACKed this chunk recently (simple flood prevention)
        # A more robust system might allow re-ACKing if sender keeps retransmitting
        if seq_num in ack_sent_chunks:
            log_debug(f"Already sent ACK for chunk {seq_num}, skipping.")
            return

        # Create the ACK packet
        ack_packet = self.create_ack_packet(seq_num)
        if not ack_packet:
            return # Error logged in create_ack_packet

        # Log and send the ACK
        log_debug(f"Sending ACK for chunk {seq_num}")
        print(f"[ACK] Sending acknowledgment for chunk {seq_num:04d}")
        self.log_ack(seq_num) # Log the ACK *before* sending

        # Send the ACK packet multiple times for reliability (UDP nature of underlying layer)
        for i in range(3):  # Send 3 times
            send(ack_packet)
            time.sleep(0.05)  # Small delay between retransmissions

        # Mark this chunk as acknowledged locally
        ack_sent_chunks.add(seq_num)

    def create_syn_ack_packet(self):
        """Create a TCP SYN-ACK packet for connection establishment."""
        global sender_ip, sender_port # Use discovered IP and learned TCP port

        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender IP or TCP Port information missing")
            print("[ERROR] Cannot create SYN-ACK - sender IP/Port unknown")
            return None

        # Create a SYN-ACK packet with special markers
        # Needs to correctly acknowledge the sender's SYN sequence number
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port,
            dport=sender_port,
            seq=0xABCDEF12,      # Our initial sequence number for the SYN-ACK
            ack=0x12345678 + 1,  # Acknowledge sender's SYN seq (0x12345678) + 1
            window=0xBEEF,       # Special window value for handshake SYN-ACK
            flags="SA"           # SYN-ACK flags
        )
        log_debug(f"Created SYN-ACK packet for {sender_ip}:{sender_port}")
        return syn_ack_packet

    def send_syn_ack(self):
        """Send a SYN-ACK response for connection establishment."""
        # Create the SYN-ACK packet
        syn_ack_packet = self.create_syn_ack_packet()
        if not syn_ack_packet:
            return # Error logged in create_syn_ack_packet

        # Log and send the SYN-ACK
        log_debug("Sending SYN-ACK for connection establishment")
        print("[HANDSHAKE] Sending SYN-ACK response")

        # Send the SYN-ACK packet multiple times for reliability
        for i in range(5):  # Send 5 times to ensure receipt
            send(syn_ack_packet)
            time.sleep(0.1)  # Small delay between retransmissions


    def packet_handler(self, packet):
        """Wrapper for process_packet that handles global state and logging."""
        global packet_counter, last_activity_time, transmission_complete

        # Immediately discard if stop event is set
        if stop_sniffing_event.is_set():
             return

        # Update activity time regardless of packet validity
        last_activity_time = time.time()

        # Increment total packet counter
        packet_counter += 1

        # Basic filtering: Must be IP/TCP and from the discovered sender IP
        if not (IP in packet and TCP in packet):
            # log_debug(f"Packet #{packet_counter}: Ignored (Not IP/TCP)") # Too verbose
            return
        if packet[IP].src != sender_ip:
            # log_debug(f"Packet #{packet_counter}: Ignored (Wrong source IP: {packet[IP].src})") # Too verbose
            return

        # Print status periodically
        if packet_counter % 20 == 0 or packet_counter < 10:
             progress_perc = (len(received_chunks) / total_chunks_expected * 100) if total_chunks_expected > 0 else 0
             print(f"\r[STATUS] Pkts: {packet_counter:6d} | Valid: {valid_packet_counter:4d} | Chunks: {len(received_chunks):4d}/{total_chunks_expected:4d} ({progress_perc:3.0f}%) | Conn: {'Yes' if connection_established else 'No '}", end="")


        # Call the actual processing function
        processed = self.process_packet(packet)

        # If process_packet signals completion, set the global flag and stop event
        if processed == "COMPLETED":
            transmission_complete = True
            stop_sniffing_event.set()
            print("\n[INFO] Transmission complete signal received. Stopping sniffer.")
            log_debug("Transmission complete signal processed. Stopping sniffer.")


    def process_packet(self, packet):
        """Process a valid TCP packet from the sender."""
        # Assumes packet is IP/TCP and from sender_ip (checked in handler)
        global received_chunks, reception_start_time, last_activity_time
        global highest_seq_num, valid_packet_counter, total_chunks_expected
        global connection_established, sender_ip, sender_port

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        # Learn sender's TCP source port if not already known (from SYN or first data packet)
        if sender_port is None and tcp_layer.sport != 0:
            sender_port = tcp_layer.sport
            log_debug(f"Learned sender TCP source port: {sender_port}")
            print(f"\n[HANDSHAKE] Learned sender port: {sender_port}")


        # --- Handshake Packet Handling ---

        # 1. Check for connection establishment request (SYN packet)
        # Matches sender's create_syn_packet: SYN flag, specific window, specific seq
        if not connection_established and tcp_layer.flags & 0x02 and tcp_layer.window == 0xDEAD and tcp_layer.seq == 0x12345678:
            log_debug(f"Received connection establishment request (SYN) from {ip_layer.src}:{tcp_layer.sport}")
            print("\n[HANDSHAKE] Received connection request (SYN)")

            # Store sender's TCP port if learned here
            if sender_port != tcp_layer.sport:
                 log_debug(f"Handshake SYN source port {tcp_layer.sport} differs from previously learned {sender_port}. Updating.")
                 sender_port = tcp_layer.sport

            # Send SYN-ACK response
            self.send_syn_ack()
            # Do not mark connection established yet, wait for final ACK from sender
            return True # Packet processed


        # 2. Check for sender's final ACK confirming connection
        # Matches sender's create_ack_packet: ACK flag, specific window, specific seq/ack
        if not connection_established and tcp_layer.flags & 0x10 and tcp_layer.window == 0xF00D \
           and tcp_layer.seq == 0x87654321 and tcp_layer.ack == 0xABCDEF12 + 1: # Acks our SYN-ACK seq+1
            log_debug(f"Received connection confirmation (Handshake ACK) from {ip_layer.src}:{tcp_layer.sport}")
            print("\n[HANDSHAKE] Connection established with sender")
            connection_established = True
            # Record start time when connection is fully established
            if reception_start_time == 0:
                 reception_start_time = time.time()
                 log_debug(f"Reception timer started at {reception_start_time}")
            return True # Packet processed


        # --- Data and Completion Packet Handling (Requires established connection) ---
        if not connection_established:
            # log_debug(f"Ignored packet from {ip_layer.src}:{tcp_layer.sport} - Connection not yet established.")
            return False # Ignore other packets until connection is up

        # 3. Check for completion signal (FIN packet)
        # Matches sender's create_completion_packet: FIN flag, specific window
        if tcp_layer.flags & 0x01 and tcp_layer.window == 0xFFFF:
            log_debug(f"Received transmission complete signal (FIN) from {ip_layer.src}:{tcp_layer.sport}")
            # This signals the *end* of the transmission.
            # The handler wrapper will set global flags based on return value.
            return "COMPLETED" # Special return value for completion


        # 4. Check for Data Packet
        # Matches sender's create_packet: SYN flag (used for data), seq/ack carry data, window carries seq_num
        # We also rely on the source IP filter.
        # Check for SYN flag (used for data packets in this protocol)
        # Check if window could be a sequence number (e.g., > 0 and not the handshake/completion values)
        is_potential_data = False
        if tcp_layer.flags & 0x02: # SYN flag must be set
             if tcp_layer.window > 0 and tcp_layer.window not in [0xDEAD, 0xBEEF, 0xF00D, 0xFFFF, 0xCAFE]:
                  is_potential_data = True

        if is_potential_data:
            seq_num = tcp_layer.window # Sequence number is in the window field

            # Extract total chunks from MSS option (should be present in data packets)
            current_total_chunks = None
            try:
                for option in tcp_layer.options:
                    if isinstance(option, tuple) and option[0] == 'MSS':
                        current_total_chunks = option[1]
                        break
            except Exception as e:
                 log_debug(f"Error parsing TCP options for packet seq {seq_num}: {e}")


            # If MSS option is missing, maybe it's not our data packet after all
            if current_total_chunks is None:
                log_debug(f"Ignored potential data packet (seq {seq_num}): Missing MSS option.")
                return False

            # Store the total expected chunks if we learn it for the first time
            global total_chunks_expected
            if total_chunks_expected == 0 and current_total_chunks > 0:
                total_chunks_expected = current_total_chunks
                print(f"\n[INFO] Learned total expected chunks: {total_chunks_expected}")
                log_debug(f"Learned total expected chunks: {total_chunks_expected}")
            elif total_chunks_expected > 0 and current_total_chunks != total_chunks_expected:
                 log_debug(f"Warning: Packet seq {seq_num} MSS ({current_total_chunks}) differs from expected total ({total_chunks_expected})")
                 # Decide how to handle this - maybe ignore the packet? For now, just log.


            # We have a plausible data packet
            valid_packet_counter += 1
            log_debug(f"Processing potential data packet (Seq: {seq_num}, Total: {current_total_chunks})")

            # Extract data from sequence and acknowledge numbers
            # Handle potential size differences if seq/ack are not full 4 bytes
            try:
                 seq_bytes = tcp_layer.seq.to_bytes(4, byteorder='big', signed=False)
                 ack_bytes = tcp_layer.ack.to_bytes(4, byteorder='big', signed=False)
                 data = seq_bytes + ack_bytes
            except OverflowError:
                 log_debug(f"Warning: Seq ({tcp_layer.seq}) or Ack ({tcp_layer.ack}) number too large for 4 bytes in packet {seq_num}. Skipping.")
                 return False


            # Extract checksum from IP ID
            checksum = ip_layer.id

            # Verify checksum
            calc_checksum = binascii.crc32(data) & 0xFFFF
            if checksum != calc_checksum:
                log_debug(f"Checksum MISMATCH for chunk {seq_num}. Expected={checksum:04x}, Calculated={calc_checksum:04x}. Data={data.hex()}")
                print(f"\n[WARN] Checksum mismatch for chunk {seq_num:04d}! Data may be corrupt.")
                # Decide whether to store corrupt data or discard. Currently storing.
            else:
                log_debug(f"Checksum VALID for chunk {seq_num} ({checksum:04x})")


            # Check for duplicates before storing
            if seq_num in received_chunks:
                log_debug(f"Received duplicate chunk {seq_num}. Re-sending ACK.")
                print(f"\n[DUPLICATE] Chunk {seq_num:04d} received again.")
                # Still send an ACK again, sender probably missed the first one
                self.send_ack(seq_num)
                return True # Packet processed (as a duplicate)


            # Store the chunk (even if checksum failed, maybe partial recovery is possible)
            log_debug(f"Storing chunk {seq_num} (Size: {len(data)})")
            received_chunks[seq_num] = data
            self.log_chunk(seq_num, data) # Log to files

            # Send acknowledgment for this chunk
            self.send_ack(seq_num)

            # Update highest sequence number seen
            if seq_num > highest_seq_num:
                highest_seq_num = seq_num
                log_debug(f"New highest sequence number seen: {highest_seq_num}")

            # Print detailed info (avoid printing inside the status line update)
            progress = (len(received_chunks) / total_chunks_expected) * 100 if total_chunks_expected > 0 else 0
            chunk_info_str = f"Received: {seq_num:04d}/{total_chunks_expected:04d} | Total: {len(received_chunks):04d}/{total_chunks_expected:04d} | Progress: {progress:.1f}%"
            print(f"\n[CHUNK] {chunk_info_str} {'(Checksum OK)' if checksum == calc_checksum else '(CHECKSUM FAIL)'}")
            log_debug(f"[CHUNK] {chunk_info_str}")

            return True # Data packet processed

        # If the packet was from the sender and connection is established, but didn't match any pattern
        log_debug(f"Ignored unexpected packet from {ip_layer.src}:{tcp_layer.sport}. Flags={tcp_layer.flags:#x}, Window={tcp_layer.window:#x}, Seq={tcp_layer.seq:#x}, Ack={tcp_layer.ack:#x}")
        return False # Packet not processed by our logic

# --- Functions for post-reception processing (unchanged from original) ---

def prepare_key(key_data):
    """Prepare the encryption key in correct format and return bytes and hex hash."""
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')

    is_hex = False
    try:
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             key_bytes_from_hex = bytes.fromhex(key_data.decode('ascii'))
             key_data = key_bytes_from_hex
             is_hex = True
             log_debug("Interpreted key data as hex string and converted to bytes")
             print("Interpreted key data as hex string.")
    except ValueError:
        pass # Not a valid hex string

    original_len = len(key_data)
    if original_len < 32:
        key_data = key_data.ljust(32, b'\0')
        log_debug(f"Key padded from {original_len} bytes to 32 bytes.")
    elif original_len > 32:
        key_data = key_data[:32]
        log_debug(f"Key truncated from {original_len} bytes to 32 bytes.")

    log_debug(f"Final key bytes (used for decryption): {key_data.hex()}")

    key_file = os.path.join(DATA_DIR, "key.bin")
    with open(key_file, "wb") as f:
        f.write(key_data)

    key_hash = hashlib.sha256(key_data).digest()
    key_hash_hex = key_hash.hex()
    log_debug(f"Key hash (SHA256 for discovery): {key_hash_hex}")
    print(f"[KEY] Key Hash (SHA256): {key_hash_hex}")

    return key_data, key_hash_hex


def decrypt_data(data, key):
    """Decrypt data using AES."""
    # Data should be IV + Ciphertext
    iv_len = 16 # AES block size / IV size
    if len(data) < iv_len:
        log_debug(f"Decryption error: Data length ({len(data)}) is less than IV length ({iv_len}).")
        print("[DECRYPT] Error: Data too short to contain IV.")
        return None

    try:
        iv = data[:iv_len]
        encrypted_data = data[iv_len:]

        log_debug(f"Extracted IV: {iv.hex()}")
        log_debug(f"Encrypted data size for decryption: {len(encrypted_data)} bytes")

        # Save components for debugging
        iv_file = os.path.join(DATA_DIR, "extracted_iv.bin")
        with open(iv_file, "wb") as f: f.write(iv)
        encrypted_file = os.path.join(DATA_DIR, "encrypted_data_for_decryption.bin")
        with open(encrypted_file, "wb") as f: f.write(encrypted_data)

        # Initialize AES cipher with key and extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Save for debugging
        decrypted_file = os.path.join(DATA_DIR, "decrypted_data.bin")
        with open(decrypted_file, "wb") as f: f.write(decrypted_data)

        log_debug(f"Decryption successful. Decrypted data size: {len(decrypted_data)}")
        # log_debug(f"Decrypted data sample hex: {decrypted_data[:32].hex() if len(decrypted_data) > 0 else ''}")

        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"[DECRYPT] Decryption error: {e}")
        return None

def verify_data_integrity(data):
    """Verify the integrity of reassembled data using MD5 checksum."""
    if len(data) < INTEGRITY_CHECK_SIZE:
        log_debug(f"Integrity check error: Data length ({len(data)}) is less than checksum size ({INTEGRITY_CHECK_SIZE}).")
        print("[VERIFY] Error: Data too short to contain integrity checksum.")
        return None, False # Return None for data, False for validity

    # Extract the data and checksum
    payload_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]

    log_debug(f"Verifying integrity. Payload size: {len(payload_data)}, Received checksum: {received_checksum.hex()}")

    # Save components for debugging
    data_file = os.path.join(DATA_DIR, "data_before_checksum_verification.bin")
    with open(data_file, "wb") as f: f.write(payload_data)
    checksum_file = os.path.join(DATA_DIR, "received_checksum.bin")
    with open(checksum_file, "wb") as f: f.write(received_checksum)

    # Calculate checksum of the payload data
    calculated_checksum = hashlib.md5(payload_data).digest()
    log_debug(f"Calculated checksum: {calculated_checksum.hex()}")

    # Save the calculated checksum
    calc_checksum_file = os.path.join(DATA_DIR, "calculated_checksum.bin")
    with open(calc_checksum_file, "wb") as f: f.write(calculated_checksum)

    # Compare checksums
    checksum_match = (calculated_checksum == received_checksum)

    # Save checksum comparison results
    checksum_info = {
        "expected_calculated": calculated_checksum.hex(),
        "received": received_checksum.hex(),
        "match": checksum_match
    }
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")
    with open(checksum_json, "w") as f: json.dump(checksum_info, f, indent=2)

    if checksum_match:
        log_debug("Data integrity verified successfully.")
        print("[VERIFY] Data integrity check successful.")
        return payload_data, True # Return payload data and True for validity
    else:
        log_debug("CHECKSUM MISMATCH: Data integrity check failed!")
        print("[VERIFY] Warning: Data integrity check FAILED! Checksums do not match.")
        # Return the payload data anyway, but signal failure
        return payload_data, False # Return payload data and False for validity


def reassemble_data():
    """Reassemble the received chunks in correct order."""
    global received_chunks, highest_seq_num # Use global highest_seq_num learned

    if not received_chunks:
        log_debug("Reassembly failed: No chunks received.")
        return None, 0 # Return None data, 0 missing count

    # Sort chunks by sequence number (keys are integers)
    print(f"[REASSEMBLY] Sorting {len(received_chunks)} received chunks...")
    log_debug(f"Reassembling {len(received_chunks)} chunks. Highest seq seen: {highest_seq_num}")
    sorted_seq_nums = sorted(received_chunks.keys())
    if not sorted_seq_nums:
         log_debug("Reassembly failed: Sorted sequence numbers list is empty.")
         return None, highest_seq_num

    # Determine the expected number of chunks
    # Use highest_seq_num as the best guess if total_chunks_expected wasn't learned
    expected_total = total_chunks_expected if total_chunks_expected > 0 else highest_seq_num
    if expected_total == 0 and sorted_seq_nums:
         expected_total = sorted_seq_nums[-1] # Fallback if highest_seq_num is also 0

    log_debug(f"Expected total chunks for gap check: {expected_total}")

    # Check for missing chunks based on the expected range 1 to expected_total
    missing_chunks_count = 0
    missing_chunks_list = []
    if expected_total > 0:
        present_chunks_set = set(sorted_seq_nums)
        for i in range(1, expected_total + 1):
            if i not in present_chunks_set:
                missing_chunks_count += 1
                if len(missing_chunks_list) < 20: # Log first 20 missing
                     missing_chunks_list.append(i)


    if missing_chunks_count > 0:
        log_debug(f"Warning: Detected {missing_chunks_count} missing chunks based on expected total {expected_total}.")
        print(f"[REASSEMBLY] Warning: Missing {missing_chunks_count} chunks!")
        if missing_chunks_list:
            log_debug(f"First missing chunks: {missing_chunks_list}")
            print(f"[REASSEMBLY] Missing chunks sample: {missing_chunks_list}")
    else:
        log_debug(f"No missing chunks detected up to expected total {expected_total}.")
        print("[REASSEMBLY] No missing chunks detected.")

    # Save diagnostic information
    print("[REASSEMBLY] Saving diagnostic info...")
    chunk_info = {
        "received_chunks_count": len(received_chunks),
        "highest_seq_num_seen": highest_seq_num,
        "total_chunks_expected_from_mss": total_chunks_expected,
        "final_expected_total_for_gap_check": expected_total,
        "missing_chunks_count": missing_chunks_count,
        "missing_chunks_sample": missing_chunks_list,
        "received_seq_nums": sorted_seq_nums # Can be large, consider limiting
    }
    reassembly_file = os.path.join(LOGS_DIR, "reassembly_info.json")
    with open(reassembly_file, "w") as f: json.dump(chunk_info, f, indent=2)

    # Assemble chunks in order
    print("[REASSEMBLY] Concatenating received chunks...")
    reassembled_list = []
    last_seq = 0
    for seq in sorted_seq_nums:
         # Optional: Check for gaps again during assembly
         if seq != last_seq + 1 and last_seq != 0:
              log_debug(f"Gap detected during assembly: Jump from {last_seq} to {seq}")
         reassembled_list.append(received_chunks[seq])
         last_seq = seq

    # Concatenate all chunks
    reassembled_data = b"".join(reassembled_list)
    log_debug(f"Reassembled data size: {len(reassembled_data)} bytes")

    # Save the raw reassembled data before cleaning/stripping
    reassembled_raw_file = os.path.join(DATA_DIR, "reassembled_data_raw.bin")
    with open(reassembled_raw_file, "wb") as f: f.write(reassembled_data)

    # --- Padding Removal ---
    # The sender pads the *last* chunk with nulls to reach MAX_CHUNK_SIZE.
    # We only need to potentially remove these trailing nulls from the *very end*
    # of the reassembled data, but only if the last received chunk's sequence number
    # matches the highest expected sequence number (meaning we likely got the *actual* last chunk).
    final_data = reassembled_data
    if sorted_seq_nums and expected_total > 0 and sorted_seq_nums[-1] == expected_total:
         # We received the chunk with the highest expected sequence number.
         # Check if the original size of this last chunk was less than MAX_CHUNK_SIZE.
         last_chunk_original = received_chunks[expected_total]
         if len(last_chunk_original) == MAX_CHUNK_SIZE:
             # It might have padding. Cautiously strip trailing nulls from the *entire* reassembled data.
             # Find the last non-null byte.
             last_non_null = -1
             for i in range(len(reassembled_data) - 1, -1, -1):
                  if reassembled_data[i] != 0:
                       last_non_null = i
                       break
             if last_non_null != -1:
                  original_total_len = len(final_data)
                  final_data = reassembled_data[:last_non_null + 1]
                  stripped_count = original_total_len - len(final_data)
                  if stripped_count > 0:
                       log_debug(f"Stripped {stripped_count} trailing null bytes based on receiving expected last chunk.")
                       print(f"[REASSEMBLY] Removed {stripped_count} likely padding bytes from the end.")
             else:
                  # Entire file was null bytes? Keep at least one.
                  final_data = b'\0'
                  log_debug("Warning: Reassembled data consisted entirely of null bytes. Kept one.")
         else:
              # Last received chunk was already smaller than MAX_CHUNK_SIZE, no padding added by sender.
              log_debug("Last received chunk was smaller than max size, no padding removal needed.")
    else:
         log_debug("Did not receive the expected last chunk or expected total is unknown. Skipping padding removal.")
         print("[REASSEMBLY] Could not confirm receipt of last chunk, skipping padding removal.")


    # Save the final reassembled data (potentially stripped)
    reassembled_final_file = os.path.join(DATA_DIR, "reassembled_data_final.bin")
    with open(reassembled_final_file, "wb") as f: f.write(final_data)

    print(f"[REASSEMBLY] Completed! Final data size: {len(final_data)} bytes")
    return final_data, missing_chunks_count


def save_to_file(data, output_path):
    """Save data to a file."""
    if data is None:
        log_debug("Save error: Data is None.")
        print("[SAVE] Error: Cannot save None data.")
        return False
    try:
        with open(output_path, 'wb') as file:
            file.write(data)
        log_debug(f"Final payload data saved to {output_path} ({len(data)} bytes)")
        print(f"[SAVE] Data successfully saved to: {output_path}")

        # Copy to the data directory as well for session archive
        output_name = os.path.basename(output_path)
        output_copy = os.path.join(DATA_DIR, f"output_{output_name}")
        with open(output_copy, "wb") as f: f.write(data)

        # Try to print the content as UTF-8 text (limited)
        try:
            text_content = data.decode('utf-8')
            preview = text_content[:200] # Limit preview size
            log_debug(f"Saved content preview (UTF-8): {preview}{'...' if len(text_content) > 200 else ''}")
            print(f"Saved content preview:\n---\n{preview}{'...' if len(text_content) > 200 else ''}\n---")

            # Save as text file for easy viewing if it decoded fully
            text_file = os.path.join(DATA_DIR, "output_content.txt")
            with open(text_file, "w", encoding='utf-8') as f: f.write(text_content)
        except UnicodeDecodeError:
            log_debug("Saved content is not valid UTF-8 text.")
            print("(Saved content is binary or non-UTF8 text)")

        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"[SAVE] Error saving data to {output_path}: {e}")
        return False


def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity."""
    global last_activity_time, transmission_complete # Use global transmission_complete

    log_debug(f"Monitor thread started. Inactivity timeout: {timeout}s")
    while not stop_event.is_set():
        # Check for inactivity timeout only if reception has started
        if reception_start_time > 0 and (time.time() - last_activity_time > timeout):
            log_debug(f"Inactivity timeout reached ({timeout} seconds). Signaling stop.")
            print(f"\n[TIMEOUT] Inactivity timeout reached ({timeout}s). Stopping.")
            transmission_complete = True # Mark as complete due to timeout
            stop_sniffing_event.set() # Signal sniffing thread to stop
            break

        # Sleep a bit to avoid consuming CPU
        time.sleep(1) # Check every second

    log_debug("Monitor thread stopped.")


def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Discover sender and receive a file via steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time
    global highest_seq_num, packet_counter, valid_packet_counter, connection_established
    global sender_ip, stop_sniffing_event, total_chunks_expected, ack_sent_chunks

    # Create a summary file with reception parameters
    summary = {
        "timestamp": time.time(),
        "output_path": output_path,
        "key_path": key_path,
        "interface": interface,
        "timeout": timeout,
        "discovery_port": DISCOVERY_PORT
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f: json.dump(summary, f, indent=2)

    # Reset global variables for this session
    received_chunks = {}
    transmission_complete = False
    reception_start_time = 0
    last_activity_time = time.time() # Initialize last activity time
    highest_seq_num = 0
    total_chunks_expected = 0
    packet_counter = 0
    valid_packet_counter = 0
    connection_established = False
    sender_ip = None
    sender_port = None
    ack_sent_chunks = set()
    stop_sniffing_event.clear() # Ensure stop event is clear

    # --- Key Processing and Discovery ---
    key_bytes = None
    key_hash_hex = None
    if key_path:
        log_debug(f"Reading key from: {key_path}")
        print(f"[KEY] Reading key file: {key_path}")
        try:
            with open(key_path, 'rb') as key_file:
                key_data_raw = key_file.read()
            key_bytes, key_hash_hex = prepare_key(key_data_raw)
            if not key_bytes or not key_hash_hex:
                 print("[ERROR] Failed to process key file.")
                 return False
        except Exception as e:
            log_debug(f"Error reading/processing key file {key_path}: {e}")
            print(f"[ERROR] Failed reading key file: {e}")
            return False
    else:
        # Key is required for discovery and potentially decryption
        print("[ERROR] Key file (--key) is required for receiver operation.")
        log_debug("Receiver cannot operate without a key file.")
        return False


    # Discover sender using UDP broadcast beacon
    discovered_ip = listen_for_sender(key_hash_hex, DISCOVERY_PORT)
    if not discovered_ip:
        print("[DISCOVERY] Failed to discover sender. Aborting.")
        log_debug("Discovery failed or was interrupted.")
        return False

    # Set the global sender IP
    sender_ip = discovered_ip
    print(f"[INFO] Sender identified at {sender_ip}. Proceeding with TCP reception.")
    log_debug(f"Sender IP set to {sender_ip}. Starting TCP sniff.")


    # --- TCP Reception ---
    stego = SteganographyReceiver() # Initialize receiver class

    # Start inactivity monitor thread
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(
        target=monitor_transmission,
        args=(stop_monitor, timeout) # Pass the stop event for the monitor itself
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    log_debug("Inactivity monitor thread started.")

    # Start packet capture for TCP packets from the discovered sender
    log_debug(f"Listening for TCP data from {sender_ip} on interface {interface or 'default'}...")
    print(f"Listening for TCP communication from {sender_ip}...")
    print("Press Ctrl+C to stop listening manually")

    try:
        # Filter specifically for TCP packets from the discovered sender IP
        filter_str = f"tcp and src host {sender_ip}"
        log_debug(f"Using Scapy filter: {filter_str}")

        # Start packet sniffing
        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.packet_handler, # Wrapper handles state and logging
            store=0,
            stop_filter=lambda p: stop_sniffing_event.is_set() # Stop when event is set
        )
        # Sniffing stops when stop_filter returns true (event set) or manually interrupted

    except KeyboardInterrupt:
        log_debug("Sniffing stopped by user (Ctrl+C).")
        print("\n[INFO] Sniffing stopped by user.")
        transmission_complete = True # Mark as complete as we are stopping reception
        stop_sniffing_event.set() # Ensure event is set if loop exited this way
    except Exception as e:
         log_debug(f"An error occurred during packet sniffing: {e}")
         print(f"\n[ERROR] Packet sniffing failed: {e}")
         transmission_complete = True # Assume completion/failure on error
         stop_sniffing_event.set()
    finally:
        stop_monitor.set() # Signal monitor thread to stop cleanly
        monitor_thread.join(1.0) # Wait briefly for monitor thread
        if monitor_thread.is_alive():
             log_debug("Warning: Monitor thread did not stop.")
        print("\n[INFO] Packet sniffing stopped.")
        log_debug("Packet sniffing process finished.")


    # --- Post-Reception Processing ---
    print("\n--- Post-Reception Processing ---")
    log_debug("Starting post-reception processing.")

    if not received_chunks:
        log_debug("No data chunks received.")
        print("[RESULT] No data chunks were received.")
        # Save completion info
        completion_info = {"completed_at": time.time(), "status": "failed", "reason": "no_chunks"}
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
        return False


    # Calculate reception statistics
    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)
    # Use expected total learned from packets if available
    final_expected_total = total_chunks_expected if total_chunks_expected > 0 else highest_seq_num

    reception_rate = (chunk_count / final_expected_total * 100) if final_expected_total > 0 else (100 if chunk_count > 0 else 0)
    missing_count = (final_expected_total - chunk_count) if final_expected_total > 0 else 0

    stats = {
        "total_packets_processed": packet_counter,
        "valid_steg_packets_identified": valid_packet_counter,
        "unique_chunks_received": chunk_count,
        "highest_seq_num_seen": highest_seq_num,
        "total_chunks_expected_from_mss": total_chunks_expected,
        "final_expected_total_used_for_stats": final_expected_total,
        "reception_duration_seconds": duration,
        "chunk_reception_rate_percent": reception_rate,
        "estimated_missing_chunks": missing_count,
        "connection_established": connection_established,
        "transmission_complete_signal_received": transmission_complete and not stop_monitor.is_set() # True if FIN received
    }

    stats_file = os.path.join(LOGS_DIR, "reception_stats.json")
    with open(stats_file, "w") as f: json.dump(stats, f, indent=2)

    log_debug(f"Reception summary: {stats}")
    print("\n[STATS] Reception Summary:")
    print(f"- Processed {packet_counter} total packets from sender.")
    print(f"- Identified {valid_packet_counter} valid steg packets.")
    print(f"- Received {chunk_count} unique data chunks.")
    print(f"- Expected ~{final_expected_total} chunks.")
    print(f"- Reception Rate: {reception_rate:.1f}%")
    if missing_count > 0: print(f"- Estimated Missing: {missing_count} chunks")
    print(f"- Duration: {duration:.2f} seconds")


    # Reassemble the data
    log_debug("Reassembling data chunks...")
    print("[REASSEMBLY] Reassembling received data...")
    reassembled_data, reassembly_missing_count = reassemble_data()

    if reassembled_data is None:
        log_debug("Reassembly failed.")
        print("[RESULT] Failed to reassemble data.")
        completion_info = {"completed_at": time.time(), "status": "failed", "reason": "reassembly_failed", **stats}
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
        return False

    log_debug(f"Reassembled {len(reassembled_data)} bytes. Missing count from reassembly: {reassembly_missing_count}")
    print(f"[REASSEMBLY] Reassembled {len(reassembled_data)} bytes.")


    # Verify data integrity using checksum (applied before potential decryption)
    print("[VERIFY] Verifying data integrity...")
    payload_data, checksum_ok = verify_data_integrity(reassembled_data)

    if payload_data is None:
         log_debug("Integrity check failed critically (payload is None).")
         print("[RESULT] Failed integrity check critically.")
         completion_info = {"completed_at": time.time(), "status": "failed", "reason": "integrity_check_failed", **stats}
         completion_path = os.path.join(LOGS_DIR, "completion_info.json")
         with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
         return False

    data_to_process = payload_data # Use the data part, regardless of checksum status

    if not checksum_ok:
        log_debug("Integrity check failed, proceeding with potentially corrupt data.")
        print("[VERIFY] Warning: Checksum mismatch! Data might be corrupt.")
    else:
         log_debug("Integrity check successful.")
         print("[VERIFY] Data integrity check passed.")


    # Decrypt the data if key was provided (which it must have been for receiver)
    final_data = data_to_process
    decryption_status = "not_attempted"
    if key_bytes: # Should always be true if we got here
        log_debug("Decrypting data...")
        print("[DECRYPT] Decrypting data...")
        decrypted_result = decrypt_data(data_to_process, key_bytes)

        if decrypted_result is None:
            log_debug("Decryption failed. Output will be the raw (potentially corrupt) payload.")
            print("[DECRYPT] Error: Decryption failed! Saving raw payload instead.")
            final_data = data_to_process # Keep the undecrypted payload
            decryption_status = "failed"
        else:
            log_debug(f"Decryption successful. Final data size: {len(decrypted_result)}")
            print(f"[DECRYPT] Decryption successful. Result size: {len(decrypted_result)} bytes.")
            final_data = decrypted_result
            decryption_status = "success"
    else:
         # This case shouldn't be reachable due to earlier checks
         log_debug("Internal logic error: Reached decryption step without key bytes.")
         print("[ERROR] Internal error: No key available for decryption.")
         decryption_status = "key_missing"


    # Save the final data (decrypted or raw payload)
    print(f"[SAVE] Saving final data to {output_path}...")
    save_success = save_to_file(final_data, output_path)

    # Determine overall status
    overall_status = "unknown"
    if save_success:
        if decryption_status == "success" and checksum_ok and missing_count == 0 and reassembly_missing_count == 0:
             overall_status = "completed_perfect"
        elif decryption_status == "success" and checksum_ok:
             overall_status = "completed_with_missing_chunks"
        elif decryption_status == "success": # Checksum failed or missing chunks
             overall_status = "completed_decrypted_potential_errors"
        elif decryption_status == "failed":
             overall_status = "completed_decryption_failed"
        elif decryption_status == "not_attempted": # Should not happen if key was required
             overall_status = "completed_raw_no_decryption"
    else:
        overall_status = "failed_save_error"


    # Save final completion info
    completion_info = {
        "completed_at": time.time(),
        "status": overall_status,
        "bytes_saved": len(final_data) if final_data else 0,
        "checksum_verified": checksum_ok,
        "decryption_status": decryption_status,
        **stats # Merge in the reception stats
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)

    print(f"\n[RESULT] Operation finished. Status: {overall_status}")
    print(f"[INFO] All session data saved to: {SESSION_DIR}")

    # Return success if saved successfully, even if data has issues
    return save_success


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Receiver with Discovery')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    # Key is now mandatory for receiver (discovery + potential decryption)
    parser.add_argument('--key', '-k', required=True, help='Decryption/Discovery key file')
    parser.add_argument('--interface', '-i', help='Network interface to listen on (Scapy syntax)')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity timeout in seconds (default: 120)')
    parser.add_argument('--output-dir', '-d', help='Custom output directory for logs/data')
    parser.add_argument('--discovery-port', '-dp', type=int, default=DISCOVERY_PORT,
                        help=f'UDP port for discovery (default: {DISCOVERY_PORT})')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()

    # Setup output directory structure first
    global OUTPUT_DIR, DISCOVERY_PORT
    if args.output_dir:
        OUTPUT_DIR = args.output_dir
    setup_directories() # Creates dirs and initializes log file

    log_debug("Receiver starting...")
    log_debug(f"Arguments: {vars(args)}")

    # Set discovery port from args
    DISCOVERY_PORT = args.discovery_port

    # Receive the file (includes discovery)
    success = receive_file(
        args.output,
        args.key,
        args.interface,
        args.timeout
    )

    # Exit with appropriate status
    log_debug(f"Receiver finished. Success status: {success}")
    print(f"Receiver finished. {'Operation completed (check logs for details).' if success else 'Operation failed.'}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
