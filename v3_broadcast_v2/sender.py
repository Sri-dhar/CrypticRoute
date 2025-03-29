
#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure, acknowledgment system, and IP discovery.
"""

import sys
import os
import argparse
import time
import random
import hashlib
import json
import binascii
import datetime
import threading
import socket # Added for UDP discovery
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, sniff, conf

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
RETRANSMIT_ATTEMPTS = 5
ACK_WAIT_TIMEOUT = 10  # Seconds to wait for an ACK before retransmission
MAX_RETRANSMISSIONS = 10  # Maximum number of times to retransmit a chunk
DISCOVERY_PORT = 54321 # UDP port for discovery
DISCOVERY_MAGIC_BEACON = b"CRYPTRT_DISC_v1:" # Magic bytes for discovery beacon
DISCOVERY_MAGIC_ACK = b"CRYPTRT_ACK_v1:"   # Magic bytes for discovery ack
DISCOVERY_TIMEOUT = 60 # Seconds to wait for discovery


# Global variables for the acknowledgment system
acked_chunks = set()  # Set of sequence numbers that have been acknowledged
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None # Will be discovered or provided
receiver_port = None
stop_sniffing = False

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
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"sender_session_{timestamp}")
    os.makedirs(SESSION_DIR)

    # Create subdirectories
    LOGS_DIR = os.path.join(SESSION_DIR, "logs")
    DATA_DIR = os.path.join(SESSION_DIR, "data")
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks")

    os.makedirs(LOGS_DIR)
    os.makedirs(DATA_DIR)
    os.makedirs(CHUNKS_DIR)

    # Set debug log path
    DEBUG_LOG = os.path.join(LOGS_DIR, "sender_debug.log")

    # Initialize debug log file here
    with open(DEBUG_LOG, "w") as f:
         f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    # Create or update symlink to the latest session for convenience
    latest_link = os.path.join(OUTPUT_DIR, "sender_latest")

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
        # This path might not be ideal, but prevents crashing before setup
        temp_log_path = "sender_debug_early.log"
        with open(temp_log_path, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] [EARLY] {message}\n")
        return

    with open(DEBUG_LOG, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def get_broadcast_address():
    """Attempt to find a suitable broadcast address."""
    # Common default
    default_broadcast = "255.255.255.255"
    try:
        # Try getting local IP and inferring broadcast - this is complex and platform-dependent
        # Using 255.255.255.255 is generally safer and more compatible
        # s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # s.connect(("8.8.8.8", 80)) # Connect to external server to find default interface IP
        # local_ip = s.getsockname()[0]
        # s.close()
        # # Crude assumption for /24 subnet
        # ip_parts = local_ip.split('.')
        # broadcast_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
        # print(f"[DISCOVERY] Inferred broadcast address: {broadcast_ip}")
        # log_debug(f"[DISCOVERY] Inferred broadcast address: {broadcast_ip}")
        # return broadcast_ip
        print(f"[DISCOVERY] Using default broadcast address: {default_broadcast}")
        log_debug(f"[DISCOVERY] Using default broadcast address: {default_broadcast}")
        return default_broadcast
    except Exception as e:
        print(f"[DISCOVERY] Warning: Could not determine local broadcast address, using {default_broadcast}. Error: {e}")
        log_debug(f"[DISCOVERY] Warning: Could not determine local broadcast address, using {default_broadcast}. Error: {e}")
        return default_broadcast

# def discover_receiver(key_hash_hex, discovery_port, timeout):
#     """Broadcasts a discovery beacon and listens for a response."""
#     broadcast_addr = get_broadcast_address()
#     key_hash = bytes.fromhex(key_hash_hex)
#     beacon_payload = DISCOVERY_MAGIC_BEACON + key_hash

#     print(f"[DISCOVERY] Starting discovery on UDP port {discovery_port}...")
#     log_debug(f"[DISCOVERY] Starting discovery. Key hash: {key_hash_hex}")

#     # Create UDP socket
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
#     sock.settimeout(1.0) # Set a timeout for receiving ACKs (1 second)

#     start_time = time.time()
#     beacon_interval = 2 # Send beacon every 2 seconds
#     last_beacon_time = 0

#     try:
#         while time.time() - start_time < timeout:
#             # Send beacon periodically
#             current_time = time.time()
#             if current_time - last_beacon_time > beacon_interval:
#                 print(f"[DISCOVERY] Sending beacon to {broadcast_addr}:{discovery_port}")
#                 log_debug(f"[DISCOVERY] Sending beacon (payload: {beacon_payload.hex()})")
#                 sock.sendto(beacon_payload, (broadcast_addr, discovery_port))
#                 last_beacon_time = current_time

#             # Listen for response
#             try:
#                 data, addr = sock.recvfrom(1024) # Buffer size 1024 bytes
#                 log_debug(f"[DISCOVERY] Received UDP packet from {addr}: {data.hex()}")

#                 # Check if it's the ACK we expect
#                 if data.startswith(DISCOVERY_MAGIC_ACK):
#                     received_hash = data[len(DISCOVERY_MAGIC_ACK):]
#                     if received_hash == key_hash:
#                         receiver_ip = addr[0]
#                         print(f"[DISCOVERY] Success! Receiver found at {receiver_ip}")
#                         log_debug(f"[DISCOVERY] Valid ACK received from {receiver_ip}. Discovery successful.")
#                         sock.close()
#                         return receiver_ip
#                     else:
#                         log_debug(f"[DISCOVERY] Received ACK with mismatching hash from {addr}. Ignoring.")
#                 else:
#                     log_debug(f"[DISCOVERY] Received non-ACK UDP packet from {addr}. Ignoring.")

#             except socket.timeout:
#                 # No response received within the timeout, loop will continue
#                 log_debug("[DISCOVERY] Socket timeout while waiting for ACK. Will resend beacon.")
#                 continue
#             except Exception as e:
#                 log_debug(f"[DISCOVERY] Error receiving UDP packet: {e}")
#                 time.sleep(0.5) # Avoid busy-looping on error

#         print("[DISCOVERY] Failed: Timeout waiting for receiver response.")
#         log_debug("[DISCOVERY] Discovery timeout reached.")
#         sock.close()
#         return None

#     except KeyboardInterrupt:
#         print("\n[DISCOVERY] Discovery interrupted by user.")
#         log_debug("[DISCOVERY] Discovery interrupted by user.")
#         sock.close()
#         return None
#     except Exception as e:
#         print(f"[DISCOVERY] An error occurred during discovery: {e}")
#         log_debug(f"[DISCOVERY] An error occurred during discovery: {e}")
#         sock.close()
#         return None

def discover_receiver(key_hash_hex, discovery_port, timeout):
    """Broadcasts a discovery beacon and listens for a response."""
    broadcast_addr = get_broadcast_address()
    key_hash = bytes.fromhex(key_hash_hex)
    beacon_payload = DISCOVERY_MAGIC_BEACON + key_hash

    print(f"[DISCOVERY] Starting discovery on UDP port {discovery_port}...")
    log_debug(f"[DISCOVERY] Starting discovery. Key hash: {key_hash_hex}")

    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Added for quicker restarts if needed
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    # *** BIND the socket to receive the ACK ***
    try:
        # Bind to '' (all available interfaces) and the discovery port
        sock.bind(('', discovery_port))
        log_debug(f"[DISCOVERY] Sender socket bound to port {discovery_port} for receiving ACKs.")
        print(f"[DISCOVERY] Sender listening for ACKs on port {discovery_port}")
    except OSError as e:
        print(f"[ERROR] Could not bind sender discovery socket to port {discovery_port}: {e}")
        print("       Check if another process (maybe a previous run?) is using the port.")
        log_debug(f"[DISCOVERY] Failed to bind sender socket: {e}")
        sock.close()
        return None
    # *** End of BIND modification ***

    sock.settimeout(1.0) # Set a timeout for receiving ACKs (1 second)

    start_time = time.time()
    beacon_interval = 2 # Send beacon every 2 seconds
    last_beacon_time = 0

    try:
        while time.time() - start_time < timeout:
            # Send beacon periodically
            current_time = time.time()
            if current_time - last_beacon_time > beacon_interval:
                print(f"[DISCOVERY] Sending beacon to {broadcast_addr}:{discovery_port}")
                log_debug(f"[DISCOVERY] Sending beacon (payload: {beacon_payload.hex()})")
                try:
                    sock.sendto(beacon_payload, (broadcast_addr, discovery_port))
                except OSError as e:
                     # Handle potential network errors during send, e.g., network unreachable
                     print(f"[DISCOVERY] Warning: Error sending beacon: {e}")
                     log_debug(f"[DISCOVERY] Error sending beacon: {e}")
                     # Continue trying, maybe the network will recover
                     time.sleep(1) # Wait a bit before next attempt
                     continue # Skip receive attempt for this cycle

                last_beacon_time = current_time

            # Listen for response
            try:
                data, addr = sock.recvfrom(1024) # Buffer size 1024 bytes
                log_debug(f"[DISCOVERY] Received UDP packet from {addr}: {data.hex()}")

                # Check if it's the ACK we expect
                if data.startswith(DISCOVERY_MAGIC_ACK):
                    received_hash = data[len(DISCOVERY_MAGIC_ACK):]
                    if received_hash == key_hash:
                        receiver_ip = addr[0]
                        print(f"\n[DISCOVERY] Success! Receiver ACK received from {receiver_ip}") # Added newline for clarity
                        log_debug(f"[DISCOVERY] Valid ACK received from {receiver_ip}. Discovery successful.")
                        sock.close()
                        return receiver_ip
                    else:
                        log_debug(f"[DISCOVERY] Received ACK with mismatching hash from {addr}. Ignoring.")
                        print(f"[DISCOVERY] Ignored ACK from {addr[0]} (Hash mismatch)")
                else:
                    log_debug(f"[DISCOVERY] Received non-ACK UDP packet from {addr}. Ignoring.")
                    # Optional: print a message if you receive unexpected UDP traffic
                    # print(f"[DISCOVERY] Ignored unexpected UDP packet from {addr[0]}")


            except socket.timeout:
                # No response received within the timeout, loop will continue to send next beacon
                log_debug("[DISCOVERY] Socket timeout while waiting for ACK. Will resend beacon.")
                continue # Explicitly continue to the start of the while loop
            except Exception as e:
                log_debug(f"[DISCOVERY] Error receiving UDP packet: {e}")
                print(f"[DISCOVERY] Error receiving packet: {e}")
                time.sleep(0.5) # Avoid busy-looping on error

        # If the loop finishes without returning, it timed out
        print("\n[DISCOVERY] Failed: Timeout waiting for receiver response.") # Added newline
        log_debug("[DISCOVERY] Discovery timeout reached.")
        sock.close()
        return None

    except KeyboardInterrupt:
        print("\n[DISCOVERY] Discovery interrupted by user.")
        log_debug("[DISCOVERY] Discovery interrupted by user.")
        sock.close()
        return None
    except Exception as e:
        print(f"\n[DISCOVERY] An error occurred during discovery: {e}") # Added newline
        log_debug(f"[DISCOVERY] An error occurred during discovery: {e}")
        sock.close()
        return None

    finally:
        # Ensure socket is closed if it exists and wasn't closed earlier
        if 'sock' in locals() and sock.fileno() != -1:
             sock.close()
             log_debug("[DISCOVERY] Sender discovery socket closed in finally block.")
class SteganographySender:
    """Simple steganography sender using only TCP with acknowledgment."""

    def __init__(self, target_ip):
        """Initialize the sender."""
        global receiver_ip # Ensure we use the globally set receiver_ip

        # Use the discovered/provided target_ip
        if not target_ip:
             raise ValueError("Target IP cannot be None for SteganographySender")
        self.target_ip = target_ip
        receiver_ip = target_ip # Set the global variable too

        self.source_port = random.randint(10000, 60000)

        # Create debug file
        chunks_json = os.path.join(LOGS_DIR, "sent_chunks.json")
        with open(chunks_json, "w") as f:
            f.write("{}")
        self.sent_chunks = {}
        self.chunks_json_path = chunks_json

        # Create debug file for received ACKs
        acks_json = os.path.join(LOGS_DIR, "received_acks.json")
        with open(acks_json, "w") as f:
            f.write("{}")
        self.acks_json_path = acks_json
        self.received_acks = {}

        # Initialize values for packet processing threads
        self.ack_processing_thread = None
        self.stop_ack_processing = threading.Event()
        log_debug(f"Sender initialized for target {self.target_ip}, source port {self.source_port}")


    def start_ack_listener(self):
        """Start a thread to listen for ACK packets."""
        self.ack_processing_thread = threading.Thread(
            target=self.ack_listener_thread
        )
        self.ack_processing_thread.daemon = True
        self.ack_processing_thread.start()
        log_debug("Started ACK listener thread")
        print("[THREAD] Started ACK listener thread")

    def stop_ack_listener(self):
        """Stop the ACK listener thread."""
        if self.ack_processing_thread:
            self.stop_ack_processing.set()
            # No need to set global stop_sniffing here, the lambda in sniff handles it
            print("[THREAD] Signalling ACK listener thread to stop...")
            log_debug("Signalling ACK listener thread to stop...")
            self.ack_processing_thread.join(2)  # Wait up to 2 seconds for thread to finish
            if self.ack_processing_thread.is_alive():
                 print("[THREAD] Warning: ACK listener thread did not stop gracefully.")
                 log_debug("Warning: ACK listener thread did not stop gracefully.")
            else:
                 print("[THREAD] Stopped ACK listener thread")
                 log_debug("Stopped ACK listener thread")


    def ack_listener_thread(self):
        """Thread function to listen for and process ACK packets."""
        # No global stop_sniffing needed here

        log_debug("ACK listener thread started")

        try:
            # Set up sniffing for TCP ACK packets FROM the specific receiver IP
            # Ensure receiver_ip is set before starting the listener
            if not receiver_ip:
                 log_debug("[ERROR] Receiver IP not set when starting ACK listener thread.")
                 print("[ERROR] Internal error: Receiver IP unknown.")
                 return

            filter_str = f"tcp and src host {receiver_ip} and dst port {self.source_port}"
            log_debug(f"Sniffing for ACKs with filter: {filter_str}")

            # Start packet sniffing for ACKs
            sniff(
                filter=filter_str,
                prn=self.process_ack_packet,
                store=0,
                stop_filter=lambda p: self.stop_ack_processing.is_set() # Stop when event is set
            )
        except Exception as e:
            log_debug(f"Error in ACK listener thread: {e}")
            print(f"[ERROR] ACK listener thread: {e}")

        log_debug("ACK listener thread stopped")

    def log_chunk(self, seq_num, data):
        """Save chunk data to debug file."""
        self.sent_chunks[str(seq_num)] = {
            "data": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }
        with open(self.chunks_json_path, "w") as f:
            json.dump(self.sent_chunks, f, indent=2)

        # Also save the raw chunk data
        chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:03d}.bin")
        with open(chunk_file, "wb") as f:
            f.write(data)

    def log_ack(self, seq_num):
        """Save received ACK to debug file."""
        self.received_acks[str(seq_num)] = {
            "timestamp": time.time()
        }
        with open(self.acks_json_path, "w") as f:
            json.dump(self.received_acks, f, indent=2)

    def create_syn_packet(self):
        """Create a SYN packet for connection establishment."""
        # Create a SYN packet with special markers
        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000), # Receiver listens broadly, but send to a random port
            seq=0x12345678,  # Fixed pattern for SYN
            window=0xDEAD,   # Special window value for handshake
            flags="S"        # SYN flag
        )
        log_debug(f"Created SYN packet for {self.target_ip}")
        return syn_packet

    def create_ack_packet(self):
        """Create an ACK packet to complete connection establishment."""
        global receiver_ip, receiver_port # Use global receiver info

        if not receiver_ip or not receiver_port:
            log_debug("Cannot create handshake ACK - receiver IP or Port information missing")
            print("[ERROR] Cannot create handshake ACK - receiver IP/Port unknown")
            return None

        # Create an ACK packet with special markers
        ack_packet = IP(dst=receiver_ip) / TCP(
            sport=self.source_port,
            dport=receiver_port,
            seq=0x87654321,  # Fixed pattern for final ACK
            ack=0xABCDEF12,  # Should match receiver's SYN-ACK seq number
            window=0xF00D,   # Special window value for handshake completion
            flags="A"        # ACK flag
        )
        log_debug(f"Created Handshake ACK packet for {receiver_ip}:{receiver_port}")
        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data."""
        # Ensure data is exactly MAX_CHUNK_SIZE bytes
        if len(data) < MAX_CHUNK_SIZE:
            data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE:
            data = data[:MAX_CHUNK_SIZE]

        # Create random destination port for stealth (Receiver should filter on source IP and SYN flag)
        dst_port = random.randint(10000, 60000)

        # Embed first 4 bytes in sequence number and last 4 in ack number
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,  # Put sequence number in window field
            flags="S",  # SYN packet (Receiver identifies data packets by SYN + specific window range + source IP)
            options=[('MSS', total_chunks)]  # Store total chunks in MSS option
        )

        # Store checksum in ID field
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum

        log_debug(f"Created data packet: SeqNum={seq_num}, Total={total_chunks}, Data={data.hex()}, Checksum={checksum:04x}")
        return tcp_packet

    def create_completion_packet(self):
        """Create a packet signaling transmission completion."""
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000),
            window=0xFFFF,  # Special value for completion
            flags="F"  # FIN packet signals completion
        )
        log_debug(f"Created completion packet (FIN) for {self.target_ip}")
        return tcp_packet

    def process_ack_packet(self, packet):
        """Process a received ACK packet."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_ip, receiver_port

        # Basic check (already filtered by Scapy, but good practice)
        if not (IP in packet and TCP in packet):
             return False
        # Ensure it's from the expected receiver
        if packet[IP].src != receiver_ip:
             log_debug(f"Ignored packet from unexpected IP {packet[IP].src}")
             return False

        # Store receiver's source port if not known (from SYN-ACK or first data ACK)
        if receiver_port is None and packet[TCP].sport != 0:
            receiver_port = packet[TCP].sport
            log_debug(f"Learned receiver port: {receiver_port}")
            print(f"[HANDSHAKE] Learned receiver port: {receiver_port}")


        # Check for SYN-ACK packet (connection establishment)
        # Receiver sends SYN-ACK with specific seq, ack, and window
        if not connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == 0xBEEF \
           and packet[TCP].seq == 0xABCDEF12 and packet[TCP].ack == 0x12345678 + 1: # TCP ACK is SYN's seq + 1
            log_debug(f"Received SYN-ACK for connection establishment from {packet[IP].src}:{packet[TCP].sport}")
            print("[HANDSHAKE] Received SYN-ACK response")

            # Store receiver info specifically from this packet (IP should match, port might be learned)
            if receiver_ip != packet[IP].src:
                 log_debug(f"WARNING: SYN-ACK source IP {packet[IP].src} differs from expected {receiver_ip}")
                 # Decide how to handle this - maybe update receiver_ip? For now, log warning.
            receiver_port = packet[TCP].sport # Update port based on SYN-ACK source port

            # Send final ACK to complete handshake
            ack_packet = self.create_ack_packet()
            if ack_packet:
                log_debug("Sending final ACK to complete handshake")
                print("[HANDSHAKE] Sending final ACK to complete connection")

                # Send multiple times for reliability
                for i in range(5):
                    send(ack_packet)
                    time.sleep(0.1)

                # Mark connection as established
                connection_established = True
                print("[HANDSHAKE] Connection established successfully")
                # No return needed, let it fall through to maybe process as data ack if flags match

            # Don't immediately return true, maybe it's also a data ack (unlikely but possible)

        # Check for data chunk ACK
        # Receiver sends ACK with specific seq, window, and ack = seq_num being acked
        if connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xCAFE \
           and packet[TCP].seq == 0x12345678: # ACK for data uses specific seq
            # Extract the sequence number from the ack field
            seq_num = packet[TCP].ack

            # Ignore ACKs for sequence 0 or very large numbers (likely not ours)
            if seq_num == 0 or seq_num > 65535: # Assuming seq_num fits in window, upper bound helps
                log_debug(f"Received potential data ACK packet with suspicious seq_num {seq_num}. Ignored.")
                return False

            log_debug(f"Received potential data ACK for chunk {seq_num}")

            # Add to acknowledged chunks
            if seq_num not in acked_chunks:
                acked_chunks.add(seq_num)
                self.log_ack(seq_num)
                log_debug(f"Added chunk {seq_num} to acked_chunks set.")

            # If this is the chunk we're currently waiting for, clear the wait flag
            if waiting_for_ack and seq_num == current_chunk_seq:
                log_debug(f"Chunk {seq_num} acknowledgment confirmed.")
                print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                waiting_for_ack = False
            elif seq_num == current_chunk_seq:
                 # We were not waiting, but it's the current one. Useful log.
                 log_debug(f"Received ACK for current chunk {seq_num}, but wasn't in waiting state.")
            else:
                 # Received ACK for a previous/future chunk (e.g., due to reordering or retransmits)
                 log_debug(f"Received ACK for chunk {seq_num}, while waiting for {current_chunk_seq}.")

            return True # Indicate packet processed

        # Log if packet was from receiver but didn't match expected patterns
        log_debug(f"Received packet from {packet[IP].src}:{packet[TCP].sport} did not match SYN-ACK or Data-ACK patterns. Flags={packet[TCP].flags:#x}, Window={packet[TCP].window:#x}, Seq={packet[TCP].seq:#x}, Ack={packet[TCP].ack:#x}")
        return False


    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq

        # Skip if this chunk has already been acknowledged
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping send.")
            print(f"[SKIP] Chunk {seq_num:04d} already acknowledged")
            return True

        # Create the packet
        packet = self.create_packet(data, seq_num, total_chunks)

        # Log the chunk (only log when actually attempting send)
        self.log_chunk(seq_num, data)

        # Set current chunk and waiting flag
        current_chunk_seq = seq_num
        waiting_for_ack = True

        # Initial transmission attempt
        log_debug(f"Attempting to send chunk {seq_num}/{total_chunks}")
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:.2f}%")
        send(packet)

        # Wait for ACK with retransmission
        retransmit_count = 0
        max_retransmits = MAX_RETRANSMISSIONS

        start_time = time.time()

        while waiting_for_ack and retransmit_count < max_retransmits:
            # Wait a bit for ACK. Check more frequently.
            wait_start = time.time()
            while waiting_for_ack and (time.time() - wait_start < ACK_WAIT_TIMEOUT):
                time.sleep(0.1) # Check every 100ms
                # Loop condition 'waiting_for_ack' handles the break

            # If we're still waiting for ACK after the timeout period, retransmit
            if waiting_for_ack:
                retransmit_count += 1
                log_debug(f"ACK timeout for chunk {seq_num}. Retransmitting (attempt {retransmit_count}/{max_retransmits})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{max_retransmits}")
                send(packet)

        # After loop, check final status
        if waiting_for_ack:
            # We've exhausted retransmissions and still no ACK
            log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions")
            print(f"[WARNING] No ACK received for chunk {seq_num:04d} after {max_retransmits} attempts")
            waiting_for_ack = False # Reset for next chunk attempt
            return False
        else:
            # Success - chunk was acknowledged sometime during the loop
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} confirmed acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
            print(f"[CONFIRMED] Chunk {seq_num:04d} successfully delivered")
            return True


def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            data = file.read()
            log_debug(f"Read {len(data)} bytes from {file_path}")
            return data
    except Exception as e:
        log_debug(f"Error reading file {file_path}: {e}")
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def prepare_key(key_data):
    """Prepare the encryption key in correct format and return bytes and hex hash."""
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')

    # Check if it's a hex string and convert if needed
    is_hex = False
    try:
        # Basic check: length must be even, chars must be hex digits
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             key_bytes_from_hex = bytes.fromhex(key_data.decode('ascii'))
             # If conversion succeeds, assume it was hex
             key_data = key_bytes_from_hex
             is_hex = True
             log_debug("Interpreted key data as hex string and converted to bytes")
             print("Interpreted key data as hex string.")
    except ValueError:
        pass # Not a valid hex string, treat as raw bytes/string

    # Ensure key is 32 bytes (256 bits) for AES-256
    original_len = len(key_data)
    if original_len < 32:
        key_data = key_data.ljust(32, b'\0')  # Pad to 32 bytes
        log_debug(f"Key padded from {original_len} bytes to 32 bytes with nulls.")
    elif original_len > 32:
        key_data = key_data[:32] # Truncate to 32 bytes
        log_debug(f"Key truncated from {original_len} bytes to 32 bytes.")

    log_debug(f"Final key bytes (used for encryption): {key_data.hex()}")

    # Save key for debugging
    key_file = os.path.join(DATA_DIR, "key.bin")
    with open(key_file, "wb") as f:
        f.write(key_data)

    # Calculate SHA256 hash for discovery
    key_hash = hashlib.sha256(key_data).digest()
    key_hash_hex = key_hash.hex()
    log_debug(f"Key hash (SHA256 for discovery): {key_hash_hex}")
    print(f"[KEY] Key Hash (SHA256): {key_hash_hex}")


    return key_data, key_hash_hex

def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        # Generate a random IV (more secure than fixed IV)
        iv = os.urandom(16)
        log_debug(f"Generated random IV: {iv.hex()}")

        # Save IV for debugging
        iv_file = os.path.join(DATA_DIR, "iv.bin")
        with open(iv_file, "wb") as f:
            f.write(iv)

        # Initialize AES cipher with key and IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Save original and encrypted data for debugging
        original_file = os.path.join(DATA_DIR, "original_data.bin")
        with open(original_file, "wb") as f:
            f.write(data)

        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        with open(encrypted_file, "wb") as f:
            f.write(encrypted_data)

        # Prepend IV to the encrypted data for use in decryption
        package_data = iv + encrypted_data

        # Save a complete package (IV + encrypted data) for debugging
        package_file = os.path.join(DATA_DIR, "encrypted_package.bin")
        with open(package_file, "wb") as f:
            f.write(package_data)

        log_debug(f"Original data size: {len(data)}")
        log_debug(f"Encrypted data size (excl IV): {len(encrypted_data)}")
        log_debug(f"Total package size (incl IV): {len(package_data)}")
        # log_debug(f"Encrypted package hex: {package_data.hex() if len(package_data) <= 64 else package_data[:64].hex() + '...'}")

        return package_data
    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"Encryption error: {e}")
        sys.exit(1)

def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks of specified size."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data into {len(chunks)} chunks of max size {chunk_size}")

    # Save chunk details for debugging
    # Limit logged data for large files
    max_logged_chunks = 100
    log_all_chunks = len(chunks) <= max_logged_chunks
    chunk_info = {
         i+1: {"size": len(chunk), "data": chunk.hex() if log_all_chunks else (chunk.hex() if i<max_logged_chunks else "...") }
         for i, chunk in enumerate(chunks)
    }
    if not log_all_chunks:
         chunk_info[f"NOTE"] = f"Only first {max_logged_chunks} chunks' data logged."

    chunks_json = os.path.join(LOGS_DIR, "chunks_info.json")
    with open(chunks_json, "w") as f:
        json.dump(chunk_info, f, indent=2)

    return chunks

def establish_connection(stego):
    """Establish connection with the receiver using three-way handshake."""
    global connection_established # No stop_sniffing here

    log_debug("Starting connection establishment...")
    print("[HANDSHAKE] Initiating connection with receiver...")

    # Start ACK listener thread *before* sending SYN
    stego.start_ack_listener()
    time.sleep(0.5) # Give listener thread a moment to start sniffing

    # Send SYN packet
    syn_packet = stego.create_syn_packet()
    if not syn_packet:
         log_debug("Failed to create SYN packet.")
         print("[ERROR] Failed to create SYN packet.")
         stego.stop_ack_listener()
         return False

    log_debug("Sending SYN packet")
    print("[HANDSHAKE] Sending SYN packet...")

    # Send multiple times initially for reliability
    send_attempts = 5
    for i in range(send_attempts):
        send(syn_packet)
        time.sleep(0.2)
        if connection_established:
            log_debug(f"Connection established after {i+1} SYN attempts.")
            print("[HANDSHAKE] Connection established successfully (during initial SYNs)")
            return True # Already connected


    # Wait for the connection to be established by listener thread
    max_wait = 30  # seconds total wait time
    wait_interval = 1 # seconds between checks
    resend_interval = 5 # seconds between SYN resends
    start_time = time.time()
    last_resend_time = time.time()

    print(f"[HANDSHAKE] Waiting up to {max_wait}s for SYN-ACK...")
    while not connection_established and (time.time() - start_time < max_wait):
        time.sleep(wait_interval)

        # Resend SYN periodically if no connection yet
        if not connection_established and (time.time() - last_resend_time > resend_interval):
            log_debug("Resending SYN packet (waiting for SYN-ACK)")
            print("[HANDSHAKE] Resending SYN packet...")
            send(syn_packet)
            last_resend_time = time.time()

    # Check final status after loop
    if connection_established:
        log_debug("Connection established successfully (confirmed by listener)")
        print("[HANDSHAKE] Connection established successfully")
        return True
    else:
        log_debug("Failed to establish connection (timeout waiting for SYN-ACK)")
        print("[HANDSHAKE] Failed to establish connection with receiver (Timeout)")
        stego.stop_ack_listener() # Stop listener if connection failed
        return False


def send_file(file_path, discovered_target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt and send a file via steganography after IP discovery."""
    global connection_established, stop_sniffing, acked_chunks, receiver_ip

    # Use the IP passed from discovery/main
    if not discovered_target_ip:
        log_debug("Cannot send file: Target IP is missing.")
        print("[ERROR] Cannot send file: Target IP is unknown.")
        return False
    receiver_ip = discovered_target_ip # Ensure global receiver_ip is set

    # Create a summary file with transmission parameters
    summary = {
        "timestamp": time.time(),
        "file_path": file_path,
        "target_ip": receiver_ip, # Log the used IP
        "key_path": key_path,
        "chunk_size": chunk_size,
        "delay": delay,
        "ack_timeout": ACK_WAIT_TIMEOUT,
        "max_retransmissions": MAX_RETRANSMISSIONS,
        "discovery_port": DISCOVERY_PORT
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Reset global transmission variables
    acked_chunks = set()
    connection_established = False
    # stop_sniffing = False # This is controlled by the listener thread's event now

    # Create steganography sender instance with the discovered IP
    try:
        stego = SteganographySender(receiver_ip)
    except ValueError as e:
        log_debug(f"Error initializing sender: {e}")
        print(f"[ERROR] {e}")
        return False

    # Read the input file FIRST
    log_debug(f"Reading file: {file_path}")
    print(f"[FILE] Reading: {file_path}")
    file_data_plain = read_file(file_path, 'rb')
    if file_data_plain is None: # read_file exits on error, but check anyway
        return False
    print(f"[FILE] Read {len(file_data_plain)} bytes successfully")

    # Print the content for debugging (if text)
    try:
        text_content = file_data_plain.decode('utf-8')
        log_debug(f"File content (as text, limit 100 chars): {text_content[:100]}{'...' if len(text_content)>100 else ''}")
        # Save the text content as a text file
        text_file = os.path.join(DATA_DIR, "original_content.txt")
        with open(text_file, "w", encoding='utf-8') as f:
            f.write(text_content)
    except UnicodeDecodeError:
        log_debug(f"File content (binary, first 32 bytes hex): {file_data_plain[:32].hex()}{'...' if len(file_data_plain)>32 else ''}")

    # Prepare key and encrypt data (if key provided)
    # Note: Key was already read and processed in main() for discovery
    file_data_to_send = file_data_plain
    if key_path: # Key path implies encryption is desired
        log_debug("Using pre-processed key for encryption.")
        # We need the actual key bytes, not the hash, which were returned by prepare_key
        # Re-read or get from main() scope if possible. Assuming re-read is necessary here.
        key_data_raw = read_file(key_path, 'rb')
        if key_data_raw is None: return False
        key_bytes, _ = prepare_key(key_data_raw) # Re-process to get bytes

        log_debug("Encrypting data...")
        print(f"[ENCRYPT] Starting encryption of {len(file_data_plain)} bytes...")
        file_data_to_send = encrypt_data(file_data_plain, key_bytes)
        if file_data_to_send is None: # encrypt_data exits, but check
            return False
        log_debug(f"Data encrypted. Total size to send (incl IV): {len(file_data_to_send)} bytes")
        print(f"[ENCRYPT] Completed encryption. Result size: {len(file_data_to_send)} bytes")
    else:
        log_debug("No encryption key provided. Sending data in plaintext.")
        print("[WARN] No encryption key provided. Data will be sent unencrypted.")


    # Add MD5 checksum for integrity check (applied to data being sent, after potential encryption)
    file_checksum = hashlib.md5(file_data_to_send).digest()
    log_debug(f"Generated MD5 checksum for payload: {file_checksum.hex()}")
    print(f"[CHECKSUM] Generated MD5 for payload: {file_checksum.hex()}")
    final_data_package = file_data_to_send + file_checksum

    # Save the checksum and final data package for debugging
    checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
    with open(checksum_file, "wb") as f:
        f.write(file_checksum)

    final_package_file = os.path.join(DATA_DIR, "final_data_package.bin")
    with open(final_package_file, "wb") as f:
        f.write(final_data_package)
    log_debug(f"Final package size (incl checksum): {len(final_data_package)} bytes")


    # Establish TCP connection *after* preparing data
    if not establish_connection(stego):
        log_debug("Aborting transmission due to connection failure")
        print("[ERROR] Aborting transmission due to connection failure")
        # Listener is stopped by establish_connection on failure
        return False


    # Chunk the final data package
    print(f"[PREP] Splitting data into chunks of size {chunk_size} bytes...")
    chunks = chunk_data(final_data_package, chunk_size)
    total_chunks = len(chunks)
    if total_chunks == 0:
         log_debug("Warning: No data chunks to send (file might be empty).")
         print("[WARN] Input file resulted in zero data chunks. Sending completion signal only.")
         # Skip chunk sending loop, go directly to completion signal
    else:
        log_debug(f"Payload split into {total_chunks} chunks")
        print(f"[PREP] Data split into {total_chunks} chunks")


    # Send all chunks in order with acknowledgment
    log_debug(f"Sending {total_chunks} data chunks to {receiver_ip}...")
    print(f"[TRANSMISSION] Starting data transmission to {receiver_ip}...")

    transmission_success = True
    start_chunk_time = time.time()
    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Start sequence numbers from 1

        print(f"[PROGRESS] Preparing chunk {seq_num:04d}/{total_chunks:04d}")
        success = stego.send_chunk(chunk, seq_num, total_chunks)

        # Update status
        progress = (seq_num / total_chunks) * 100 if total_chunks > 0 else 100
        if success:
            print(f"[STATUS] Completed chunk {seq_num:04d}/{total_chunks:04d} | Progress: {progress:.2f}%")
        else:
            print(f"[WARNING] Chunk {seq_num:04d} failed delivery after retries | Progress: {progress:.2f}%")
            transmission_success = False
            # Decide whether to abort or continue on failure. Currently continues.
            # break # Uncomment to abort on first failure

        # Add delay between packets
        time.sleep(delay)

    end_chunk_time = time.time()
    chunk_duration = end_chunk_time - start_chunk_time
    log_debug(f"Finished sending {total_chunks} chunks in {chunk_duration:.2f} seconds.")
    print(f"[TRANSMISSION] Finished sending chunks in {chunk_duration:.2f}s")


    # Send completion signal
    completion_packet = stego.create_completion_packet()
    if completion_packet:
        print("[COMPLETE] Sending transmission completion signals...")
        # Send multiple times to increase chance of receipt
        for i in range(10):
            log_debug(f"Sending completion signal (attempt {i+1}/10)")
            send(completion_packet)
            time.sleep(0.2) # Spaced out completion signals
    else:
        log_debug("Failed to create completion packet.")
        print("[ERROR] Failed to create completion packet.")


    # Stop the ACK listener thread (signal it)
    stego.stop_ack_listener()

    # Calculate and log final statistics
    ack_rate = (len(acked_chunks) / total_chunks) * 100 if total_chunks > 0 else 100
    log_debug(f"Transmission summary: ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks})")
    print(f"[STATS] Final ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks} chunks acknowledged)")

    final_status = "unknown"
    if transmission_success and len(acked_chunks) == total_chunks:
         final_status = "completed_fully_acked"
         log_debug("Transmission appears fully successful.")
         print("[COMPLETE] Transmission successfully completed!")
    elif transmission_success:
         final_status = "completed_partially_acked"
         log_debug("Transmission completed, but some chunks might be missing ACKs.")
         print("[COMPLETE] Transmission finished, but some chunks lack acknowledgment.")
    else:
         final_status = "failed_chunks_undelivered"
         log_debug("Transmission failed: Not all chunks could be delivered.")
         print("[COMPLETE] Transmission finished, but FAILED to deliver all chunks.")


    # Save session completion info
    completion_info = {
        "completed_at": time.time(),
        "total_chunks_sent": total_chunks,
        "chunks_acknowledged": len(acked_chunks),
        "ack_rate": ack_rate,
        "status": final_status,
        "duration_seconds": end_chunk_time - start_chunk_time # Chunk sending duration
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f:
        json.dump(completion_info, f, indent=2)

    print(f"[INFO] All session data saved to: {SESSION_DIR}")

    # Return True if we attempted the whole process, False only on early critical errors
    # The 'status' in completion_info indicates the actual success level.
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Sender with Discovery')
    parser.add_argument('--target', '-t', help='Target IP address (optional, overrides discovery)')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    # Key is now required if target is not specified, needed for discovery
    parser.add_argument('--key', '-k', required=False, help='Encryption/Discovery key file (required if --target is not specified)')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets in seconds (default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE,
                        help=f'Chunk size in bytes (default/max: {MAX_CHUNK_SIZE})')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for logs/data')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT,
                        help=f'Timeout for waiting for TCP ACK in seconds (default: {ACK_WAIT_TIMEOUT})')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS,
                        help=f'Maximum TCP retransmission attempts per chunk (default: {MAX_RETRANSMISSIONS})')
    parser.add_argument('--discovery-port', '-dp', type=int, default=DISCOVERY_PORT,
                        help=f'UDP port for discovery (default: {DISCOVERY_PORT})')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT,
                        help=f'Timeout for discovery in seconds (default: {DISCOVERY_TIMEOUT})')

    args = parser.parse_args()

    # Validate arguments: Need target IP OR a key for discovery
    if not args.target and not args.key:
         parser.error("Either --target IP or --key for discovery must be provided.")
    # If target is not given, key becomes mandatory
    if not args.target and args.key is None:
         parser.error("--key is required when --target is not specified (for discovery).")

    return args


def main():
    """Main function."""
    args = parse_arguments()

    # Setup output directory structure first
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, DISCOVERY_PORT, DISCOVERY_TIMEOUT
    if args.output_dir:
        OUTPUT_DIR = args.output_dir
    setup_directories() # Creates dirs and initializes log file

    log_debug("Sender starting...")
    log_debug(f"Arguments: {vars(args)}")


    # Set configurable parameters
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    DISCOVERY_PORT = args.discovery_port
    DISCOVERY_TIMEOUT = args.discovery_timeout

    # Adjust chunk size if needed
    chunk_size = min(args.chunk_size, MAX_CHUNK_SIZE)
    if args.chunk_size > MAX_CHUNK_SIZE:
        print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE} (maximum supported)")
        log_debug(f"Chunk size clamped to {MAX_CHUNK_SIZE}")


    target_ip = args.target
    key_hash_hex = None

    # Read key file early if needed for discovery or encryption
    if args.key:
        log_debug(f"Reading key file: {args.key}")
        print(f"[KEY] Reading key file: {args.key}")
        key_data_raw = read_file(args.key, 'rb')
        if key_data_raw is None:
            sys.exit(1) # read_file already printed error
        # Prepare key returns bytes for encryption AND hash_hex for discovery
        _, key_hash_hex = prepare_key(key_data_raw)
        if not key_hash_hex:
             print("[ERROR] Could not generate key hash.")
             log_debug("Failed to generate key hash from key file.")
             sys.exit(1)


    # Perform discovery if target IP is not provided
    if not target_ip:
        if not key_hash_hex:
             print("[ERROR] Cannot perform discovery without a key hash.")
             log_debug("Discovery aborted: key hash missing.")
             sys.exit(1)
        print("[DISCOVERY] Target IP not provided, attempting discovery...")
        log_debug("Target IP not provided, starting discovery process.")
        target_ip = discover_receiver(key_hash_hex, DISCOVERY_PORT, DISCOVERY_TIMEOUT)

        if not target_ip:
            print("[DISCOVERY] Failed to discover receiver. Aborting.")
            log_debug("Discovery failed or timed out. Aborting.")
            sys.exit(1)
        else:
            print(f"[DISCOVERY] Successfully discovered receiver at {target_ip}")
            log_debug(f"Discovery successful. Receiver IP: {target_ip}")
    else:
        print(f"[INFO] Using provided target IP: {target_ip}. Skipping discovery.")
        log_debug(f"Using provided target IP: {target_ip}. Skipping discovery.")


    # Send the file using the determined target_ip
    success = send_file(
        args.input,
        target_ip, # Pass the discovered or provided IP
        args.key,  # Pass key path for encryption check inside send_file
        chunk_size,
        args.delay
    )

    # Exit with appropriate status
    log_debug(f"Sender finished. Success status: {success}")
    print(f"Sender finished. {'Operation completed (check logs for details).' if success else 'Operation failed.'}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

