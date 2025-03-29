#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure, acknowledgment system, and IP discovery
using key hash in discovery packets.
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
DISCOVERY_TIMEOUT = 60 # Seconds to wait for discovery
HASH_LEN_FOR_DISCOVERY = 16 # Use first 16 bytes (128 bits) of SHA256 hash

# Discovery Packet Prefixes
BEACON_PREFIX = b"CRYPTRT_BCN:" # Fixed prefix for sender beacon
READY_PREFIX = b"CRYPTRT_RDY:"   # Fixed prefix for receiver ready signal


# Global variables for the acknowledgment system
acked_chunks = set()  # Set of sequence numbers that have been acknowledged
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None # Will be discovered or provided
receiver_port = None
stop_sniffing = False # (Legacy, might be removable if listener uses event solely)

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

    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"sender_session_{timestamp}")
    os.makedirs(SESSION_DIR)
    LOGS_DIR = os.path.join(SESSION_DIR, "logs"); os.makedirs(LOGS_DIR)
    DATA_DIR = os.path.join(SESSION_DIR, "data"); os.makedirs(DATA_DIR)
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks"); os.makedirs(CHUNKS_DIR)
    DEBUG_LOG = os.path.join(LOGS_DIR, "sender_debug.log")

    with open(DEBUG_LOG, "w") as f:
         f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    latest_link = os.path.join(OUTPUT_DIR, "sender_latest")
    try:
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link):
            backup_name = f"{latest_link}_{int(time.time())}"
            os.rename(latest_link, backup_name)
            print(f"Renamed existing file to {backup_name}")
        os.symlink(SESSION_DIR, latest_link)
        print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e:
        print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    if not DEBUG_LOG: return # Avoid writing before setup
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log: {e}")


def get_broadcast_address():
    """Attempt to find a suitable broadcast address."""
    default_broadcast = "255.255.255.255"
    print(f"[DISCOVERY] Using default broadcast address: {default_broadcast}")
    log_debug(f"[DISCOVERY] Using default broadcast address: {default_broadcast}")
    return default_broadcast

def discover_receiver(key_hash_hex, discovery_port, timeout):
    """Broadcasts a discovery beacon (Prefix + Hash) and listens for a READY response (Prefix + Hash)."""
    broadcast_addr = get_broadcast_address()
    try:
        full_key_hash_bytes = bytes.fromhex(key_hash_hex)
    except ValueError:
        log_debug("[DISCOVERY] Error: Invalid key_hash_hex provided.")
        print("[ERROR] Internal error: Invalid key hash format for discovery.")
        return None

    if len(full_key_hash_bytes) < HASH_LEN_FOR_DISCOVERY:
        log_debug(f"[DISCOVERY] Error: Key hash length {len(full_key_hash_bytes)} is less than required {HASH_LEN_FOR_DISCOVERY}.")
        print("[ERROR] Internal error: Key hash too short for discovery.")
        return None

    truncated_hash = full_key_hash_bytes[:HASH_LEN_FOR_DISCOVERY]

    # Construct the specific payloads using prefixes and truncated hash
    beacon_payload = BEACON_PREFIX + truncated_hash
    expected_ready_payload = READY_PREFIX + truncated_hash

    sock = None
    print(f"[DISCOVERY] Starting discovery on UDP port {discovery_port}...")
    log_debug(f"[DISCOVERY] Starting discovery. Truncated Key hash (first {HASH_LEN_FOR_DISCOVERY} bytes): {truncated_hash.hex()}")
    log_debug(f"[DISCOVERY] Beacon Payload: {beacon_payload.hex()}")
    log_debug(f"[DISCOVERY] Expected Ready Payload: {expected_ready_payload.hex()}")


    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind the socket to receive the READY signal
        try:
            sock.bind(('', discovery_port))
            log_debug(f"[DISCOVERY] Sender socket bound to '' port {discovery_port} for receiving READY signals.")
            print(f"[DISCOVERY] Sender listening for READY signals on port {discovery_port}")
        except OSError as e:
            print(f"[ERROR] Could not bind sender discovery socket to port {discovery_port}: {e}")
            log_debug(f"[DISCOVERY] Failed to bind sender socket: {e}")
            if sock: sock.close()
            return None

        sock.settimeout(1.0) # Timeout for recvfrom

        start_time = time.time()
        beacon_interval = 2 # Send beacon every 2 seconds
        last_beacon_time = 0

        while time.time() - start_time < timeout:
            # Send beacon periodically
            current_time = time.time()
            if current_time - last_beacon_time > beacon_interval:
                print(f"[DISCOVERY] Sending beacon ({len(beacon_payload)} bytes) to {broadcast_addr}:{discovery_port}")
                log_debug(f"[DISCOVERY] Sending beacon: {beacon_payload.hex()}")
                try:
                    sock.sendto(beacon_payload, (broadcast_addr, discovery_port))
                except OSError as e:
                     print(f"[DISCOVERY] Warning: Error sending beacon: {e}")
                     log_debug(f"[DISCOVERY] Error sending beacon: {e}")
                     time.sleep(1)
                     continue
                last_beacon_time = current_time

            # Listen for READY response
            try:
                data, addr = sock.recvfrom(1024) # Use a reasonable buffer size
                log_debug(f"[DISCOVERY] Received {len(data)} UDP bytes from {addr}: {data.hex()}")

                # **** COMPARE ENTIRE EXPECTED READY PAYLOAD ****
                if data == expected_ready_payload:
                    receiver_ip = addr[0]
                    print(f"\n[DISCOVERY] Success! Receiver READY signal received from {receiver_ip}")
                    log_debug(f"[DISCOVERY] Valid READY signal received from {receiver_ip}. Discovery successful.")
                    # Crucial: Close socket BEFORE returning
                    sock.close()
                    log_debug("[DISCOVERY] Sender discovery socket closed.")
                    return receiver_ip # Success!
                else:
                    # Log unexpected data for debugging
                    if data.startswith(READY_PREFIX):
                        log_debug(f"[DISCOVERY] Received READY signal from {addr} but payload mismatch. Got: {data.hex()}, Expected: {expected_ready_payload.hex()}")
                        print(f"[DISCOVERY] Ignored READY from {addr[0]} (Payload mismatch)")
                    elif data.startswith(BEACON_PREFIX):
                         log_debug(f"[DISCOVERY] Ignored own beacon echo from {addr}.")
                    else:
                        log_debug(f"[DISCOVERY] Received unexpected UDP data from {addr}: {data.hex()}")
                        print(f"[DISCOVERY] Ignored unexpected UDP data from {addr[0]}")


            except socket.timeout:
                log_debug("[DISCOVERY] Socket timeout while waiting for READY signal.")
                continue # Explicitly continue
            except Exception as e:
                log_debug(f"[DISCOVERY] Error receiving UDP packet: {e}")
                print(f"[DISCOVERY] Error receiving packet: {e}")
                time.sleep(0.5)

        # Loop finished without success
        print("\n[DISCOVERY] Failed: Timeout waiting for receiver READY signal.")
        log_debug("[DISCOVERY] Discovery timeout reached.")
        if sock: sock.close()
        return None

    except KeyboardInterrupt:
        print("\n[DISCOVERY] Discovery interrupted by user.")
        log_debug("[DISCOVERY] Discovery interrupted by user.")
        if sock: sock.close()
        return None
    except Exception as e:
        print(f"\n[DISCOVERY] An error occurred during discovery: {e}")
        log_debug(f"[DISCOVERY] An error occurred during discovery: {e}")
        if sock: sock.close()
        return None


class SteganographySender:
    """Simple steganography sender using only TCP with acknowledgment."""

    def __init__(self, target_ip):
        """Initialize the sender."""
        global receiver_ip # Ensure we use the globally set receiver_ip

        if not target_ip:
             raise ValueError("Target IP cannot be None for SteganographySender")
        self.target_ip = target_ip
        receiver_ip = target_ip # Set the global variable too

        self.source_port = random.randint(10000, 60000)
        log_debug(f"Sender TCP initialized. Target: {self.target_ip}, Source Port: {self.source_port}")


        # Create debug file paths
        self.chunks_json_path = os.path.join(LOGS_DIR, "sent_chunks.json")
        self.acks_json_path = os.path.join(LOGS_DIR, "received_acks.json")

        # Initialize log files
        with open(self.chunks_json_path, "w") as f: json.dump({}, f)
        with open(self.acks_json_path, "w") as f: json.dump({}, f)

        self.sent_chunks = {}
        self.received_acks = {}

        # ACK listener thread setup
        self.ack_processing_thread = None
        self.stop_ack_processing = threading.Event()


    def start_ack_listener(self):
        """Start a thread to listen for TCP ACK packets."""
        if not receiver_ip:
             log_debug("[ERROR] Cannot start ACK listener: Receiver IP not set.")
             print("[ERROR] Internal error: Cannot listen for ACKs without receiver IP.")
             return False # Indicate failure

        self.stop_ack_processing.clear() # Ensure event is clear
        self.ack_processing_thread = threading.Thread(
            target=self.ack_listener_thread,
            name="AckListenerThread" # Give thread a name
        )
        self.ack_processing_thread.daemon = True
        self.ack_processing_thread.start()
        log_debug(f"Started ACK listener thread (Filter: tcp and src host {receiver_ip} and dst port {self.source_port})")
        print("[THREAD] Started ACK listener thread")
        return True # Indicate success


    def stop_ack_listener(self):
        """Stop the ACK listener thread."""
        if self.ack_processing_thread and self.ack_processing_thread.is_alive():
            print("[THREAD] Signalling ACK listener thread to stop...")
            log_debug("Signalling ACK listener thread to stop...")
            self.stop_ack_processing.set()
            self.ack_processing_thread.join(2.0) # Wait up to 2 seconds
            if self.ack_processing_thread.is_alive():
                 print("[THREAD] Warning: ACK listener thread did not stop gracefully.")
                 log_debug("Warning: ACK listener thread did not stop gracefully.")
            else:
                 print("[THREAD] Stopped ACK listener thread.")
                 log_debug("Stopped ACK listener thread.")
        else:
             log_debug("ACK listener thread was not running or already stopped.")


    def ack_listener_thread(self):
        """Thread function to listen for and process TCP ACK packets."""
        log_debug("ACK listener thread running.")
        # Receiver IP should be set before this thread starts
        filter_str = f"tcp and src host {receiver_ip} and dst port {self.source_port}"

        try:
            sniff(
                filter=filter_str,
                prn=self.process_ack_packet,
                store=0,
                stop_filter=lambda p: self.stop_ack_processing.is_set()
            )
        except ImportError as e:
             # Handle case where Scapy might not have full functionality (e.g., missing winpcap/npcap)
             log_debug(f"FATAL: Scapy sniffing dependency error in ACK thread: {e}. Cannot receive ACKs.")
             print(f"[FATAL ERROR] Scapy cannot sniff packets: {e}. Please install dependencies (e.g., Npcap on Windows).")
             # Maybe signal main thread to stop? Difficult from daemon thread.
        except OSError as e:
            # Handle permission errors (common if not run as root/admin)
            log_debug(f"FATAL: OS error during sniff in ACK thread (Permissions?): {e}")
            print(f"[FATAL ERROR] Cannot sniff packets (Permissions issue?): {e}. Try running with sudo/Administrator.")
        except Exception as e:
            log_debug(f"Error in ACK listener thread: {e}")
            print(f"[ERROR] ACK listener thread encountered an error: {e}")

        log_debug("ACK listener thread finished.")


    def log_chunk(self, seq_num, data):
        """Save chunk data to JSON log and raw file."""
        self.sent_chunks[str(seq_num)] = {
            "data": data.hex(), "size": len(data), "timestamp": time.time()
        }
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(self.sent_chunks, f, indent=2)
            chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:03d}.bin")
            with open(chunk_file, "wb") as f: f.write(data)
        except Exception as e:
            log_debug(f"Error logging chunk {seq_num}: {e}")


    def log_ack(self, seq_num):
        """Save received ACK info to JSON log."""
        self.received_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.received_acks, f, indent=2)
        except Exception as e:
             log_debug(f"Error logging ACK {seq_num}: {e}")


    def create_syn_packet(self):
        """Create the initial TCP SYN packet for connection establishment."""
        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000), # Receiver listens broadly
            seq=0x12345678,  # Fixed pattern for initial SYN
            window=0xDEAD,   # Special window value for handshake SYN
            flags="S"
        )
        log_debug(f"Created Handshake SYN packet for {self.target_ip}")
        return syn_packet

    def create_ack_packet(self):
        """Create the final TCP ACK packet to complete connection establishment."""
        global receiver_ip, receiver_port # Use global receiver info

        if not receiver_ip or not receiver_port:
            log_debug("Cannot create handshake ACK - receiver IP or Port information missing")
            return None

        ack_packet = IP(dst=receiver_ip) / TCP(
            sport=self.source_port,
            dport=receiver_port,
            seq=0x87654321,  # Fixed pattern for final Handshake ACK
            ack=0xABCDEF12 + 1, # Acknowledge receiver's SYN-ACK seq number + 1
            window=0xF00D,   # Special window value for handshake completion ACK
            flags="A"
        )
        log_debug(f"Created Handshake ACK packet for {receiver_ip}:{receiver_port}")
        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data (using SYN flag)."""
        if len(data) < MAX_CHUNK_SIZE: data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE: data = data[:MAX_CHUNK_SIZE]

        dst_port = random.randint(10000, 60000)
        try:
            tcp_seq = int.from_bytes(data[0:4], byteorder='big')
            tcp_ack = int.from_bytes(data[4:8], byteorder='big')
        except Exception as e:
             log_debug(f"Error converting data chunk {seq_num} to int: {e}, Data: {data.hex()}")
             return None # Cannot create packet

        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=tcp_seq, # Embed first 4 bytes
            ack=tcp_ack, # Embed last 4 bytes
            window=seq_num,  # Put sequence number in window field
            flags="S",       # SYN flag identifies data packet in this protocol
            options=[('MSS', total_chunks)]
        )

        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum # Store checksum in IP ID

        # log_debug(f"Created data packet: Win={seq_num}, Total={total_chunks}, Data={data.hex()}, Chk={checksum:04x}") # Verbose
        return tcp_packet

    def create_completion_packet(self):
        """Create a TCP FIN packet signaling transmission completion."""
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000),
            window=0xFFFF,  # Special value for completion
            flags="F"       # FIN flag signals completion
        )
        log_debug(f"Created completion packet (FIN) for {self.target_ip}")
        return tcp_packet

    def process_ack_packet(self, packet):
        """Process a received TCP ACK packet (either handshake SYN-ACK or data ACK)."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_ip, receiver_port

        # Basic checks (already filtered by Scapy for IP/TCP/SrcIP/DstPort)
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Learn receiver's source port if not known (expecting it from SYN-ACK mostly)
        if receiver_port is None and tcp_layer.sport != 0:
            receiver_port = tcp_layer.sport
            log_debug(f"Learned receiver port: {receiver_port} from packet with flags {tcp_layer.flags:#x}")
            print(f"[HANDSHAKE] Learned receiver port: {receiver_port}")

        # 1. Check for Handshake SYN-ACK
        # Matches receiver's create_syn_ack_packet: SA flags, specific seq, window, ack
        if not connection_established and tcp_layer.flags & 0x12 == 0x12 \
           and tcp_layer.window == 0xBEEF and tcp_layer.seq == 0xABCDEF12 \
           and tcp_layer.ack == (0x12345678 + 1):
            log_debug(f"Received Handshake SYN-ACK from {ip_layer.src}:{tcp_layer.sport}")
            print("[HANDSHAKE] Received SYN-ACK response")

            if receiver_port != tcp_layer.sport:
                 log_debug(f"SYN-ACK source port {tcp_layer.sport} differs from previously learned {receiver_port}. Updating.")
                 receiver_port = tcp_layer.sport

            # Send final Handshake ACK to complete handshake
            ack_packet = self.create_ack_packet()
            if ack_packet:
                log_debug("Sending final Handshake ACK to complete connection")
                print("[HANDSHAKE] Sending final ACK to complete connection")
                for i in range(5): # Send multiple times for reliability
                    send(ack_packet)
                    time.sleep(0.1)
                connection_established = True
                print("[HANDSHAKE] Connection established successfully")
                log_debug("[HANDSHAKE] Connection established.")
                # Return True because we processed this specific packet type
                return True
            else:
                 log_debug("[ERROR] Failed to create final Handshake ACK packet.")
                 # Connection remains not established
                 return False


        # 2. Check for Data Chunk ACK (after connection established)
        # Matches receiver's create_ack_packet: ACK flag, specific seq, window, ack=chunk_seq_num
        if connection_established and tcp_layer.flags & 0x10 and tcp_layer.window == 0xCAFE \
           and tcp_layer.seq == 0x12345678:
            seq_num = tcp_layer.ack # Acknowledged chunk number is in TCP ACK field

            # Ignore invalid sequence numbers
            if seq_num <= 0 or seq_num > 65535: # Basic sanity check
                log_debug(f"Received Data ACK packet with invalid seq_num {seq_num}. Ignored.")
                return False

            log_debug(f"Received potential Data ACK for chunk {seq_num} from {ip_layer.src}:{tcp_layer.sport}")

            if seq_num not in acked_chunks:
                acked_chunks.add(seq_num)
                self.log_ack(seq_num)
                log_debug(f"Added chunk {seq_num} to acked_chunks set.")

            if waiting_for_ack and seq_num == current_chunk_seq:
                log_debug(f"Chunk {seq_num} acknowledgment confirmed.")
                print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                waiting_for_ack = False # Stop waiting
            else:
                log_debug(f"Received ACK for chunk {seq_num}, but waiting_for_ack={waiting_for_ack} (current_chunk_seq={current_chunk_seq}).")

            # Return True because we processed this specific packet type
            return True

        # If packet didn't match known patterns
        log_debug(f"Ignored packet from {ip_layer.src}:{tcp_layer.sport}. Flags={tcp_layer.flags:#x}, Window={tcp_layer.window:#x}, Seq={tcp_layer.seq:#x}, Ack={tcp_layer.ack:#x}")
        return False


    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq

        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping send.")
            print(f"[SKIP] Chunk {seq_num:04d} already acknowledged")
            return True

        packet = self.create_packet(data, seq_num, total_chunks)
        if not packet:
             print(f"[ERROR] Failed to create packet for chunk {seq_num}. Skipping.")
             log_debug(f"Failed to create packet for chunk {seq_num}. Aborting send attempt for this chunk.")
             return False # Indicate failure for this chunk

        self.log_chunk(seq_num, data) # Log only when attempting to send

        current_chunk_seq = seq_num
        waiting_for_ack = True
        retransmit_count = 0
        start_time = time.time()

        log_debug(f"Attempting to send chunk {seq_num}/{total_chunks}")
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:.2f}%")
        send(packet) # Initial send

        while waiting_for_ack and retransmit_count < MAX_RETRANSMISSIONS:
            wait_start = time.time()
            while waiting_for_ack and (time.time() - wait_start < ACK_WAIT_TIMEOUT):
                time.sleep(0.1) # Check frequently if ACK received

            if waiting_for_ack: # If still waiting after timeout period
                retransmit_count += 1
                log_debug(f"ACK timeout for chunk {seq_num}. Retransmitting (attempt {retransmit_count}/{max_retransmits})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{MAX_RETRANSMISSIONS}")
                send(packet) # Resend

        # Check final status after loop
        if waiting_for_ack:
            log_debug(f"Failed to get ACK for chunk {seq_num} after {MAX_RETRANSMISSIONS} retransmissions")
            print(f"[WARNING] No ACK received for chunk {seq_num:04d} after {MAX_RETRANSMISSIONS} attempts")
            waiting_for_ack = False # Reset for next chunk attempt
            return False # Indicate failure
        else:
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} confirmed acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
            print(f"[CONFIRMED] Chunk {seq_num:04d} successfully delivered")
            return True # Indicate success


def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            data = file.read()
            log_debug(f"Read {len(data)} bytes from {file_path}")
            return data
    except FileNotFoundError:
        log_debug(f"Error: File not found {file_path}")
        print(f"Error: Input file not found at {file_path}")
        sys.exit(1)
    except Exception as e:
        log_debug(f"Error reading file {file_path}: {e}")
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def prepare_key(key_data):
    """Prepare the encryption key (32 bytes) and return bytes and SHA256 hex hash."""
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try: # Check if hex
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             key_bytes_from_hex = bytes.fromhex(key_data.decode('ascii'))
             key_data = key_bytes_from_hex
             log_debug("Interpreted key data as hex string.")
             print("Interpreted key data as hex string.")
    except ValueError: pass # Not hex

    original_len = len(key_data)
    if original_len < 32: key_data = key_data.ljust(32, b'\0')
    elif original_len > 32: key_data = key_data[:32]
    if original_len != 32: log_debug(f"Key adjusted from {original_len} bytes to 32 bytes.")

    log_debug(f"Final key bytes (for encryption): {key_data.hex()}")
    try: # Save key for debugging
        key_file = os.path.join(DATA_DIR, "key.bin")
        with open(key_file, "wb") as f: f.write(key_data)
    except Exception as e: log_debug(f"Error saving key.bin: {e}")

    key_hash = hashlib.sha256(key_data).digest()
    key_hash_hex = key_hash.hex()
    log_debug(f"Key hash (SHA256 for discovery): {key_hash_hex}")
    print(f"[KEY] Key Hash (SHA256): {key_hash_hex}")
    return key_data, key_hash_hex

def encrypt_data(data, key):
    """Encrypt data using AES-256-CFB with a random IV."""
    try:
        iv = os.urandom(16) # Generate random 16-byte IV
        log_debug(f"Generated random IV: {iv.hex()}")
        try: # Save IV for debugging
            with open(os.path.join(DATA_DIR, "iv.bin"), "wb") as f: f.write(iv)
        except Exception as e: log_debug(f"Error saving iv.bin: {e}")

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        package_data = iv + encrypted_data # Prepend IV
        log_debug(f"Encryption successful. Input size: {len(data)}, Output size (incl IV): {len(package_data)}")
        try: # Save debug files
            with open(os.path.join(DATA_DIR, "original_data.bin"), "wb") as f: f.write(data)
            with open(os.path.join(DATA_DIR, "encrypted_package.bin"), "wb") as f: f.write(package_data)
        except Exception as e: log_debug(f"Error saving encrypted debug files: {e}")

        return package_data
    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"[ERROR] Encryption error: {e}")
        return None # Indicate failure

def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data ({len(data)} bytes) into {len(chunks)} chunks of max size {chunk_size}")
    # Maybe add limited chunk logging here if needed
    return chunks

def establish_connection(stego):
    """Establish TCP connection using custom 3-way handshake."""
    global connection_established
    connection_established = False # Reset status

    log_debug("Starting TCP connection establishment...")
    print("[HANDSHAKE] Initiating connection with receiver...")

    if not stego.start_ack_listener(): # Start listener thread first
         log_debug("Failed to start ACK listener thread. Aborting handshake.")
         return False

    time.sleep(0.5) # Give listener a moment

    syn_packet = stego.create_syn_packet()
    if not syn_packet:
         log_debug("Failed to create SYN packet.")
         print("[ERROR] Failed to create SYN packet.")
         stego.stop_ack_listener()
         return False

    log_debug("Sending initial SYN packet")
    print("[HANDSHAKE] Sending SYN packet...")

    send_attempts = 5
    resend_interval = 0.3 # Faster resends for initial SYN
    for i in range(send_attempts):
        send(syn_packet)
        time.sleep(resend_interval)
        if connection_established: # Listener might set this quickly
            log_debug(f"Connection established after {i+1} SYN attempts.")
            print("[HANDSHAKE] Connection established successfully (during initial SYNs)")
            return True

    # Wait longer for SYN-ACK if not established yet
    max_wait = 20 # Reduced wait time for SYN-ACK phase
    wait_interval = 1
    resend_interval_wait = 5 # Slower resends while waiting
    start_time = time.time()
    last_resend_time = time.time()

    print(f"[HANDSHAKE] Waiting up to {max_wait}s for SYN-ACK...")
    while not connection_established and (time.time() - start_time < max_wait):
        if time.time() - last_resend_time > resend_interval_wait:
            log_debug("Resending SYN packet (waiting for SYN-ACK)")
            print("[HANDSHAKE] Resending SYN packet...")
            send(syn_packet)
            last_resend_time = time.time()
        time.sleep(wait_interval) # Check connection status periodically

    if connection_established:
        log_debug("Connection established successfully (confirmed by listener after wait)")
        print("[HANDSHAKE] Connection established successfully")
        return True
    else:
        log_debug("Failed to establish connection (timeout waiting for SYN-ACK)")
        print("[HANDSHAKE] Failed to establish connection with receiver (Timeout)")
        stego.stop_ack_listener() # Stop listener if connection failed
        return False


def send_file(file_path, discovered_target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt (if key) and send a file via steganography after potential IP discovery."""
    global connection_established, acked_chunks, receiver_ip

    if not discovered_target_ip:
        log_debug("Cannot send file: Target IP is missing.")
        return False
    receiver_ip = discovered_target_ip # Use the confirmed IP

    # --- Prepare Data ---
    log_debug(f"Preparing file: {file_path} for target {receiver_ip}")
    file_data_plain = read_file(file_path, 'rb')
    if file_data_plain is None: return False

    key_bytes = None
    if key_path:
        log_debug(f"Reading key file {key_path} for encryption.")
        key_data_raw = read_file(key_path, 'rb')
        if key_data_raw is None: return False
        key_bytes, _ = prepare_key(key_data_raw) # We only need key bytes now
        if not key_bytes: return False # prepare_key handles errors

        log_debug(f"Encrypting {len(file_data_plain)} bytes...")
        print(f"[ENCRYPT] Encrypting {len(file_data_plain)} bytes...")
        file_data_to_send = encrypt_data(file_data_plain, key_bytes)
        if file_data_to_send is None: return False # Encryption failed
        log_debug(f"Encrypted data size (incl IV): {len(file_data_to_send)}")
        print(f"[ENCRYPT] Encrypted size: {len(file_data_to_send)} bytes")
    else:
        log_debug("No encryption key provided. Sending data in plaintext.")
        print("[WARN] No encryption key provided. Sending unencrypted.")
        file_data_to_send = file_data_plain

    # Add MD5 checksum
    file_checksum = hashlib.md5(file_data_to_send).digest()
    final_data_package = file_data_to_send + file_checksum
    log_debug(f"Added MD5 checksum ({file_checksum.hex()}). Final package size: {len(final_data_package)} bytes")
    print(f"[CHECKSUM] Added MD5: {file_checksum.hex()}")

    try: # Save final package for debugging
        with open(os.path.join(DATA_DIR, "final_data_package.bin"), "wb") as f: f.write(final_data_package)
        with open(os.path.join(DATA_DIR, "md5_checksum.bin"), "wb") as f: f.write(file_checksum)
    except Exception as e: log_debug(f"Error saving final package/checksum: {e}")

    # --- Initialize Sender & Establish Connection ---
    acked_chunks = set()
    connection_established = False
    try:
        stego = SteganographySender(receiver_ip)
    except ValueError as e:
        log_debug(f"Error initializing sender: {e}"); print(f"[ERROR] {e}"); return False

    if not establish_connection(stego):
        log_debug("Aborting transmission due to connection failure")
        print("[ERROR] Aborting transmission: Connection failed")
        # Listener stopped by establish_connection
        return False # Indicate failure

    # --- Chunk and Send Data ---
    chunks = chunk_data(final_data_package, chunk_size)
    total_chunks = len(chunks)
    if total_chunks == 0:
         log_debug("Warning: No data chunks to send (file might be empty or just IV/checksum?).")
         print("[WARN] Input file resulted in zero data chunks. Sending completion signal only.")
    else:
        log_debug(f"Starting transmission of {total_chunks} chunks to {receiver_ip}...")
        print(f"[TRANSMISSION] Sending {total_chunks} chunks to {receiver_ip}...")
        transmission_success = True
        start_chunk_time = time.time()
        for i, chunk in enumerate(chunks):
            seq_num = i + 1
            if not stego.send_chunk(chunk, seq_num, total_chunks):
                transmission_success = False
                print(f"[ERROR] Failed to send chunk {seq_num} after retries. Aborting.")
                log_debug(f"Aborting transmission after failure on chunk {seq_num}.")
                break # Abort on first failure
            time.sleep(delay) # Inter-packet delay

        chunk_duration = time.time() - start_chunk_time
        log_debug(f"Chunk transmission phase completed in {chunk_duration:.2f} seconds. Success={transmission_success}")
        if not transmission_success:
             # Don't send completion if aborted? Or send anyway? Send anyway for now.
             print("[TRANSMISSION] Phase completed with errors.")
        else:
             print(f"[TRANSMISSION] Finished sending chunks in {chunk_duration:.2f}s")


    # --- Send Completion Signal ---
    completion_packet = stego.create_completion_packet()
    if completion_packet:
        print("[COMPLETE] Sending transmission completion signals...")
        for i in range(10):
            log_debug(f"Sending completion signal (attempt {i+1}/10)")
            send(completion_packet)
            time.sleep(0.2)
    else:
        log_debug("Failed to create completion packet.")


    # --- Cleanup and Stats ---
    stego.stop_ack_listener() # Stop the listener thread

    ack_rate = (len(acked_chunks) / total_chunks * 100) if total_chunks > 0 else 100
    log_debug(f"Transmission summary: ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks})")
    print(f"[STATS] Final ACK rate: {ack_rate:.1f}% ({len(acked_chunks)}/{total_chunks})")

    # Determine final status more accurately
    final_status = "unknown"
    if 'transmission_success' not in locals(): transmission_success = True # Case for 0 chunks
    if transmission_success and len(acked_chunks) == total_chunks: final_status = "completed_fully_acked"
    elif transmission_success: final_status = "completed_partially_acked"
    else: final_status = "failed_chunks_undelivered"

    log_debug(f"Final transmission status: {final_status}")
    print(f"[COMPLETE] Transmission status: {final_status}")

    # Save session summary including status
    summary = { "timestamp": time.time(), "file_path": file_path, "target_ip": receiver_ip,
                "key_path": key_path, "chunk_size": chunk_size, "delay": delay,
                "ack_timeout": ACK_WAIT_TIMEOUT, "max_retransmissions": MAX_RETRANSMISSIONS,
                "discovery_port": DISCOVERY_PORT, "total_chunks": total_chunks,
                "chunks_acked": len(acked_chunks), "ack_rate": ack_rate, "final_status": final_status }
    try:
        with open(os.path.join(LOGS_DIR, "session_summary.json"), "w") as f: json.dump(summary, f, indent=2)
    except Exception as e: log_debug(f"Error saving session summary: {e}")

    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    return final_status.startswith("completed") # Return True if it completed sending, False if critical error early


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Sender with Discovery')
    parser.add_argument('--target', '-t', help='Target IP address (optional, overrides discovery)')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=False, help='Encryption/Discovery key file (required if --target is not specified)')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets (s, default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE, help=f'Chunk size (bytes, default/max: {MAX_CHUNK_SIZE})')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for logs/data')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT, help=f'TCP ACK timeout (s, default: {ACK_WAIT_TIMEOUT})')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS, help=f'Max TCP retransmissions (default: {MAX_RETRANSMISSIONS})')
    parser.add_argument('--discovery-port', '-dp', type=int, default=DISCOVERY_PORT, help=f'UDP discovery port (default: {DISCOVERY_PORT})')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT, help=f'Discovery timeout (s, default: {DISCOVERY_TIMEOUT})')
    args = parser.parse_args()
    if not args.target and not args.key: parser.error("Either --target IP or --key for discovery must be provided.")
    return args

def main():
    """Main function."""
    args = parse_arguments()

    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, DISCOVERY_PORT, DISCOVERY_TIMEOUT
    if args.output_dir: OUTPUT_DIR = args.output_dir
    setup_directories() # Creates dirs and initializes log file

    log_debug("Sender starting...")
    log_debug(f"Arguments: {vars(args)}")

    # Apply settings from args
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    DISCOVERY_PORT = args.discovery_port
    DISCOVERY_TIMEOUT = args.discovery_timeout
    chunk_size = min(args.chunk_size, MAX_CHUNK_SIZE)
    if args.chunk_size > MAX_CHUNK_SIZE:
        print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE} (maximum supported)")
        log_debug(f"Chunk size clamped to {MAX_CHUNK_SIZE}")

    target_ip = args.target
    key_hash_hex = None

    # Process key file if provided (needed for discovery OR encryption)
    if args.key:
        log_debug(f"Reading key file: {args.key}")
        key_data_raw = read_file(args.key, 'rb')
        if key_data_raw is None: sys.exit(1) # Error already printed
        _, key_hash_hex = prepare_key(key_data_raw) # Get hash for discovery
        if not key_hash_hex:
             print("[ERROR] Could not generate key hash from key file.")
             log_debug("Failed to generate key hash from key file.")
             sys.exit(1)

    # Perform discovery if target IP is not provided
    if not target_ip:
        if not key_hash_hex:
             # This case is caught by arg parser, but double-check
             print("[ERROR] Cannot perform discovery without a key (--key).")
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


    # Send the file
    success = send_file(
        args.input,
        target_ip, # Discovered or provided IP
        args.key,  # Pass key path again for encryption check inside send_file
        chunk_size,
        args.delay
    )

    log_debug(f"Sender finished. Overall success status: {success}")
    print(f"Sender finished. {'Operation completed (check logs/status).' if success else 'Operation failed.'}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    # Check for root/admin privileges needed for raw sockets/sniffing
    if os.name == 'posix' and os.geteuid() != 0:
         print("Warning: Scapy often requires root privileges for sending/receiving packets.")
         print("         Please run with 'sudo python3 sender.py ...'")
    elif os.name == 'nt':
         # Less direct check on Windows, but remind user about Npcap/Admin
         print("Info: Ensure Npcap is installed and Python has necessary permissions (Run as Administrator if needed).")

    main()