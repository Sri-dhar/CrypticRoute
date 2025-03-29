#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure and acknowledgment system
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, sniff, conf

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
RETRANSMIT_ATTEMPTS = 5 # This is not directly used in the current send_chunk logic, MAX_RETRANSMISSIONS is used instead.
ACK_WAIT_TIMEOUT = 10  # Seconds to wait for an ACK before retransmission
MAX_RETRANSMISSIONS = 10  # Maximum number of times to retransmit a chunk

# Global variables for the acknowledgment system
acked_chunks = set()  # Set of sequence numbers that have been acknowledged
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None
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
            print(f"Renamed existing file/directory to {backup_name}")

        # Create new symlink pointing to the absolute path of the session directory
        # This ensures the symlink works correctly regardless of where it's accessed from
        abs_session_dir = os.path.abspath(SESSION_DIR)
        os.symlink(abs_session_dir, latest_link)
        print(f"Created symlink: {latest_link} -> {abs_session_dir}")
    except Exception as e:
        print(f"Warning: Could not create/update symlink '{latest_link}': {e}")
        # Continue without the symlink - this is not critical

    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log {DEBUG_LOG}: {e}")


class SteganographySender:
    """Simple steganography sender using only TCP with acknowledgment."""

    def __init__(self, target_ip):
        """Initialize the sender."""
        self.target_ip = target_ip
        self.source_port = random.randint(10000, 60000)

        # Ensure log directory exists before creating files within it
        if not os.path.exists(LOGS_DIR):
             os.makedirs(LOGS_DIR) # Should have been created by setup_directories, but good safeguard

        # Create debug file for sent chunks
        chunks_json = os.path.join(LOGS_DIR, "sent_chunks.json")
        try:
            with open(chunks_json, "w") as f:
                json.dump({}, f) # Start with an empty JSON object
            self.sent_chunks = {}
            self.chunks_json_path = chunks_json
        except Exception as e:
            print(f"Error initializing sent_chunks.json: {e}")
            self.chunks_json_path = None # Prevent further errors


        # Create debug file for received ACKs
        acks_json = os.path.join(LOGS_DIR, "received_acks.json")
        try:
            with open(acks_json, "w") as f:
                 json.dump({}, f) # Start with an empty JSON object
            self.acks_json_path = acks_json
            self.received_acks = {}
        except Exception as e:
             print(f"Error initializing received_acks.json: {e}")
             self.acks_json_path = None # Prevent further errors


        # Initialize values for packet processing threads
        self.ack_processing_thread = None
        self.stop_ack_processing = threading.Event()

    def start_ack_listener(self):
        """Start a thread to listen for ACK packets."""
        if self.ack_processing_thread and self.ack_processing_thread.is_alive():
            log_debug("ACK listener thread already running.")
            print("[THREAD] ACK listener thread already running.")
            return

        self.stop_ack_processing.clear() # Ensure flag is reset
        self.ack_processing_thread = threading.Thread(
            target=self.ack_listener_thread
        )
        self.ack_processing_thread.daemon = True
        self.ack_processing_thread.start()
        log_debug("Started ACK listener thread")
        print("[THREAD] Started ACK listener thread")

    def stop_ack_listener(self):
        """Stop the ACK listener thread."""
        if self.ack_processing_thread and self.ack_processing_thread.is_alive():
            self.stop_ack_processing.set()
            self.ack_processing_thread.join(2)  # Wait up to 2 seconds for thread to finish
            if self.ack_processing_thread.is_alive():
                 log_debug("ACK listener thread did not stop gracefully.")
                 print("[THREAD] Warning: ACK listener thread did not stop gracefully.")
            else:
                 log_debug("Stopped ACK listener thread")
                 print("[THREAD] Stopped ACK listener thread")
            self.ack_processing_thread = None
        else:
             log_debug("ACK listener thread was not running or already stopped.")
             # print("[THREAD] ACK listener thread was not running.")


    def ack_listener_thread(self):
        """Thread function to listen for and process ACK packets."""
        global stop_sniffing

        log_debug("ACK listener thread started")

        try:
            # Set up sniffing for TCP ACK packets coming to our source port
            filter_str = f"tcp and dst port {self.source_port}"
            log_debug(f"Sniffing for ACKs with filter: {filter_str}")

            # Start packet sniffing for ACKs
            # Use stop_event for cleaner shutdown
            sniff(
                filter=filter_str,
                prn=self.process_ack_packet,
                store=0,
                stop_filter=lambda p: stop_sniffing or self.stop_ack_processing.is_set()
                # stop_event=self.stop_ack_processing # Alternative way to stop, might be cleaner
            )
        except Exception as e:
            log_debug(f"Error in ACK listener thread: {e}")
            print(f"[ERROR] ACK listener thread encountered an error: {e}")

        log_debug("ACK listener thread stopped")

    def log_chunk(self, seq_num, data):
        """Save chunk data to debug file."""
        if not self.chunks_json_path: return # Skip if file init failed

        self.sent_chunks[str(seq_num)] = {
            "data": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }
        try:
            with open(self.chunks_json_path, "w") as f:
                json.dump(self.sent_chunks, f, indent=2)
        except Exception as e:
             print(f"Error writing to chunks log {self.chunks_json_path}: {e}")

        # Also save the raw chunk data
        chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:04d}.bin") # Use 4 digits padding
        try:
            with open(chunk_file, "wb") as f:
                f.write(data)
        except Exception as e:
             print(f"Error writing chunk file {chunk_file}: {e}")

    def log_ack(self, seq_num):
        """Save received ACK to debug file."""
        if not self.acks_json_path: return # Skip if file init failed

        self.received_acks[str(seq_num)] = {
            "timestamp": time.time()
        }
        try:
            with open(self.acks_json_path, "w") as f:
                json.dump(self.received_acks, f, indent=2)
        except Exception as e:
            print(f"Error writing to ACK log {self.acks_json_path}: {e}")


    def create_syn_packet(self):
        """Create a SYN packet for connection establishment."""
        # Create a SYN packet with special markers
        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000), # Randomize dest port for SYN
            seq=0x12345678,  # Fixed pattern for SYN identification on receiver
            window=0xDEAD,   # Special window value for handshake identification
            flags="S"        # SYN flag
        )

        return syn_packet

    def create_ack_packet(self):
        """Create an ACK packet to complete connection establishment."""
        global receiver_ip, receiver_port

        if not receiver_ip or not receiver_port:
            log_debug("Cannot create final ACK - receiver information missing")
            print("[HANDSHAKE] Error: Cannot send final ACK, receiver IP/Port unknown.")
            return None

        # Create an ACK packet with special markers
        ack_packet = IP(dst=receiver_ip) / TCP(
            sport=self.source_port,
            dport=receiver_port, # Use the port the receiver responded from
            seq=0x87654321,  # Fixed pattern for final ACK identification
            ack=0xABCDEF12,  # This should ideally match receiver's SYN-ACK seq number + 1, but receiver might ignore it. Using fixed for simplicity.
            window=0xF00D,   # Special window value for handshake completion identification
            flags="A"        # ACK flag
        )

        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data."""
        # Ensure data is exactly MAX_CHUNK_SIZE bytes
        if len(data) < MAX_CHUNK_SIZE:
            data = data.ljust(MAX_CHUNK_SIZE, b'\0') # Pad with null bytes if too short
        elif len(data) > MAX_CHUNK_SIZE:
            data = data[:MAX_CHUNK_SIZE] # Truncate if too long

        # Create random destination port for stealth/obfuscation
        dst_port = random.randint(10000, 60000)

        # Embed first 4 bytes in sequence number and last 4 in ack number
        # Use a fixed flag pattern (e.g., PSH+ACK) for data packets for easier filtering? Or keep SYN?
        # Using SYN as per original logic, but receiver needs to handle this.
        # PSH+ACK (0x18) might be more 'normal' for data transfer. Let's stick to SYN for now.
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,  # Put sequence number in window field
            flags="S",       # SYN flag (as per original - receiver must expect this for data)
            # flags="PA",    # Alternative: PSH+ACK flags might look more like data transfer
            options=[('MSS', total_chunks)]  # Store total chunks in MSS option
        )

        # Store checksum in IP ID field (simple checksum)
        checksum = binascii.crc32(data) & 0xFFFF # Calculate CRC32 checksum, take lower 16 bits
        tcp_packet[IP].id = checksum

        return tcp_packet

    def create_completion_packet(self):
        """Create a packet signaling transmission completion."""
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000), # Random dest port
            window=0xFFFF,  # Special value indicating completion
            flags="F",      # FIN flag signals completion
            seq=0xFFFFFFFF  # Optional: Add a distinct sequence number
        )
        return tcp_packet

    def process_ack_packet(self, packet):
        """Process a received packet, looking for handshake or data ACKs."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_ip, receiver_port

        # Check if it's a TCP packet from the target IP we expect (or haven't identified yet)
        if IP in packet and TCP in packet and (receiver_ip is None or packet[IP].src == receiver_ip):
            src_ip = packet[IP].src
            src_port = packet[TCP].sport

            # --- Handshake Processing ---
            # Check for SYN-ACK response to our initial SYN
            # Flags: SYN=1, ACK=1 -> 0x12. Window: 0xBEEF (marker)
            if not connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == 0xBEEF:
                log_debug(f"Received SYN-ACK for connection establishment from {src_ip}:{src_port}")
                print(f"[HANDSHAKE] Received SYN-ACK response from {src_ip}:{src_port}")

                # Store receiver info (use info from this packet)
                receiver_ip = src_ip
                receiver_port = src_port
                log_debug(f"Receiver identified as {receiver_ip}:{receiver_port}")

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
                    log_debug("Connection established successfully")
                    print("[HANDSHAKE] Connection established successfully")
                else:
                    log_debug("Failed to create final ACK packet")
                    print("[HANDSHAKE] Error: Failed to create final ACK packet")

                return True # Processed handshake packet

            # --- Data ACK Processing ---
            # Check for ACK packet signaling receipt of a data chunk
            # Flags: ACK=1 -> 0x10. Window: 0xCAFE (marker)
            if connection_established and packet[TCP].flags & 0x10 == 0x10 and packet[TCP].window == 0xCAFE:
                # Extract the sequence number from the ack field (as sent by receiver)
                seq_num = packet[TCP].ack

                # Check if the source IP/port matches the established receiver
                if src_ip != receiver_ip or src_port != receiver_port:
                    log_debug(f"Received ACK packet from unexpected source {src_ip}:{src_port}. Expected {receiver_ip}:{receiver_port}. Ignoring.")
                    return False

                log_debug(f"Received ACK for chunk {seq_num}")
                self.log_ack(seq_num)

                # Add to acknowledged chunks
                acked_chunks.add(seq_num)

                # If this is the chunk we're currently waiting for, clear the wait flag
                if waiting_for_ack and seq_num == current_chunk_seq:
                    log_debug(f"Chunk {seq_num} acknowledged by receiver.")
                    print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                    waiting_for_ack = False

                return True # Processed data ACK packet

            # Log unexpected packets if needed
            # else:
            #    log_debug(f"Received unexpected TCP packet from {src_ip}:{src_port} flags={packet[TCP].flags_str} window={packet[TCP].window}")

        return False # Packet not processed by this function


    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq

        # Skip if this chunk has already been acknowledged (e.g., from a previous run/reconnect)
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping transmission.")
            print(f"[SKIP] Chunk {seq_num:04d} already acknowledged")
            return True

        # Create the packet
        packet = self.create_packet(data, seq_num, total_chunks)

        # Log the chunk being sent
        self.log_chunk(seq_num, data)

        # Set current chunk and waiting flag
        current_chunk_seq = seq_num
        waiting_for_ack = True

        # Initial transmission
        log_debug(f"Sending chunk {seq_num}/{total_chunks}")
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:.2f}%")
        send(packet)

        # Wait for ACK with retransmission
        retransmit_count = 0
        max_retransmits = MAX_RETRANSMISSIONS
        start_time = time.time()

        while waiting_for_ack and retransmit_count < max_retransmits:
            # Wait for ACK_WAIT_TIMEOUT seconds
            wait_end_time = time.time() + ACK_WAIT_TIMEOUT
            while waiting_for_ack and time.time() < wait_end_time:
                time.sleep(0.1) # Check frequently without busy-waiting

            # If we're still waiting for ACK after the timeout, retransmit
            if waiting_for_ack:
                retransmit_count += 1
                log_debug(f"Timeout waiting for ACK for chunk {seq_num}. Retransmitting (attempt {retransmit_count}/{max_retransmits})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} (Timeout) | Attempt: {retransmit_count}/{max_retransmits}")
                send(packet)

        # Check final status after loop
        if waiting_for_ack:
            # Failed to get ACK after all retransmissions
            log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions.")
            print(f"[FAIL] No ACK received for chunk {seq_num:04d} after {max_retransmits} attempts.")
            waiting_for_ack = False  # Reset for next chunk
            return False
        else:
            # Success - chunk was acknowledged
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} acknowledged. Took {elapsed:.2f}s with {retransmit_count} retransmissions.")
            # Confirmation message printed by process_ack_packet now
            # print(f"[CONFIRMED] Chunk {seq_num:04d} successfully delivered")
            return True


def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            data = file.read()
            log_debug(f"Read {len(data)} bytes from {file_path}")
            return data
    except FileNotFoundError:
         log_debug(f"Error: File not found at {file_path}")
         print(f"Error: File not found at {file_path}")
         sys.exit(1)
    except Exception as e:
        log_debug(f"Error reading file {file_path}: {e}")
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def prepare_key(key_data):
    """Prepare the encryption key to be exactly 32 bytes (AES-256)."""
    # If it's a string, encode to bytes first
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')

    # Check if it looks like a hex string (common way to provide keys)
    is_hex = False
    try:
        # Basic check: length is even, contains only hex chars
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             # More robust: try decoding
             decoded_key = bytes.fromhex(key_data.decode('ascii'))
             key_data = decoded_key # Use decoded key if successful
             is_hex = True
             log_debug("Interpreted key data as hex string and decoded.")
             print("[KEY] Interpreted key file content as hex string.")
    except ValueError:
        log_debug("Key data is not a valid hex string, using raw bytes.")
        # Not a hex string, treat as raw bytes
        pass
    except Exception as e:
        log_debug(f"Error during key hex check: {e}. Using raw bytes.")
        pass # Fallback to raw bytes


    # Ensure key is exactly 32 bytes for AES-256
    key_len = len(key_data)
    if key_len == 32:
        log_debug("Provided key is already 32 bytes.")
    elif key_len < 32:
        # Pad with null bytes if too short
        key_data = key_data.ljust(32, b'\0')
        log_debug(f"Padded key from {key_len} bytes to 32 bytes.")
        print(f"[KEY] Warning: Key was < 32 bytes, padded to 32 bytes.")
    else: # key_len > 32
        # Truncate if too long
        key_data = key_data[:32]
        log_debug(f"Truncated key from {key_len} bytes to 32 bytes.")
        print(f"[KEY] Warning: Key was > 32 bytes, truncated to 32 bytes.")

    log_debug(f"Using AES-256 key: {key_data.hex()}")

    # Save final key for debugging
    key_file = os.path.join(DATA_DIR, "key.bin")
    try:
        with open(key_file, "wb") as f:
            f.write(key_data)
    except Exception as e:
        print(f"Error saving final key file {key_file}: {e}")


    return key_data

def encrypt_data(data, key):
    """Encrypt data using AES-CFB."""
    try:
        # Generate a random 16-byte IV for each encryption
        iv = os.urandom(16)
        log_debug(f"Generated random IV: {iv.hex()}")

        # Save IV for debugging/decryption reference
        iv_file = os.path.join(DATA_DIR, "iv.bin")
        try:
            with open(iv_file, "wb") as f:
                f.write(iv)
        except Exception as e:
            print(f"Error saving IV file {iv_file}: {e}")

        # Initialize AES cipher with key and IV in CFB mode
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Save original and encrypted data for debugging
        original_file = os.path.join(DATA_DIR, "original_data.bin")
        try:
            with open(original_file, "wb") as f:
                f.write(data)
        except Exception as e:
            print(f"Error saving original data file: {e}")

        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        try:
            with open(encrypted_file, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
             print(f"Error saving encrypted data file: {e}")

        # Prepend IV to the encrypted data (common practice for CFB/CBC)
        packaged_data = iv + encrypted_data

        # Save a complete package (IV + encrypted data) for debugging
        package_file = os.path.join(DATA_DIR, "encrypted_package.bin")
        try:
            with open(package_file, "wb") as f:
                f.write(packaged_data)
        except Exception as e:
             print(f"Error saving encrypted package file: {e}")


        log_debug(f"Original data length: {len(data)}")
        log_debug(f"Encrypted data length (without IV): {len(encrypted_data)}")
        log_debug(f"Total packaged data length (IV + encrypted): {len(packaged_data)}")

        # Return IV prepended to encrypted data
        return packaged_data
    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"[ERROR] Encryption failed: {e}")
        sys.exit(1)

def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks of specified size."""
    if chunk_size <= 0:
        log_debug(f"Error: Chunk size must be positive, got {chunk_size}. Using default {MAX_CHUNK_SIZE}.")
        print(f"[ERROR] Invalid chunk size {chunk_size}, using default {MAX_CHUNK_SIZE}.")
        chunk_size = MAX_CHUNK_SIZE

    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split {len(data)} bytes into {len(chunks)} chunks of max size {chunk_size}")

    # Save chunk details for debugging (only first few bytes if large)
    chunk_info = {
         i+1: {
             "size": len(chunk),
             "data_hex_preview": chunk[:16].hex() + ('...' if len(chunk) > 16 else '') # Preview hex
        } for i, chunk in enumerate(chunks)
    }
    chunks_json = os.path.join(LOGS_DIR, "chunks_info.json")
    try:
        with open(chunks_json, "w") as f:
            json.dump(chunk_info, f, indent=2)
    except Exception as e:
         print(f"Error saving chunks info json: {e}")


    return chunks

def establish_connection(stego):
    """Establish connection with the receiver using custom three-way handshake."""
    global connection_established, stop_sniffing

    log_debug("Starting connection establishment...")
    print("[HANDSHAKE] Initiating connection with receiver...")

    # Reset connection state
    connection_established = False
    stop_sniffing = False # Ensure sniffing isn't stopped prematurely

    # Start ACK listener thread if not already running
    stego.start_ack_listener()

    # Send initial SYN packet
    syn_packet = stego.create_syn_packet()
    log_debug("Sending initial SYN packet")
    print("[HANDSHAKE] Sending SYN packet...")

    # Send SYN multiple times initially for reliability, then wait
    initial_sends = 5
    for i in range(initial_sends):
        if connection_established: break # Stop sending if already connected
        send(syn_packet)
        time.sleep(0.2)

    # Wait for the connection to be established (SYN-ACK received and final ACK sent)
    max_wait_time = 30  # Total seconds to wait for handshake completion
    check_interval = 0.5 # How often to check status
    resend_interval = 5  # How often to resend SYN while waiting
    start_time = time.time()
    last_resend_time = start_time

    print(f"[HANDSHAKE] Waiting up to {max_wait_time}s for receiver response...")
    while not connection_established and time.time() - start_time < max_wait_time:
        # Check if it's time to resend SYN
        if time.time() - last_resend_time >= resend_interval:
             log_debug("Resending SYN packet during wait period")
             print("[HANDSHAKE] Resending SYN...")
             send(syn_packet)
             last_resend_time = time.time()

        time.sleep(check_interval)

    # Check final status
    if connection_established:
        log_debug("Connection established successfully within timeout.")
        # Success message printed by process_ack_packet
        # print("[HANDSHAKE] Connection established successfully")
        return True
    else:
        log_debug("Failed to establish connection within timeout.")
        print("[HANDSHAKE] Failed to establish connection with receiver (Timeout).")
        # Stop the listener thread as we failed
        stego.stop_ack_listener()
        return False


def send_file(file_path, target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt and send a file via steganography."""
    global connection_established, stop_sniffing, acked_chunks

    # Initialize debug log for this session
    try:
        with open(DEBUG_LOG, "w") as f:
            f.write(f"=== CrypticRoute Sender Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
            f.write(f"Target: {target_ip}, Input: {file_path}, Key: {key_path}, Chunk: {chunk_size}, Delay: {delay}\n")
            f.write("="*60 + "\n")
    except Exception as e:
        print(f"Error initializing debug log {DEBUG_LOG}: {e}")


    # Create a summary file with transmission parameters
    summary = {
        "session_start_time": datetime.datetime.now().isoformat(),
        "file_path": os.path.abspath(file_path),
        "target_ip": target_ip,
        "key_path": os.path.abspath(key_path) if key_path else None,
        "chunk_size_bytes": chunk_size,
        "inter_packet_delay_sec": delay,
        "ack_wait_timeout_sec": ACK_WAIT_TIMEOUT,
        "max_retransmissions": MAX_RETRANSMISSIONS,
        "session_directory": os.path.abspath(SESSION_DIR)
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    try:
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
    except Exception as e:
        print(f"Error writing session summary {summary_path}: {e}")

    # Reset global state variables for this session
    acked_chunks = set()
    connection_established = False
    stop_sniffing = False
    global receiver_ip, receiver_port # Reset receiver info too
    receiver_ip = None
    receiver_port = None


    # Create steganography sender instance
    stego = SteganographySender(target_ip)

    # --- Phase 1: Establish Connection ---
    if not establish_connection(stego):
        log_debug("Aborting transmission due to connection establishment failure.")
        print("[ERROR] Aborting transmission: Could not establish connection.")
        # Listener should be stopped by establish_connection on failure
        return False # Indicate failure

    log_debug("Connection established. Proceeding with data preparation.")
    print("[INFO] Connection established. Preparing data...")


    # --- Phase 2: Prepare Data ---
    # Read the input file
    log_debug(f"Reading input file: {file_path}")
    print(f"[FILE] Reading input file: {file_path}")
    file_data = read_file(file_path, 'rb') # read_file handles exit on error
    print(f"[FILE] Read {len(file_data)} bytes successfully.")

    # Log preview of file content if possible
    try:
        text_content_preview = file_data[:100].decode('utf-8', errors='ignore') # Try decoding first 100 bytes
        log_debug(f"File content preview (UTF-8): {text_content_preview}...")
        # Optionally save the decoded preview
        # preview_file = os.path.join(DATA_DIR, "original_content_preview.txt")
        # with open(preview_file, "w", encoding='utf-8', errors='ignore') as f:
        #     f.write(text_content_preview)
    except Exception: # If it's binary or fails
        log_debug(f"File content preview (Hex): {file_data[:32].hex()}...") # Log hex preview


    # Encrypt the data if a key is provided
    data_to_send = file_data
    if key_path:
        log_debug(f"Encryption requested. Reading key from: {key_path}")
        print(f"[ENCRYPT] Reading encryption key from: {key_path}")
        key_data = read_file(key_path, 'rb') # read_file handles exit on error
        key = prepare_key(key_data) # Handles padding/truncating

        log_debug("Encrypting data...")
        print(f"[ENCRYPT] Starting encryption of {len(data_to_send)} bytes...")
        data_to_send = encrypt_data(data_to_send, key) # Handles exit on error, returns IV + ciphertext
        log_debug(f"Data encrypted. Total size (IV + ciphertext): {len(data_to_send)} bytes")
        print(f"[ENCRYPT] Encryption complete. Result size: {len(data_to_send)} bytes (includes IV)")
    else:
        log_debug("No encryption key provided. Sending data in plaintext.")
        print("[INFO] No encryption key provided. Data will be sent unencrypted.")
        # Save plaintext data for consistency in debugging structure
        plaintext_file = os.path.join(DATA_DIR, "final_data_package.bin")
        try:
            with open(plaintext_file, "wb") as f:
                f.write(data_to_send)
        except Exception as e:
             print(f"Error saving plaintext package file: {e}")


    # Add a checksum (e.g., MD5) for integrity verification at the receiver
    # Checksum is calculated *after* encryption (if any)
    file_checksum = hashlib.md5(data_to_send).digest() # 16 bytes
    log_debug(f"Generated MD5 checksum for final data: {file_checksum.hex()}")
    print(f"[CHECKSUM] Generated MD5 checksum for data: {file_checksum.hex()}")
    data_with_checksum = data_to_send + file_checksum # Append checksum

    # Save the checksum and the final package (data + checksum) for debugging
    checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
    try:
        with open(checksum_file, "wb") as f:
            f.write(file_checksum)
    except Exception as e:
         print(f"Error saving checksum file: {e}")

    final_package_file = os.path.join(DATA_DIR, "final_data_package_with_checksum.bin")
    try:
        with open(final_package_file, "wb") as f:
            f.write(data_with_checksum)
        log_debug(f"Saved final data package with checksum ({len(data_with_checksum)} bytes) to {final_package_file}")
    except Exception as e:
         print(f"Error saving final data package file: {e}")


    # Chunk the final data (data + checksum)
    print(f"[PREP] Splitting {len(data_with_checksum)} bytes into chunks of size {chunk_size} bytes...")
    chunks = chunk_data(data_with_checksum, chunk_size)
    total_chunks = len(chunks)
    log_debug(f"Data split into {total_chunks} chunks")
    print(f"[PREP] Data split into {total_chunks} chunks.")

    # --- Phase 3: Transmit Data ---
    log_debug(f"Starting transmission of {total_chunks} chunks to {target_ip}...")
    print(f"[TRANSMISSION] Starting data transmission to {target_ip}...")

    transmission_fully_acked = True # Assume success until a chunk fails
    start_transmission_time = time.time()

    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Sequence numbers start from 1

        log_debug(f"Preparing to send chunk {seq_num}/{total_chunks}")
        # print(f"[PROGRESS] Preparing chunk {seq_num:04d}/{total_chunks:04d}") # Moved inside send_chunk

        # Send the chunk using the method with ACK and retransmission logic
        success = stego.send_chunk(chunk, seq_num, total_chunks)

        # Update overall success status
        if not success:
            transmission_fully_acked = False
            log_debug(f"Chunk {seq_num} failed to get acknowledged.")
            # Continue sending other chunks unless critical failure needed

        # Optional: Update progress status after send attempt
        progress = (seq_num / total_chunks) * 100
        status_msg = "Confirmed" if success else "Failed (No ACK)"
        print(f"[STATUS] Chunk {seq_num:04d}/{total_chunks:04d} | {status_msg} | Overall Progress: {progress:.2f}%")


        # Add delay between sending chunks (after ACK wait/retransmissions for the current chunk)
        if delay > 0:
            # log_debug(f"Waiting for inter-packet delay: {delay}s")
            time.sleep(delay)


    # --- Phase 4: Finalize Transmission ---
    end_transmission_time = time.time()
    duration = end_transmission_time - start_transmission_time
    log_debug(f"Finished sending all {total_chunks} chunks. Duration: {duration:.2f}s")
    print(f"[COMPLETE] Finished sending all chunks. Transmission duration: {duration:.2f} seconds.")

    # Send completion signal packets
    completion_packet = stego.create_completion_packet()
    print("[COMPLETE] Sending transmission completion signals...")
    completion_sends = 10 # Send multiple times for reliability
    for i in range(completion_sends):
        log_debug(f"Sending completion signal ({i+1}/{completion_sends})")
        send(completion_packet)
        time.sleep(0.2) # Small delay between completion signals
    print(f"[COMPLETE] Sent {completion_sends} completion signals.")


    # Stop the ACK listener thread cleanly
    stop_sniffing = True # Signal sniffer thread to stop
    stego.stop_ack_listener() # Join the thread

    # --- Phase 5: Report Statistics ---
    acked_count = len(acked_chunks)
    ack_rate = (acked_count / total_chunks) * 100 if total_chunks > 0 else 100.0 # Avoid division by zero
    
    final_status = "Completed Successfully"
    if not transmission_fully_acked:
        final_status = "Completed with Unacknowledged Chunks"
    elif acked_count < total_chunks: # Should not happen if transmission_fully_acked is True, but double check
        final_status = "Completed with Missing ACKs"


    log_debug(f"Transmission finished. Status: {final_status}. ACK rate: {ack_rate:.2f}% ({acked_count}/{total_chunks})")
    print("-" * 40)
    print(f"[STATS] Transmission Summary:")
    print(f"[STATS]   Total Chunks:      {total_chunks}")
    print(f"[STATS]   Acknowledged Chunks: {acked_count}")
    print(f"[STATS]   ACK Rate:          {ack_rate:.2f}%")
    print(f"[STATS]   Final Status:      {final_status}")
    print("-" * 40)


    # Save session completion info
    completion_info = {
        "session_end_time": datetime.datetime.now().isoformat(),
        "duration_sec": duration,
        "total_chunks_sent": total_chunks,
        "chunks_acknowledged": acked_count,
        "ack_rate_percent": ack_rate,
        "final_status": final_status
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    try:
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
    except Exception as e:
        print(f"Error saving completion info json: {e}")


    print(f"[INFO] All session data, logs, and outputs saved to: {SESSION_DIR}")
    print(f"[INFO] Check the 'sender_latest' symlink in '{OUTPUT_DIR}' for the most recent session.")


    return transmission_fully_acked # Return True if all ACKs received, False otherwise


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CrypticRoute - Simplified Network Steganography Sender',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show default values in help
        )
    parser.add_argument('--target', '-t', required=True, help='Target IP address of the receiver')
    parser.add_argument('--input', '-i', required=True, help='Input file path to send')
    parser.add_argument('--key', '-k', help='Path to the encryption key file (optional). If provided, AES-256 encryption is used.')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between sending data packets in seconds')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE,
                        help=f'Size of data payload per packet in bytes. Max recommended: {MAX_CHUNK_SIZE}')
    parser.add_argument('--output-dir', '-o', default=OUTPUT_DIR, help='Parent directory for session outputs')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT,
                        help='Seconds to wait for an ACK before retransmitting a chunk')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS,
                        help='Maximum retransmission attempts for a single chunk before failing it')
    return parser.parse_args()

def main():
    """Main execution function."""
    # Parse arguments
    args = parse_arguments()

    # Set global configuration from arguments
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, MAX_CHUNK_SIZE
    OUTPUT_DIR = args.output_dir
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries

    # Validate and set chunk size (ensure it doesn't exceed hardcoded max if necessary)
    if args.chunk_size > MAX_CHUNK_SIZE:
        print(f"Warning: Requested chunk size ({args.chunk_size}) exceeds the design maximum ({MAX_CHUNK_SIZE}).")
        print(f"         Using maximum chunk size: {MAX_CHUNK_SIZE} bytes.")
        chunk_size = MAX_CHUNK_SIZE
    elif args.chunk_size <= 0:
         print(f"Error: Invalid chunk size ({args.chunk_size}). Must be positive. Using default {MAX_CHUNK_SIZE}.")
         chunk_size = MAX_CHUNK_SIZE
    else:
        chunk_size = args.chunk_size

    # Setup output directory structure (needs to be done after OUTPUT_DIR is set)
    setup_directories() # Handles exit on critical error

    # Start the file sending process
    print("--- CrypticRoute Sender Initializing ---")
    print(f"Target:       {args.target}")
    print(f"Input File:   {args.input}")
    print(f"Key File:     {args.key if args.key else 'None (plaintext)'}")
    print(f"Chunk Size:   {chunk_size} bytes")
    print(f"Delay:        {args.delay}s")
    print(f"ACK Timeout:  {ACK_WAIT_TIMEOUT}s")
    print(f"Max Retries:  {MAX_RETRANSMISSIONS}")
    print(f"Output Dir:   {os.path.abspath(SESSION_DIR)}")
    print("-" * 40)


    # Execute the core sending logic
    success = send_file(
        file_path=args.input,
        target_ip=args.target,
        key_path=args.key,
        chunk_size=chunk_size,
        delay=args.delay
    )

    # Exit with appropriate status code
    print("--- CrypticRoute Sender Finished ---")
    if success:
        print("Result: Success (All chunks acknowledged)")
        sys.exit(0)
    else:
        print("Result: Failure (One or more chunks were not acknowledged)")
        sys.exit(1)

if __name__ == "__main__":
    # Ensure the script is run with root/administrator privileges for raw socket access (sniffing/sending)
    if os.geteuid() != 0:
        print("Error: This script requires root/administrator privileges to send/sniff raw packets.")
        print("Please run using 'sudo'.")
        sys.exit(1)
    main()