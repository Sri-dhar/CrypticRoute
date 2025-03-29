#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
V3: Simplified UDP Beacon + Receiver Initiates TCP Handshake.
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
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, sniff, conf

# Configure Scapy settings
conf.verb = 0

# --- Global Settings ---
MAX_CHUNK_SIZE = 8
ACK_WAIT_TIMEOUT = 10
MAX_RETRANSMISSIONS = 10
DISCOVERY_PORT = 54321
HASH_LEN_FOR_DISCOVERY = 16 # Use first 16 bytes of SHA256
BEACON_INTERVAL = 2 # Seconds between UDP beacons
BEACON_PREFIX = b"CRYPTRT_BCN:"

# --- Global State ---
acked_chunks = set()
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None # Learned during TCP handshake
receiver_port = None
stop_beacon_event = threading.Event() # Signal to stop UDP broadcasts
sender_tcp_ready_event = threading.Event() # Signal that TCP listener is ready

# --- Output Directories ---
OUTPUT_DIR = "stealth_output"
SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG = "", "", "", "", ""

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
         f.write(f"=== CrypticRoute Sender Session (v3): {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    latest_link = os.path.join(OUTPUT_DIR, "sender_latest")
    try: # Create symlink
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link): os.rename(latest_link, f"{latest_link}_{int(time.time())}")
        os.symlink(SESSION_DIR, latest_link)
        print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e: print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    if not DEBUG_LOG: return
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {message}\n")
    except Exception as e: print(f"Error writing log: {e}")

def get_broadcast_address():
    """Return the standard broadcast address."""
    return "255.255.255.255"

# --- UDP Beacon Thread ---
def broadcast_beacon_thread(key_hash_hex, discovery_port):
    """Sends UDP beacon packets periodically until stop_beacon_event is set."""
    broadcast_addr = get_broadcast_address()
    try:
        full_hash_bytes = bytes.fromhex(key_hash_hex)
        truncated_hash = full_hash_bytes[:HASH_LEN_FOR_DISCOVERY]
        beacon_payload = BEACON_PREFIX + truncated_hash
    except Exception as e:
        log_debug(f"[BEACON ERR] Failed to create beacon payload: {e}"); return

    log_debug(f"[BEACON] Thread started. Payload: {beacon_payload.hex()}")
    print(f"[DISCOVERY] Starting UDP beacon broadcast on port {discovery_port}...")

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # No bind needed for sending only

        while not stop_beacon_event.is_set():
            try:
                bytes_sent = sock.sendto(beacon_payload, (broadcast_addr, discovery_port))
                log_debug(f"[BEACON] Sent beacon ({bytes_sent} bytes) to {broadcast_addr}:{discovery_port}")
                print(f"\r[DISCOVERY] Broadcasting beacon...", end="")
            except OSError as e:
                log_debug(f"[BEACON ERR] Error sending beacon: {e}")
                print(f"\n[DISCOVERY WARN] Error sending beacon: {e}")
            except Exception as e:
                 log_debug(f"[BEACON ERR] Unexpected error sending beacon: {e}")
                 print(f"\n[DISCOVERY ERR] Beacon send failed: {e}")
                 # Maybe stop if sending fails repeatedly? For now, keep trying.

            # Wait for interval or until stop event is set
            stop_beacon_event.wait(BEACON_INTERVAL)

    except Exception as e:
        log_debug(f"[BEACON ERR] Beacon thread error: {e}")
    finally:
        if sock: sock.close()
        log_debug("[BEACON] Thread finished.")
        print("\n[DISCOVERY] Beacon broadcast stopped.")


class SteganographySender:
    """Handles TCP communication (handshake, data, ACKs)."""

    def __init__(self):
        """Initialize sender TCP components."""
        # NOTE: Target IP (receiver_ip) is not known at init time in this version.
        self.target_ip = None # Will be set when first SYN is received
        self.source_port = random.randint(10000, 60000)
        log_debug(f"Sender TCP handler initialized. Source Port: {self.source_port}. Waiting for Receiver SYN.")

        # Log file paths
        self.chunks_json_path = os.path.join(LOGS_DIR, "sent_chunks.json")
        self.acks_json_path = os.path.join(LOGS_DIR, "received_acks.json")
        try: # Initialize log files
            with open(self.chunks_json_path, "w") as f: json.dump({}, f)
            with open(self.acks_json_path, "w") as f: json.dump({}, f)
        except Exception as e: log_debug(f"Error initializing sender log files: {e}")
        self.sent_chunks = {}
        self.received_acks = {}

        # ACK listener thread setup (Not started here, started by main process)
        self.stop_ack_listener_event = threading.Event()


    # --- TCP Packet Creation Methods (Mostly unchanged) ---
    def create_syn_ack_packet(self):
        """Create the TCP SYN-ACK packet in response to Receiver's initial SYN."""
        # Requires receiver_ip and receiver_port to be learned first
        if not receiver_ip or not receiver_port:
            log_debug("[TCP ERR] Cannot create SYN-ACK: Receiver IP/Port unknown.")
            return None
        syn_ack_packet = IP(dst=receiver_ip) / TCP(
            sport=self.source_port, dport=receiver_port,
            seq=0xABCDEF12,      # Our initial sequence number for SYN-ACK
            ack=0x12345678 + 1,  # Acknowledge Receiver's SYN seq + 1
            window=0xBEEF,       # Special window for handshake SYN-ACK
            flags="SA"
        )
        log_debug(f"Created Handshake SYN-ACK packet for {receiver_ip}:{receiver_port}")
        return syn_ack_packet

    def create_ack_packet(self):
        """Create the final TCP ACK packet (sender doesn't usually send this in this flow)."""
        # This packet was previously used by sender to ACK the SYN-ACK.
        # In the new flow, the RECEIVER sends the final ACK. Sender just waits for it.
        # Keeping the function signature for potential future use, but it's likely unused now.
        log_debug("[TCP WARN] create_ack_packet (Handshake ACK) called, likely unused in new flow.")
        if not receiver_ip or not receiver_port: return None
        ack_packet = IP(dst=receiver_ip) / TCP(
            sport=self.source_port, dport=receiver_port,
            seq=0x87654321, ack=0xABCDEF12 + 1, window=0xF00D, flags="A"
        )
        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data (using SYN flag)."""
        # Requires self.target_ip (receiver_ip) to be set
        if not self.target_ip:
             log_debug("[TCP ERR] Cannot create data packet: Target IP not set.")
             return None
        if len(data) < MAX_CHUNK_SIZE: data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE: data = data[:MAX_CHUNK_SIZE]
        try:
            tcp_seq = int.from_bytes(data[0:4], byteorder='big')
            tcp_ack = int.from_bytes(data[4:8], byteorder='big')
        except Exception: return None # Cannot create packet
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port, dport=random.randint(10000, 60000), # Send to random port
            seq=tcp_seq, ack=tcp_ack, window=seq_num, flags="S", # SYN flag marks data
            options=[('MSS', total_chunks)]
        )
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum
        return tcp_packet

    def create_completion_packet(self):
        """Create a TCP FIN packet signaling transmission completion."""
        if not self.target_ip: return None
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port, dport=random.randint(10000, 60000),
            window=0xFFFF, flags="F"
        )
        log_debug(f"Created completion packet (FIN) for {self.target_ip}")
        return tcp_packet

    # --- Packet Processing Logic (Called by Scapy Sniff) ---
    def process_packet(self, packet):
        """Process received TCP packet (Initial SYN, final ACK, or Data ACK)."""
        global receiver_ip, receiver_port, connection_established
        global acked_chunks, waiting_for_ack, current_chunk_seq, stop_beacon_event

        if not (IP in packet and TCP in packet): return # Ignore non-IP/TCP

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        src_port = tcp_layer.sport

        # 1. Handle Initial Handshake SYN from Receiver
        # Matches receiver's initial SYN packet: SYN flag, specific seq, specific window
        if not connection_established and tcp_layer.flags & 0x02 and tcp_layer.seq == 0x12345678 and tcp_layer.window == 0xDEAD:
            # First valid SYN establishes the connection partner
            if receiver_ip is None: # Learn receiver IP and port
                receiver_ip = src_ip
                receiver_port = src_port
                self.target_ip = receiver_ip # Set target for subsequent sends
                log_debug(f"[TCP HANDSHAKE] Received initial SYN from {receiver_ip}:{receiver_port}. Learned receiver.")
                print(f"\n[HANDSHAKE] Received initial SYN from {receiver_ip}:{receiver_port}")

                # Stop UDP beaconing now that we have a partner
                if not stop_beacon_event.is_set():
                    log_debug("[TCP HANDSHAKE] Signaling UDP beacon thread to stop.")
                    stop_beacon_event.set()

                # Send SYN-ACK response
                syn_ack_packet = self.create_syn_ack_packet()
                if syn_ack_packet:
                    log_debug("[TCP HANDSHAKE] Sending SYN-ACK response.")
                    print("[HANDSHAKE] Sending SYN-ACK response...")
                    try:
                        for _ in range(5): # Send multiple times
                            send(syn_ack_packet); time.sleep(0.1)
                    except Exception as e:
                         log_debug(f"[TCP ERR] Failed to send SYN-ACK: {e}")
                         print(f"\n[ERROR] Failed to send SYN-ACK: {e}")
                         # Problematic: Handshake might fail here.
                else:
                     log_debug("[TCP ERR] Failed to create SYN-ACK packet.")
                return # Processed this packet

            elif src_ip == receiver_ip:
                 log_debug(f"[TCP HANDSHAKE] Received duplicate initial SYN from {src_ip}:{src_port}. Resending SYN-ACK.")
                 print("\n[HANDSHAKE] Duplicate initial SYN received. Resending SYN-ACK...")
                 syn_ack_packet = self.create_syn_ack_packet()
                 if syn_ack_packet:
                      try: send(syn_ack_packet) # Resend once
                      except Exception: pass
                 return # Processed duplicate
            else:
                 log_debug(f"[TCP WARN] Received initial SYN from unexpected IP {src_ip} while already targeting {receiver_ip}. Ignored.")
                 return # Ignore SYN from others once paired


        # Ignore packets from other IPs once receiver is known
        if receiver_ip and src_ip != receiver_ip:
            # log_debug(f"[TCP] Ignored packet from wrong IP {src_ip} (expecting {receiver_ip})") # Verbose
            return

        # 2. Handle Final Handshake ACK from Receiver
        # Matches receiver's final ACK: ACK flag, specific seq, specific window, ack
        if not connection_established and receiver_ip and tcp_layer.flags & 0x10 and tcp_layer.seq == 0x87654321 and tcp_layer.window == 0xF00D and tcp_layer.ack == (0xABCDEF12 + 1):
             log_debug(f"[TCP HANDSHAKE] Received final ACK from {src_ip}:{src_port}. Connection established.")
             print("\n[HANDSHAKE] Connection established successfully.")
             connection_established = True
             sender_tcp_ready_event.set() # Signal main thread that connection is up
             return # Processed


        # 3. Handle Data Chunk ACK from Receiver (after connection established)
        # Matches receiver's data ACK packet: ACK flag, specific seq, specific window, ack=chunk_seq
        if connection_established and tcp_layer.flags & 0x10 and tcp_layer.window == 0xCAFE and tcp_layer.seq == 0x12345678:
            seq_num = tcp_layer.ack # Acknowledged chunk number

            if seq_num <= 0 or seq_num > 65535: # Basic sanity check
                log_debug(f"[TCP ACK] Ignored Data ACK with invalid seq_num {seq_num}.")
                return

            log_debug(f"[TCP ACK] Received potential Data ACK for chunk {seq_num}")
            if seq_num not in acked_chunks:
                acked_chunks.add(seq_num)
                self.log_ack(seq_num) # Log to file
            if waiting_for_ack and seq_num == current_chunk_seq:
                log_debug(f"Chunk {seq_num} acknowledged.")
                print(f"\r[ACK] Received ack for chunk {seq_num:04d}        ", end="") # Overwrite status
                waiting_for_ack = False # Stop waiting
            else:
                log_debug(f"Rcvd ACK for chunk {seq_num}, but waiting={waiting_for_ack}, current={current_chunk_seq}")
            return # Processed


        # Log unexpected packets from the receiver if connection is established
        # if connection_established:
        #     log_debug(f"[TCP WARN] Ignored unexpected packet from {src_ip}:{src_port}. Flags={tcp_layer.flags:#x}, Win={tcp_layer.window:#x}, Seq={tcp_layer.seq:#x}, Ack={tcp_layer.ack:#x}")


    # --- Logging Methods (Unchanged) ---
    def log_chunk(self, seq_num, data):
        """Save chunk data to JSON log and raw file."""
        self.sent_chunks[str(seq_num)] = {"data": data.hex(), "size": len(data), "timestamp": time.time()}
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(self.sent_chunks, f, indent=2)
            chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:03d}.bin")
            with open(chunk_file, "wb") as f: f.write(data)
        except Exception as e: log_debug(f"Error logging chunk {seq_num}: {e}")

    def log_ack(self, seq_num):
        """Save received ACK info to JSON log."""
        self.received_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.received_acks, f, indent=2)
        except Exception as e: log_debug(f"Error logging ACK {seq_num}: {e}")

    # --- Chunk Sending Method (Unchanged) ---
    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acked, skipping send.")
            print(f"\r[SKIP] Chunk {seq_num:04d} already acknowledged.", end="")
            return True
        packet = self.create_packet(data, seq_num, total_chunks)
        if not packet:
             print(f"\n[ERROR] Failed to create packet for chunk {seq_num}. Skipping.")
             log_debug(f"Failed create packet chunk {seq_num}."); return False
        self.log_chunk(seq_num, data)
        current_chunk_seq = seq_num
        waiting_for_ack = True
        retransmit_count = 0
        start_time = time.time()
        log_debug(f"Sending chunk {seq_num}/{total_chunks}")
        print(f"\r[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:3.0f}%", end="")
        send(packet) # Initial send
        while waiting_for_ack and retransmit_count < MAX_RETRANSMISSIONS:
            wait_start = time.time()
            while waiting_for_ack and (time.time() - wait_start < ACK_WAIT_TIMEOUT):
                time.sleep(0.1)
            if waiting_for_ack:
                retransmit_count += 1
                log_debug(f"ACK timeout chunk {seq_num}. Retransmit {retransmit_count}/{MAX_RETRANSMISSIONS}")
                print(f"\r[RETRY {retransmit_count}] Chunk {seq_num:04d}...", end="")
                send(packet)
        if waiting_for_ack:
            log_debug(f"Failed ACK chunk {seq_num} after {MAX_RETRANSMISSIONS} retries")
            print(f"\n[WARNING] No ACK for chunk {seq_num:04d} after {MAX_RETRANSMISSIONS} attempts")
            waiting_for_ack = False; return False # Failure
        else:
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} acked after {retransmit_count} retries ({elapsed:.2f}s)")
            # Ack message printed by process_packet
            return True # Success


# --- Utility Functions (Unchanged) ---
def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file: data = file.read()
        log_debug(f"Read {len(data)} bytes from {file_path}"); return data
    except FileNotFoundError: log_debug(f"Error: File not found {file_path}"); print(f"Error: Input file not found: {file_path}"); sys.exit(1)
    except Exception as e: log_debug(f"Error reading file {file_path}: {e}"); print(f"Error reading file: {e}"); sys.exit(1)

def prepare_key(key_data):
    """Prepare the encryption key (32 bytes) and return bytes and SHA256 hex hash."""
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try: # Check if hex
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             key_data = bytes.fromhex(key_data.decode('ascii'))
             log_debug("Interpreted key data as hex string.")
    except ValueError: pass # Not hex
    original_len = len(key_data)
    if original_len < 32: key_data = key_data.ljust(32, b'\0')
    elif original_len > 32: key_data = key_data[:32]
    if original_len != 32: log_debug(f"Key adjusted from {original_len} to 32 bytes.")
    log_debug(f"Final key bytes: {key_data.hex()}")
    try: # Save key for debugging
        with open(os.path.join(DATA_DIR, "key.bin"), "wb") as f: f.write(key_data)
    except Exception: pass
    key_hash = hashlib.sha256(key_data).digest()
    key_hash_hex = key_hash.hex()
    log_debug(f"Key hash (SHA256): {key_hash_hex}")
    print(f"[KEY] Key Hash: {key_hash_hex}"); return key_data, key_hash_hex

def encrypt_data(data, key):
    """Encrypt data using AES-256-CFB with a random IV."""
    try:
        iv = os.urandom(16)
        log_debug(f"Generated random IV: {iv.hex()}")
        try: # Save IV
            with open(os.path.join(DATA_DIR, "iv.bin"), "wb") as f: f.write(iv)
        except Exception: pass
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        package_data = iv + encrypted_data
        log_debug(f"Encryption successful. Input: {len(data)}, Output (incl IV): {len(package_data)}")
        try: # Save debug files
            with open(os.path.join(DATA_DIR, "original_data.bin"), "wb") as f: f.write(data)
            with open(os.path.join(DATA_DIR, "encrypted_package.bin"), "wb") as f: f.write(package_data)
        except Exception: pass
        return package_data
    except Exception as e: log_debug(f"Encryption error: {e}"); print(f"[ERROR] Encryption error: {e}"); return None

def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data ({len(data)} bytes) into {len(chunks)} chunks (max size {chunk_size})")
    return chunks

# --- Main Execution Logic ---
def main():
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, DISCOVERY_PORT
    args = parse_arguments()
    if args.output_dir: OUTPUT_DIR = args.output_dir
    setup_directories()
    log_debug("Sender starting...")
    log_debug(f"Args: {vars(args)}")

    # Apply settings
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    DISCOVERY_PORT = args.discovery_port
    chunk_size = min(args.chunk_size, MAX_CHUNK_SIZE)
    if args.chunk_size > MAX_CHUNK_SIZE: print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE}")

    # Process Key File (Mandatory)
    if not args.key: print("[ERROR] Key file (--key) is required."); sys.exit(1)
    log_debug(f"Reading key file: {args.key}")
    key_data_raw = read_file(args.key, 'rb')
    if key_data_raw is None: sys.exit(1)
    key_bytes, key_hash_hex = prepare_key(key_data_raw)
    if not key_bytes or not key_hash_hex: sys.exit(1)

    # Prepare data BEFORE starting network activity
    log_debug(f"Preparing file: {args.input}")
    file_data_plain = read_file(args.input, 'rb')
    if file_data_plain is None: sys.exit(1)
    # Encrypt if key provided (always true now)
    log_debug(f"Encrypting {len(file_data_plain)} bytes...")
    print(f"[ENCRYPT] Encrypting {len(file_data_plain)} bytes...")
    file_data_to_send = encrypt_data(file_data_plain, key_bytes)
    if file_data_to_send is None: sys.exit(1)
    log_debug(f"Encrypted size: {len(file_data_to_send)}")
    print(f"[ENCRYPT] Encrypted size: {len(file_data_to_send)} bytes")
    # Add Checksum
    file_checksum = hashlib.md5(file_data_to_send).digest()
    final_data_package = file_data_to_send + file_checksum
    log_debug(f"Added MD5 ({file_checksum.hex()}). Final package size: {len(final_data_package)}")
    print(f"[CHECKSUM] Added MD5: {file_checksum.hex()}")
    try: # Save final package
        with open(os.path.join(DATA_DIR, "final_data_package.bin"), "wb") as f: f.write(final_data_package)
    except Exception: pass
    # Chunk data
    chunks = chunk_data(final_data_package, chunk_size)
    total_chunks = len(chunks)
    if total_chunks == 0: log_debug("Warning: No data chunks generated.")

    # --- Start Networking ---
    stego_sender = SteganographySender() # Init TCP handler

    # Start UDP beacon thread
    stop_beacon_event.clear()
    beacon_thread = threading.Thread(target=broadcast_beacon_thread,
                                     args=(key_hash_hex, DISCOVERY_PORT),
                                     name="BeaconThread", daemon=True)
    beacon_thread.start()

    # Start main TCP listener (Sniff)
    # Filter for the initial SYN packet from ANY source IP with the specific window
    initial_syn_filter = f"tcp and tcp[tcpflags] & tcp-syn != 0 and tcp[14:2] = {0xDEAD}"
    log_debug(f"Starting main TCP sniff loop (Filter: {initial_syn_filter})")
    print("[INFO] Listening for initial TCP SYN from receiver...")

    # Reset connection state before starting sniff
    global connection_established, receiver_ip, receiver_port, acked_chunks
    connection_established = False
    receiver_ip = None
    receiver_port = None
    acked_chunks = set()
    sender_tcp_ready_event.clear()

    # Sniffing runs in the main thread until connection is established or error/interrupt
    sniffer_thread = None # Will hold the sniffer thread object
    try:
        # Define a wrapper function for sniffing in a thread
        def sniff_wrapper():
            log_debug("Sniffer thread started.")
            try:
                 sniff(
                     filter=initial_syn_filter,
                     prn=stego_sender.process_packet,
                     stop_filter=lambda p: connection_established or stop_beacon_event.is_set() # Stop if connected or beacon stopped early
                 )
            except ImportError as e: log_debug(f"FATAL: Scapy sniffing dependency error: {e}"); print(f"\n[FATAL ERROR] Scapy cannot sniff packets: {e}")
            except OSError as e: log_debug(f"FATAL: OS error during sniff (Permissions?): {e}"); print(f"\n[FATAL ERROR] Cannot sniff packets (Permissions?): {e}")
            except Exception as e: log_debug(f"Error in main sniff loop: {e}"); print(f"\n[ERROR] Sniffer failed: {e}")
            finally:
                 log_debug("Sniffer thread finished.")
                 # If connection wasn't established, ensure beacon stops
                 if not connection_established: stop_beacon_event.set()

        sniffer_thread = threading.Thread(target=sniff_wrapper, name="MainSnifferThread")
        sniffer_thread.start()

        # Wait for connection established event, with a timeout similar to discovery
        connection_wait_timeout = args.discovery_timeout + 10 # Allow extra time
        log_debug(f"Main thread waiting up to {connection_wait_timeout}s for connection_established event...")
        connection_established = sender_tcp_ready_event.wait(connection_wait_timeout)

        if not connection_established:
             print("\n[ERROR] Timeout waiting for TCP handshake to complete after discovery signal.")
             log_debug("Timeout waiting for connection_established event. Aborting.")
             stop_beacon_event.set() # Ensure beacon stops
             if sniffer_thread: sniffer_thread.join(1.0) # Attempt to join sniffer thread
             sys.exit(1)

        # --- Connection Established - Start Sending Chunks ---
        print(f"\n[TRANSMISSION] Starting data transmission ({total_chunks} chunks) to {receiver_ip}...")
        log_debug(f"Starting transmission of {total_chunks} chunks to {receiver_ip}")
        transmission_success = True
        start_chunk_time = time.time()
        if total_chunks > 0:
            for i, chunk in enumerate(chunks):
                seq_num = i + 1
                if not stego_sender.send_chunk(chunk, seq_num, total_chunks):
                    transmission_success = False
                    print(f"\n[ERROR] Failed to send chunk {seq_num} after retries. Aborting.")
                    log_debug(f"Aborting transmission after failure on chunk {seq_num}.")
                    break # Abort on first failure
                time.sleep(args.delay) # Inter-packet delay
            chunk_duration = time.time() - start_chunk_time
            log_debug(f"Chunk transmission phase completed in {chunk_duration:.2f}s. Success={transmission_success}")
            print(f"\n[TRANSMISSION] Finished sending chunks in {chunk_duration:.2f}s.")
        else:
             print("[TRANSMISSION] No data chunks to send.")


        # --- Send Completion Signal ---
        completion_packet = stego_sender.create_completion_packet()
        if completion_packet:
            print("[COMPLETE] Sending transmission completion signals...")
            log_debug("Sending completion signals...")
            for i in range(10): send(completion_packet); time.sleep(0.2)
        else: log_debug("Failed to create completion packet.")


        # --- Final Stats & Cleanup ---
        # Beacon thread should have stopped when connection was established
        # Sniffer thread likely stopped too, but join it to be sure
        if sniffer_thread: sniffer_thread.join(1.0)

        ack_rate = (len(acked_chunks) / total_chunks * 100) if total_chunks > 0 else 100
        final_status = "unknown"
        if transmission_success and len(acked_chunks) == total_chunks: final_status = "completed_fully_acked"
        elif transmission_success: final_status = "completed_partially_acked"
        else: final_status = "failed_chunks_undelivered"
        log_debug(f"Transmission summary: ACK rate: {ack_rate:.1f}% ({len(acked_chunks)}/{total_chunks}), Status: {final_status}")
        print(f"[STATS] Final ACK rate: {ack_rate:.1f}% ({len(acked_chunks)}/{total_chunks})")
        print(f"[COMPLETE] Transmission status: {final_status}")

        # Save session summary
        summary = { "timestamp": time.time(), "file_path": args.input, "target_ip": receiver_ip, "key_path": args.key,
                    "chunk_size": chunk_size, "delay": args.delay, "ack_timeout": ACK_WAIT_TIMEOUT,
                    "max_retransmissions": MAX_RETRANSMISSIONS, "discovery_port": DISCOVERY_PORT,
                    "total_chunks": total_chunks, "chunks_acked": len(acked_chunks), "ack_rate": ack_rate,
                    "final_status": final_status }
        try:
            with open(os.path.join(LOGS_DIR, "session_summary.json"), "w") as f: json.dump(summary, f, indent=2)
        except Exception as e: log_debug(f"Error saving session summary: {e}")

        print(f"[INFO] All session data saved to: {SESSION_DIR}")
        sys.exit(0 if final_status.startswith("completed") else 1)

    except KeyboardInterrupt:
         print("\n[INFO] Operation interrupted by user.")
         log_debug("Operation interrupted by user (Ctrl+C).")
         stop_beacon_event.set() # Signal threads to stop
         # Main sniff loop might exit automatically on interrupt
         if sniffer_thread: sniffer_thread.join(1.0)
         if beacon_thread: beacon_thread.join(1.0)
         sys.exit(1)
    except Exception as e:
         print(f"\n[FATAL ERROR] An unexpected error occurred: {e}")
         log_debug(f"FATAL ERROR in main: {e}", exc_info=True)
         stop_beacon_event.set()
         if sniffer_thread: sniffer_thread.join(1.0)
         if beacon_thread: beacon_thread.join(1.0)
         sys.exit(1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Sender (v3 Discovery)')
    # Target IP is no longer used/needed
    # parser.add_argument('--target', '-t', help='Target IP address (Not used in this version)')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=True, help='Encryption/Discovery key file')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets (s, default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE, help=f'Chunk size (bytes, default/max: {MAX_CHUNK_SIZE})')
    parser.add_argument('--output-dir', '-o', help='Custom output directory for logs/data')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT, help=f'TCP ACK timeout (s, default: {ACK_WAIT_TIMEOUT})')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS, help=f'Max TCP retransmissions (default: {MAX_RETRANSMISSIONS})')
    parser.add_argument('--discovery-port', '-dp', type=int, default=DISCOVERY_PORT, help=f'UDP discovery port (default: {DISCOVERY_PORT})')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT, help=f'Discovery timeout (s, default: {DISCOVERY_TIMEOUT})')
    args = parser.parse_args()
    # Key is now always required
    # if not args.key: parser.error("--key is required.") # Already handled by required=True
    return args


if __name__ == "__main__":
    if os.name == 'posix' and os.geteuid() != 0:
         print("Warning: Scapy requires root privileges. Run with 'sudo'.")
    elif os.name == 'nt':
         print("Info: Ensure Npcap installed & Python has Admin permissions if needed.")
    main()