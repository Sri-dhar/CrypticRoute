#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure, acknowledgment system, key-based discovery,
length prefix handling, and robust completion.
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
import struct # For unpacking length
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, sniff, conf, send

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
LENGTH_PREFIX_SIZE = 8  # Bytes for length (unsigned long long)
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size in bytes
DISCOVERY_PORT = 54321 # Port for discovery probes/responses
DISCOVERY_TIMEOUT = 60 # Seconds to wait for a discovery probe initially

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
expected_total_chunks = None # Learned from MSS option
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None  # Sender's IP (set during handshake)
sender_port = None  # Sender's source port (set during handshake)
ack_sent_chunks = set()
discovery_sender_ip = None # IP from discovery probe
discovery_sender_port = None # Port from discovery probe
discovery_probe_received = False # Flag
receiver_key_hash_probe_expected = b'' # Derived from key
receiver_key_hash_response = b'' # Derived from key

# Output directory structure
OUTPUT_DIR = "stealth_output"
SESSION_DIR = ""
LOGS_DIR = ""
DATA_DIR = ""
CHUNKS_DIR = ""
DEBUG_LOG = ""

# --- Utility Functions (Directory Setup, Logging, Key Derivation) ---

def setup_directories():
    """Create organized directory structure for outputs."""
    global OUTPUT_DIR, SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"receiver_session_{timestamp}")
    os.makedirs(SESSION_DIR)
    LOGS_DIR = os.path.join(SESSION_DIR, "logs"); os.makedirs(LOGS_DIR)
    DATA_DIR = os.path.join(SESSION_DIR, "data"); os.makedirs(DATA_DIR)
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks"); os.makedirs(CHUNKS_DIR)
    os.makedirs(os.path.join(CHUNKS_DIR, "raw")); os.makedirs(os.path.join(CHUNKS_DIR, "cleaned")) # Added cleaned
    DEBUG_LOG = os.path.join(LOGS_DIR, "receiver_debug.log")
    latest_link = os.path.join(OUTPUT_DIR, "receiver_latest")
    try:
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link): os.rename(latest_link, f"{latest_link}_{int(time.time())}")
        os.symlink(SESSION_DIR, latest_link); print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e: print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    if not DEBUG_LOG: return
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e: print(f"Error writing to debug log {DEBUG_LOG}: {e}")

def derive_key_identifiers(key):
    """Derive probe and response identifiers from the key."""
    global receiver_key_hash_probe_expected, receiver_key_hash_response
    hasher = hashlib.sha256(); hasher.update(key); full_hash = hasher.digest()
    receiver_key_hash_probe_expected = full_hash[:4]
    receiver_key_hash_response = full_hash[4:8]
    log_debug(f"Derived Expected Probe ID: {receiver_key_hash_probe_expected.hex()}")
    log_debug(f"Derived Response ID: {receiver_key_hash_response.hex()}")

# --- Steganography Receiver Class ---
class SteganographyReceiver:
    """Simple steganography receiver using TCP with acknowledgment and discovery."""

    def __init__(self):
        """Initialize the receiver."""
        self._init_log_file("received_chunks.json", "{}")
        self.chunks_json_path = os.path.join(LOGS_DIR, "received_chunks.json")
        self.my_port = random.randint(10000, 60000) # Our port for sending ACKs/SYN-ACKs
        self._init_log_file("sent_acks.json", "{}")
        self.acks_json_path = os.path.join(LOGS_DIR, "sent_acks.json")
        self.sent_acks = {}
        log_debug(f"Receiver initialized. Listening port (for sending ACKs): {self.my_port}")

    def _init_log_file(self, filename, initial_content="{}"):
        filepath = os.path.join(LOGS_DIR, filename)
        try:
            if not os.path.exists(filepath):
                with open(filepath, "w") as f: f.write(initial_content)
        except Exception as e: log_debug(f"Failed to initialize log file {filename}: {e}")

    def _send_packet(self, packet):
         """Internal helper to send packets."""
         send(packet) # Can add interface later if needed

    def log_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        try:
            with open(self.chunks_json_path, "r") as f: chunk_info = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): chunk_info = {}
        log_data_hex = data.hex()[:20] + ('...' if len(data.hex()) > 20 else '')
        chunk_info[str(seq_num)] = {"data_start": log_data_hex, "size": len(data), "timestamp": time.time()}
        with open(self.chunks_json_path, "w") as f: json.dump(chunk_info, f, indent=2)
        chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:04d}.bin")
        with open(chunk_file, "wb") as f: f.write(data)

    def log_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.sent_acks, f, indent=2)
        except Exception as e: log_debug(f"Error logging ACK {seq_num}: {e}")

    # --- Discovery Response ---
    def create_discovery_response_packet(self, probe_packet):
        global receiver_key_hash_response
        sender_ip = probe_packet[IP].src
        sender_port = probe_packet[TCP].sport # Port the probe came from
        probe_seq = probe_packet[TCP].seq # Seq from the probe (contains their key hash part)
        response_packet = IP(dst=sender_ip) / TCP(
            sport=DISCOVERY_PORT, dport=sender_port, # Respond FROM discovery TO their ephemeral port
            flags="PF", window=0xCAFE, # Use PSH|FIN and magic window
            seq=int.from_bytes(receiver_key_hash_response, 'big'), # Our key hash part in seq
            ack=probe_seq) # Acknowledge their seq (technically their key hash)
        return response_packet

    def send_discovery_response(self, probe_packet):
        response_pkt = self.create_discovery_response_packet(probe_packet)
        if response_pkt:
            log_debug(f"Sending Discovery Response -> {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            print(f"[DISCOVERY] Sending response to sender at {probe_packet[IP].src}")
            for _ in range(3): self._send_packet(response_pkt); time.sleep(0.1) # Send multiple

    def process_discovery_probe(self, packet):
        global discovery_sender_ip, discovery_sender_port, discovery_probe_received, receiver_key_hash_probe_expected
        if discovery_probe_received: return False # Already found

        # Check signature: Correct port, PU flags, magic window
        if IP in packet and TCP in packet and packet[TCP].dport == DISCOVERY_PORT \
           and packet[TCP].flags & 0x28 == 0x28 and packet[TCP].window == 0xFACE:
            probe_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery probe from {packet[IP].src}:{packet[TCP].sport} (Hash: {probe_hash_received.hex()})")
            if probe_hash_received == receiver_key_hash_probe_expected:
                log_debug(f"*** Valid Discovery Probe received from {packet[IP].src}:{packet[TCP].sport} ***")
                print(f"\n[DISCOVERY] Valid probe received from sender at {packet[IP].src}")
                discovery_sender_ip = packet[IP].src
                discovery_sender_port = packet[TCP].sport # Store sender's source port for response
                self.send_discovery_response(packet) # Send response
                discovery_probe_received = True
                return True # Signal sniff to stop discovery phase
            else: log_debug("Probe key hash mismatch.")
        return False

    # --- Connection and Data Handling ---
    def create_data_ack_packet(self, data_seq_num):
        """Create ACK for a specific data chunk sequence number."""
        global sender_ip, sender_port # Should be set by handshake
        if not sender_ip or not sender_port: log_debug("Cannot create data ACK - sender info missing"); return None
        # ACK packet has specific signature
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, dport=sender_port, # Send FROM our ephemeral TO sender's ephemeral
            seq=random.randint(1, 0xFFFFFFFF), # Random seq for ACK
            ack=data_seq_num,       # Acknowledge the DATA chunk seq num
            window=0xCAFE,          # Special window value for data ACKs
            flags="A")
        return ack_packet

    def send_data_ack(self, seq_num):
        """Send acknowledgment for a data chunk."""
        global ack_sent_chunks
        if seq_num in ack_sent_chunks: return # Don't resend ACK if already sent once
        ack_packet = self.create_data_ack_packet(seq_num)
        if not ack_packet: return
        # log_debug(f"Sending ACK for chunk {seq_num} -> {sender_ip}:{sender_port}") # Reduce noise
        print(f"[ACK] Sending acknowledgment for chunk {seq_num:04d}         ", end='\r')
        self.log_ack(seq_num)
        for _ in range(2): self._send_packet(ack_packet); time.sleep(0.05) # Send fewer times
        ack_sent_chunks.add(seq_num)

    def create_syn_ack_packet(self, incoming_syn_packet):
        """Create SYN-ACK in response to a valid SYN."""
        global sender_ip, sender_port # Set based on incoming SYN
        if not sender_ip or not sender_port: log_debug("Cannot create SYN-ACK - SYN info missing"); return None
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, dport=sender_port, # Respond FROM our ephemeral TO sender's ephemeral
            seq=random.randint(1, 0xFFFFFFFF), # Our random seq for SYN-ACK
            ack=incoming_syn_packet[TCP].seq + 1, # Ack their SYN seq
            window=0xBEEF, # Magic window for SYN-ACK
            flags="SA")
        return syn_ack_packet

    def send_syn_ack(self, incoming_syn_packet):
        """Send SYN-ACK response."""
        syn_ack_packet = self.create_syn_ack_packet(incoming_syn_packet)
        if not syn_ack_packet: return
        log_debug(f"Sending SYN-ACK -> {sender_ip}:{sender_port}")
        print("[HANDSHAKE] Sending SYN-ACK response...")
        for _ in range(3): self._send_packet(syn_ack_packet); time.sleep(0.1) # Send multiple

    def packet_handler(self, packet):
        """Wrapper for process_packet for counting."""
        global packet_counter, expected_total_chunks, valid_packet_counter
        packet_counter += 1
        # Show progress less frequently
        if packet_counter % 50 == 0:
             chunk_status = f"{len(received_chunks):04d}"
             if expected_total_chunks: chunk_status += f"/{expected_total_chunks:04d}"
             ratio = f"{valid_packet_counter}/{packet_counter}" if packet_counter > 0 else "0/0"
             print(f"[STATUS] Pkts:{packet_counter:6d} | Chunks:{chunk_status} | Valid:{ratio}        ", end='\r')
        self.process_packet(packet)
        return None # Prevent scapy printing summary

    def process_packet(self, packet):
        """Process packets for discovery response, connection, data, or completion."""
        global received_chunks, transmission_complete, reception_start_time, last_activity_time
        global highest_seq_num, valid_packet_counter, connection_established, expected_total_chunks
        global sender_ip, sender_port, discovery_sender_ip

        last_activity_time = time.time()

        # --- Filter by Discovered IP (if known) ---
        if discovery_sender_ip and IP in packet and packet[IP].src != discovery_sender_ip: return False

        if IP in packet and TCP in packet:
            packet_src_ip = packet[IP].src
            packet_src_port = packet[TCP].sport

            # Use discovered IP if sender IP isn't set yet from handshake
            if sender_ip is None and discovery_sender_ip: sender_ip = discovery_sender_ip

            # --- Handshake Phase ---
            # 1. Check for SYN (Magic Window 0xDEAD)
            if not connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == 0xDEAD and packet_src_ip == sender_ip:
                log_debug(f"Received Handshake SYN from {packet_src_ip}:{packet_src_port}")
                print("\n[HANDSHAKE] Received connection request (SYN)")
                # Set sender IP and PORT based on *this* packet for the connection
                sender_ip = packet_src_ip
                sender_port = packet_src_port
                log_debug(f"Sender connection endpoint set: {sender_ip}:{sender_port}")
                self.send_syn_ack(packet) # Send SYN-ACK response
                return True

            # 2. Check for Final ACK (Magic Window 0xF00D, destined for our ACK port)
            if not connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xF00D \
               and packet_src_ip == sender_ip and packet[TCP].dport == self.my_port:
                # Verify ACK number (should ack our SYN-ACK seq + 1 - but we used random seq, so can't easily check)
                # Trust the magic window and source for now
                log_debug(f"Received Handshake ACK from {packet_src_ip}:{packet_src_port}. Connection established.")
                print("[HANDSHAKE] Connection established with sender.")
                connection_established = True
                return True

            # --- Data/Completion Phase (Requires Established Connection) ---
            if not connection_established: return False # Ignore other packets before connection
            if packet_src_ip != sender_ip or packet_src_port != sender_port: return False # Must come from established endpoint

            # 3. Check for FIN Completion Signal (Magic Window 0xFFFF)
            if packet[TCP].flags & 0x01 and packet[TCP].window == 0xFFFF:
                log_debug("Received transmission complete signal (FIN)")
                print("\n[COMPLETE] Received transmission complete signal.")
                transmission_complete = True
                return True

            # 4. Check for Data Packet (PSH+ACK flags, MSS option)
            # *** FIX: Check for PA flags and MSS option ***
            if packet[TCP].flags & 0x18 == 0x18: # Check if PSH and ACK flags are set
                total_chunks_in_mss = None
                for option in packet[TCP].options:
                    if option[0] == 'MSS':
                        total_chunks_in_mss = option[1]; break
                if total_chunks_in_mss is not None: # Found potential data packet
                     # Learn expected total chunks if not known
                     if expected_total_chunks is None:
                          expected_total_chunks = total_chunks_in_mss
                          log_debug(f"Learned expected total chunks: {expected_total_chunks}")

                     seq_num = packet[TCP].window # Sequence number is in window field
                     # Plausibility check (adjust max based on expected?)
                     if seq_num <= 0 or (expected_total_chunks and seq_num > expected_total_chunks + 10): # Allow some buffer
                          # log_debug(f"Ignoring packet with implausible sequence number: {seq_num}")
                          return False

                     valid_packet_counter += 1

                     # Extract data and chunk checksum
                     seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
                     ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
                     chunk_data = seq_bytes + ack_bytes
                     received_chunk_checksum = packet[IP].id
                     calculated_chunk_checksum = binascii.crc32(chunk_data) & 0xFFFF

                     # Verify chunk checksum
                     if received_chunk_checksum != calculated_chunk_checksum:
                         log_debug(f"Chunk {seq_num}: CRC32 Checksum mismatch! Rcvd:{received_chunk_checksum:#06x}, Calc:{calculated_chunk_checksum:#06x}. Discarding.")
                         print(f"[CHECKSUM] Warning: Chunk {seq_num:04d} CRC32 mismatch. Discarded.")
                         return False # Discard corrupted chunk

                     # Check for duplicates
                     if seq_num in received_chunks:
                         # log_debug(f"Received duplicate chunk {seq_num}, resending ACK.")
                         self.send_data_ack(seq_num) # Resend ACK for duplicates
                         return False

                     # First chunk received?
                     if len(received_chunks) == 0:
                         reception_start_time = time.time()
                         log_debug(f"First chunk {seq_num} received. Starting timer.")
                         print(f"\n[START] First chunk {seq_num} received, starting timer.")

                     # Store valid chunk
                     log_debug(f"Received valid chunk {seq_num} (Size: {len(chunk_data)})")
                     received_chunks[seq_num] = chunk_data
                     self.log_chunk(seq_num, chunk_data) # Log to files
                     self.send_data_ack(seq_num) # Send ACK

                     # Update highest sequence number
                     if seq_num > highest_seq_num: highest_seq_num = seq_num

                     # Update progress display (handled by packet_handler wrapper now)
                     return True # Processed a valid data chunk

        return False # Packet was not relevant

# --- Key Prep, Decryption, Reassembly, Saving ---

def prepare_key(key_data):
    """Prepare the decryption key (32 bytes) and derive identifiers."""
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try:
        is_hex = all(c in '0123456789abcdefABCDEF' for c in key_data.decode('ascii', errors='ignore'))
        if is_hex and len(key_data) % 2 == 0: key_data = bytes.fromhex(key_data.decode('ascii')); log_debug("Interpreted key data as hex")
        else: log_debug("Key data is not hex, using raw.")
    except Exception as e: log_debug(f"Could not process key as hex ({e}), using raw.")
    orig_len = len(key_data)
    if orig_len < 32: key_data = key_data.ljust(32, b'\0')
    elif orig_len > 32: key_data = key_data[:32]
    if orig_len != 32: log_debug(f"Key size adjusted from {orig_len} to 32 bytes.")
    log_debug(f"Using final key (AES-256): {key_data.hex()}")
    try:
        with open(os.path.join(DATA_DIR, "key.bin"), "wb") as f: f.write(key_data)
    except Exception as e: log_debug(f"Failed to save key file: {e}")
    derive_key_identifiers(key_data) # Derive hashes AFTER finalizing key
    return key_data

def decrypt_data(data_package, key):
    """Decrypt data using AES (expects IV prepended)."""
    if not key: log_debug("Decryption skipped: No key provided."); return data_package # Return as is if no key
    try:
        if len(data_package) < 16: log_debug("Error: Data too short for IV."); return None
        iv = data_package[:16]; encrypted_data = data_package[16:]
        log_debug(f"Extracted IV: {iv.hex()} for decryption.")
        try: # Save extracted IV/data for debug
             with open(os.path.join(DATA_DIR, "extracted_iv.bin"), "wb") as f: f.write(iv)
             with open(os.path.join(DATA_DIR, "encrypted_data_for_decryption.bin"), "wb") as f: f.write(encrypted_data)
        except Exception as e: log_debug(f"Failed to save decryption debug files: {e}")
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        log_debug(f"Decryption successful. Result size: {len(decrypted_data)}")
        try: # Save decrypted data for debug
             with open(os.path.join(DATA_DIR, "decrypted_data.bin"), "wb") as f: f.write(decrypted_data)
        except Exception as e: log_debug(f"Failed to save decrypted data file: {e}")
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}"); print(f"\n[ERROR] Decryption failed: {e}"); return None

def verify_and_extract_data(reassembled_data):
    """Verifies checksum, extracts length, and returns the final data payload."""
    log_debug("Verifying integrity and extracting final payload...")
    min_len = LENGTH_PREFIX_SIZE + INTEGRITY_CHECK_SIZE
    if len(reassembled_data) < min_len:
        log_debug(f"Error: Reassembled data ({len(reassembled_data)}B) too short. Min required: {min_len}B")
        print("\n[ERROR] Reassembled data too short for length prefix and checksum.")
        return None

    # 1. Extract components
    length_bytes = reassembled_data[:LENGTH_PREFIX_SIZE]
    received_checksum = reassembled_data[-INTEGRITY_CHECK_SIZE:]
    checksummed_part = reassembled_data[:-INTEGRITY_CHECK_SIZE] # Contains length + data package

    log_debug(f"Extracted Length Prefix: {length_bytes.hex()}")
    log_debug(f"Extracted Received MD5: {received_checksum.hex()}")
    log_debug(f"Part used for MD5 calculation (Len+Data): {len(checksummed_part)} bytes")

    # 2. Calculate checksum
    calculated_checksum = hashlib.md5(checksummed_part).digest()
    log_debug(f"Calculated Expected MD5: {calculated_checksum.hex()}")

    # Save checksum info for debugging
    checksum_info = {"expected": calculated_checksum.hex(), "received": received_checksum.hex(), "match": False}
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")

    # 3. Verify checksum
    if calculated_checksum != received_checksum:
        log_debug("Error: Overall data integrity check failed (MD5 mismatch)!")
        print("\n[ERROR] Data integrity check failed! MD5 does not match.")
        checksum_info["match"] = False
        with open(checksum_json, "w") as f: json.dump(checksum_info, f, indent=2)
        return None # Abort on integrity failure
    else:
        log_debug("Overall data integrity verified successfully (MD5 match).")
        print("\n[VERIFY] Data integrity check successful (MD5 OK).")
        checksum_info["match"] = True
        with open(checksum_json, "w") as f: json.dump(checksum_info, f, indent=2)

    # 4. Unpack length
    try:
        original_data_length = struct.unpack('!Q', length_bytes)[0]
        log_debug(f"Unpacked original data length: {original_data_length} bytes")
    except struct.error as e:
        log_debug(f"Error unpacking length prefix {length_bytes.hex()}: {e}")
        print("\n[ERROR] Failed to read data length prefix.")
        return None

    # 5. Extract data package
    data_package = checksummed_part[LENGTH_PREFIX_SIZE:]
    log_debug(f"Extracted data package size: {len(data_package)} bytes")

    # 6. Crucial Check: Compare extracted length with expected length
    if len(data_package) != original_data_length:
        log_debug(f"Error: Length mismatch! Expected {original_data_length} bytes, got {len(data_package)} bytes.")
        print(f"\n[ERROR] Data length mismatch! Expected {original_data_length}, got {len(data_package)}.")
        # This could indicate chunk loss despite checksum passing (unlikely with MD5) or a sender bug
        return None

    log_debug("Data package extracted successfully with correct length.")
    print(f"[VERIFY] Data package length ({original_data_length} bytes) consistent.")
    # Save data package for debug
    try:
        with open(os.path.join(DATA_DIR, "verified_data_package.bin"), "wb") as f: f.write(data_package)
    except Exception as e: log_debug(f"Failed to save verified data package: {e}")

    return data_package # Return IV+encrypted_data or raw_data

def reassemble_data():
    """Reassemble received chunks in order. NO cleaning/stripping here."""
    global received_chunks, expected_total_chunks
    if not received_chunks: log_debug("Reassembly skipped: No chunks received."); return None

    print(f"\n[REASSEMBLY] Sorting {len(received_chunks)} received chunks...")
    sorted_seq_nums = sorted(received_chunks.keys())
    highest_rcvd = sorted_seq_nums[-1] if sorted_seq_nums else 0

    # Check for missing chunks (more accurate if expected_total_chunks is known)
    expected_max_seq = expected_total_chunks if expected_total_chunks else highest_rcvd
    missing_chunks = []
    if expected_max_seq > 0 :
        all_expected = set(range(1, expected_max_seq + 1))
        missing_chunks = sorted(list(all_expected - set(sorted_seq_nums)))

    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks. Expected: 1-{expected_max_seq}. Missing: {missing_chunks[:20]}...")
        print(f"[REASSEMBLY] Warning: Detected {len(missing_chunks)} missing chunks (Expected up to {expected_max_seq}).")
        if len(missing_chunks) < 20: print(f"   Missing: {missing_chunks}")
        else: print(f"   Missing (first 20): {missing_chunks[:20]}...")
        # Decide whether to proceed? For now, proceed and let checksum fail if critical data is missing.

    chunk_info = {"received_chunks": len(received_chunks), "highest_seq_num_received": highest_rcvd,
                  "expected_total_chunks": expected_total_chunks, "missing_chunks": missing_chunks,
                  "received_seq_nums": sorted_seq_nums}
    with open(os.path.join(LOGS_DIR, "reassembly_info.json"), "w") as f: json.dump(chunk_info, f, indent=2)

    # Concatenate chunks exactly as received (including any padding)
    print("[REASSEMBLY] Concatenating received chunks...")
    reassembled_data = b"".join(received_chunks[seq] for seq in sorted_seq_nums)

    # Save raw reassembled data (before verification/decryption)
    try:
        with open(os.path.join(DATA_DIR, "reassembled_raw_data.bin"), "wb") as f: f.write(reassembled_data)
        log_debug(f"Reassembled {len(reassembled_data)} raw bytes.")
        print(f"[REASSEMBLY] Completed. Raw reassembled size: {len(reassembled_data)} bytes")
    except Exception as e: log_debug(f"Failed to save raw reassembled data: {e}")

    return reassembled_data

def save_to_file(data, output_path):
    """Save final data to file."""
    try:
        with open(output_path, 'wb') as file: file.write(data)
        log_debug(f"Final data saved successfully to {output_path} ({len(data)} bytes)")
        print(f"\n[SAVE] Final data saved successfully to: {output_path}")
        try: # Also save copy in session data dir
             output_name = os.path.basename(output_path)
             with open(os.path.join(DATA_DIR, f"output_{output_name}"), "wb") as f: f.write(data)
        except Exception as e: log_debug(f"Failed to save copy to data dir: {e}")
        try: # Log text sample
            text_content = data.decode('utf-8', errors='ignore')
            log_debug(f"Saved text sample: {text_content[:100]}...")
            print(f"Saved text sample: {text_content[:60]}...")
            with open(os.path.join(DATA_DIR, "output_content_sample.txt"), "w") as f: f.write(text_content)
        except Exception: log_debug("Saved content is binary data.")
        return True
    except Exception as e:
        log_debug(f"Error saving final data to {output_path}: {e}"); print(f"\n[ERROR] Failed to save output file: {e}"); return False

# --- Main Receive Logic ---

def listen_for_discovery(stego, interface, timeout=DISCOVERY_TIMEOUT):
    """Listen for discovery probe packets."""
    global discovery_probe_received
    log_debug(f"Listening for discovery probes on TCP/{DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Listening for sender probe on TCP/{DISCOVERY_PORT} (Timeout: {timeout}s)...")
    discovery_probe_received = False # Reset flag
    try:
        sniff(iface=interface, filter=f"tcp and dst port {DISCOVERY_PORT}",
              prn=stego.process_discovery_probe, store=0, timeout=timeout,
              stop_filter=lambda p: discovery_probe_received)
    except Exception as e: log_debug(f"Error during discovery sniffing: {e}"); print(f"\nError during discovery listening: {e}")
    if discovery_probe_received:
         log_debug(f"Discovery probe processed from {discovery_sender_ip}:{discovery_sender_port}"); return True
    else: log_debug("No valid discovery probe received within timeout."); print("\n[DISCOVERY] No sender probe received."); return False

def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Discover sender, receive file via steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time
    global highest_seq_num, packet_counter, valid_packet_counter, connection_established
    global sender_ip, sender_port, discovery_sender_ip, discovery_sender_port, discovery_probe_received, expected_total_chunks

    # --- Initialization ---
    with open(DEBUG_LOG, "w") as f: f.write(f"=== CrypticRoute Receiver Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    summary = {"timestamp_start": time.time(), "output_path": output_path, "key_path": key_path, "interface": interface, "activity_timeout": timeout}
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    def write_summary():
         try:
             with open(summary_path, "w") as f: json.dump(summary, f, indent=2)
         except Exception as e: log_debug(f"Failed to write session summary: {e}")
    write_summary()

    # Reset state
    received_chunks = {}; transmission_complete = False; reception_start_time = 0; last_activity_time = time.time()
    highest_seq_num = 0; packet_counter = 0; valid_packet_counter = 0; connection_established = False
    sender_ip = None; sender_port = None; discovery_sender_ip = None; discovery_sender_port = None
    discovery_probe_received = False; ack_sent_chunks.clear(); expected_total_chunks = None

    stego = SteganographyReceiver()

    # Prepare key (Required for Discovery)
    if not key_path: print("Error: Key file (-k) is required."); sys.exit(1)
    try:
        with open(key_path, 'rb') as key_file: key_data = key_file.read()
        key = prepare_key(key_data) # Exits on error
    except Exception as e: log_debug(f"Error reading key file: {e}"); print(f"Error reading key file: {e}"); return False

    # --- Discovery Phase ---
    if not listen_for_discovery(stego, interface, DISCOVERY_TIMEOUT):
        log_debug("Discovery failed."); print("[ERROR] Could not discover sender."); summary["status"] = "failed_discovery"; summary["timestamp_end"] = time.time(); write_summary(); return False
    # discovery_sender_ip is now set

    # --- Main Listening Phase ---
    sender_ip = discovery_sender_ip # Use discovered IP for filtering
    log_debug(f"Proceeding to listen for connection/data from discovered sender: {sender_ip}")
    print(f"[INFO] Now listening for connection and data from {sender_ip}...")

    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(target=monitor_transmission, args=(stop_monitor, timeout), daemon=True)
    monitor_thread.start()

    log_debug(f"Listening for steganographic data on interface {interface or 'default'}...")
    print(f"Press Ctrl+C to stop listening.")
    last_activity_time = time.time() # Reset activity timer

    try:
        filter_str = f"tcp and src host {sender_ip}" # Filter by known sender IP
        log_debug(f"Using main data filter: {filter_str}")
        sniff(iface=interface, filter=filter_str, prn=stego.packet_handler, store=0,
              stop_filter=lambda p: transmission_complete)
    except KeyboardInterrupt: log_debug("Receiving stopped by user"); print("\nReceiving stopped by user.")
    except Exception as e: log_debug(f"Sniffing error: {e}"); print(f"\nSniffing error: {e}")
    finally: stop_monitor.set()

    # --- Post-Reception Processing ---
    print("\n" + "="*20 + " Processing Received Data " + "="*20)

    if not received_chunks:
        log_debug("No data chunks received."); print("No data chunks were received."); summary["status"] = "failed_no_data"; summary["timestamp_end"] = time.time(); write_summary(); return False

    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)
    log_debug(f"Reception ended. Received {chunk_count} chunks in ~{duration:.2f}s. Highest seq#: {highest_seq_num}. Total pkts: {packet_counter}, Valid data pkts: {valid_packet_counter}")
    print(f"\nReception Summary:")
    print(f"- Received {chunk_count} unique chunks in ~{duration:.2f}s.")
    print(f"- Highest sequence number seen: {highest_seq_num} (Expected total: {expected_total_chunks})")
    print(f"- Processed {packet_counter} packets total from {sender_ip}.")
    print(f"- Identified {valid_packet_counter} valid data packets.")

    missing = 0
    if expected_total_chunks and chunk_count < expected_total_chunks:
         missing = expected_total_chunks - chunk_count
         log_debug(f"Missing {missing} chunks based on expected total.")
         print(f"- Missing {missing} chunks (based on expected total).")

    # Update summary with reception stats
    summary.update({"chunks_received": chunk_count, "highest_seq_num_seen": highest_seq_num, "expected_total_chunks": expected_total_chunks,
                    "missing_chunks_approx": missing, "duration_seconds": duration, "sender_ip": sender_ip, "sender_port": sender_port})

    # Reassemble data (raw concatenation)
    reassembled_data = reassemble_data()
    if not reassembled_data:
        log_debug("Failed to reassemble data."); print("[ERROR] Reassembly failed."); summary["status"] = "failed_reassembly"; summary["timestamp_end"] = time.time(); write_summary(); return False

    # Verify integrity (checksum) and extract data package
    data_package = verify_and_extract_data(reassembled_data)
    if data_package is None:
        log_debug("Integrity verification failed."); print("[ERROR] Data verification failed."); summary["status"] = "failed_integrity"; summary["timestamp_end"] = time.time(); write_summary(); return False
    log_debug(f"Data package extracted size: {len(data_package)} bytes.")

    # Decrypt (if key provided)
    final_data = decrypt_data(data_package, key)
    if final_data is None: # Decryption failed
        log_debug("Decryption failed."); print("[ERROR] Decryption failed."); summary["status"] = "failed_decryption"; summary["timestamp_end"] = time.time(); write_summary(); return False
    elif key is None: # No key, used raw data package
        log_debug("No decryption performed (no key).")

    # Save final data
    print(f"[SAVE] Saving final data ({len(final_data)} bytes) to {output_path}...")
    success = save_to_file(final_data, output_path)

    # Final Summary
    summary["status"] = "completed_successfully" if success else "failed_save"
    summary["bytes_saved"] = len(final_data) if success else 0
    summary["timestamp_end"] = time.time(); write_summary()
    print(f"[INFO] Session logs saved to: {SESSION_DIR}")
    return success

# --- Monitor Thread ---
def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity."""
    global last_activity_time, transmission_complete
    while not stop_event.is_set():
        if time.time() - last_activity_time > timeout:
            log_debug(f"Inactivity timeout ({timeout}s) reached."); print(f"\n\n[TIMEOUT] Inactivity timeout ({timeout}s). Stopping listening.")
            transmission_complete = True; break # Signal main sniff to stop
        time.sleep(1) # Check every second

# --- Main Execution ---
def parse_arguments():
    parser = argparse.ArgumentParser(description='CrypticRoute - Receiver with Key-Based Discovery')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption key file (REQUIRED)')
    parser.add_argument('--interface', '-i', help='Network interface to listen on')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity timeout seconds (default: 120)')
    parser.add_argument('--output-dir', '-d', help='Custom base output directory')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT, help=f'Initial discovery timeout (default: {DISCOVERY_TIMEOUT}s)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    global OUTPUT_DIR, DISCOVERY_TIMEOUT
    if args.output_dir: OUTPUT_DIR = args.output_dir
    setup_directories() # Setup logs ASAP
    DISCOVERY_TIMEOUT = args.discovery_timeout
    if args.interface: conf.iface = args.interface; log_debug(f"Set Scapy interface: {conf.iface}")
    success = receive_file(args.output, args.key, args.interface, args.timeout)
    print(f"\nReceiver finished. Overall status: {'Success' if success else 'Failed'}")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()