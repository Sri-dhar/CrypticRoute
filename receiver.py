#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure, acknowledgment system, AND key-based discovery
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # type: ignore
from cryptography.hazmat.backends import default_backend # type: ignore
from scapy.all import IP, TCP, sniff, conf, send # type: ignore

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size in bytes
DISCOVERY_PORT = 54321 # Port for discovery probes/responses (Added from v2)
DISCOVERY_TIMEOUT = 60 # Seconds to wait for a discovery probe initially (Added from v2)

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None           # Will store the sender's IP (set after discovery/first SYN)
sender_port = None         # Will store the sender's port (set after first SYN)
ack_sent_chunks = set()    # Keep track of chunks we've acknowledged

# Discovery specific globals (Added from v2)
discovery_sender_ip = None          # IP from the valid discovery probe
discovery_sender_port = None        # Port the probe came *from*
discovery_probe_received = False    # Flag set when a valid probe is processed
receiver_key_hash_probe_expected = b'' # Derived from key, expected in probe's seq
receiver_key_hash_response = b''    # Derived from key, sent in response's seq

# Output directory structure
OUTPUT_DIR = "stealth_output"
SESSION_DIR = ""  # Will be set based on timestamp
LOGS_DIR = ""     # Will be set based on session dir
DATA_DIR = ""     # Will be set based on session dir
CHUNKS_DIR = ""   # Will be set based on session dir

# Debug log file
DEBUG_LOG = ""  # Will be set based on logs dir


# --- Directory Setup and Logging (Original from v1) ---

def setup_directories():
    """Create organized directory structure for outputs."""
    global OUTPUT_DIR, SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG

    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"receiver_session_{timestamp}")
    os.makedirs(SESSION_DIR)

    LOGS_DIR = os.path.join(SESSION_DIR, "logs")
    DATA_DIR = os.path.join(SESSION_DIR, "data")
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks")
    os.makedirs(LOGS_DIR); os.makedirs(DATA_DIR); os.makedirs(CHUNKS_DIR)
    os.makedirs(os.path.join(CHUNKS_DIR, "raw"))
    os.makedirs(os.path.join(CHUNKS_DIR, "cleaned"))

    DEBUG_LOG = os.path.join(LOGS_DIR, "receiver_debug.log")

    latest_link = os.path.join(OUTPUT_DIR, "receiver_latest")
    try:
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link):
            backup_name = f"{latest_link}_{int(time.time())}"
            os.rename(latest_link, backup_name)
            print(f"Renamed existing file to {backup_name}")
        # Use relative path for symlink if possible
        relative_session_dir = os.path.relpath(SESSION_DIR, start=OUTPUT_DIR)
        os.symlink(relative_session_dir, latest_link)
        print(f"Created symlink: {latest_link} -> {relative_session_dir}")
    except Exception as e:
        print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    # Check if DEBUG_LOG is initialized
    if not DEBUG_LOG:
        print(f"DEBUG (log not ready): {message}")
        return
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log {DEBUG_LOG}: {e}")


# --- Key Derivation (Added from v2) ---
def derive_key_identifiers(key):
    """Derive probe and response identifiers from the key."""
    global receiver_key_hash_probe_expected, receiver_key_hash_response
    hasher = hashlib.sha256()
    hasher.update(key)
    full_hash = hasher.digest()
    receiver_key_hash_probe_expected = full_hash[:4] # Expect first 4 bytes in probe's seq
    receiver_key_hash_response = full_hash[4:8] # Use next 4 bytes for response's seq
    log_debug(f"Derived Expected Probe ID (in Seq): {receiver_key_hash_probe_expected.hex()}")
    log_debug(f"Derived Response ID (for Seq): {receiver_key_hash_response.hex()}")

# --- SteganographyReceiver Class (Merging Discovery into Original v1) ---

class SteganographyReceiver:
    """Simple steganography receiver using TCP with acknowledgment and discovery."""

    def __init__(self):
        """Initialize the receiver."""
        # Initialize debug file paths (from v1)
        chunks_json = os.path.join(LOGS_DIR, "received_chunks.json")
        acks_json = os.path.join(LOGS_DIR, "sent_acks.json")

        # Create the files immediately (from v1)
        try:
            with open(chunks_json, "w") as f: f.write("{}")
            with open(acks_json, "w") as f: f.write("{}")
        except IOError as e:
            log_debug(f"Error creating initial log files: {e}")

        self.chunks_json_path = chunks_json
        self.acks_json_path = acks_json

        # Initialize tracking dictionaries (from v1)
        self.sent_acks = {}

        # Port *we* use for sending ACKs/SYN-ACKs (randomly chosen, from v1)
        self.my_port = random.randint(10000, 60000)
        log_debug(f"Receiver using source port {self.my_port} for sending responses (SYN-ACK, ACKs)")


    # --- Original Logging Methods (v1) ---
    def log_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        try:
            with open(self.chunks_json_path, "r") as f: chunk_info = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): chunk_info = {}
        chunk_info[str(seq_num)] = {
            "data": data.hex(), "size": len(data), "timestamp": time.time()
        }
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(chunk_info, f, indent=2)
        except IOError as e: log_debug(f"Error writing received chunks log: {e}")

        chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:03d}.bin")
        try:
            with open(chunk_file, "wb") as f: f.write(data)
        except IOError as e: log_debug(f"Error writing raw chunk file {chunk_file}: {e}")

    def log_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.sent_acks, f, indent=2)
        except IOError as e: log_debug(f"Error writing sent ACKs log: {e}")

    # --- Discovery Response Methods (Added from v2) ---
    def create_discovery_response_packet(self, probe_packet):
        """Create a discovery response packet."""
        global receiver_key_hash_response
        sender_ip = probe_packet[IP].src
        sender_port = probe_packet[TCP].sport # Port the probe came *from*
        probe_seq = probe_packet[TCP].seq # Seq from the probe (contains sender's probe hash)

        # Create response packet according to v2 spec
        response_packet = IP(dst=sender_ip) / TCP(
            sport=DISCOVERY_PORT, # Respond *from* the well-known discovery port
            dport=sender_port,    # Respond *to* the sender's ephemeral source port
            flags="PF",           # PSH | FIN (0x09)
            window=0xCAFE,        # Magic value 2 for discovery response
            seq=int.from_bytes(receiver_key_hash_response, 'big'), # Our response hash in seq
            ack=probe_seq + 1 if probe_seq is not None else 1 # Acknowledge the probe's sequence number (+1 typically, handle None just in case)
        )
        log_debug(f"Created discovery response: Target={sender_ip}:{sender_port}, "
                  f"Flags={response_packet[TCP].flags}, Win={response_packet[TCP].window:#x}, "
                  f"Seq={response_packet[TCP].seq:#x}, Ack={response_packet[TCP].ack:#x}")
        return response_packet

    def send_discovery_response(self, probe_packet):
        """Sends the discovery response packet back to the sender."""
        response_pkt = self.create_discovery_response_packet(probe_packet)
        if response_pkt:
            log_debug(f"Sending Discovery Response to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            print(f"[DISCOVERY] Sending response to sender at {probe_packet[IP].src}")
            print(f"[IP_EXCHANGE] Sending confirmation to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            # Send multiple times for reliability (as in v2)
            for _ in range(5):
                 send(response_pkt)
                 time.sleep(0.1)

    def process_discovery_probe(self, packet):
        """Process incoming packets during discovery phase. Returns True if valid probe processed."""
        global discovery_sender_ip, discovery_sender_port, discovery_probe_received
        global receiver_key_hash_probe_expected

        if discovery_probe_received: # Already found one probe in this run
             # log_debug("Ignoring potential probe, already processed one.")
             return False # Stop processing further probes

        # Check for discovery probe signature: PSH|URG (0x28), Window 0xFACE, coming to DISCOVERY_PORT
        if IP in packet and TCP in packet and packet[TCP].dport == DISCOVERY_PORT \
           and packet[TCP].flags & 0x28 == 0x28 and packet[TCP].window == 0xFACE:

            probe_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery probe from {packet[IP].src}:{packet[TCP].sport}")
                        # Convert flags to int for hex formatting, and also log the string representation
            log_debug(f"  Flags={int(packet[TCP].flags):#x} ({packet[TCP].flags}), Window={packet[TCP].window:#x}, SeqHash={probe_hash_received.hex()}")

            # Verify key hash embedded in sequence number
            if probe_hash_received == receiver_key_hash_probe_expected:
                log_debug(f"Valid Discovery Probe received from {packet[IP].src}:{packet[TCP].sport}. Key hash MATCH.")
                print(f"\n[DISCOVERY] Valid probe received from sender at {packet[IP].src}") # Newline for clarity
                print(f"[IP_EXCHANGE] Sender IP identified: {packet[IP].src}:{packet[TCP].sport}")

                # Store sender info from the probe
                discovery_sender_ip = packet[IP].src
                discovery_sender_port = packet[TCP].sport # This is the port *they* sent from

                # Send response back
                self.send_discovery_response(packet)

                # Mark discovery as done for this phase
                discovery_probe_received = True
                return True # Signal sniff to stop (discovery successful)
            else:
                log_debug(f"Probe received from {packet[IP].src}, but key hash mismatch (Expected {receiver_key_hash_probe_expected.hex()}, Got {probe_hash_received.hex()}). Ignoring.")
                # Optional: Print a less verbose message for the user?
                # print(f"\n[DISCOVERY] Probe received from {packet[IP].src}, but key mismatch. Ignoring.")

        # If not the expected probe packet
        return False # Continue sniffing

    # --- Original Connection/Data ACK Methods (v1) ---
    def create_ack_packet(self, seq_num):
        """Create an ACK packet for a specific DATA sequence number (using v1 logic)."""
        global sender_ip, sender_port # These should be set by the connection SYN

        if not sender_ip or not sender_port:
            log_debug("Cannot create data ACK - sender connection info missing")
            return None

        # Create an ACK packet with special markers (v1 specification)
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, # Send from our random port
            dport=sender_port,  # Send TO the port the SYN came from
            seq=0x12345678,     # Fixed pattern to identify this as our ACK
            ack=seq_num,        # Use the ack field to specify which DATA chunk seq_num we're acknowledging
            window=0xCAFE,      # Special window value for data ACKs (v1 specification)
            flags="A"           # ACK flag
        )
        log_debug(f"Created data ACK: Target={sender_ip}:{sender_port}, "
                  f"Flags={ack_packet[TCP].flags}, Win={ack_packet[TCP].window:#x}, "
                  f"Seq={ack_packet[TCP].seq:#x}, Ack(ChunkSeq)={ack_packet[TCP].ack}")
        return ack_packet

    def send_ack(self, seq_num):
        """Send an acknowledgment for a specific sequence number (using v1 logic)."""
        global ack_sent_chunks

        if seq_num in ack_sent_chunks:
            # log_debug(f"ACK for chunk {seq_num} already sent, skipping duplicate send.")
            # Resending on duplicate chunk received is handled in process_packet
            return

        ack_packet = self.create_ack_packet(seq_num)
        if not ack_packet:
            return

        log_debug(f"Sending ACK for data chunk {seq_num} to {sender_ip}:{sender_port}")
        print(f"[ACK] Sending acknowledgment for chunk {seq_num}")
        self.log_ack(seq_num) # Log the ACK we are sending

        # Send the ACK packet multiple times for reliability (v1 logic)
        for i in range(3):
            send(ack_packet)
            time.sleep(0.05)

        ack_sent_chunks.add(seq_num) # Mark as sent

    def create_syn_ack_packet(self, incoming_syn_packet): # Take incoming SYN to get correct ACK number
        """Create a SYN-ACK packet for connection establishment (using v1 logic)."""
        global sender_ip, sender_port # These should be set when SYN is processed

        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender connection info missing")
            return None

        # Create a SYN-ACK packet with special markers (v1 specification)
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, # Send from our random port
            dport=sender_port,  # Send TO the port the SYN came from
            seq=0xABCDEF12,     # Fixed pattern for our SYN-ACK seq
            ack=incoming_syn_packet[TCP].seq + 1, # Acknowledge the *actual* received SYN seq + 1
            window=0xBEEF,      # Special window value for handshake SYN-ACK (v1 spec)
            flags="SA"          # SYN-ACK flags
        )
        log_debug(f"Created SYN-ACK: Target={sender_ip}:{sender_port}, "
                  f"Flags={syn_ack_packet[TCP].flags}, Win={syn_ack_packet[TCP].window:#x}, "
                  f"Seq={syn_ack_packet[TCP].seq:#x}, Ack={syn_ack_packet[TCP].ack:#x}")
        return syn_ack_packet

    def send_syn_ack(self, incoming_syn_packet):
        """Send a SYN-ACK response based on an incoming SYN (using v1 logic)."""
        syn_ack_packet = self.create_syn_ack_packet(incoming_syn_packet)
        if not syn_ack_packet:
            return

        log_debug(f"Sending SYN-ACK for connection establishment to {sender_ip}:{sender_port}")
        print(f"[HANDSHAKE] Sending SYN-ACK response to {sender_ip}:{sender_port}")

        # Send the SYN-ACK packet multiple times for reliability (v1 logic)
        for i in range(5):
            send(syn_ack_packet)
            time.sleep(0.1)

    # --- Original Packet Processing (v1, Modified for Discovery IP Check) ---
    def packet_handler(self, packet):
        """Wrapper for process_packet that handles packet counting."""
        global packet_counter
        packet_counter += 1
        # Print status update periodically
        if packet_counter <= 10 or packet_counter % 50 == 0: # Reduced frequency
             # Ensure we don't divide by zero if packet_counter is 0 somehow
             valid_ratio_str = f"{valid_packet_counter}/{packet_counter}" if packet_counter > 0 else "0/0"
             print(f"[SCAN] Pkts: {packet_counter:06d} | Chunks Rcvd: {len(received_chunks):04d} | Valid Ratio: {valid_ratio_str}", end='\r', flush=True)

        # Call the actual processing function
        processed = self.process_packet(packet)

        # Return None to prevent scapy printing summary
        return None

    def process_packet(self, packet):
        """Process packets for discovery, connection, data, or completion."""
        global received_chunks, transmission_complete, reception_start_time
        global last_activity_time, highest_seq_num, valid_packet_counter
        global connection_established, sender_ip, sender_port
        global discovery_sender_ip # Use the IP identified during discovery

        # Update last activity time regardless of packet validity
        last_activity_time = time.time()

        # --- Phase 1: Check Source IP (Crucial after Discovery) ---
        # Once discovery is done, only accept packets from the discovered sender IP.
        # Before discovery, discovery_sender_ip is None, so this check passes.
        # During connection setup and data transfer, packet source must match.
        if discovery_sender_ip is not None:
            if IP not in packet or packet[IP].src != discovery_sender_ip:
                # Log less frequently to avoid spamming logs
                if packet_counter % 100 == 0:
                     src_ip = packet[IP].src if IP in packet else "Unknown"
                     log_debug(f"Ignoring packet from non-discovered source {src_ip} (expected {discovery_sender_ip})")
                return False # Ignore packet

        # --- Phase 2: Process Packet Content ---
        if IP in packet and TCP in packet:
            # If sender_ip is not yet set (first packet after discovery), set it.
            if sender_ip is None and discovery_sender_ip is not None:
                sender_ip = discovery_sender_ip
                log_debug(f"Sender IP confirmed as {sender_ip} (from discovery)")

            current_sender_ip = packet[IP].src
            current_sender_port = packet[TCP].sport

            # --- Connection Establishment Handling (v1 Logic) ---
            # Check for SYN packet with special window (from the *discovered* sender)
            if not connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == 0xDEAD:
                log_debug(f"Received connection establishment request (SYN) from {current_sender_ip}:{current_sender_port}")
                print(f"\n[HANDSHAKE] Received connection request (SYN) from {current_sender_ip}:{current_sender_port}")
                print(f"[IP_EXCHANGE] Connection request from {current_sender_ip}:{current_sender_port}")

                # Set sender IP and *PORT* based on this SYN packet
                sender_ip = current_sender_ip # Should match discovery_sender_ip if check above passed
                sender_port = current_sender_port # **** Get the port from the SYN ****
                log_debug(f"Set sender port for connection: {sender_port}")

                self.send_syn_ack(packet) # Pass SYN to get correct ACK number
                return True # Packet processed

            # Check for final ACK confirming connection (from sender IP/Port, to our random port)
            if not connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xF00D and packet[TCP].dport == self.my_port:
                log_debug(f"Received connection confirmation (ACK) from {current_sender_ip}:{current_sender_port}")
                print(f"[HANDSHAKE] Connection established with sender")
                print(f"[IP_EXCHANGE] Connection confirmed with {current_sender_ip}:{current_sender_port}")
                connection_established = True
                return True # Packet processed

            # --- Completion Signal Handling (v1 Logic) ---
            # Check for FIN flag and special window value (must be from established sender)
            if connection_established and packet[TCP].flags & 0x01 and packet[TCP].window == 0xFFFF:
                log_debug(f"Received transmission complete signal (FIN) from {current_sender_ip}:{current_sender_port}")
                print("\n[COMPLETE] Reception complete") # Newline for clarity
                transmission_complete = True
                return True # Packet processed, signal sniff to stop

            # --- Data Packet Handling (v1 Logic) ---
            # Only process data packets if connection is established
            if not connection_established:
                # Log infrequently if unexpected packets arrive before connection
                if packet_counter % 100 == 0: log_debug("Ignoring packet - connection not yet established.")
                return False

            # Check if packet structure matches our data packets (SYN flag, Window=SeqNum, MSS=TotalChunks)
            # Extract sequence number from window field
            seq_num = packet[TCP].window
            # Extract total chunks from MSS option (first check SYN flag)
            total_chunks = None
            if packet[TCP].flags & 0x02: # Data packets use SYN flag in v1
                for option in packet[TCP].options:
                    if option[0] == 'MSS':
                        total_chunks = option[1]
                        break

            # Heuristic check: Is it plausible this is our data packet?
            # Requires SYN flag, a plausible sequence number, and MSS option.
            if packet[TCP].flags & 0x02 and 0 < seq_num <= 60000 and total_chunks is not None:
                 # --- It looks like our data packet, proceed with v1 extraction ---
                 valid_packet_counter += 1
                 # log_debug(f"Processing potential data packet: Seq={seq_num}, Total={total_chunks}") # Can be verbose

                 # Extract data from sequence and acknowledge numbers (v1 encoding)
                 seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
                 ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
                 data = seq_bytes + ack_bytes

                 # Extract checksum from IP ID (v1 encoding)
                 checksum = packet[IP].id

                 # Verify checksum (v1 method)
                 calc_checksum = binascii.crc32(data) & 0xFFFF
                 checksum_ok = (checksum == calc_checksum)

                 if not checksum_ok:
                     log_debug(f"Warning: Checksum mismatch for packet {seq_num}. Expected {calc_checksum:#06x}, Got {checksum:#06x}")
                     # Optional: Print warning, but can be noisy
                     # print(f"[WARN] Checksum fail for chunk {seq_num:04d}")
                     # Decide whether to drop or accept checksum-failed packets. Current logic accepts.

                 # Check for duplicate chunk
                 if seq_num in received_chunks:
                     # log_debug(f"Duplicate chunk {seq_num} received, resending ACK.")
                     if valid_packet_counter % 20 == 0: # Reduce print frequency for duplicates
                          print(f"[DUPLICATE] Chunk {seq_num:04d} already received, resending ACK", end='\r', flush=True)
                     self.send_ack(seq_num) # Resend ACK for duplicates
                     return False # Don't process duplicate further

                 # --- Process New Chunk ---
                 # Record start time on first valid chunk
                 if len(received_chunks) == 0:
                     reception_start_time = time.time()
                     log_debug(f"First chunk {seq_num} received, starting timer.")
                     print(f"\n[START] First chunk {seq_num} received, timer started.") # Newline

                 # Store the chunk
                 log_debug(f"Received chunk {seq_num} (size: {len(data)}, chksum: {'OK' if checksum_ok else 'FAIL'})")
                 received_chunks[seq_num] = data
                 self.log_chunk(seq_num, data) # Log to JSON and raw file

                 # Send acknowledgment (using v1 method)
                 if valid_packet_counter % 10 == 0 or len(received_chunks) < 10: # Reduce ACK print frequency
                     print(f"[ACK] Sending acknowledgment for chunk {seq_num:04d}       ", end='\r', flush=True) # Overwrite progress
                 self.send_ack(seq_num)

                 # Update highest sequence number seen
                 if seq_num > highest_seq_num:
                     highest_seq_num = seq_num
                     log_debug(f"Highest sequence number seen updated to {highest_seq_num}")

                 # Print progress update (less frequently maybe?)
                 if valid_packet_counter % 5 == 0 or len(received_chunks) < 10:
                     progress = (len(received_chunks) / total_chunks) * 100 if total_chunks else 0
                     print(f"[CHUNK] Received chunk {seq_num:04d}/{total_chunks:04d} | Total: {len(received_chunks):04d}/{total_chunks:04d} | Progress: {progress:.1f}% ", end='\r', flush=True)
                     # Add a clear message in format expected by GUI
                     print(f"[CHUNK] Received chunk {seq_num}/{total_chunks} | Progress: {progress:.1f}%")

                 return True # Processed a valid data chunk

        # If packet didn't match any expected pattern
        return False


# --- Key Prep, Decryption, Integrity, Reassembly, Saving (Original from v1) ---

def prepare_key(key_data):
    """Prepare the encryption key in correct format and derive identifiers."""
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')

    # Check if it's a hex string and convert if needed (v1 logic)
    try:
        # More robust check: try decoding as ascii first
        is_hex = False
        if isinstance(key_data, bytes):
             try:
                  decoded = key_data.decode('ascii')
                  if all(c in '0123456789abcdefABCDEF' for c in decoded):
                      is_hex = True
             except UnicodeDecodeError:
                  pass # Cannot be hex string if not ascii

        if is_hex:
            key_data = bytes.fromhex(decoded)
            log_debug("Converted hex key string to bytes")
            # print("Interpreted key as hex string")
    except ValueError:
         log_debug("Key provided is not a valid hex string, using raw bytes.")
    except Exception as e:
         log_debug(f"Error during hex key check: {e}")

    # Ensure key is 32 bytes (256 bits) for AES-256 (v1 logic)
    if len(key_data) < 32:
        key_data = key_data.ljust(32, b'\0')
    elif len(key_data) > 32:
        key_data = key_data[:32]
    log_debug(f"Final key (used for decryption): {key_data.hex()}")

    # Save key for debugging (v1 logic)
    key_file = os.path.join(DATA_DIR, "key.bin")
    try:
        with open(key_file, "wb") as f: f.write(key_data)
    except IOError as e: log_debug(f"Error saving key file: {e}")

    # --- Derive Identifiers (Added) ---
    derive_key_identifiers(key_data)

    return key_data

def decrypt_data(data, key):
    """Decrypt data using AES (v1 logic)."""
    try:
        if len(data) < 16:
            log_debug("Error: Encrypted data too short (missing IV)")
            print("Error: Encrypted data too short (missing IV)")
            return None
        iv = data[:16]
        encrypted_data = data[16:]
        log_debug(f"Extracted IV: {iv.hex()}")
        log_debug(f"Encrypted data size: {len(encrypted_data)} bytes")

        # Save components for debugging (v1 logic)
        iv_file = os.path.join(DATA_DIR, "extracted_iv.bin")
        with open(iv_file, "wb") as f: f.write(iv)
        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        with open(encrypted_file, "wb") as f: f.write(encrypted_data)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_file = os.path.join(DATA_DIR, "decrypted_data.bin")
        with open(decrypted_file, "wb") as f: f.write(decrypted_data)
        log_debug(f"Decrypted data size: {len(decrypted_data)}")
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"\nDecryption error: {e}") # Newline for clarity
        return None

def verify_data_integrity(data):
    """Verify the integrity of reassembled data using MD5 checksum (v1 logic)."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        log_debug("Error: Data too short to contain integrity checksum")
        print("Error: Data too short to contain integrity checksum")
        return None # Cannot verify, return None to indicate failure

    file_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]

    # Save components for debugging (v1 logic)
    data_file = os.path.join(DATA_DIR, "data_without_checksum.bin")
    with open(data_file, "wb") as f: f.write(file_data)
    checksum_file = os.path.join(DATA_DIR, "received_checksum.bin")
    with open(checksum_file, "wb") as f: f.write(received_checksum)

    calculated_checksum = hashlib.md5(file_data).digest()
    calc_checksum_file = os.path.join(DATA_DIR, "calculated_checksum.bin")
    with open(calc_checksum_file, "wb") as f: f.write(calculated_checksum)

    checksum_match = (calculated_checksum == received_checksum)

    checksum_info = { "expected": calculated_checksum.hex(), "received": received_checksum.hex(), "match": checksum_match }
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")
    with open(checksum_json, "w") as f: json.dump(checksum_info, f, indent=2)

    if not checksum_match:
        log_debug("Warning: Data integrity check failed - checksums don't match")
        log_debug(f"  Expected: {calculated_checksum.hex()}")
        log_debug(f"  Received: {received_checksum.hex()}")
        print("\nWarning: Data integrity check failed!") # Newline
        # CRITICAL: Return the data *without* the bad checksum (v1 behavior)
        return file_data
    else:
        log_debug("Data integrity verified successfully")
        print("\nData integrity verified successfully") # Newline
        # Return data *without* the verified checksum (v1 behavior)
        return file_data


def reassemble_data():
    """Reassemble the received chunks in correct order (using detailed v1 logic)."""
    global received_chunks

    if not received_chunks:
        log_debug("Reassembly skipped: No chunks received.")
        return None

    print(f"\n[REASSEMBLY] Sorting {len(received_chunks)} received chunks...") # Newline
    sorted_seq_nums = sorted(received_chunks.keys())

    # Check for missing chunks (v1 logic)
    expected_seq = 1
    missing_chunks = []
    # print("[REASSEMBLY] Checking for missing chunks...") # Can be verbose
    for seq in sorted_seq_nums:
        if seq != expected_seq:
            missing_chunks.extend(range(expected_seq, seq))
        expected_seq = seq + 1

    # Check for missing chunks *after* the last received one, only if highest_seq_num > last received
    # This assumes highest_seq_num is somewhat reliable (e.g., from MSS option)
    last_received_seq = sorted_seq_nums[-1] if sorted_seq_nums else 0
    if expected_seq <= highest_seq_num and highest_seq_num > last_received_seq:
         log_debug(f"Checking for missing chunks between {expected_seq} and {highest_seq_num}")
         missing_chunks.extend(range(expected_seq, highest_seq_num + 1))


    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks detected. IDs (sample): {missing_chunks[:20]}...")
        print(f"[REASSEMBLY] Warning: Detected {len(missing_chunks)} missing chunks.")
        if len(missing_chunks) <= 20: print(f"[REASSEMBLY] Missing Sequence Numbers: {missing_chunks}")
        else: print(f"[REASSEMBLY] First 20 Missing Sequence Numbers: {missing_chunks[:20]}...")

    # Save diagnostic information (v1 logic)
    chunk_info = {
        "received_chunk_count": len(received_chunks),
        "highest_seq_num_seen": highest_seq_num, # Based on window field
        "missing_chunk_count": len(missing_chunks),
        "missing_chunks_list": missing_chunks,
        "received_seq_nums_list": sorted_seq_nums
    }
    reassembly_file = os.path.join(LOGS_DIR, "reassembly_info.json")
    with open(reassembly_file, "w") as f: json.dump(chunk_info, f, indent=2)

    # Process chunks in order, cleaning padding (detailed v1 logic)
    print("[REASSEMBLY] Cleaning received chunks (removing potential padding)...")
    print(f"[PROGRESS] Processing received data | Total chunks: {len(received_chunks)}")
    cleaned_chunks = []
    num_sorted = len(sorted_seq_nums)
    for i, seq in enumerate(sorted_seq_nums):
        chunk = received_chunks[seq]
        # Log progress less frequently
        if i == 0 or (i + 1) % 50 == 0 or i == num_sorted - 1:
            print(f"[REASSEMBLY] Processing chunk {seq:04d} ({i+1}/{num_sorted})", end='\r', flush=True)

        # Save raw chunk (already done in log_chunk)

        # Clean padding logic from v1 (conservative removal, esp. for last chunk)
        cleaned_chunk = chunk # Default to original
        is_last_chunk = (i == num_sorted - 1)

        if not is_last_chunk:
             # For non-last chunks, aggressively remove all trailing nulls
             stripped = chunk.rstrip(b'\0')
             # Handle case where chunk was all nulls
             cleaned_chunk = stripped if stripped else b'\0'
        else:
             # For the last chunk, be more careful
             if all(b == 0 for b in chunk):
                  cleaned_chunk = b'\0' # Keep one null if all nulls
             else:
                  # Only strip if multiple trailing nulls exist (heuristic for padding)
                  trailing_nulls = 0
                  for byte in reversed(chunk):
                      if byte == 0: trailing_nulls += 1
                      else: break
                  # Threshold from v1 was 3
                  if trailing_nulls >= 3:
                      cleaned_chunk = chunk.rstrip(b'\0')
                  # else: keep original chunk (trailing nulls might be data)

        cleaned_chunks.append(cleaned_chunk)

        # Save cleaned chunk (v1 logic)
        cleaned_file = os.path.join(CHUNKS_DIR, "cleaned", f"chunk_{seq:03d}.bin")
        with open(cleaned_file, "wb") as f: f.write(cleaned_chunk)

    print("\n[REASSEMBLY] Concatenating cleaned chunks...") # Newline after progress indicator
    reassembled_data = b"".join(cleaned_chunks)

    # Save the final reassembled data (v1 logic)
    reassembled_file = os.path.join(DATA_DIR, "reassembled_data.bin")
    with open(reassembled_file, "wb") as f: f.write(reassembled_data)

    print(f"[REASSEMBLY] Completed! Final reassembled size: {len(reassembled_data)} bytes")
    return reassembled_data


def save_to_file(data, output_path):
    """Save data to a file (v1 logic)."""
    try:
        with open(output_path, 'wb') as file: file.write(data)
        log_debug(f"Data saved to {output_path}")
        print(f"Data saved to {output_path}")

        # Copy to the data directory as well (v1 logic)
        output_name = os.path.basename(output_path)
        output_copy = os.path.join(DATA_DIR, f"output_{output_name}")
        with open(output_copy, "wb") as f: f.write(data)

        # Try to print/save as text (v1 logic)
        try:
            text_content = data.decode('utf-8', errors='ignore') # More robust decoding
            log_debug(f"Saved text content (sample): {text_content[:100]}...")
            print(f"Saved content appears to be text (sample): {text_content[:60]}...")
            text_file = os.path.join(DATA_DIR, "output_content.txt")
            with open(text_file, "w", encoding='utf-8', errors='ignore') as f: f.write(text_content)
        except Exception as e: # Catch potential errors if decode succeeds but write fails
            log_debug(f"Content is not valid UTF-8 text or failed to save as text: {e}")
            print("Saved content is binary data or could not be saved as text.")

        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"Error saving data to {output_path}: {e}")
        return False

# --- Discovery Listening Function (Added from v2) ---
def listen_for_discovery(stego, interface, timeout=DISCOVERY_TIMEOUT):
    """Listen for discovery probe packets."""
    global discovery_probe_received, discovery_sender_ip, discovery_sender_port
    log_debug(f"Listening for discovery probes on TCP port {DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Listening for sender probe on TCP/{DISCOVERY_PORT} (up to {timeout}s)...")

    discovery_probe_received = False # Reset flag for this attempt
    discovery_sender_ip = None       # Reset IP found
    discovery_sender_port = None     # Reset port found

    try:
        # Sniff specifically for TCP packets destined for our discovery port
        sniff(
            iface=interface,
            filter=f"tcp and dst port {DISCOVERY_PORT}",
            prn=stego.process_discovery_probe, # This will set flags and globals if valid probe found
            store=0,
            timeout=timeout, # Stop sniffing after the timeout
            # Stop immediately once a valid probe is processed
            stop_filter=lambda p: discovery_probe_received
        )
    except Exception as e:
        # Catch potential Scapy/socket errors during sniffing
        log_debug(f"Error during discovery sniffing: {e}")
        print(f"\n[ERROR] An error occurred during discovery listening: {e}")
        # Depending on the error, might indicate interface issues
        return False # Indicate failure

    # Check the flag set by process_discovery_probe
    if discovery_probe_received:
         log_debug(f"Discovery successful. Sender identified: {discovery_sender_ip}:{discovery_sender_port}")
         # Success message printed within process_discovery_probe when response is sent
         return True
    else:
         log_debug("Discovery timed out or no valid probe received.")
         print("\n[DISCOVERY] No valid sender probe received within the timeout period.")
         return False

# --- Main Receive Function (Modified Workflow for Discovery) ---

def receive_file(output_path, key_path, interface=None, timeout=120): # key_path is now required
    """Discover sender, then receive a file via steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time
    global highest_seq_num, packet_counter, valid_packet_counter, connection_established
    global sender_ip, sender_port, discovery_sender_ip, discovery_probe_received # Include discovery globals

    # --- Phase 0: Initialization and Key Prep ---
    # Create summary file (v1 logic)
    summary = {
        "session_start_time": time.time(), "output_path": os.path.abspath(output_path),
        "key_path": os.path.abspath(key_path) if key_path else None,
        "interface": interface or 'auto', "inactivity_timeout": timeout,
        "discovery_timeout": DISCOVERY_TIMEOUT # Log discovery timeout used
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f: json.dump(summary, f, indent=2)

    # Initialize debug log (v1 logic)
    with open(DEBUG_LOG, "a") as f: # Append if already exists
        f.write(f"\n=== CrypticRoute Receiver Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    # Reset global state variables (v1 logic + discovery flags)
    received_chunks = {}; transmission_complete = False; reception_start_time = 0
    last_activity_time = time.time(); highest_seq_num = 0; packet_counter = 0
    valid_packet_counter = 0; connection_established = False
    sender_ip = None; sender_port = None; ack_sent_chunks.clear()
    discovery_sender_ip = None; discovery_sender_port = None; discovery_probe_received = False

    # Create steganography receiver instance (v1)
    stego = SteganographyReceiver()

    # Prepare decryption key *early* - needed for discovery identifiers
    log_debug(f"Reading key from: {key_path}")
    print(f"Reading key: {key_path}")
    try:
        with open(key_path, 'rb') as key_file: key_data = key_file.read()
        key = prepare_key(key_data) # prepare_key now calls derive_key_identifiers
        if not receiver_key_hash_probe_expected or not receiver_key_hash_response:
             print("Error: Failed to derive discovery identifiers from key.")
             log_debug("Failed to derive key identifiers.")
             return False
    except Exception as e:
        log_debug(f"Error reading or preparing key file {key_path}: {e}")
        print(f"Error reading or preparing key file: {e}")
        return False # Cannot proceed without key

    # --- Phase 1: Discovery ---
    log_debug("Starting Discovery Phase...")
    if not listen_for_discovery(stego, interface, DISCOVERY_TIMEOUT):
        log_debug("Discovery failed. Exiting.")
        print("[ERROR] Could not discover sender. Ensure sender is running with the correct key.")
        return False # Cannot proceed without discovering sender
    # If discovery succeeded, discovery_sender_ip is set globally.

    # --- Phase 2: Main Listening for Connection & Data ---
    log_debug(f"Discovery successful. Proceeding to listen for connection/data from discovered sender: {discovery_sender_ip}")
    print(f"\n[INFO] Sender discovered at {discovery_sender_ip}. Now listening for connection and data...")

    # Start monitoring thread (v1 logic)
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(target=monitor_transmission, args=(stop_monitor, timeout))
    monitor_thread.daemon = True
    monitor_thread.start()
    log_debug("Started inactivity monitor thread.")

    # Start packet capture, now filtering on the discovered sender IP
    log_debug(f"Listening for connection/data packets from {discovery_sender_ip}...")
    print(f"Listening for subsequent packets from {discovery_sender_ip}...")
    print("Press Ctrl+C to stop listening manually.")
    last_activity_time = time.time() # Reset activity timer before main sniff loop

    try:
        # Filter specifically for TCP packets originating from the discovered sender
        filter_str = f"tcp and src host {discovery_sender_ip}"
        log_debug(f"Using main sniffing filter: '{filter_str}'")

        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.packet_handler, # Use the v1 handler (now checks sender IP)
            store=0,
            # Stop sniffing if transmission_complete flag is set (by FIN or timeout)
            stop_filter=lambda p: transmission_complete
        )
    except KeyboardInterrupt:
        log_debug("Receiving stopped by user (Ctrl+C).")
        print("\nReceiving stopped by user.")
        transmission_complete = True # Mark as complete to allow processing
    except Exception as e:
         log_debug(f"Error during main sniffing loop: {e}")
         print(f"\n[ERROR] Sniffing loop failed: {e}")
         transmission_complete = True # Stop processing
    finally:
        log_debug("Stopping inactivity monitor thread.")
        stop_monitor.set() # Signal monitor thread to stop
        if monitor_thread.is_alive():
             monitor_thread.join(1.0) # Wait briefly for monitor to exit


    # --- Phase 3: Post-Reception Processing (v1 Logic) ---
    print("\n" + "="*20 + " Processing Received Data " + "="*20) # Separator

    if not received_chunks:
        log_debug("Processing complete: No data chunks were received.")
        print("No data chunks were received during the session.")
        # Consider if this is success or failure. Arguably failure if sender was expected.
        return False

    # Calculate statistics (v1 logic)
    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)
    stats = {
        "total_packets_processed": packet_counter, "valid_data_packets": valid_packet_counter,
        "chunks_received": chunk_count, "highest_seq_num_seen": highest_seq_num,
        "duration_seconds": round(duration, 2),
        "reception_rate_percent": round((chunk_count / highest_seq_num * 100), 1) if highest_seq_num > 0 else (100.0 if chunk_count > 0 else 0.0),
        "missing_chunks_approx": (highest_seq_num - chunk_count) if highest_seq_num > chunk_count else 0,
        "sender_ip_discovered": discovery_sender_ip, # Log discovered IP
        "sender_ip_connected": sender_ip,     # Log IP from SYN
        "sender_port_connected": sender_port  # Log port from SYN
    }
    stats_file = os.path.join(LOGS_DIR, "reception_stats.json")
    with open(stats_file, "w") as f: json.dump(stats, f, indent=2)
    log_debug(f"Reception Stats: {stats}")
    print(f"\nReception summary:")
    print(f"- Processed {packet_counter} packets total (from sender: {sender_ip or 'Unknown'})")
    print(f"- Identified {valid_packet_counter} valid data packets")
    print(f"- Received {chunk_count} unique data chunks in ~{duration:.2f}s")
    print(f"- Highest sequence number seen: {highest_seq_num}")
    if stats["missing_chunks_approx"] > 0:
        print(f"- Reception rate: {stats['reception_rate_percent']:.1f}% ({stats['missing_chunks_approx']} missing)")

    # Reassemble data (v1 logic)
    log_debug("Reassembling data...")
    print("[REASSEMBLY] Starting data reassembly process...")
    reassembled_data = reassemble_data()
    if reassembled_data is None: # Handles case where received_chunks was empty
        log_debug("Failed to reassemble data (no chunks or error).")
        print("[REASSEMBLY] Failed!")
        status = "failed_reassembly"
        success = False
    else:
        log_debug(f"Reassembled {len(reassembled_data)} bytes.")
        # Verify data integrity (v1 logic)
        print("[VERIFY] Verifying data integrity...")
        verified_data = verify_data_integrity(reassembled_data)
        if verified_data is None: # Checksum failed or data too short
             log_debug("Integrity check failed or data too short. Using raw reassembled data.")
             print("[VERIFY] Warning: Checksum verification failed or data too short. Proceeding with raw data.")
             final_data_to_decrypt = reassembled_data # Use raw data before checksum check
             status = "partial_checksum_failed"
        else: # Checksum verified (and removed) or wasn't present/expected correctly
             log_debug(f"Integrity check passed. Verified data size: {len(verified_data)} bytes.")
             print(f"[VERIFY] Integrity check passed/skipped. Data size: {len(verified_data)} bytes")
             final_data_to_decrypt = verified_data
             status = "ok_integrity_checked" # Intermediate status

        # Decrypt the data (using v1 logic, key is required now)
        log_debug("Decrypting data...")
        print("[DECRYPT] Starting decryption...")
        decrypted_data = decrypt_data(final_data_to_decrypt, key)
        if decrypted_data is None:
            log_debug("Decryption failed. Saving raw (verified/reassembled) data instead.")
            print("[DECRYPT] Failed! Saving raw data instead.")
            final_data_to_save = final_data_to_decrypt # Fallback
            status = "failed_decryption"
            success = False # Mark overall process as failed if decryption fails
        else:
            log_debug(f"Successfully decrypted {len(decrypted_data)} bytes.")
            print(f"[DECRYPT] Successfully decrypted {len(decrypted_data)} bytes.")
            final_data_to_save = decrypted_data
            status = "completed" # Update status
            success = True # Mark as successful for now

        # Save final data (v1 logic)
        print(f"[SAVE] Saving {len(final_data_to_save)} bytes to {output_path}...")
        save_success = save_to_file(final_data_to_save, output_path)
        print(f"[SAVE] File saved successfully")
        if not save_success:
            status = "failed_save"
            success = False # Override success if saving fails

    # Save completion info (v1 logic, updated status)
    completion_info = {
        "session_end_time": time.time(),
        "status": status,
        "bytes_saved": len(final_data_to_save) if 'final_data_to_save' in locals() and save_success else 0,
        # Add more details?
        "chunks_received": len(received_chunks),
        "missing_chunks": stats.get("missing_chunks_approx", "N/A"),
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)

    print(f"\n[INFO] All session data saved to: {SESSION_DIR}")
    print(f"[INFO] Latest session link: {os.path.join(OUTPUT_DIR, 'receiver_latest')}")

    return success


# --- Monitor Thread (Original v1) ---
def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity."""
    global last_activity_time, transmission_complete
    log_debug(f"Inactivity monitor started (timeout: {timeout}s).")
    while not stop_event.is_set():
        time_since_last_activity = time.time() - last_activity_time
        if time_since_last_activity > timeout:
            log_debug(f"Inactivity timeout reached ({timeout} seconds). Stopping reception.")
            print(f"\n\n[TIMEOUT] No activity detected for {timeout} seconds. Stopping listening.")
            transmission_complete = True # Signal main sniff loop to stop
            break # Exit monitor thread
        # Sleep for a short duration before checking again
        # Check more frequently near the timeout? For now, simple check.
        time_to_wait = min(1.0, timeout - time_since_last_activity) # Sleep 1s or until timeout
        if time_to_wait > 0:
             time.sleep(time_to_wait)
        else: # Should theoretically be caught by the check above, but as safety
             time.sleep(0.1)
    log_debug("Inactivity monitor stopped.")


# --- Argument Parsing (Modified for Discovery) ---
def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CrypticRoute - Receiver with Key-Based Discovery',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults
        )
    parser.add_argument('--output', '-o', required=True, help='Output file path for received data')
    parser.add_argument('--key', '-k', required=True,
                        help='Decryption key file (REQUIRED for discovery/decryption)')
    parser.add_argument('--interface', '-i',
                        help='Network interface to listen on (e.g., eth0). If omitted, Scapy attempts default.')
    parser.add_argument('--timeout', '-t', type=int, default=120,
                        help='Inactivity timeout in seconds (stops listening if no packets received).')
    parser.add_argument('--output-dir', '-d', default=OUTPUT_DIR,
                        help='Parent directory for session outputs.')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT,
                        help='Timeout (seconds) for initial sender discovery phase.')
    return parser.parse_args()

# --- Main Execution ---
def main():
    """Main function."""
    global OUTPUT_DIR, DISCOVERY_TIMEOUT # Allow modification from args

    args = parse_arguments()

    # Set output dir and discovery timeout from args *before* setup/run
    OUTPUT_DIR = args.output_dir
    DISCOVERY_TIMEOUT = args.discovery_timeout

    # Setup directories early for logging
    setup_directories()
    log_debug("--- Receiver Start ---")
    log_debug(f"Command line arguments: {sys.argv}")
    log_debug(f"Parsed arguments: {args}")

    # Check key file existence
    if not os.path.isfile(args.key):
        print(f"Error: Key file not found: {args.key}")
        log_debug(f"Key file not found: {args.key}")
        sys.exit(1)

    # Start the main reception process
    success = False
    try:
        success = receive_file(
            args.output,
            args.key, # Key path is now mandatory
            args.interface,
            args.timeout # Inactivity timeout
        )
    except PermissionError:
         print("\n[ERROR] Permission denied. Please run this script as root or with capabilities to sniff packets (e.g., sudo).")
         log_debug("PermissionError caught - script needs root/capabilities.")
         sys.exit(1)
    except Exception as e:
         print(f"\n[FATAL ERROR] An unexpected error occurred: {e}")
         import traceback
         traceback.print_exc()
         log_debug(f"FATAL ERROR: {e}\n{traceback.format_exc()}")
         # Attempt to save completion status even on fatal error
         completion_info = { "session_end_time": time.time(), "status": "failed_fatal_error", "error": str(e) }
         completion_path = os.path.join(LOGS_DIR, "completion_info.json")
         try:
             with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
         except Exception as save_e:
             log_debug(f"Could not save completion info after fatal error: {save_e}")
         success = False # Ensure failure exit code


    log_debug(f"--- Receiver End (Overall Success: {success}) ---")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    # Check for root privileges (needed for raw socket operations with Scapy)
    # Check this early before attempting file operations or sniffing
    if os.geteuid() != 0:
        print("Error: This script requires root privileges to send/sniff packets.")
        # No logging setup yet, just print and exit
        sys.exit(1)
    main()