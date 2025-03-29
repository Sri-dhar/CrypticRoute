#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure, acknowledgment system, and dynamic IP discovery.
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
DISCOVERY_PORT = 54321    # UDP port for broadcast discovery
KEY_HASH_ALGO = 'sha256'  # Algorithm for key hashing

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None          # Will be discovered
sender_port = None        # Will be discovered
my_tcp_port = None        # Our TCP listening port (chosen dynamically)
ack_sent_chunks = set()   # Keep track of chunks we've acknowledged

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
        # Use absolute path for symlink target
        abs_session_dir = os.path.abspath(SESSION_DIR)
        os.symlink(abs_session_dir, latest_link)
        print(f"Created symlink: {latest_link} -> {abs_session_dir}")
    except Exception as e:
        print(f"Warning: Could not create symlink: {e}")
        # Continue without the symlink - this is not critical

    print(f"Created output directory structure at: {SESSION_DIR}")


def log_debug(message):
    """Write debug message to log file."""
    if not DEBUG_LOG: # Ensure log path is set
        return
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log: {e}")


def calculate_key_hash(key_data):
    """Calculate the hash of the key."""
    hasher = hashlib.new(KEY_HASH_ALGO)
    hasher.update(key_data)
    return hasher.hexdigest()

class SteganographyReceiver:
    """Simple steganography receiver using only TCP with acknowledgment."""

    def __init__(self, tcp_port):
        """Initialize the receiver."""
        global my_tcp_port
        # Initialize debug file for received chunks
        chunks_json = os.path.join(LOGS_DIR, "received_chunks.json")
        with open(chunks_json, "w") as f:
            f.write("{}")
        self.chunks_json_path = chunks_json

        # Initialize values for ACK responses
        self.my_port = tcp_port # Use the assigned TCP port
        my_tcp_port = tcp_port  # Update global as well
        log_debug(f"Receiver initialized with TCP port: {self.my_port}")

        # Create debug file for sent ACKs
        acks_json = os.path.join(LOGS_DIR, "sent_acks.json")
        with open(acks_json, "w") as f:
            f.write("{}")
        self.acks_json_path = acks_json
        self.sent_acks = {}

    def log_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        # Load existing file
        try:
            with open(self.chunks_json_path, "r") as f:
                chunk_info = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            chunk_info = {}

        # Add this chunk
        chunk_info[str(seq_num)] = {
            "data": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }

        # Save back to file
        with open(self.chunks_json_path, "w") as f:
            json.dump(chunk_info, f, indent=2)

        # Also save the raw chunk data
        chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:03d}.bin")
        with open(chunk_file, "wb") as f:
            f.write(data)

    def log_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks[str(seq_num)] = {
            "timestamp": time.time()
        }
        with open(self.acks_json_path, "w") as f:
            json.dump(self.sent_acks, f, indent=2)

    def create_ack_packet(self, seq_num):
        """Create an ACK packet for a specific sequence number."""
        global sender_ip, sender_port

        if not sender_ip or not sender_port:
            log_debug("Cannot create ACK - sender information missing")
            return None

        # Create an ACK packet with special markers
        # Use a specific bit pattern in seq and ack fields
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port,
            dport=sender_port,
            seq=0x12345678,  # Fixed pattern to identify this as an ACK
            ack=seq_num,     # Use the ack field to specify which chunk we're acknowledging
            window=0xCAFE,   # Special window value for ACKs
            flags="A"        # ACK flag
        )

        return ack_packet

    def send_ack(self, seq_num):
        """Send an acknowledgment for a specific sequence number."""
        global ack_sent_chunks

        # Skip if we've already ACKed this chunk
        if seq_num in ack_sent_chunks:
            return

        # Create the ACK packet
        ack_packet = self.create_ack_packet(seq_num)
        if not ack_packet:
            return

        # Log and send the ACK
        log_debug(f"Sending ACK for chunk {seq_num}")
        print(f"[ACK] Sending acknowledgment for chunk {seq_num:04d}")
        self.log_ack(seq_num)

        # Send the ACK packet multiple times for reliability
        for i in range(3):  # Send 3 times
            send(ack_packet)
            time.sleep(0.05)  # Small delay between retransmissions

        # Mark this chunk as acknowledged
        ack_sent_chunks.add(seq_num)

    def create_syn_ack_packet(self):
        """Create a SYN-ACK packet for connection establishment."""
        global sender_ip, sender_port

        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender information missing")
            return None

        # Create a SYN-ACK packet with special markers
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port,
            dport=sender_port,
            seq=0xABCDEF12,  # Fixed pattern for SYN-ACK
            ack=0x12345678,  # Fixed pattern to acknowledge SYN
            window=0xBEEF,   # Special window value for handshake
            flags="SA"       # SYN-ACK flags
        )

        return syn_ack_packet

    def send_syn_ack(self):
        """Send a SYN-ACK response for connection establishment."""
        # Create the SYN-ACK packet
        syn_ack_packet = self.create_syn_ack_packet()
        if not syn_ack_packet:
            return

        # Log and send the SYN-ACK
        log_debug("Sending SYN-ACK for connection establishment")
        print("[HANDSHAKE] Sending SYN-ACK response")

        # Send the SYN-ACK packet multiple times for reliability
        for i in range(5):  # Send 5 times to ensure receipt
            send(syn_ack_packet)
            time.sleep(0.1)  # Small delay between retransmissions

    def packet_handler(self, packet):
        """Wrapper for process_packet that doesn't print the return value."""
        global packet_counter, sender_ip, sender_port

        # Increment packet counter
        packet_counter += 1

        # Filter packets not from the discovered sender IP
        if sender_ip and packet.haslayer(IP) and packet[IP].src != sender_ip:
             # Only log occasionally to avoid flooding
            if packet_counter % 100 == 0:
                log_debug(f"Packet #{packet_counter} ignored (source {packet[IP].src} != discovered {sender_ip})")
            return None

        # Print status for every packet or at a regular interval
        if packet_counter <= 10 or packet_counter % 10 == 0:
            chunk_count = len(received_chunks)
            valid_ratio = f"{valid_packet_counter}/{packet_counter}" if packet_counter > 0 else "0/0"
            print(f"[PACKET] #{packet_counter:08d} | Chunks: {chunk_count:04d} | Valid ratio: {valid_ratio}")

        # Call the actual processing function but don't return its value
        self.process_packet(packet)

        # Always return None to prevent printing
        return None

    def process_packet(self, packet):
        """Process a packet to extract steganographic data."""
        global received_chunks, transmission_complete, reception_start_time
        global last_activity_time, highest_seq_num, valid_packet_counter
        global connection_established, sender_ip, sender_port # sender_ip/port are now discovered

        # Update last activity time
        last_activity_time = time.time()

        # Check if it's a valid TCP packet from the discovered sender
        if IP in packet and TCP in packet and packet[IP].src == sender_ip:
            # Check sender port if we know it
            if sender_port is not None and packet[TCP].sport != sender_port:
                log_debug(f"Packet received from {sender_ip} but wrong port {packet[TCP].sport} (expected {sender_port})")
                return False # Ignore packet from wrong port

            # Check for connection establishment (SYN packet with special window value)
            # This SYN should come from the discovered sender_ip and sender_port
            if not connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == 0xDEAD:  # SYN flag and special window
                log_debug(f"Received connection establishment request (SYN) from {packet[IP].src}:{packet[TCP].sport}")
                print(f"\n[HANDSHAKE] Received connection request (SYN) from {packet[IP].src}:{packet[TCP].sport}")

                # Verify against discovered sender port if not already set
                if sender_port is None:
                    sender_port = packet[TCP].sport
                    log_debug(f"Confirmed sender TCP port: {sender_port}")
                elif packet[TCP].sport != sender_port:
                     log_debug(f"Handshake SYN port mismatch: Got {packet[TCP].sport}, expected {sender_port}")
                     print(f"[ERROR] Handshake SYN port mismatch!")
                     return False

                # Send SYN-ACK response
                self.send_syn_ack()
                return True

            # Check for established connection (ACK packet with special value)
            # This ACK should come from the discovered sender_ip and sender_port
            if not connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xF00D:  # ACK flag and special window
                log_debug(f"Received connection confirmation (ACK) from {packet[IP].src}:{packet[TCP].sport}")
                print("[HANDSHAKE] Connection established with sender")
                connection_established = True
                return True

            # Check for completion signal (FIN flag and special window value)
            if packet[TCP].flags & 0x01 and packet[TCP].window == 0xFFFF:  # FIN flag is set and window is 0xFFFF
                log_debug("Received transmission complete signal")
                print("\n[COMPLETE] Received transmission complete signal")
                transmission_complete = True
                return True

            # Only process data packets if connection is established
            if not connection_established:
                # Log unexpected data packets before connection established
                if packet_counter % 50 == 0: # Log occasionally
                     log_debug(f"Ignoring potential data packet from {sender_ip}:{packet[TCP].sport} before connection established")
                return False

            # Extract sequence number from window field
            seq_num = packet[TCP].window

            # Ignore packets that don't have our data (window will be 0 or very large normally)
            # Allow seq_num 0 if it's a FIN/ACK potentially
            if (seq_num == 0 and not (packet[TCP].flags & 0x11)) or seq_num > 65535: # Window is 16 bit
                # Log occasionally
                if packet_counter % 100 == 0:
                    log_debug(f"Ignoring packet with suspicious window field: {seq_num}")
                return False

            # Extract total chunks from MSS option
            total_chunks = None
            if packet[TCP].options: # Check if options exist
                for option in packet[TCP].options:
                    if isinstance(option, tuple) and option[0] == 'MSS':
                        total_chunks = option[1]
                        break # Found MSS

            # If we can't find total chunks in MSS, this might not be our data packet
            # (Could be the final ACK or other traffic)
            if total_chunks is None:
                 # Log occasionally if flags indicate data potential (SYN used here)
                 if packet[TCP].flags & 0x02 and packet_counter % 50 == 0:
                     log_debug(f"Packet from {sender_ip} has no MSS option, seq={packet[TCP].seq}, win={seq_num}")
                 return False

            # We have a potentially valid data packet at this point
            valid_packet_counter += 1
            log_debug(f"[VALID] Packet #{packet_counter} from {sender_ip}:{packet[TCP].sport} identified as potential steganographic data (win={seq_num}, total={total_chunks})")
            # Don't print for every valid packet to reduce noise, use chunk receive print instead

            # Extract data from sequence and acknowledge numbers
            seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
            ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
            data = seq_bytes + ack_bytes

            # Extract checksum from IP ID
            checksum = packet[IP].id

            # Verify checksum
            calc_checksum = binascii.crc32(data) & 0xFFFF
            if checksum != calc_checksum:
                log_debug(f"Warning: Checksum mismatch for packet {seq_num}")
                print(f"[CHECKSUM] Warning: Mismatch for chunk {seq_num:04d}")
                # Decide whether to discard or process despite mismatch - currently processing
            # else:
            #     print(f"[CHECKSUM] Valid for chunk {seq_num:04d}") # Reduced verbosity

            # Skip if we already have this chunk
            if seq_num in received_chunks:
                log_debug(f"[DUPLICATE] Chunk {seq_num:04d} already received, sending ACK again")
                # Still send an ACK since the sender probably didn't receive our previous ACK
                self.send_ack(seq_num)
                return False

            # If this is the first chunk, record start time
            if len(received_chunks) == 0:
                reception_start_time = time.time()
                log_debug(f"[START] First chunk {seq_num} received, starting timer")
                print(f"[START] First chunk received, starting timer")

            # Store the chunk
            log_debug(f"Received chunk {seq_num} (size: {len(data)})")
            received_chunks[seq_num] = data

            # Log the chunk
            self.log_chunk(seq_num, data)

            # Send acknowledgment for this chunk
            self.send_ack(seq_num)

            # Update highest sequence number seen
            if seq_num > highest_seq_num:
                highest_seq_num = seq_num
                log_debug(f"[PROGRESS] New highest sequence: {highest_seq_num:04d}")
                # print(f"[PROGRESS] New highest sequence: {highest_seq_num:04d}") # Reduced verbosity

            # Print detailed information for every received chunk
            if total_chunks:
                progress = (len(received_chunks) / total_chunks) * 100 if total_chunks > 0 else 0
                print(f"[CHUNK] Received: {seq_num:04d}/{total_chunks:04d} | Total: {len(received_chunks):04d}/{total_chunks:04d} | Progress: {progress:.2f}%")
            else:
                print(f"[CHUNK] Received: {seq_num:04d} | Total received: {len(received_chunks):04d}")

            return True # Indicate a valid data chunk was processed

        # Log ignored packets occasionally
        elif packet_counter % 100 == 0:
             src_ip = packet[IP].src if IP in packet else "Unknown IP"
             proto = "TCP" if TCP in packet else "Other"
             log_debug(f"Ignored packet #{packet_counter} (Src: {src_ip}, Proto: {proto}, Target IP: {sender_ip})")

        return False # Packet was not processed


def prepare_key(key_data):
    """Prepare the encryption key in correct format."""
    log_debug(f"Preparing key data (type: {type(key_data)}, len: {len(key_data)})")
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        log_debug("Key data is string, encoding to utf-8")
        key_data = key_data.encode('utf-8')

    # Check if it's a hex string and convert if needed
    # More robust hex check
    is_hex = False
    if isinstance(key_data, bytes):
        try:
            # Attempt to decode as ascii then check if all chars are hex digits
            ascii_str = key_data.decode('ascii')
            if all(c in '0123456789abcdefABCDEF' for c in ascii_str):
                 # Ensure even length for fromhex
                 if len(ascii_str) % 2 == 0:
                    key_data = bytes.fromhex(ascii_str)
                    log_debug("Converted presumed hex key string to bytes")
                    print("Interpreted key file content as hex string")
                    is_hex = True
                 else:
                    log_debug("Odd length hex string found, treating as raw bytes")

        except UnicodeDecodeError:
            log_debug("Key data not ASCII, treating as raw bytes")
        except ValueError:
             log_debug("Key data contains non-hex chars, treating as raw bytes")


    # Ensure key is 32 bytes (256 bits) for AES-256 ONLY IF it wasn't hex
    # If it was hex, user likely provided exactly 32 bytes hex (64 chars)
    if not is_hex and len(key_data) != 32 :
         log_debug(f"Key length is {len(key_data)}, adjusting to 32 bytes.")
         if len(key_data) < 32:
             key_data = key_data.ljust(32, b'\0')  # Pad to 32 bytes
             log_debug(f"Key padded to 32 bytes.")
         else:
            key_data = key_data[:32] # Truncate to 32 bytes maximum
            log_debug(f"Key truncated to 32 bytes.")

    # Final check after potential padding/truncation
    if len(key_data) != 32:
         log_debug(f"Error: Final key length is not 32 bytes ({len(key_data)}). This is required for AES-256.")
         print(f"Error: Key processing resulted in a key of length {len(key_data)} bytes. AES-256 requires exactly 32 bytes.")
         # Decide how to handle this - raise error? Return None?
         # For now, let it proceed, decryption will likely fail.
         # Or better: exit
         print("Exiting due to invalid key length.")
         sys.exit(1)


    log_debug(f"Final key (hex): {key_data.hex()}")

    # Save key for debugging
    key_file = os.path.join(DATA_DIR, "key.bin")
    with open(key_file, "wb") as f:
        f.write(key_data)

    return key_data

def decrypt_data(data, key):
    """Decrypt data using AES."""
    try:
        # Check if data is long enough to contain the IV
        if len(data) < 16:
            log_debug("Error: Encrypted data is too short (missing IV)")
            print("Error: Encrypted data is too short (missing IV)")
            return None

        # Extract IV from the beginning of the data
        iv = data[:16]
        encrypted_data = data[16:]

        log_debug(f"Extracted IV: {iv.hex()}")
        log_debug(f"Encrypted data size: {len(encrypted_data)} bytes")

        # Save components for debugging
        iv_file = os.path.join(DATA_DIR, "extracted_iv.bin")
        with open(iv_file, "wb") as f:
            f.write(iv)

        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        with open(encrypted_file, "wb") as f:
            f.write(encrypted_data)

        # Initialize AES cipher with key and extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Save for debugging
        decrypted_file = os.path.join(DATA_DIR, "decrypted_data.bin")
        with open(decrypted_file, "wb") as f:
            f.write(decrypted_data)

        log_debug(f"Decrypted data head (hex): {decrypted_data[:32].hex()}...")

        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"Decryption error: {e}")
        return None

def verify_data_integrity(data):
    """Verify the integrity of reassembled data using MD5 checksum."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        log_debug("Error: Data too short to contain integrity checksum")
        print("Error: Data too short to contain integrity checksum")
        return None, False # Return None for data, False for match status

    # Extract the data and checksum
    file_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]

    # Save components for debugging
    data_file = os.path.join(DATA_DIR, "data_without_checksum.bin")
    with open(data_file, "wb") as f:
        f.write(file_data)

    checksum_file = os.path.join(DATA_DIR, "received_checksum.bin")
    with open(checksum_file, "wb") as f:
        f.write(received_checksum)

    # Calculate checksum of the data
    calculated_checksum = hashlib.md5(file_data).digest()

    # Save the calculated checksum
    calc_checksum_file = os.path.join(DATA_DIR, "calculated_checksum.bin")
    with open(calc_checksum_file, "wb") as f:
        f.write(calculated_checksum)

    # Compare checksums
    checksum_match = (calculated_checksum == received_checksum)

    # Save checksum comparison results
    checksum_info = {
        "expected": calculated_checksum.hex(),
        "received": received_checksum.hex(),
        "match": checksum_match
    }
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")
    with open(checksum_json, "w") as f:
        json.dump(checksum_info, f, indent=2)

    if not checksum_match:
        log_debug("Warning: Data integrity check failed - checksums don't match")
        log_debug(f"Expected: {calculated_checksum.hex()}")
        log_debug(f"Received: {received_checksum.hex()}")
        print("Warning: Data integrity check failed - checksums don't match")
        print(f"Expected: {calculated_checksum.hex()}")
        print(f"Received: {received_checksum.hex()}")
    else:
        log_debug("Data integrity verified successfully")
        print("Data integrity verified successfully")

    # Return the data without checksum, and the match status
    return file_data, checksum_match


def reassemble_data():
    """Reassemble the received chunks in correct order."""
    global received_chunks, highest_seq_num

    if not received_chunks:
        log_debug("Reassembly called with no chunks received.")
        return None

    # Determine the highest sequence number we should have received
    # If transmission wasn't marked complete, highest_seq_num might be the best guess
    # If it was complete, we assume highest_seq_num is the total number of chunks
    # (This logic might need refinement based on how sender signals total chunks reliably)
    total_expected_chunks = highest_seq_num # Best guess for now
    log_debug(f"Reassembling based on highest seen sequence number: {total_expected_chunks}")


    # Sort chunks by sequence number
    print(f"[REASSEMBLY] Sorting {len(received_chunks)} chunks by sequence number...")
    sorted_seq_nums = sorted(received_chunks.keys())

    if not sorted_seq_nums:
         log_debug("No sequence numbers found in received chunks.")
         return None

    # Check for missing chunks up to the highest number received
    expected_seq = 1  # Assume chunks start from 1
    missing_chunks = []
    last_received = 0

    print("[REASSEMBLY] Checking for missing chunks...")
    for seq in sorted_seq_nums:
        if seq < expected_seq:
            log_debug(f"Warning: Received out-of-order or duplicate chunk number {seq} (expected >= {expected_seq})")
            continue # Skip duplicates or unexpected lowers
        if seq > expected_seq:
            # Found a gap
            missing = list(range(expected_seq, seq))
            missing_chunks.extend(missing)
            log_debug(f"Detected missing chunks: {missing}")
        expected_seq = seq + 1
        last_received = seq

    # Check for chunks missing at the end, up to highest_seq_num
    if total_expected_chunks > last_received:
         missing_at_end = list(range(last_received + 1, total_expected_chunks + 1))
         missing_chunks.extend(missing_at_end)
         log_debug(f"Detected missing chunks at the end: {missing_at_end}")


    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks in total.")
        print(f"[REASSEMBLY] Warning: Missing {len(missing_chunks)} chunks")
        if len(missing_chunks) <= 20:
            print(f"[REASSEMBLY] Missing chunk sequence numbers: {missing_chunks}")
        else:
            print(f"[REASSEMBLY] First 10 missing: {missing_chunks[:10]}... Last 10 missing: {missing_chunks[-10:]}")


    # Save diagnostic information
    print("[REASSEMBLY] Saving diagnostic information...")
    chunk_info = {
        "received_chunks_count": len(received_chunks),
        "highest_seq_num_received": last_received,
        "inferred_total_chunks": total_expected_chunks, # Based on highest seen
        "missing_chunks_count": len(missing_chunks),
        "missing_chunks_list": missing_chunks,
        "received_seq_nums": sorted_seq_nums
    }
    reassembly_file = os.path.join(LOGS_DIR, "reassembly_info.json")
    with open(reassembly_file, "w") as f:
        json.dump(chunk_info, f, indent=2)

    # Get chunks in order
    print("[REASSEMBLY] Processing chunks in sequence order...")
    sorted_chunks_data = [received_chunks[seq] for seq in sorted_seq_nums]

    # Clean chunks (remove trailing null bytes - CAREFUL with this)
    # This was problematic before, let's just concatenate first and deal with potential padding later if needed.
    # print("[REASSEMBLY] Concatenating all received chunks...")
    # reassembled_data = b"".join(sorted_chunks_data)

    # # Save the raw concatenated data
    # raw_reassembled_file = os.path.join(DATA_DIR, "reassembled_raw.bin")
    # with open(raw_reassembled_file, "wb") as f:
    #     f.write(reassembled_data)
    # log_debug(f"Saved raw reassembled data ({len(reassembled_data)} bytes) to {raw_reassembled_file}")


    # Let's re-evaluate the stripping logic. Padding is added by sender if chunk < 8 bytes.
    # The *last* chunk might contain the actual end of the data + checksum, potentially shorter than 8.
    # All *other* chunks should ideally be 8 bytes unless sender implementation changed.
    # Stripping trailing nulls might remove legitimate data.
    # Recommendation: DO NOT STRIP NULLS HERE. Let decryption and checksum handle it.
    # If decryption works and checksum matches, the data up to the checksum is valid.

    print("[REASSEMBLY] Concatenating all received chunks (without stripping)...")
    reassembled_data = b"".join(sorted_chunks_data)

    # Save the reassembled data (without stripping)
    reassembled_file = os.path.join(DATA_DIR, "reassembled_data_unstripped.bin")
    with open(reassembled_file, "wb") as f:
        f.write(reassembled_data)
    log_debug(f"Saved unstripped reassembled data ({len(reassembled_data)} bytes)")

    print(f"[REASSEMBLY] Completed concatenation! Total size: {len(reassembled_data)} bytes")
    return reassembled_data


def save_to_file(data, output_path):
    """Save data to a file."""
    try:
        with open(output_path, 'wb') as file:
            file.write(data)
        log_debug(f"Data saved to {output_path}")
        print(f"Data saved to {output_path}")

        # Copy to the data directory as well
        output_name = os.path.basename(output_path)
        output_copy = os.path.join(DATA_DIR, f"final_output_{output_name}")
        with open(output_copy, "wb") as f:
            f.write(data)
        log_debug(f"Copied final output to {output_copy}")


        # Try to print the content as UTF-8 text
        try:
            # Limit preview to avoid huge console output
            preview_len = 500
            text_content = data[:preview_len].decode('utf-8')
            suffix = "..." if len(data) > preview_len else ""
            log_debug(f"Saved text content (preview): {text_content}{suffix}")
            print(f"Saved text content (preview): {text_content}{suffix}")

            # Save as text file for easy viewing
            text_file = os.path.join(DATA_DIR, "output_content_preview.txt")
            with open(text_file, "w", encoding='utf-8', errors='replace') as f:
                # Write the whole content, replacing errors
                f.write(data.decode('utf-8', errors='replace'))
            log_debug(f"Saved full content (UTF-8 decoded with replacements) to {text_file}")

        except UnicodeDecodeError:
            log_debug("Saved content is not valid UTF-8 text")
            print("Saved content is not valid UTF-8 text (or is binary data)")
            # Save a hex dump preview
            hex_preview = data[:64].hex()
            hex_file = os.path.join(DATA_DIR, "output_content_preview.hex")
            with open(hex_file, "w") as f:
                 f.write(hex_preview + ("..." if len(data) > 64 else ""))
            log_debug(f"Saved hex preview to {hex_file}")


        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"Error saving data to {output_path}: {e}")
        return False

def listen_for_sender(expected_key_hash, my_tcp_port, discovery_timeout=600):
    """Listen for sender's broadcast UDP packet and reply."""
    global sender_ip, sender_port

    log_debug(f"Starting UDP discovery listener on port {DISCOVERY_PORT}")
    print(f"[DISCOVERY] Listening for sender broadcast on UDP port {DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Will reply with my TCP port: {my_tcp_port}")
    print(f"[DISCOVERY] Matching key hash: {expected_key_hash[:8]}...") # Show partial hash

    udp_socket = None
    try:
        # Create UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow reuse of address
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Enable broadcasting for some systems (though we listen here)
        # udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) # Not needed for listener

        # Bind to the broadcast port on all interfaces
        udp_socket.bind(("", DISCOVERY_PORT))
        log_debug(f"UDP socket bound to ('', {DISCOVERY_PORT})")

        # Set a timeout for listening
        udp_socket.settimeout(discovery_timeout)

        while True: # Keep listening until timeout or valid packet found
            log_debug(f"Waiting for UDP packet (timeout={discovery_timeout}s)...")
            try:
                data, addr = udp_socket.recvfrom(1024) # Buffer size
                log_debug(f"Received UDP packet from {addr}: {data}")

                # Attempt to decode JSON payload
                try:
                    payload = json.loads(data.decode('utf-8'))
                    log_debug(f"Decoded JSON payload: {payload}")

                    # Check for required fields and type
                    if (payload.get("type") == "crypticroute_discover" and
                            "key_hash" in payload and
                            "sender_port" in payload):

                        received_hash = payload["key_hash"]
                        s_port = payload["sender_port"]
                        s_ip = addr[0]

                        log_debug(f"Potential sender found: IP={s_ip}, Port={s_port}, Hash={received_hash}")

                        # Compare key hash
                        if received_hash == expected_key_hash:
                            log_debug(f"Key hash MATCH! Sender identified: {s_ip}:{s_port}")
                            print(f"\n[DISCOVERY] Sender found via broadcast: {s_ip}:{s_port}")
                            sender_ip = s_ip
                            sender_port = s_port # This is the sender's TCP port

                            # Send reply back to the sender
                            reply_payload = {
                                "type": "crypticroute_reply",
                                "key_hash": expected_key_hash,
                                "receiver_port": my_tcp_port # Our TCP port
                            }
                            reply_data = json.dumps(reply_payload).encode('utf-8')

                            log_debug(f"Sending UDP reply to {sender_ip}:{sender_port}: {reply_payload}")
                            # Send reply directly back to the sender's address and *its* port
                            udp_socket.sendto(reply_data, (sender_ip, sender_port))
                            print(f"[DISCOVERY] Sent confirmation reply back to sender.")

                            # Discovery successful
                            return sender_ip, sender_port

                        else:
                            log_debug(f"Key hash mismatch: Expected {expected_key_hash}, Got {received_hash}. Ignoring.")
                            print(f"[DISCOVERY] Received broadcast from {s_ip} with non-matching key hash. Ignoring.")

                    else:
                        log_debug("UDP packet ignored: Invalid format or type.")

                except json.JSONDecodeError:
                    log_debug(f"UDP packet ignored: Not valid JSON.")
                except UnicodeDecodeError:
                    log_debug(f"UDP packet ignored: Cannot decode as UTF-8.")
                except Exception as e:
                     log_debug(f"Error processing UDP packet: {e}")


            except socket.timeout:
                log_debug(f"UDP discovery timeout after {discovery_timeout} seconds.")
                print(f"\n[DISCOVERY] No valid sender broadcast received within {discovery_timeout} seconds.")
                return None, None # Indicate timeout/failure

            # We only loop if we ignored a packet; success returns, timeout returns

    except OSError as e:
        log_debug(f"UDP Socket Error: {e}. Check port {DISCOVERY_PORT} availability and permissions.")
        print(f"[ERROR] UDP Socket Error: {e}. Cannot listen for broadcasts.")
        return None, None
    except Exception as e:
        log_debug(f"Unexpected error during UDP discovery: {e}")
        print(f"[ERROR] Unexpected error during UDP discovery: {e}")
        return None, None
    finally:
        if udp_socket:
            udp_socket.close()
            log_debug("UDP discovery socket closed.")


def receive_file(output_path, key, interface=None, timeout=120):
    """Receive a file via steganography after discovering sender."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time, highest_seq_num
    global packet_counter, valid_packet_counter, connection_established
    global sender_ip, sender_port # These are now set by discovery

    # Note: sender_ip and sender_port should be populated by listen_for_sender before calling this

    if not sender_ip or not sender_port:
         log_debug("receive_file called without discovered sender IP/Port. Aborting.")
         print("[ERROR] Sender IP and Port not discovered. Cannot proceed.")
         return False

    log_debug(f"Proceeding with reception from sender: {sender_ip}:{sender_port}")
    print(f"[INFO] Starting TCP reception phase with sender: {sender_ip}:{sender_port}")


    # Create a summary file with reception parameters
    summary = {
        "timestamp_start": time.time(),
        "output_path": output_path,
        # Key path is not available here, but we have the key itself
        # "key_path": key_path, # Removed
        "key_hash": calculate_key_hash(key), # Log hash instead
        "interface": interface, # Still relevant for Scapy sniff
        "timeout_inactivity": timeout,
        "discovered_sender_ip": sender_ip,
        "discovered_sender_port": sender_port,
        "receiver_tcp_port": my_tcp_port
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    # Reset global variables for the TCP phase
    received_chunks = {}
    transmission_complete = False
    reception_start_time = 0
    last_activity_time = time.time()
    highest_seq_num = 0
    packet_counter = 0
    valid_packet_counter = 0
    connection_established = False
    ack_sent_chunks.clear() # Clear previously sent ACKs if any


    # Create steganography receiver - Pass the chosen TCP port
    stego = SteganographyReceiver(my_tcp_port)

    # Key is already prepared and passed in

    # Start monitoring thread
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(
        target=monitor_transmission,
        args=(stop_monitor, timeout)
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    log_debug("Started inactivity monitor thread")

    # Start packet capture
    log_debug(f"Listening for TCP data on interface {interface or 'default'} from {sender_ip}...")
    print(f"Listening for TCP data on interface {interface or 'default'} from {sender_ip}...")
    print("Press Ctrl+C to stop listening")

    try:
        # Use a filter for TCP packets potentially from the sender
        # We filter more specifically in the handler now, but this can help Scapy
        filter_str = f"tcp and host {sender_ip}" # Filter by sender IP
        if sender_port:
            # Can't easily filter *source* port reliably here if sender uses random dest ports for data
            # But we can filter for packets destined *to* our listening port for handshake/acks
             filter_str += f" and (dst port {my_tcp_port} or src port {sender_port})" # Handshake/ACKs or Data
        log_debug(f"Using Scapy filter: {filter_str}")

        # Start packet sniffing - use packet_handler wrapper to avoid printing return values
        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.packet_handler,  # Use the wrapper function
            store=0,
            stop_filter=lambda p: transmission_complete or stop_monitor.is_set() # Add monitor stop condition
        )
        log_debug("Scapy sniff loop finished.")

    except KeyboardInterrupt:
        log_debug("\nReceiving stopped by user (Ctrl+C)")
        print("\nReceiving stopped by user")
        transmission_complete = True # Treat as completed to proceed with processing
    except Exception as e:
         log_debug(f"\nError during packet sniffing: {e}")
         print(f"\nError during packet sniffing: {e}")
         transmission_complete = True # Try processing what we have
    finally:
        stop_monitor.set()  # Signal monitor thread to stop
        monitor_thread.join(1.0) # Wait briefly for monitor thread
        log_debug("Stopped inactivity monitor thread")


    # ---- Post-Reception Processing ----

    # Check if we received any data
    if not received_chunks:
        log_debug("No data chunks received during TCP phase")
        print("No data chunks received")
        # Save completion info
        completion_info = {
            "completed_at": time.time(),
            "status": "failed",
            "reason": "no_data_chunks",
            "total_packets_processed": packet_counter,
            "valid_stego_packets": valid_packet_counter,
        }
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
        return False

    # Calculate reception statistics
    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)

    # Prepare reception statistics
    missing_count = (highest_seq_num - chunk_count) if highest_seq_num > chunk_count else 0
    reception_rate = (chunk_count / highest_seq_num * 100) if highest_seq_num > 0 else (100 if chunk_count > 0 else 0)

    stats = {
        "total_packets_processed": packet_counter,
        "valid_stego_packets": valid_packet_counter,
        "chunks_received_count": chunk_count,
        "highest_seq_num_received": highest_seq_num,
        "duration_seconds": duration,
        "reception_rate_percent": reception_rate,
        "missing_chunks_estimated": missing_count,
        "transmission_complete_signal_received": transmission_complete # Check if FIN was received
    }

    stats_file = os.path.join(LOGS_DIR, "reception_stats.json")
    with open(stats_file, "w") as f:
        json.dump(stats, f, indent=2)

    log_debug(f"\nReception summary:")
    log_debug(f"- Processed {packet_counter} packets total")
    log_debug(f"- Identified {valid_packet_counter} valid steganography packets")
    log_debug(f"- Received {chunk_count} unique data chunks in {duration:.2f} seconds")
    log_debug(f"- Highest sequence number seen: {highest_seq_num}")
    log_debug(f"- Estimated packet reception rate: {reception_rate:.1f}%")
    log_debug(f"- Estimated missing chunks: {missing_count}")

    print(f"\nReception summary:")
    print(f"- Processed {packet_counter} packets total")
    print(f"- Identified {valid_packet_counter} valid steganography packets")
    print(f"- Received {chunk_count} unique data chunks in {duration:.2f} seconds")
    print(f"- Highest sequence number seen: {highest_seq_num}")
    print(f"- Estimated packet reception rate: {reception_rate:.1f}%")
    print(f"- Estimated missing chunks: {missing_count}")


    # Reassemble the data
    log_debug("Reassembling data...")
    print("[REASSEMBLY] Starting data reassembly process...")
    reassembled_data = reassemble_data()

    if not reassembled_data:
        log_debug("Failed to reassemble data (no chunks or error).")
        print("[REASSEMBLY] Failed to reassemble data.")
        completion_info = {
            "completed_at": time.time(),
            "status": "failed",
            "reason": "reassembly_failed"
        }
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
        return False

    log_debug(f"Reassembled {len(reassembled_data)} bytes of raw data")
    print(f"[REASSEMBLY] Successfully reassembled {len(reassembled_data)} bytes of raw data")

    # Verify data integrity (using MD5 checksum appended by sender)
    print("[VERIFY] Verifying data integrity using appended checksum...")
    verified_data, checksum_match = verify_data_integrity(reassembled_data)

    if verified_data is None: # This happens if data too short for checksum
         log_debug("Integrity check skipped: Reassembled data too short.")
         print("[VERIFY] Skipped: Reassembled data too short for checksum.")
         # Use the raw reassembled data, maybe log a warning
         verified_data = reassembled_data # Fallback to raw data
         checksum_match = False # Mark as failed
    elif not checksum_match:
        log_debug("Warning: Using data despite checksum mismatch.")
        print("[VERIFY] Warning: Checksum verification failed! Data might be corrupt.")
        # Proceeding with the data portion anyway
    else:
        log_debug(f"Integrity verified. Data size after removing checksum: {len(verified_data)} bytes.")
        print(f"[VERIFY] Data integrity verified successfully ({len(verified_data)} bytes)")


    # Decrypt the data (key was already prepared)
    log_debug("Decrypting data...")
    print("[DECRYPT] Starting decryption process...")

    final_data = None
    decryption_status = "failed"

    if len(verified_data) >= 16: # Need at least IV size
        print(f"[DECRYPT] Attempting to decrypt {len(verified_data)} bytes...")
        decrypted_data_attempt = decrypt_data(verified_data, key)

        if decrypted_data_attempt is not None:
            log_debug(f"Successfully decrypted {len(decrypted_data_attempt)} bytes")
            print(f"[DECRYPT] Successfully decrypted {len(decrypted_data_attempt)} bytes")
            final_data = decrypted_data_attempt
            decryption_status = "success"

            # Try to detect text data
            try:
                sample_text = final_data[:100].decode('utf-8')
                log_debug(f"Sample of decrypted text: {sample_text}")
                print(f"[DECRYPT] Sample of decrypted text: {sample_text[:30]}...")
            except UnicodeDecodeError:
                log_debug("Decrypted data is not text/UTF-8")
                print("[DECRYPT] Decrypted data does not appear to be UTF-8 text")

        else:
            log_debug("Decryption failed. Output will be the raw (verified/unverified) data.")
            print("[DECRYPT] Failed! Saving raw data (before decryption attempt) instead.")
            final_data = verified_data # Save the data before decryption attempt
            # Status remains "failed"

    else:
        log_debug("Decryption skipped: Data too short (less than 16 bytes).")
        print("[DECRYPT] Skipped: Data too short for decryption (missing IV).")
        final_data = verified_data # Use the verified (or unverified) data
        decryption_status = "skipped_too_short"

    # Save the final data (either decrypted or the raw verified data)
    print(f"[SAVE] Saving final data ({len(final_data)} bytes) to {output_path}...")
    save_success = save_to_file(final_data, output_path)

    if save_success:
        print(f"[SAVE] File saved successfully")
    else:
        print(f"[SAVE] Error saving file")


    # Save final completion info
    final_status = "completed"
    if missing_count > 0:
        final_status = "partial_missing_chunks"
    if not checksum_match:
        final_status += "_checksum_mismatch"
    if decryption_status != "success":
         final_status += f"_decryption_{decryption_status}"
    if not save_success:
         final_status = "failed_save"


    completion_info = {
        "completed_at": time.time(),
        "status": final_status,
        "bytes_saved": len(final_data) if final_data else 0,
        "checksum_match": checksum_match,
        "decryption_status": decryption_status,
        "save_status": "success" if save_success else "failed"
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f:
        json.dump(completion_info, f, indent=2)

    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    print(f"[INFO] Final status: {final_status}")

    # Return True if saving was successful, even if data incomplete/corrupt
    return save_success


def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity and completion."""
    global last_activity_time, transmission_complete

    log_debug(f"Inactivity monitor started (timeout={timeout}s)")
    start_time = time.time()
    while not stop_event.wait(1.0): # Check every second
        if transmission_complete: # Check global flag set by FIN packet
            log_debug("Monitor: Transmission complete signal received.")
            break

        # Check for inactivity timeout
        inactive_time = time.time() - last_activity_time
        if inactive_time > timeout:
            log_debug(f"Monitor: Inactivity timeout reached ({inactive_time:.1f}s > {timeout}s)")
            print(f"\n[TIMEOUT] Inactivity timeout reached ({timeout} seconds). Stopping reception.")
            transmission_complete = True # Signal main thread to stop sniffing
            stop_event.set() # Ensure sniff stops if it hasn't already
            break

    log_debug(f"Inactivity monitor stopped after {time.time() - start_time:.1f}s.")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Simplified Network Steganography Receiver')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption key file (must match sender)') # Made required
    parser.add_argument('--interface', '-i', help='Network interface to listen on (for Scapy)')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity timeout in seconds (default: 120)')
    parser.add_argument('--discovery-timeout', type=int, default=600, help='Timeout for UDP discovery in seconds (default: 600)')
    parser.add_argument('--output-dir', '-d', help='Custom base directory for session outputs')
    return parser.parse_args()

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()

    # Setup output directory structure
    global OUTPUT_DIR
    if args.output_dir:
        OUTPUT_DIR = args.output_dir
    setup_directories() # Call this early to ensure log file exists

    # Log arguments
    log_debug("Receiver started with arguments:")
    for arg, value in vars(args).items():
        log_debug(f"  --{arg}: {value}")


    # Prepare decryption key and calculate hash
    key = None
    key_hash = None
    log_debug(f"Reading key file from: {args.key}")
    print(f"Reading key from: {args.key}")
    try:
        with open(args.key, 'rb') as key_file:
            key_data = key_file.read()
        key = prepare_key(key_data) # Prepare key (e.g., ensure 32 bytes)
        key_hash = calculate_key_hash(key) # Calculate hash AFTER preparation
        log_debug(f"Calculated key hash ({KEY_HASH_ALGO}): {key_hash}")
        print(f"Key loaded successfully. Hash ({KEY_HASH_ALGO}): {key_hash[:8]}...")
    except Exception as e:
        log_debug(f"Fatal Error reading or preparing key file: {e}")
        print(f"Fatal Error reading or preparing key file: {e}")
        sys.exit(1)


    # Choose a random TCP port for this session
    # Do this *before* discovery so we can send it in the reply
    receiver_tcp_port = random.randint(10000, 60000)
    log_debug(f"Chosen receiver TCP port for this session: {receiver_tcp_port}")


    # --- UDP Discovery Phase ---
    discovered_ip, discovered_port = listen_for_sender(key_hash, receiver_tcp_port, args.discovery_timeout)

    if not discovered_ip:
        log_debug("Sender discovery failed. Exiting.")
        print("[FAIL] Could not discover sender. Exiting.")
        sys.exit(1)
    else:
        log_debug(f"Discovery successful. Sender: {discovered_ip}:{discovered_port}")
        print(f"[SUCCESS] Sender located at {discovered_ip}:{discovered_port}")
        # Globals sender_ip and sender_port are set within listen_for_sender

    # --- TCP Reception Phase ---
    success = receive_file(
        args.output,
        key, # Pass the prepared key bytes
        args.interface,
        args.timeout
    )

    # Exit with appropriate status
    log_debug(f"Receiver finished. Success status: {success}")
    print(f"\nReceiver finished. {'File potentially saved.' if success else 'Operation failed or incomplete.'}")
    sys.exit(0 if success else 1) # Exit 0 if save worked, 1 otherwise

if __name__ == "__main__":
    main()