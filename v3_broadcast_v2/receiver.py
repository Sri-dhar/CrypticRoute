

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
sender_port = None        # Will be discovered (Sender's TCP port for ACKs)
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
        global sender_ip, sender_port # Use discovered sender info

        if not sender_ip or not sender_port:
            log_debug("Cannot create ACK - sender information missing")
            return None

        # Create an ACK packet with special markers, target the discovered sender port
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, # Our TCP listener port
            dport=sender_port, # Sender's TCP port (discovered)
            seq=0x12345678,  # Fixed pattern to identify this as an ACK
            ack=seq_num,     # Use the ack field to specify which chunk we're acknowledging
            window=0xCAFE,   # Special window value for ACKs
            flags="A"        # ACK flag
        )
        log_debug(f"Created ACK packet for chunk {seq_num} -> {sender_ip}:{sender_port}")
        return ack_packet

    def send_ack(self, seq_num):
        """Send an acknowledgment for a specific sequence number."""
        global ack_sent_chunks

        # Skip if we've already ACKed this chunk
        if seq_num in ack_sent_chunks:
            log_debug(f"Skipping ACK send for chunk {seq_num} (already sent)")
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
        global sender_ip, sender_port # Use discovered sender info

        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender information missing")
            return None

        # Create a SYN-ACK packet with special markers, target the discovered sender port
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, # Our TCP listener port
            dport=sender_port, # Sender's TCP port (discovered)
            seq=0xABCDEF12,  # Fixed pattern for SYN-ACK
            ack=0x12345678,  # Fixed pattern to acknowledge SYN (matches sender's SYN seq)
            window=0xBEEF,   # Special window value for handshake
            flags="SA"       # SYN-ACK flags
        )
        log_debug(f"Created SYN-ACK packet -> {sender_ip}:{sender_port}")
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
        global packet_counter, sender_ip # Need sender_ip for filtering

        # Increment packet counter
        packet_counter += 1

        # Filter packets not from the discovered sender IP
        # This is a first layer filter; more specific checks happen in process_packet
        if sender_ip and packet.haslayer(IP) and packet[IP].src != sender_ip:
             # Only log occasionally to avoid flooding the log/console
            if packet_counter % 100 == 0:
                log_debug(f"Packet #{packet_counter} ignored (source {packet[IP].src} != discovered sender {sender_ip})")
            return None # Ignore packet from other IPs

        # Print status for every Nth packet to reduce console noise
        if packet_counter <= 10 or packet_counter % 20 == 0: # Print less often
            chunk_count = len(received_chunks)
            valid_ratio = f"{valid_packet_counter}/{packet_counter}" if packet_counter > 0 else "0/0"
            # Add connection status indication
            conn_status = "ESTABLISHED" if connection_established else "WAITING"
            print(f"[PACKET] #{packet_counter:06d} | Chunks: {chunk_count:04d} | Valid: {valid_ratio} | Conn: {conn_status}")

        # Call the actual processing function but don't return its value
        # process_packet will return True/False indicating if it was relevant, but we ignore it here
        self.process_packet(packet)

        # Always return None to prevent Scapy from printing packet summaries
        return None

    def process_packet(self, packet):
        """Process a packet to extract steganographic data."""
        global received_chunks, transmission_complete, reception_start_time
        global last_activity_time, highest_seq_num, valid_packet_counter
        global connection_established, sender_ip, sender_port # sender_ip/port are now discovered

        # Update last activity time whenever we process a packet potentially from sender
        last_activity_time = time.time()

        # Check if it's a valid TCP packet FROM the discovered sender IP
        # The packet_handler wrapper already filtered by IP source
        if TCP in packet:
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            window = packet[TCP].window
            seq = packet[TCP].seq
            ack = packet[TCP].ack

            # Log the packet details for debugging potential issues
            # Log less frequently to avoid overwhelming logs
            # if packet_counter % 10 == 0:
            #     log_debug(f"Processing TCP packet from {src_ip}:{src_port} -> {my_tcp_port}, Flags={flags}, Win={window}, Seq={seq}, Ack={ack}")


            # Check if the packet is destined for our chosen TCP listening port
            if dst_port != self.my_port:
                 # This packet might be using a random destination port (sender's data packets)
                 # Or it could be unrelated traffic. We need to check content.
                 # Log occasionally if it looks like data but isn't for our port
                 if flags.S and window > 0 and window < 65530 and packet_counter % 50 == 0:
                     log_debug(f"Received packet for wrong Dst Port {dst_port} (expected {self.my_port}). Flags={flags}, Win={window}. Might be data?")
                 # Allow processing based on content below, but be stricter.
                 pass # Don't immediately return False, let content checks proceed

            # --- Handshake Packet Checks ---
            # These MUST be destined for our listening port (my_tcp_port)

            # Check for connection establishment request (SYN packet with special window value)
            # This SYN should come from the discovered sender_ip and sender_port
            if (not connection_established and
                    flags.S and not flags.A and # SYN flag only
                    window == 0xDEAD and
                    src_port == sender_port and # Must come from discovered sender TCP port
                    dst_port == self.my_port):  # Must be for our listening port
                log_debug(f"Received connection establishment request (SYN) from {src_ip}:{src_port} (Seq={seq})")
                print(f"\n[HANDSHAKE] Received connection request (SYN) from {src_ip}:{src_port}")

                # Send SYN-ACK response
                self.send_syn_ack()
                return True # Handled handshake packet

            # Check for connection confirmation (ACK packet with special window value)
            # This ACK should come from the discovered sender_ip and sender_port
            if (not connection_established and
                    flags.A and not flags.S and # ACK flag only
                    window == 0xF00D and
                    ack == 0xABCDEF12 and # Must acknowledge our SYN-ACK sequence number
                    src_port == sender_port and # Must come from discovered sender TCP port
                    dst_port == self.my_port):  # Must be for our listening port
                log_debug(f"Received connection confirmation (ACK) from {src_ip}:{src_port} (Seq={seq}, Ack={ack})")
                print("[HANDSHAKE] Connection established with sender")
                connection_established = True
                # Record start time more accurately when connection is fully established
                if reception_start_time == 0:
                    reception_start_time = time.time()
                    log_debug(f"[START] Connection established, starting reception timer.")
                    print(f"[START] Connection established, starting reception timer.")
                return True # Handled handshake packet

            # --- Data/Completion Packet Checks ---

            # Check for completion signal (FIN/ACK flag and special window value)
            # This *should* also come from the sender_port and to our my_tcp_port
            if (flags.F and flags.A and # FIN and ACK flags set
                    window == 0xFFFF and
                    src_port == sender_port and # Check source port
                    dst_port == self.my_port):  # Check destination port
                log_debug(f"Received transmission complete signal (FIN/ACK) from {src_ip}:{src_port}")
                print("\n[COMPLETE] Received transmission complete signal")
                transmission_complete = True
                return True # Handled completion packet

            # Only process potential data packets if connection is established
            if not connection_established:
                # Log unexpected packets before connection established occasionally
                if packet_counter % 50 == 0: # Log occasionally
                     log_debug(f"Ignoring packet from {src_ip}:{src_port} before connection established. Flags={flags}, Win={window}")
                return False

            # --- Potential Data Packet Processing ---
            # Data packets use SYN flag and random dest port in this scheme
            # We already know src_ip == sender_ip from packet_handler filter

            # Check for SYN flag (used for data packets) and non-zero window
            # Window field contains the sequence number (should be > 0)
            # Ignore packets with window 0 or obviously wrong values like handshake/completion markers
            if flags.S and window > 0 and window != 0xDEAD and window != 0xFFFF and window != 0xCAFE and window != 0xBEEF and window != 0xF00D:

                # Extract sequence number from window field
                seq_num = window

                # Extract total chunks from MSS option
                total_chunks = None
                if packet[TCP].options: # Check if options exist
                    for option_kind, option_value in packet[TCP].options:
                        # Scapy parses MSS option as ('MSS', value)
                        if option_kind == 'MSS':
                            total_chunks = option_value
                            break # Found MSS

                # If no MSS option, it's unlikely to be our data packet
                if total_chunks is None:
                     # Log occasionally if flags indicate data potential
                     if packet_counter % 50 == 0:
                         log_debug(f"Packet from {sender_ip}:{src_port} looks like data (SYN flag, Win={seq_num}) but missing MSS option. Ignoring.")
                     return False

                # At this point, it strongly looks like a valid data packet
                valid_packet_counter += 1
                # Log less frequently to reduce noise
                if valid_packet_counter <= 5 or valid_packet_counter % 10 == 0:
                     log_debug(f"[VALID] Packet #{packet_counter} from {sender_ip}:{src_port} -> DstPort {dst_port} identified as potential stego data (Seq={seq_num}, Total={total_chunks})")
                # Don't print for every valid packet to reduce noise, use chunk receive print instead

                # Extract data from TCP sequence and acknowledge numbers
                seq_bytes = seq.to_bytes(4, byteorder='big')
                ack_bytes = ack.to_bytes(4, byteorder='big')
                data = seq_bytes + ack_bytes

                # Extract checksum from IP ID field
                checksum = packet[IP].id

                # Verify checksum embedded in IP ID
                calc_checksum = binascii.crc32(data) & 0xFFFF
                checksum_match = (checksum == calc_checksum)

                if not checksum_match:
                    log_debug(f"Warning: Checksum mismatch for chunk {seq_num}. Expected {calc_checksum}, Got {checksum}.")
                    print(f"[CHECKSUM] Warning: Mismatch for chunk {seq_num:04d}")
                    # Decide whether to discard or process despite mismatch - currently processing
                # else:
                #     # Log checksum success less often
                #     if valid_packet_counter % 20 == 0:
                #          log_debug(f"[CHECKSUM] Valid for chunk {seq_num:04d}")
                #     # print(f"[CHECKSUM] Valid for chunk {seq_num:04d}") # Reduced verbosity

                # Skip if we already have this chunk
                if seq_num in received_chunks:
                    log_debug(f"[DUPLICATE] Chunk {seq_num:04d} already received. Sending ACK again.")
                    print(f"[DUPLICATE] Chunk {seq_num:04d} already received, skipping storage.")
                    # Still send an ACK since the sender probably didn't receive our previous ACK
                    self.send_ack(seq_num)
                    return True # Still counts as processed relevant packet

                # If this is the first *data* chunk, record start time (if not already set by handshake ACK)
                if reception_start_time == 0:
                    reception_start_time = time.time()
                    log_debug(f"[START] First data chunk {seq_num} received, starting timer (handshake ACK missed?).")
                    print(f"[START] First data chunk received, starting timer.")

                # Store the chunk
                log_debug(f"Received chunk {seq_num} (size: {len(data)} bytes)")
                received_chunks[seq_num] = data

                # Log the chunk data to files
                self.log_chunk(seq_num, data)

                # Send acknowledgment for this chunk
                self.send_ack(seq_num)

                # Update highest sequence number seen
                if seq_num > highest_seq_num:
                    highest_seq_num = seq_num
                    # Log progress less often
                    if highest_seq_num % 10 == 0 or highest_seq_num == 1:
                        log_debug(f"[PROGRESS] New highest sequence: {highest_seq_num:04d}")
                    # print(f"[PROGRESS] New highest sequence: {highest_seq_num:04d}") # Reduced verbosity

                # Print detailed information for every received chunk
                if total_chunks:
                    progress = (len(received_chunks) / total_chunks) * 100 if total_chunks > 0 else 0
                    print(f"[CHUNK] Received: {seq_num:04d}/{total_chunks:04d} | Total Stored: {len(received_chunks):04d}/{total_chunks:04d} | Progress: {progress:.2f}%")
                else:
                    # Fallback if total_chunks somehow becomes None (shouldn't happen)
                    print(f"[CHUNK] Received: {seq_num:04d} | Total stored: {len(received_chunks):04d}")

                return True # Indicate a valid data chunk was processed

        # Log ignored packets occasionally if they came from the sender IP but weren't handled
        elif packet_counter % 100 == 0:
             proto = packet.sprintf("%IP.proto%")
             log_debug(f"Ignored packet #{packet_counter} from sender {sender_ip} (Proto: {proto}, DstPort: {packet.dport if TCP in packet or UDP in packet else 'N/A'}) - Didn't match expected patterns.")

        return False # Packet was not processed as relevant stego traffic


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
         print("Exiting due to invalid key length.")
         sys.exit(1)


    log_debug(f"Final prepared key (hex): {key_data.hex()}")

    # Save prepared key for debugging
    key_file = os.path.join(DATA_DIR, "prepared_key.bin")
    with open(key_file, "wb") as f:
        f.write(key_data)

    return key_data

def decrypt_data(data, key):
    """Decrypt data using AES."""
    try:
        # Check if data is long enough to contain the IV
        if len(data) < 16: # AES IV size is 16 bytes
            log_debug("Error: Encrypted data is too short (less than 16 bytes for IV)")
            print("[DECRYPT] Error: Encrypted data is too short (missing IV)")
            return None

        # Extract IV from the beginning of the data
        iv = data[:16]
        encrypted_data = data[16:]

        log_debug(f"Extracted IV: {iv.hex()}")
        log_debug(f"Encrypted data size for decryption: {len(encrypted_data)} bytes")

        # Save components for debugging
        iv_file = os.path.join(DATA_DIR, "extracted_iv.bin")
        with open(iv_file, "wb") as f:
            f.write(iv)

        encrypted_file = os.path.join(DATA_DIR, "encrypted_data_for_decryption.bin")
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

        log_debug(f"Decryption successful. Output size: {len(decrypted_data)} bytes")
        log_debug(f"Decrypted data head (hex): {decrypted_data[:32].hex()}...")

        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"[DECRYPT] Error during decryption: {e}")
        return None

def verify_data_integrity(data):
    """Verify the integrity of reassembled data using MD5 checksum."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        log_debug("Error: Data too short to contain integrity checksum")
        print("[VERIFY] Error: Data too short to contain integrity checksum")
        return None, False # Return None for data, False for match status

    # Extract the data and checksum
    payload_data = data[:-INTEGRITY_CHECK_SIZE] # This is the (IV + encrypted_data) part
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]

    log_debug(f"Verifying integrity. Data part size: {len(payload_data)}, Checksum size: {len(received_checksum)}")

    # Save components for debugging
    data_file = os.path.join(DATA_DIR, "data_before_checksum_verification.bin")
    with open(data_file, "wb") as f:
        f.write(payload_data)

    checksum_file = os.path.join(DATA_DIR, "received_checksum.bin")
    with open(checksum_file, "wb") as f:
        f.write(received_checksum)

    # Calculate checksum of the extracted data part
    calculated_checksum = hashlib.md5(payload_data).digest()
    log_debug(f"Calculated MD5 checksum: {calculated_checksum.hex()}")
    log_debug(f"Received MD5 checksum:  {received_checksum.hex()}")


    # Save the calculated checksum
    calc_checksum_file = os.path.join(DATA_DIR, "calculated_checksum.bin")
    with open(calc_checksum_file, "wb") as f:
        f.write(calculated_checksum)

    # Compare checksums
    checksum_match = (calculated_checksum == received_checksum)

    # Save checksum comparison results
    checksum_info = {
        "expected_checksum": calculated_checksum.hex(),
        "received_checksum": received_checksum.hex(),
        "checksum_match": checksum_match
    }
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")
    with open(checksum_json, "w") as f:
        json.dump(checksum_info, f, indent=2)
    log_debug(f"Checksum verification result saved to {checksum_json}")

    if not checksum_match:
        log_debug("Warning: Data integrity check failed - checksums don't match!")
        print("[VERIFY] Warning: Data integrity check failed - checksums don't match!")
        print(f"  Expected: {calculated_checksum.hex()}")
        print(f"  Received: {received_checksum.hex()}")
    else:
        log_debug("Data integrity verified successfully")
        print("[VERIFY] Data integrity verified successfully")

    # Return the data *without* the checksum, and the match status
    # This payload_data is what needs decryption (contains IV + encrypted)
    return payload_data, checksum_match


def reassemble_data():
    """Reassemble the received chunks in correct order."""
    global received_chunks, highest_seq_num

    if not received_chunks:
        log_debug("Reassembly called with no chunks received.")
        print("[REASSEMBLY] Error: No data chunks were received.")
        return None

    # Determine the highest sequence number we should have received
    # If transmission wasn't marked complete, highest_seq_num might be the best guess.
    # If it was complete, highest_seq_num should ideally be the total number of chunks.
    # Note: total_chunks extracted from MSS might be more reliable if available consistently.
    # Using highest_seq_num seen as the target for checking missing chunks.
    total_expected_chunks = highest_seq_num # Best guess for now
    log_debug(f"[REASSEMBLY] Reassembling based on highest seen sequence number: {total_expected_chunks}")


    # Sort chunks by sequence number
    print(f"[REASSEMBLY] Sorting {len(received_chunks)} received chunks by sequence number...")
    sorted_seq_nums = sorted(received_chunks.keys())

    if not sorted_seq_nums:
         log_debug("No sequence numbers found in received chunks map.")
         print("[REASSEMBLY] Error: No valid sequence numbers found.")
         return None

    # Check for missing chunks up to the highest number received
    expected_seq = 1  # Assume chunks start from 1
    missing_chunks = []
    last_received_seq = 0
    if sorted_seq_nums:
        last_received_seq = sorted_seq_nums[-1]


    print("[REASSEMBLY] Checking for missing chunks...")
    current_expected = 1
    for seq_num in sorted_seq_nums:
        if seq_num < current_expected:
            log_debug(f"[REASSEMBLY] Warning: Received out-of-order or duplicate chunk number {seq_num} (expected >= {current_expected}). Ignoring for gap check.")
            continue # Skip duplicates or unexpected lowers for gap calculation

        if seq_num > current_expected:
            # Found a gap
            missing = list(range(current_expected, seq_num))
            missing_chunks.extend(missing)
            log_debug(f"[REASSEMBLY] Detected missing chunks in gap: {missing}")

        current_expected = seq_num + 1 # Next expected chunk

    # Check for chunks missing at the end, up to highest_seq_num observed
    # If the highest chunk received is less than the highest sequence number ever seen
    # (e.g. highest was 100, but last chunk in sorted list is 98)
    if total_expected_chunks > last_received_seq:
         missing_at_end = list(range(last_received_seq + 1, total_expected_chunks + 1))
         if missing_at_end:
              missing_chunks.extend(missing_at_end)
              log_debug(f"[REASSEMBLY] Detected missing chunks at the end: {missing_at_end}")


    if missing_chunks:
        log_debug(f"[REASSEMBLY] Warning: Missing {len(missing_chunks)} chunks in total.")
        print(f"[REASSEMBLY] Warning: Detected {len(missing_chunks)} missing chunks!")
        # Print summary of missing chunks
        if len(missing_chunks) <= 20:
            print(f"[REASSEMBLY]   Missing Sequence Numbers: {missing_chunks}")
            log_debug(f"[REASSEMBLY] Missing Sequence Numbers: {missing_chunks}")
        else:
            print(f"[REASSEMBLY]   First 10 missing: {missing_chunks[:10]}...")
            print(f"[REASSEMBLY]   Last 10 missing: {missing_chunks[-10:]}")
            log_debug(f"[REASSEMBLY] Missing chunks preview: {missing_chunks[:10]}...{missing_chunks[-10:]}")


    # Save diagnostic information about reassembly
    print("[REASSEMBLY] Saving reassembly diagnostic information...")
    reassembly_info = {
        "received_chunks_count": len(received_chunks),
        "highest_seq_num_received": last_received_seq, # Highest number actually stored
        "highest_seq_num_observed": highest_seq_num, # Highest number seen in any packet window
        "inferred_total_chunks": total_expected_chunks, # Based on highest observed
        "missing_chunks_count": len(missing_chunks),
        "missing_chunks_list_preview": missing_chunks[:50] + (["..."] if len(missing_chunks) > 50 else []),
        "received_seq_nums_sorted": sorted_seq_nums
    }
    reassembly_file = os.path.join(LOGS_DIR, "reassembly_info.json")
    with open(reassembly_file, "w") as f:
        json.dump(reassembly_info, f, indent=2)
    log_debug(f"Reassembly info saved to {reassembly_file}")


    # Get chunks in order based on sorted sequence numbers
    print("[REASSEMBLY] Concatenating received chunks in sequence order...")
    # Ensure we only use chunks that were actually received
    sorted_chunks_data = [received_chunks[seq] for seq in sorted_seq_nums]

    # Concatenate chunks WITHOUT stripping padding here.
    # Padding is part of the fixed 8-byte chunk structure.
    # Decryption and checksum verification happen *after* reassembly.
    # The checksum is calculated on the original (IV + encrypted data) block,
    # which includes any padding inherent in the chunking process before checksum addition.
    reassembled_data = b"".join(sorted_chunks_data)
    log_debug(f"[REASSEMBLY] Concatenated {len(sorted_chunks_data)} chunks into {len(reassembled_data)} bytes.")


    # Save the raw reassembled data (before any potential cleaning/stripping)
    raw_reassembled_file = os.path.join(DATA_DIR, "reassembled_raw_concatenated.bin")
    with open(raw_reassembled_file, "wb") as f:
        f.write(reassembled_data)
    log_debug(f"Saved raw concatenated data ({len(reassembled_data)} bytes) to {raw_reassembled_file}")

    print(f"[REASSEMBLY] Completed concatenation! Total raw size: {len(reassembled_data)} bytes")
    return reassembled_data


def save_to_file(data, output_path):
    """Save data to a file."""
    try:
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
            log_debug(f"Created output directory: {output_dir}")

        with open(output_path, 'wb') as file:
            file.write(data)
        log_debug(f"Final data ({len(data)} bytes) saved successfully to {output_path}")
        print(f"Data saved successfully to: {output_path}")

        # Copy to the session's data directory as well for archival
        output_name = os.path.basename(output_path)
        # Sanitize name slightly for session copy
        safe_output_name = "".join(c for c in output_name if c.isalnum() or c in ('-', '_', '.'))
        output_copy = os.path.join(DATA_DIR, f"final_output_{safe_output_name}")
        try:
            with open(output_copy, "wb") as f:
                f.write(data)
            log_debug(f"Copied final output to session data directory: {output_copy}")
        except Exception as copy_e:
            log_debug(f"Warning: Could not copy final output to session dir: {copy_e}")


        # Try to log/print the content as UTF-8 text for convenience
        try:
            # Limit preview length to avoid overwhelming console/logs
            preview_len = 500
            text_content = data[:preview_len].decode('utf-8')
            suffix = "..." if len(data) > preview_len else ""
            log_debug(f"Saved content preview (UTF-8): {text_content}{suffix}")
            print(f"Saved content preview:\n---\n{text_content}{suffix}\n---")

            # Save a text preview file in the session logs for easy viewing
            text_file = os.path.join(LOGS_DIR, "output_content_preview.txt")
            with open(text_file, "w", encoding='utf-8', errors='replace') as f:
                # Write the whole content, replacing errors for the preview file
                f.write(data.decode('utf-8', errors='replace'))
            log_debug(f"Saved full content preview (UTF-8 decoded with replacements) to {text_file}")

        except UnicodeDecodeError:
            log_debug("Saved content is not valid UTF-8 text (likely binary data).")
            print("Saved content appears to be binary data (not valid UTF-8).")
            # Save a hex dump preview instead
            hex_preview = data[:64].hex()
            hex_file = os.path.join(LOGS_DIR, "output_content_preview.hex")
            with open(hex_file, "w") as f:
                 f.write(hex_preview + ("..." if len(data) > 64 else ""))
            log_debug(f"Saved hex preview to {hex_file}")


        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"[ERROR] Failed to save data to {output_path}: {e}")
        return False

def listen_for_sender(expected_key_hash, my_tcp_port, discovery_timeout=600):
    """Listen for sender's broadcast UDP packet and reply."""
    global sender_ip, sender_port # These will be set on success

    log_debug(f"[DISCOVERY] Starting UDP discovery listener...")
    log_debug(f"[DISCOVERY]   Listening on UDP Port: {DISCOVERY_PORT}")
    log_debug(f"[DISCOVERY]   My TCP Port for Session: {my_tcp_port}")
    log_debug(f"[DISCOVERY]   Expected Key Hash: {expected_key_hash[:8]}...")
    print(f"[DISCOVERY] Listening for sender broadcast...")
    print(f"[DISCOVERY]   - Listening on UDP Port : {DISCOVERY_PORT}")
    print(f"[DISCOVERY]   - My Session TCP Port : {my_tcp_port}")
    print(f"[DISCOVERY]   - Matching Key Hash   : {expected_key_hash[:8]}...")
    print(f"[DISCOVERY]   - Timeout             : {discovery_timeout} seconds")

    udp_socket = None
    try:
        # Create UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow reuse of address
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Enable broadcasting for sending reply (though not strictly needed for listen)
        # udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind to the broadcast port on all interfaces ('')
        udp_socket.bind(("", DISCOVERY_PORT))
        log_debug(f"[DISCOVERY] UDP socket bound to ('', {DISCOVERY_PORT})")

        # Set a timeout for listening
        udp_socket.settimeout(discovery_timeout) # Overall timeout

        log_debug(f"[DISCOVERY] Waiting for UDP broadcast packet...")
        try:
            # Wait for one valid packet within the timeout
            data, addr = udp_socket.recvfrom(1024) # Buffer size 1024 bytes
            log_debug(f"[DISCOVERY] Received UDP packet from {addr}: {data}")

            # Attempt to decode JSON payload
            try:
                payload = json.loads(data.decode('utf-8'))
                log_debug(f"[DISCOVERY] Decoded JSON payload: {payload}")

                # Check for required fields and type
                if (payload.get("type") == "crypticroute_discover" and
                        "key_hash" in payload and
                        "sender_port" in payload):

                    received_hash = payload["key_hash"]
                    s_port = payload["sender_port"] # This is Sender's TCP Port
                    s_ip = addr[0] # Sender's actual IP address

                    log_debug(f"[DISCOVERY] Potential sender found: IP={s_ip}, Sender TCP Port={s_port}, Hash={received_hash}")

                    # Compare key hash
                    if received_hash == expected_key_hash:
                        log_debug(f"[DISCOVERY] Key hash MATCH! Sender identified.")
                        print(f"\n[DISCOVERY] Sender Found!")
                        print(f"[DISCOVERY]   - Sender IP: {s_ip}")
                        print(f"[DISCOVERY]   - Sender TCP Port: {s_port}")

                        # Store discovered info globally
                        sender_ip = s_ip
                        sender_port = s_port # Sender's TCP port (for ACKs)

                        # --- Send Reply ---
                        reply_payload = {
                            "type": "crypticroute_reply",
                            "key_hash": expected_key_hash,
                            "receiver_port": my_tcp_port # Include Our TCP port
                        }
                        reply_data = json.dumps(reply_payload).encode('utf-8')
                        log_debug(f"[DISCOVERY] Reply payload: {reply_payload}")

                        # Send reply directly back to the sender's address and *its specified TCP port*
                        # Use a temporary socket or the same socket? Using same socket is fine.
                        try:
                            udp_socket.sendto(reply_data, (sender_ip, sender_port))
                            log_debug(f"[DISCOVERY] Sent UDP reply back to {sender_ip}:{sender_port}")
                            print(f"[DISCOVERY] Sent confirmation reply back to sender.")
                        except Exception as send_e:
                             log_debug(f"[DISCOVERY] Error sending UDP reply: {send_e}")
                             print("[ERROR] Failed to send discovery reply to sender.")
                             # Discovery technically worked, but sender might not know. Proceed?
                             # Let's proceed, sender might broadcast again.

                        # Discovery successful
                        return sender_ip, sender_port

                    else:
                        log_debug(f"[DISCOVERY] Key hash mismatch: Expected {expected_key_hash[:8]}..., Got {received_hash[:8]}.... Ignoring packet.")
                        print(f"[DISCOVERY] Received broadcast from {s_ip} with non-matching key hash. Ignoring.")
                        # No need to return, just let timeout occur if no valid packet arrives

                else:
                    log_debug("[DISCOVERY] UDP packet ignored: Invalid format or type.")

            except json.JSONDecodeError:
                log_debug(f"[DISCOVERY] UDP packet from {addr} ignored: Not valid JSON.")
            except UnicodeDecodeError:
                log_debug(f"[DISCOVERY] UDP packet from {addr} ignored: Cannot decode as UTF-8.")
            except socket.timeout:
                # This means the overall discovery_timeout was reached
                log_debug(f"[DISCOVERY] UDP discovery timeout after {discovery_timeout} seconds.")
                print(f"\n[DISCOVERY] Failed: No valid sender broadcast received within {discovery_timeout} seconds.")
                return None, None # Indicate timeout/failure
            except Exception as e:
                 log_debug(f"[DISCOVERY] Error processing UDP packet from {addr}: {e}")
                 # Continue? No, recvfrom loop is exited on timeout or packet. Let timeout handle it.


        except socket.timeout:
             # This catch is redundant if recvfrom above has the same timeout, but safe to keep.
             log_debug(f"[DISCOVERY] UDP discovery timeout after {discovery_timeout} seconds (outer catch).")
             print(f"\n[DISCOVERY] Failed: No valid sender broadcast received within {discovery_timeout} seconds.")
             return None, None

        # If we processed a packet but it wasn't the right one (e.g., hash mismatch)
        log_debug("[DISCOVERY] Processed a packet, but it was not a valid discovery request. Timing out.")
        print(f"\n[DISCOVERY] Failed: Received packet was invalid. No valid sender found within timeout.")
        return None, None # Indicate failure

    except OSError as e:
        # Errors like "Address already in use" or "Permission denied"
        log_debug(f"[DISCOVERY] UDP Socket Error: {e}. Check port {DISCOVERY_PORT} availability and permissions.")
        print(f"[ERROR] UDP Socket Error: {e}. Cannot listen for broadcasts.")
        return None, None
    except Exception as e:
        log_debug(f"[DISCOVERY] Unexpected error during UDP discovery: {e}")
        print(f"[ERROR] Unexpected error during UDP discovery: {e}")
        return None, None
    finally:
        if udp_socket:
            udp_socket.close()
            log_debug("[DISCOVERY] UDP discovery socket closed.")


def receive_file(output_path, key, interface=None, timeout=120):
    """Receive a file via steganography after discovering sender."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time, highest_seq_num
    global packet_counter, valid_packet_counter, connection_established
    global sender_ip, sender_port, my_tcp_port # These are now set by discovery / chosen

    # Note: sender_ip and sender_port should be populated by listen_for_sender before calling this
    # Note: my_tcp_port should be chosen *before* discovery and passed to SteganographyReceiver

    if not sender_ip or not sender_port:
         log_debug("receive_file called without discovered sender IP/Port. Aborting.")
         print("[ERROR] Sender IP and Port not discovered. Cannot proceed with TCP reception.")
         return False

    if not my_tcp_port:
         log_debug("receive_file called without receiver TCP port being set. Aborting.")
         print("[ERROR] Internal error: Receiver TCP port not set.")
         return False

    log_debug(f"[RECV PHASE] Proceeding with reception from sender: {sender_ip}:{sender_port}")
    log_debug(f"[RECV PHASE] My listening TCP port: {my_tcp_port}")
    print(f"[INFO] Starting TCP reception phase...")
    print(f"[INFO]   - Expecting data from Sender: {sender_ip}:{sender_port}")
    print(f"[INFO]   - Listening on TCP Port   : {my_tcp_port}")


    # Create a summary file with reception parameters
    summary = {
        "timestamp_start_reception": time.time(),
        "output_path": output_path,
        "key_hash": calculate_key_hash(key), # Log hash of prepared key
        "interface": interface, # Still relevant for Scapy sniff
        "timeout_inactivity": timeout,
        "discovered_sender_ip": sender_ip,
        "discovered_sender_port": sender_port,
        "receiver_tcp_port": my_tcp_port
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    log_debug(f"[INFO] Session summary saved to {summary_path}")

    # Reset global variables specifically for the TCP reception phase state
    received_chunks = {}
    transmission_complete = False
    reception_start_time = 0 # Will be set on first valid data or connection ACK
    last_activity_time = time.time() # Reset inactivity timer start
    highest_seq_num = 0
    packet_counter = 0
    valid_packet_counter = 0
    connection_established = False
    ack_sent_chunks.clear() # Clear previously sent ACKs if any


    # Create steganography receiver - Pass the chosen TCP port
    stego = SteganographyReceiver(my_tcp_port)

    # Key is already prepared and passed in

    # Start monitoring thread for inactivity timeout
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(
        target=monitor_transmission,
        args=(stop_monitor, timeout)
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    log_debug("Started inactivity monitor thread")

    # Start packet capture
    log_debug(f"Starting Scapy sniff on interface {interface or 'default'}...")
    print(f"Listening for TCP packets from {sender_ip}...")
    print("Press Ctrl+C to stop listening")

    try:
        # Use a Scapy filter primarily based on the sender IP.
        # Further filtering (port, flags, window) happens in the packet handler.
        filter_str = f"tcp and src host {sender_ip}"
        log_debug(f"Using Scapy filter: \"{filter_str}\"")

        # Start packet sniffing - use packet_handler wrapper to avoid printing return values
        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.packet_handler,  # Use the wrapper function
            store=0,
            # Stop sniffing if transmission complete signal received OR monitor thread signals timeout
            stop_filter=lambda p: transmission_complete or stop_monitor.is_set()
        )
        log_debug("Scapy sniff loop finished.")
        if stop_monitor.is_set() and not transmission_complete:
             log_debug("Sniff loop stopped due to inactivity timeout.")
             print("\nReception stopped due to inactivity timeout.")
        elif transmission_complete:
             log_debug("Sniff loop stopped due to transmission complete signal.")
             print("\nReception stopped after receiving completion signal.")


    except KeyboardInterrupt:
        log_debug("\nReceiving stopped by user (Ctrl+C)")
        print("\nReceiving stopped by user (Ctrl+C). Processing received data...")
        transmission_complete = True # Treat as completed to proceed with processing what we have
    except Exception as e:
         log_debug(f"\nError during packet sniffing: {e}")
         print(f"\nError during packet sniffing: {e}")
         transmission_complete = True # Try processing what we have
    finally:
        # Ensure monitor thread is stopped regardless of how sniff ended
        if not stop_monitor.is_set():
            log_debug("Signaling monitor thread to stop...")
            stop_monitor.set()
        monitor_thread.join(2.0) # Wait briefly for monitor thread to exit
        if monitor_thread.is_alive():
            log_debug("Warning: Monitor thread did not stop gracefully.")
        else:
            log_debug("Stopped inactivity monitor thread.")


    # ---- Post-Reception Processing ----

    # Check if we received any data chunks at all
    if not received_chunks:
        log_debug("No data chunks received during TCP phase. Aborting post-processing.")
        print("[FAIL] No data chunks were received.")
        # Save completion info indicating failure
        completion_info = {
            "completed_at": time.time(),
            "status": "failed",
            "reason": "no_data_chunks_received",
            "total_packets_processed": packet_counter,
            "valid_stego_packets": valid_packet_counter,
        }
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
        return False

    # Calculate reception statistics
    reception_end_time = time.time()
    duration = reception_end_time - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)

    # Estimate missing chunks based on highest sequence number seen
    missing_count = 0
    if highest_seq_num > 0:
        missing_count = highest_seq_num - chunk_count
        # Correct for potential negative if highest_seq_num wasn't updated correctly
        # or if chunks received out of order made count higher temporarily.
        # Should not happen if highest_seq_num only increases.
        missing_count = max(0, missing_count)

    reception_rate = (chunk_count / highest_seq_num * 100) if highest_seq_num > 0 else (100 if chunk_count > 0 else 0)

    stats = {
        "total_packets_processed": packet_counter,
        "valid_stego_packets_identified": valid_packet_counter,
        "data_chunks_received_count": chunk_count,
        "highest_seq_num_observed": highest_seq_num,
        "reception_duration_seconds": duration,
        "estimated_reception_rate_percent": reception_rate,
        "estimated_missing_chunks": missing_count,
        "transmission_complete_signal_received": transmission_complete # Check if FIN/ACK was received
    }

    stats_file = os.path.join(LOGS_DIR, "reception_stats.json")
    with open(stats_file, "w") as f:
        json.dump(stats, f, indent=2)
    log_debug(f"Reception statistics saved to {stats_file}")

    log_debug(f"\nReception Summary:")
    log_debug(f"- Processed {packet_counter} packets total")
    log_debug(f"- Identified {valid_packet_counter} valid steganography packets")
    log_debug(f"- Received {chunk_count} unique data chunks in {duration:.2f} seconds")
    log_debug(f"- Highest sequence number seen: {highest_seq_num}")
    log_debug(f"- Estimated packet reception rate: {reception_rate:.1f}%")
    log_debug(f"- Estimated missing chunks: {missing_count}")
    log_debug(f"- Completion signal received: {transmission_complete}")

    print(f"\nReception Summary:")
    print(f"- Processed Packets   : {packet_counter}")
    print(f"- Valid Stego Packets : {valid_packet_counter}")
    print(f"- Data Chunks Received: {chunk_count}")
    print(f"- Highest Sequence Num: {highest_seq_num}")
    print(f"- Duration            : {duration:.2f} seconds")
    print(f"- Est. Reception Rate : {reception_rate:.1f}%")
    print(f"- Est. Missing Chunks : {missing_count}")
    print(f"- Completion Signal   : {'Yes' if transmission_complete else 'No / Timed Out'}")


    # Reassemble the data from received chunks
    log_debug("Reassembling data...")
    print("[REASSEMBLY] Starting data reassembly process...")
    reassembled_data = reassemble_data() # This joins chunks without stripping

    if not reassembled_data:
        log_debug("Failed to reassemble data (no chunks or error during process).")
        print("[REASSEMBLY] Failed: Could not reassemble data.")
        completion_info = {
            "completed_at": time.time(),
            "status": "failed",
            "reason": "reassembly_failed"
        }
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
        return False

    log_debug(f"Reassembled {len(reassembled_data)} bytes of raw data (includes IV, encrypted data, checksum)")
    print(f"[REASSEMBLY] Successfully reassembled {len(reassembled_data)} bytes of raw data")

    # Verify data integrity (using MD5 checksum appended by sender)
    print("[VERIFY] Verifying data integrity using appended checksum...")
    # verify_data_integrity returns (payload_data, checksum_match_status)
    # payload_data is the data *before* the checksum (i.e., IV + encrypted)
    payload_data, checksum_match = verify_data_integrity(reassembled_data)

    final_data_to_decrypt = None
    if payload_data is None: # This happens if data too short for checksum
         log_debug("Integrity check skipped: Reassembled data too short.")
         print("[VERIFY] Skipped: Reassembled data too short for checksum.")
         # Cannot proceed with decryption if data is too short anyway
         final_data_to_decrypt = None
         checksum_match = False # Mark as failed
    elif not checksum_match:
        log_debug("Warning: Checksum mismatch! Data may be corrupted. Proceeding with decryption attempt anyway.")
        print("[VERIFY] Warning: Checksum verification failed! Data might be corrupt.")
        # Use the payload_data (without checksum) for decryption attempt
        final_data_to_decrypt = payload_data
    else:
        log_debug(f"Integrity verified. Payload size for decryption: {len(payload_data)} bytes.")
        print(f"[VERIFY] Data integrity verified successfully.")
        final_data_to_decrypt = payload_data


    # Decrypt the data (key was already prepared)
    log_debug("Attempting decryption...")
    print("[DECRYPT] Starting decryption process...")

    final_output_data = None # This will hold the final data to be saved
    decryption_status = "not_attempted" # Default status

    if final_data_to_decrypt is not None:
        print(f"[DECRYPT] Attempting to decrypt {len(final_data_to_decrypt)} bytes...")
        decrypted_data_attempt = decrypt_data(final_data_to_decrypt, key)

        if decrypted_data_attempt is not None:
            log_debug(f"Successfully decrypted {len(decrypted_data_attempt)} bytes")
            print(f"[DECRYPT] Successfully decrypted {len(decrypted_data_attempt)} bytes of original data.")
            final_output_data = decrypted_data_attempt
            decryption_status = "success"

        else:
            log_debug("Decryption failed. Output will be the raw payload (before decryption attempt).")
            print("[DECRYPT] Failed! Saving raw payload (before decryption attempt) instead.")
            # Save the data that failed decryption (IV + maybe corrupted encrypted data)
            final_output_data = final_data_to_decrypt
            decryption_status = "failed"

    else:
        # This happens if integrity check found data too short
        log_debug("Decryption skipped: No valid payload data available (likely due to insufficient data length).")
        print("[DECRYPT] Skipped: Not enough data for decryption.")
        # Save the original reassembled data, even though it's too short / failed checksum
        final_output_data = reassembled_data # Save whatever was reassembled
        decryption_status = "skipped_insufficient_data"


    # Save the final data (either decrypted, or the raw verified/unverified payload, or raw reassembled)
    save_success = False
    if final_output_data is not None:
        print(f"[SAVE] Saving final data ({len(final_output_data)} bytes) to {output_path}...")
        save_success = save_to_file(final_output_data, output_path)

        if save_success:
            print(f"[SAVE] File saved successfully.")
        else:
            print(f"[SAVE] Error saving file!")
    else:
         log_debug("Save skipped: No final data generated.")
         print("[SAVE] Skipped: No final data to save.")


    # Determine final overall status based on outcomes
    final_status = "unknown"
    if save_success:
        if decryption_status == "success" and checksum_match and missing_count == 0:
            final_status = "completed_successfully"
        elif decryption_status == "success" and checksum_match and missing_count > 0:
            final_status = "completed_partial_missing_chunks"
        elif decryption_status == "success" and not checksum_match:
             final_status = "completed_checksum_mismatch"
        elif decryption_status == "failed":
             final_status = "completed_decryption_failed" # Saved raw payload
        else: # Other cases like skipped decryption but saved raw data
             final_status = "completed_raw_data_saved"
    else:
        # If save failed
        if not received_chunks:
             final_status = "failed_no_data"
        elif not reassembled_data:
             final_status = "failed_reassembly"
        else:
             final_status = "failed_save_error"


    # Save final completion info including status details
    completion_info = {
        "completed_at": time.time(),
        "overall_status": final_status,
        "bytes_saved": len(final_output_data) if final_output_data is not None else 0,
        "checksum_match": checksum_match,
        "decryption_status": decryption_status,
        "save_status": "success" if save_success else "failed",
        "estimated_missing_chunks": missing_count,
        "complete_signal_received": transmission_complete
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f:
        json.dump(completion_info, f, indent=2)
    log_debug(f"Completion info saved to {completion_path}")

    print(f"\n[INFO] All session data saved to: {SESSION_DIR}")
    print(f"[INFO] Final Status: {final_status}")

    # Return True if the process resulted in a saved file, even if incomplete/corrupt
    # Return False only if setup failed or absolutely no data could be processed/saved.
    return save_success or (final_output_data is not None)


def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity and signal main thread."""
    global last_activity_time, transmission_complete # Need access to modify transmission_complete

    log_debug(f"[MONITOR] Inactivity monitor started (timeout={timeout}s)")
    start_time = time.time()

    while not stop_event.wait(1.0): # Check every second without blocking indefinitely
        # Check for inactivity timeout
        inactive_time = time.time() - last_activity_time
        if inactive_time > timeout:
            log_debug(f"[MONITOR] Inactivity timeout reached ({inactive_time:.1f}s > {timeout}s)")
            print(f"\n[TIMEOUT] Inactivity detected ({timeout} seconds). Stopping reception...")
            # Signal the main thread (sniff loop) to stop by setting the event
            # Also set transmission_complete flag to ensure post-processing happens
            transmission_complete = True
            stop_event.set()
            break # Exit monitor thread

        # Check if transmission_complete was set by receiving FIN/ACK
        # If so, we can stop monitoring early.
        if transmission_complete:
             log_debug("[MONITOR] Transmission complete signal detected. Stopping monitor.")
             # No need to set stop_event here, sniff loop will stop on its own check
             break

    log_debug(f"[MONITOR] Inactivity monitor stopped after {time.time() - start_time:.1f}s.")


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Simplified Network Steganography Receiver')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption key file (must match sender)') # Made required for discovery
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

    # Initialize debug log file
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Receiver Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    # Log arguments
    log_debug("Receiver started with arguments:")
    for arg, value in vars(args).items():
        if arg == 'key':
            log_debug(f"  --{arg}: {value} (path specified)")
        else:
            log_debug(f"  --{arg}: {value}")


    # Prepare decryption key and calculate hash for discovery
    key = None
    key_hash = None
    log_debug(f"Reading key file from: {args.key}")
    print(f"Reading key from: {args.key}")
    try:
        with open(args.key, 'rb') as key_file:
            key_data = key_file.read()
        key = prepare_key(key_data) # Prepare key (e.g., ensure 32 bytes, handle hex)
        key_hash = calculate_key_hash(key) # Calculate hash AFTER preparation
        log_debug(f"Calculated key hash ({KEY_HASH_ALGO}): {key_hash}")
        print(f"Key loaded successfully. Hash ({KEY_HASH_ALGO}): {key_hash[:8]}...")
    except Exception as e:
        log_debug(f"Fatal Error reading or preparing key file: {e}")
        print(f"Fatal Error reading or preparing key file: {e}")
        # Write completion status before exiting
        completion_info = {"status": "failed", "reason": "key_error", "error": str(e)}
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
        sys.exit(1)


    # Choose a random TCP port for this session *before* discovery
    # This port needs to be sent in the discovery reply
    global my_tcp_port
    my_tcp_port = random.randint(10000, 60000)
    log_debug(f"Chosen receiver TCP port for this session: {my_tcp_port}")


    # --- UDP Discovery Phase ---
    discovered_ip, discovered_sender_port = listen_for_sender(key_hash, my_tcp_port, args.discovery_timeout)

    if not discovered_ip:
        log_debug("Sender discovery failed. Exiting.")
        print("[FAIL] Could not discover sender via UDP broadcast. Exiting.")
        # Write completion status
        completion_info = {"status": "failed", "reason": "discovery_timeout"}
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
        sys.exit(1)
    else:
        # Globals sender_ip and sender_port are set within listen_for_sender
        log_debug(f"Discovery successful. Sender identified: {sender_ip}:{sender_port}")
        print(f"[SUCCESS] Sender located at {sender_ip} (TCP Port {sender_port})")


    # --- TCP Reception Phase ---
    # Now call receive_file, which uses the discovered globals and the prepared key
    success = receive_file(
        args.output,
        key, # Pass the prepared key bytes
        args.interface,
        args.timeout
    )

    # Exit with appropriate status based on whether a file was saved
    log_debug(f"Receiver finished. Overall success status (file saved): {success}")
    print(f"\nReceiver finished. {'File potentially saved.' if success else 'Operation failed or did not result in a saved file.'}")
    sys.exit(0 if success else 1) # Exit 0 if save likely worked, 1 otherwise

if __name__ == "__main__":
    main()
