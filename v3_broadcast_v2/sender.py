#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure, acknowledgment system, and dynamic IP discovery.
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
DISCOVERY_PORT = 54321    # UDP port for broadcast discovery
BROADCAST_ADDR = "255.255.255.255" # Standard broadcast address
KEY_HASH_ALGO = 'sha256'  # Algorithm for key hashing

# Global variables for the acknowledgment system
acked_chunks = set()  # Set of sequence numbers that have been acknowledged
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None       # Will be discovered
receiver_port = None     # Will be discovered (TCP port)
stop_sniffing = False    # Used to stop Scapy ACK listener

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

class SteganographySender:
    """Simple steganography sender using only TCP with acknowledgment."""

    def __init__(self, tcp_source_port):
        """Initialize the sender."""
        # Removed target_ip - will be discovered
        self.source_port = tcp_source_port # Use the assigned/chosen port
        log_debug(f"Sender initialized with TCP source port: {self.source_port}")
        # Target IP and Port will be set later via set_receiver_info
        self.target_ip = None
        self.receiver_tcp_port = None

        # Create debug file for sent chunks
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

    def set_receiver_info(self, ip, port):
        """Set the discovered receiver IP and TCP port."""
        global receiver_ip, receiver_port
        self.target_ip = ip
        self.receiver_tcp_port = port
        receiver_ip = ip  # Update global as well for consistency if needed elsewhere
        receiver_port = port
        log_debug(f"Receiver info set: IP={self.target_ip}, TCP Port={self.receiver_tcp_port}")
        print(f"[INFO] Target receiver confirmed: {self.target_ip}:{self.receiver_tcp_port}")


    def start_ack_listener(self):
        """Start a thread to listen for ACK packets using Scapy."""
        if not self.target_ip or not self.receiver_tcp_port:
            log_debug("Cannot start ACK listener: Receiver info not set.")
            print("[ERROR] Cannot start ACK listener: Receiver info missing.")
            return False

        self.stop_ack_processing.clear() # Ensure flag is clear before starting
        self.ack_processing_thread = threading.Thread(
            target=self.ack_listener_thread
        )
        self.ack_processing_thread.daemon = True
        self.ack_processing_thread.start()
        log_debug("Started Scapy ACK listener thread")
        print("[THREAD] Started Scapy ACK listener thread")
        return True

    def stop_ack_listener(self):
        """Stop the ACK listener thread."""
        global stop_sniffing
        if self.ack_processing_thread and self.ack_processing_thread.is_alive():
            log_debug("Stopping Scapy ACK listener thread...")
            self.stop_ack_processing.set()
            stop_sniffing = True # Also set global Scapy stop flag
            self.ack_processing_thread.join(2)  # Wait up to 2 seconds for thread to finish
            if self.ack_processing_thread.is_alive():
                log_debug("Warning: ACK listener thread did not stop gracefully.")
            else:
                log_debug("Stopped Scapy ACK listener thread")
                print("[THREAD] Stopped Scapy ACK listener thread")
        else:
            log_debug("ACK listener thread was not running or already stopped.")
        # Reset flag
        stop_sniffing = False

    def ack_listener_thread(self):
        """Thread function to listen for and process ACK packets using Scapy."""
        global stop_sniffing

        log_debug("Scapy ACK listener thread started")
        if not self.target_ip or not self.receiver_tcp_port:
             log_debug("ACK listener thread exiting: Receiver info missing.")
             return

        try:
            # Set up sniffing for TCP ACK packets from the receiver IP, destined for our source port
            filter_str = f"tcp and src host {self.target_ip} and dst port {self.source_port}"
            log_debug(f"Sniffing for ACKs with filter: {filter_str}")

            # Start packet sniffing for ACKs
            sniff(
                filter=filter_str,
                prn=self.process_ack_packet,
                store=0,
                stop_filter=lambda p: stop_sniffing or self.stop_ack_processing.is_set()
            )
        except Exception as e:
            # Avoid logging errors if it's just stopping
            if not self.stop_ack_processing.is_set():
                log_debug(f"Error in Scapy ACK listener thread: {e}")
                print(f"[ERROR] Scapy ACK listener thread error: {e}")

        log_debug("Scapy ACK listener thread finished.")


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
        if not self.target_ip or not self.receiver_tcp_port:
            log_debug("Cannot create SYN - receiver information missing")
            return None

        # Create a SYN packet with special markers, target the discovered receiver port
        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=self.receiver_tcp_port, # Target the receiver's listening TCP port
            seq=0x12345678,  # Fixed pattern for SYN
            window=0xDEAD,   # Special window value for handshake
            flags="S"        # SYN flag
        )
        log_debug(f"Created SYN packet for {self.target_ip}:{self.receiver_tcp_port}")
        return syn_packet

    def create_ack_packet(self):
        """Create an ACK packet to complete connection establishment."""
        if not self.target_ip or not self.receiver_tcp_port:
            log_debug("Cannot create ACK - receiver information missing")
            return None

        # Create an ACK packet with special markers, target the discovered receiver port
        ack_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=self.receiver_tcp_port, # Target the receiver's listening TCP port
            seq=0x87654321,  # Fixed pattern for final ACK
            ack=0xABCDEF12,  # Should match receiver's SYN-ACK seq number
            window=0xF00D,   # Special window value for handshake completion
            flags="A"        # ACK flag
        )
        log_debug(f"Created final ACK packet for {self.target_ip}:{self.receiver_tcp_port}")
        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data."""
        if not self.target_ip:
            log_debug("Cannot create data packet - target IP missing")
            return None

        # Ensure data is exactly MAX_CHUNK_SIZE bytes
        if len(data) < MAX_CHUNK_SIZE:
            data = data.ljust(MAX_CHUNK_SIZE, b'\0')
            # No need to log padding here, it's expected
            # log_debug(f"Padded chunk {seq_num} to {MAX_CHUNK_SIZE} bytes")
        elif len(data) > MAX_CHUNK_SIZE:
            data = data[:MAX_CHUNK_SIZE]
            log_debug(f"Warning: Truncated chunk {seq_num} to {MAX_CHUNK_SIZE} bytes")


        # Create random destination port for stealth (or use receiver's port?)
        # Using random port might bypass stateful firewalls easier but looks less like a connection
        # Let's stick to random for now as per original logic
        dst_port = random.randint(10000, 60000)

        # Embed first 4 bytes in sequence number and last 4 in ack number
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port, # Random destination port
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,  # Put sequence number in window field
            flags="S",       # SYN flag (as per original logic - acts as data carrier)
            options=[('MSS', total_chunks)]  # Store total chunks in MSS option
        )

        # Calculate and store checksum in IP ID field
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum

        return tcp_packet

    def create_completion_packet(self):
        """Create a packet signaling transmission completion."""
        if not self.target_ip or not self.receiver_tcp_port:
             log_debug("Cannot create completion packet - receiver info missing")
             return None

        # Send FIN to the receiver's actual TCP port
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=self.receiver_tcp_port, # Target the actual receiver port
            window=0xFFFF,  # Special value for completion
            flags="FA"       # FIN-ACK packet signals completion gracefully
        )
        log_debug(f"Created completion (FIN/ACK) packet for {self.target_ip}:{self.receiver_tcp_port}")
        return tcp_packet

    def process_ack_packet(self, packet):
        """Process a received ACK packet (called by Scapy's sniff)."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established # No need to check receiver_ip/port here, Scapy filter does it

        # Check if it's a valid TCP packet (Scapy filter should ensure this)
        if TCP in packet:
            # Debug log every potential ACK packet received matching the filter
            log_debug(f"[ACK Listener] Received packet from {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}, Flags: {packet[TCP].flags}, Win: {packet[TCP].window}, Seq: {packet[TCP].seq}, Ack: {packet[TCP].ack}")

            # Check for SYN-ACK packet (connection establishment response)
            # Filter should ensure it's from receiver IP and to our source port
            if not connection_established and packet[TCP].flags.SA and packet[TCP].window == 0xBEEF:
                log_debug(f"Received potential SYN-ACK for connection establishment from {packet[IP].src}:{packet[TCP].sport}")

                # Verify source port matches discovered receiver TCP port
                if packet[TCP].sport != self.receiver_tcp_port:
                    log_debug(f"SYN-ACK source port mismatch! Expected {self.receiver_tcp_port}, got {packet[TCP].sport}. Ignoring.")
                    # Don't proceed with handshake if port is wrong
                    return False # Important to return False so Scapy continues sniffing

                print("[HANDSHAKE] Received valid SYN-ACK response")

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
                    log_debug("Connection marked as established")
                    print("[HANDSHAKE] Connection established successfully")
                else:
                     log_debug("Failed to create final ACK packet")

                return True # Handled SYN-ACK

            # Check for data chunk ACK (special window value)
            # Filter ensures it's from receiver IP and to our source port
            if connection_established and packet[TCP].flags.A and packet[TCP].window == 0xCAFE:
                # Extract the sequence number from the ack field
                seq_num = packet[TCP].ack
                log_debug(f"Received potential Data ACK for chunk {seq_num} from {packet[IP].src}:{packet[TCP].sport}")

                # Verify source port matches discovered receiver TCP port
                if packet[TCP].sport != self.receiver_tcp_port:
                     log_debug(f"Data ACK source port mismatch! Expected {self.receiver_tcp_port}, got {packet[TCP].sport}. Ignoring ACK for {seq_num}.")
                     return False # Ignore ACK from wrong port

                # Check if already ACKed to prevent duplicate processing/logging
                if seq_num not in acked_chunks:
                    log_debug(f"Valid ACK confirmed for chunk {seq_num}")
                    self.log_ack(seq_num) # Log it

                    # Add to acknowledged chunks
                    acked_chunks.add(seq_num)

                    # If this is the chunk we're currently waiting for, clear the wait flag
                    if waiting_for_ack and seq_num == current_chunk_seq:
                        log_debug(f"Chunk {seq_num} acknowledged, clearing wait flag.")
                        print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                        waiting_for_ack = False
                    else:
                         # Log if we receive an ACK for a chunk we weren't actively waiting for (e.g., late ACK)
                         # This is normal if ACKs arrive out of order or if previous chunk timed out
                         log_debug(f"Received ACK for chunk {seq_num}, but wasn't the one currently waited for (current: {current_chunk_seq if waiting_for_ack else 'None'}).")
                         # Check if it clears the flag for a *previous* chunk that might still be marked as waiting (though the main loop moved on)
                         # This scenario is less likely with the current `send_chunk` logic but good to be aware of.
                         pass
                else:
                     log_debug(f"Ignoring duplicate ACK for chunk {seq_num}")


                return True # Handled data ACK

            # Log other packets received from receiver if needed and verbose logging enabled
            # else:
            #    log_debug(f"Received other TCP packet from receiver {packet[IP].src}:{packet[TCP].sport}: Flags={packet[TCP].flags}, Win={packet[TCP].window}")

        return False # Packet not processed or not relevant


    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq

        # Skip if this chunk has already been acknowledged
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping send")
            # print(f"[SKIP] Chunk {seq_num:04d} already acknowledged") # Reduce noise
            return True

        # Create the packet
        packet = self.create_packet(data, seq_num, total_chunks)
        if not packet:
             log_debug(f"Failed to create packet for chunk {seq_num}. Aborting chunk send.")
             return False

        # Log the chunk being sent (before transmission)
        self.log_chunk(seq_num, data)

        # Set current chunk and waiting flag *before* sending
        current_chunk_seq = seq_num
        waiting_for_ack = True

        # Initial transmission
        log_debug(f"Sending chunk {seq_num}/{total_chunks}")
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks * 100) if total_chunks > 0 else 0:.2f}%")
        send(packet)

        # Wait for ACK with retransmission
        retransmit_count = 0
        max_retransmits = MAX_RETRANSMISSIONS
        start_time = time.time()

        while waiting_for_ack and retransmit_count < max_retransmits:
            # Use a simpler sleep-based check for the waiting_for_ack flag
            # The flag is modified directly by the ACK listener thread
            wait_start = time.time()
            ack_received_in_wait = False
            while time.time() - wait_start < ACK_WAIT_TIMEOUT:
                 if not waiting_for_ack: # Check if flag was cleared by listener
                     ack_received_in_wait = True
                     break
                 time.sleep(0.1) # Small sleep to yield CPU

            # If ACK was received, break the retransmit loop
            if ack_received_in_wait:
                log_debug(f"ACK for chunk {seq_num} detected within wait period ({time.time() - wait_start:.2f}s).")
                break

            # If we're still waiting for ACK after timeout, retransmit
            if waiting_for_ack: # Check flag again *after* the wait period completes
                retransmit_count += 1
                log_debug(f"Timeout waiting for ACK for chunk {seq_num}. Retransmitting (attempt {retransmit_count}/{max_retransmits})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{max_retransmits} (Timeout: {ACK_WAIT_TIMEOUT}s)")
                send(packet) # Resend the same packet
            # else: # This case is handled by ack_received_in_wait check above
                 # log_debug(f"ACK for chunk {seq_num} arrived just before retransmit attempt {retransmit_count+1}.")
                 # break # Ensure we exit if ACK arrived very late

        # Check final status after the loop
        if waiting_for_ack:
            # We've exhausted retransmissions and still no ACK
            log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions")
            print(f"[WARNING] No ACK received for chunk {seq_num:04d} after {max_retransmits} attempts")
            waiting_for_ack = False  # Reset wait flag anyway for the next chunk
            return False # Indicate failure for this chunk
        else:
            # Success - chunk was acknowledged (waiting_for_ack became False)
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} confirmed acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
            # print(f"[CONFIRMED] Chunk {seq_num:04d} successfully delivered") # Reduce noise
            return True # Indicate success

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
             # Pad with null bytes
             key_data = key_data.ljust(32, b'\0')
             log_debug(f"Key padded to 32 bytes.")
         else:
            # Truncate
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


def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        # Generate a random IV for each encryption for security
        iv = os.urandom(16) # AES block size for IV
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
        log_debug(f"Encryption successful. Input size: {len(data)}, Encrypted size: {len(encrypted_data)}")


        # Save original and encrypted data for debugging
        original_file = os.path.join(DATA_DIR, "original_data.bin")
        with open(original_file, "wb") as f:
            f.write(data)

        encrypted_file = os.path.join(DATA_DIR, "encrypted_data_only.bin")
        with open(encrypted_file, "wb") as f:
            f.write(encrypted_data)

        # Save a complete package (IV + encrypted data) for debugging
        package_file = os.path.join(DATA_DIR, "encrypted_package_iv_prepended.bin")
        with open(package_file, "wb") as f:
            f.write(iv + encrypted_data)

        log_debug(f"Original data head (hex): {data[:32].hex()}...")
        log_debug(f"Encrypted data head (hex): {encrypted_data[:32].hex()}...")

        # Prepend IV to the encrypted data for use in decryption
        final_package = iv + encrypted_data
        log_debug(f"Final package size (IV + data): {len(final_package)}")
        return final_package

    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"[ERROR] Encryption failed: {e}")
        # Exit or return None? Exit is safer if encryption fails.
        sys.exit(1)


def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks of specified size."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data ({len(data)} bytes) into {len(chunks)} chunks of max size {chunk_size}")

    # Save chunk details for debugging (only first/last few chunks maybe)
    chunk_info = {}
    limit = 10
    if len(chunks) <= 2 * limit:
         # Log all if few chunks
         chunk_info = {i+1: {"size": len(chunk), "hex_preview": chunk[:8].hex()} for i, chunk in enumerate(chunks)}
    else:
         # Log preview if many chunks
         for i in range(limit):
             chunk_info[i+1] = {"size": len(chunks[i]), "hex_preview": chunks[i][:8].hex()}
         chunk_info["..."] = "..."
         for i in range(len(chunks) - limit, len(chunks)):
             chunk_info[i+1] = {"size": len(chunks[i]), "hex_preview": chunks[i][:8].hex()}


    chunks_json = os.path.join(LOGS_DIR, "chunks_info_preview.json")
    with open(chunks_json, "w") as f:
        json.dump(chunk_info, f, indent=2)

    return chunks

def discover_receiver(key_hash, sender_tcp_port, discovery_timeout=60):
    """Broadcast discovery packet and listen for reply."""
    global receiver_ip, receiver_port # These will be set on success

    log_debug(f"[DISCOVERY] Starting UDP discovery...")
    log_debug(f"[DISCOVERY] Broadcasting Key Hash: {key_hash[:8]}...")
    log_debug(f"[DISCOVERY] My TCP Port for Session: {sender_tcp_port}")
    print(f"[DISCOVERY] Searching for receiver...")
    print(f"[DISCOVERY]   - Broadcasting Key Hash: {key_hash[:8]}...")
    print(f"[DISCOVERY]   - Using Sender TCP Port: {sender_tcp_port}")
    print(f"[DISCOVERY]   - Timeout: {discovery_timeout} seconds")

    udp_socket = None
    try:
        # Create UDP socket
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Allow reuse of address
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Enable broadcasting
        udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind to the sender's TCP port to listen for the unicast reply
        # Binding to '' listens on all interfaces for the reply
        udp_socket.bind(("", sender_tcp_port))
        log_debug(f"[DISCOVERY] UDP socket bound to ('', {sender_tcp_port}) for listening")

        # Prepare broadcast payload
        broadcast_payload = {
            "type": "crypticroute_discover",
            "key_hash": key_hash,
            "sender_port": sender_tcp_port # Include our TCP port
        }
        broadcast_data = json.dumps(broadcast_payload).encode('utf-8')
        log_debug(f"[DISCOVERY] Broadcast payload: {broadcast_payload}")

        # Broadcast periodically and listen for reply
        start_time = time.time()
        broadcast_interval = 2 # seconds between broadcasts
        next_broadcast_time = time.time() # Send immediately first time

        udp_socket.settimeout(1.0) # Set short timeout for recvfrom to allow checking time and broadcasting again

        while time.time() - start_time < discovery_timeout:
            # Send broadcast if interval passed
            current_time = time.time()
            if current_time >= next_broadcast_time:
                 log_debug(f"[DISCOVERY] Broadcasting discovery packet to {BROADCAST_ADDR}:{DISCOVERY_PORT}")
                 try:
                     udp_socket.sendto(broadcast_data, (BROADCAST_ADDR, DISCOVERY_PORT))
                 except OSError as e:
                      # Handle potential network errors during broadcast (e.g., network down)
                      log_debug(f"[DISCOVERY] Warning: Error sending broadcast: {e}. Check network/permissions.")
                      # Continue trying, maybe the network recovers
                 next_broadcast_time = current_time + broadcast_interval

            # Listen for reply
            try:
                data, addr = udp_socket.recvfrom(1024) # Buffer size
                log_debug(f"[DISCOVERY] Received UDP packet from {addr}: {data}")

                # Attempt to decode JSON payload
                try:
                    payload = json.loads(data.decode('utf-8'))
                    log_debug(f"[DISCOVERY] Decoded JSON payload: {payload}")

                    # Check if it's the correct reply type and matches hash
                    if (payload.get("type") == "crypticroute_reply" and
                            payload.get("key_hash") == key_hash and
                            "receiver_port" in payload):

                        r_ip = addr[0]
                        r_port = payload["receiver_port"] # This is the receiver's TCP port

                        log_debug(f"[DISCOVERY] Receiver reply MATCH! IP={r_ip}, TCP Port={r_port}")
                        print(f"\n[DISCOVERY] Receiver Found!")
                        print(f"[DISCOVERY]   - Receiver IP: {r_ip}")
                        print(f"[DISCOVERY]   - Receiver TCP Port: {r_port}")

                        # Store discovered info globally
                        receiver_ip = r_ip
                        receiver_port = r_port # Receiver's TCP port
                        return receiver_ip, receiver_port # Success

                    else:
                        log_debug("[DISCOVERY] UDP packet ignored: Invalid format, type, or non-matching hash.")
                        # Optional: Log details of mismatched packet if needed for debugging
                        # log_debug(f"[DISCOVERY] Ignored Payload Details: {payload}")

                except json.JSONDecodeError:
                    log_debug(f"[DISCOVERY] UDP packet from {addr} ignored: Not valid JSON.")
                except UnicodeDecodeError:
                    log_debug(f"[DISCOVERY] UDP packet from {addr} ignored: Cannot decode as UTF-8.")
                except Exception as e:
                     log_debug(f"[DISCOVERY] Error processing received UDP packet from {addr}: {e}")


            except socket.timeout:
                # No reply received in this 1s interval, loop continues
                pass # Just means no packet arrived in this short window, normal operation
            except ConnectionResetError:
                 # Common on Windows if previous send failed (e.g., ICMP port unreachable)
                 log_debug("[DISCOVERY] Warning: ConnectionResetError during recvfrom. Likely harmless. Continuing.")
                 pass
            except Exception as e:
                 log_debug(f"[DISCOVERY] Error receiving UDP packet: {e}")
                 # Continue trying unless it's a fatal error?


        # Loop finished without success
        log_debug(f"[DISCOVERY] UDP discovery timeout after {discovery_timeout} seconds.")
        print(f"\n[DISCOVERY] Failed: No valid receiver reply received within {discovery_timeout} seconds.")
        return None, None # Indicate timeout/failure

    except OSError as e:
         # Errors like "Address already in use" or "Permission denied"
         log_debug(f"[DISCOVERY] UDP Socket Error: {e}. Check port {sender_tcp_port} availability and broadcast permissions.")
         print(f"[ERROR] UDP Socket Error: {e}. Cannot perform discovery.")
         return None, None
    except Exception as e:
        log_debug(f"[DISCOVERY] Unexpected error during UDP discovery: {e}")
        print(f"[ERROR] Unexpected error during UDP discovery: {e}")
        return None, None
    finally:
        if udp_socket:
            udp_socket.close()
            log_debug("[DISCOVERY] UDP discovery socket closed.")

def establish_connection(stego):
    """Establish connection with the receiver using three-way handshake."""
    global connection_established

    if not stego.target_ip or not stego.receiver_tcp_port:
         log_debug("Cannot establish connection: Receiver IP/Port unknown.")
         print("[ERROR] Cannot establish connection: Receiver info missing.")
         return False

    log_debug(f"[HANDSHAKE] Starting TCP connection establishment with {stego.target_ip}:{stego.receiver_tcp_port}")
    print(f"[HANDSHAKE] Initiating TCP connection with receiver {stego.target_ip}:{stego.receiver_tcp_port}...")

    # Start Scapy ACK listener thread (to catch SYN-ACK and data ACKs)
    if not stego.start_ack_listener():
         log_debug("Failed to start ACK listener. Aborting handshake.")
         return False


    # Send SYN packet
    syn_packet = stego.create_syn_packet()
    if not syn_packet:
         log_debug("Failed to create SYN packet. Aborting.")
         stego.stop_ack_listener()
         return False

    log_debug("[HANDSHAKE] Sending initial SYN packet...")
    print("[HANDSHAKE] Sending SYN packet...")

    # Send multiple times initially and wait for connection_established flag (set by ACK listener)
    # The ACK listener thread runs concurrently and sets the global flag upon receiving SYN-ACK
    max_syn_attempts = 15 # Total attempts over the handshake period
    syn_interval = 0.5 # seconds between re-sends
    attempts = 0
    handshake_timeout = 20 # seconds overall timeout for handshake
    start_time = time.time()

    while not connection_established and time.time() - start_time < handshake_timeout:
        # Send SYN if it's the first attempt or interval has passed
        # Avoid flooding by sending only periodically
        if attempts == 0 or (time.time() - last_send_time >= syn_interval and attempts < max_syn_attempts) :
            send(syn_packet)
            attempts += 1
            last_send_time = time.time()
            log_debug(f"[HANDSHAKE] Sent SYN (Attempt {attempts}/{max_syn_attempts})")
            if attempts == 1: # Only print first send attempt
                 print("[HANDSHAKE] Sent SYN...")


        # Wait a bit, checking flag periodically
        wait_start_inner = time.time()
        while not connection_established and time.time() - wait_start_inner < 0.2: # Check flag frequently
             time.sleep(0.05) # Short sleep

        if connection_established:
             log_debug("[HANDSHAKE] Connection established flag detected during SYN send loop.")
             break # Exit loop if connected

        # Check overall timeout inside the loop as well
        if time.time() - start_time >= handshake_timeout:
             log_debug("[HANDSHAKE] Handshake attempt timed out.")
             break


    # Check final status after the loop
    if connection_established:
        log_debug("[HANDSHAKE] TCP Handshake successful (connection established flag is True)")
        print("[HANDSHAKE] TCP Handshake successful!")
        # ACK listener remains running for data phase
        return True
    else:
        log_debug(f"[HANDSHAKE] TCP Handshake failed after {time.time() - start_time:.1f} seconds and {attempts} SYN attempts.")
        print("[HANDSHAKE] Failed: Could not establish TCP connection with receiver.")
        stego.stop_ack_listener() # Stop listener if handshake failed
        return False


def send_file(file_path, key, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt and send a file via steganography after discovering receiver."""
    # Assumes receiver_ip, receiver_port are set globally by discovery
    # Assumes stego object is created and receiver info is set in it
    global connection_established, stop_sniffing, acked_chunks

    if not receiver_ip or not receiver_port:
         log_debug("send_file called without discovered receiver IP/Port. Aborting.")
         print("[ERROR] Receiver IP and Port not discovered. Cannot send file.")
         return False

    log_debug(f"[SEND PHASE] Proceeding with transmission to receiver: {receiver_ip}:{receiver_port}")
    print(f"[INFO] Starting TCP transmission phase to receiver: {receiver_ip}:{receiver_port}")

    # Create a summary file with transmission parameters
    summary = {
        "timestamp_start": time.time(),
        "input_file_path": file_path,
        "key_hash": calculate_key_hash(key), # Log hash of prepared key
        "chunk_size": chunk_size,
        "inter_packet_delay": delay,
        "discovered_receiver_ip": receiver_ip,
        "discovered_receiver_port": receiver_port, # TCP port
        "sender_tcp_port": stego.source_port, # Our TCP port
        "ack_timeout": ACK_WAIT_TIMEOUT,
        "max_retransmissions": MAX_RETRANSMISSIONS
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    log_debug(f"[INFO] Session summary saved to {summary_path}")

    # Reset global variables specifically for TCP phase state
    acked_chunks.clear()
    connection_established = False
    stop_sniffing = False # Reset Scapy stop flag

    # SteganographySender instance 'stego' should already exist from main() and have receiver info set

    # Establish TCP connection (uses info set in stego object)
    if not establish_connection(stego):
        log_debug("[SEND PHASE] Aborting transmission due to TCP connection failure")
        print("[ERROR] Aborting transmission: TCP connection failed.")
        # ACK listener is stopped by establish_connection on failure
        return False


    # Read the input file
    log_debug(f"[FILE] Reading file: {file_path}")
    print(f"[FILE] Reading: {file_path}")
    file_data = read_file(file_path, 'rb')
    log_debug(f"[FILE] Read {len(file_data)} bytes.")
    print(f"[FILE] Read {len(file_data)} bytes successfully")

    # Log the original file content preview
    try:
        # Limit preview to avoid huge console output
        preview_len = 500
        text_content = file_data[:preview_len].decode('utf-8', errors='replace')
        suffix = "..." if len(file_data) > preview_len else ""
        log_debug(f"Original file content (preview): {text_content}{suffix}")

        # Save the text content as a text file for easier debugging
        text_file = os.path.join(DATA_DIR, "original_content_preview.txt")
        with open(text_file, "w", encoding='utf-8', errors='replace') as f:
            f.write(file_data.decode('utf-8', errors='replace')) # Write full content decoded
        log_debug(f"Saved original content preview (UTF-8 decoded with replacements) to {text_file}")

    except Exception as e: # Catch potential errors during decode/write
        log_debug(f"[WARN] Could not decode/save original content as text: {e}")
        log_debug(f"File content head (hex): {file_data[:64].hex()}")

    # Encrypt the data (key is already prepared)
    log_debug("[ENCRYPT] Encrypting data...")
    print(f"[ENCRYPT] Starting encryption of {len(file_data)} bytes...")
    encrypted_payload = encrypt_data(file_data, key)
    log_debug(f"[ENCRYPT] Data encrypted. Size including IV: {len(encrypted_payload)} bytes")
    print(f"[ENCRYPT] Completed encryption. Result size (incl. IV): {len(encrypted_payload)} bytes")


    # Add MD5 checksum for integrity verification by the receiver
    # Checksum is calculated on the IV + encrypted data block
    file_checksum = hashlib.md5(encrypted_payload).digest()
    log_debug(f"[CHECKSUM] Generated MD5 checksum for (IV+encrypted_data): {file_checksum.hex()}")
    print(f"[CHECKSUM] Generated MD5 for final payload: {file_checksum.hex()}")
    final_data_package = encrypted_payload + file_checksum
    log_debug(f"[PREP] Final package size (IV+data+checksum): {len(final_data_package)}")


    # Save components for debugging locally
    checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
    with open(checksum_file, "wb") as f:
        f.write(file_checksum)

    final_package_file = os.path.join(DATA_DIR, "final_data_package_sent.bin")
    with open(final_package_file, "wb") as f:
        f.write(final_data_package)
    log_debug(f"[PREP] Saved final data package with checksum to {final_package_file}")


    # Chunk the final data package
    print(f"[PREP] Splitting final data package ({len(final_data_package)} bytes) into chunks of size {chunk_size} bytes...")
    chunks = chunk_data(final_data_package, chunk_size)
    total_chunks = len(chunks)
    log_debug(f"[PREP] Data split into {total_chunks} chunks")
    print(f"[PREP] Data split into {total_chunks} chunks")

    # Send all chunks in order with acknowledgment
    log_debug(f"[TRANSMISSION] Sending {total_chunks} chunks to {receiver_ip}:{receiver_port}...")
    print(f"[TRANSMISSION] Starting data transmission ({total_chunks} chunks) to {receiver_ip}:{receiver_port}...")

    transmission_success_all_acked = True # Track if all chunks get ACKed
    start_time = time.time()

    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Sequence numbers start from 1

        # Send the chunk using the acknowledgment system
        success_this_chunk = stego.send_chunk(chunk, seq_num, total_chunks)

        if not success_this_chunk:
             transmission_success_all_acked = False
             log_debug(f"[TRANSMISSION] Failed to get ACK for chunk {seq_num}. Continuing...")
             # Continue sending subsequent chunks anyway? Yes, current logic does.
             # Receiver will hopefully request retransmission later if needed (not implemented)
             # or indicate missing chunks upon completion.

        # Add delay between packets
        time.sleep(delay)

    duration = time.time() - start_time
    log_debug(f"[TRANSMISSION] Finished sending loop for {total_chunks} chunks in {duration:.2f} seconds.")
    print(f"[TRANSMISSION] Finished sending all chunks.")


    # Send completion signal (FIN/ACK packet)
    completion_packet = stego.create_completion_packet()
    if completion_packet:
        print("[COMPLETE] Sending transmission completion signals...")
        log_debug("[COMPLETE] Sending transmission completion signals (FIN/ACK)...")
        # Send multiple times to increase chance of receipt
        for i in range(5):
            log_debug(f"Sending completion signal (Attempt {i+1}/5)")
            send(completion_packet)
            time.sleep(0.1)
        log_debug("Finished sending completion signals.")
    else:
         log_debug("Could not create completion packet.")
         print("[WARNING] Could not send completion signal.")

    # Stop the ACK listener thread
    stego.stop_ack_listener()

    # Calculate and log final statistics
    ack_count = len(acked_chunks)
    ack_rate = (ack_count / total_chunks * 100) if total_chunks > 0 else 100
    missing_acks = total_chunks - ack_count

    log_debug(f"[STATS] Transmission Complete.")
    log_debug(f"[STATS]   Total Chunks: {total_chunks}")
    log_debug(f"[STATS]   Acknowledged: {ack_count}")
    log_debug(f"[STATS]   Missing ACKs: {missing_acks}")
    log_debug(f"[STATS]   ACK Rate: {ack_rate:.2f}%")
    log_debug(f"[STATS]   Duration: {duration:.2f} seconds")

    print(f"\n[STATS] Transmission Summary:")
    print(f"- Total Chunks Sent: {total_chunks}")
    print(f"- Chunks Acknowledged: {ack_count}")
    print(f"- ACK Rate: {ack_rate:.2f}%")
    print(f"- Missing ACKs: {missing_acks}")
    print(f"- Duration: {duration:.2f} seconds")

    final_status = "completed"
    if missing_acks > 0:
        final_status = "partial_unacked_chunks"
        print("[WARNING] Some chunks were not acknowledged by the receiver.")
    else:
        print("[COMPLETE] All chunks appear to have been acknowledged.")


    # Save session completion info
    completion_info = {
        "completed_at": time.time(),
        "total_chunks_sent": total_chunks,
        "chunks_acknowledged": ack_count,
        "ack_rate_percent": ack_rate,
        "missing_acks_count": missing_acks,
        "duration_seconds": duration,
        "status": final_status
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f:
        json.dump(completion_info, f, indent=2)
    log_debug(f"[INFO] Completion info saved to {completion_path}")

    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    print(f"[INFO] Final status: {final_status}")

    # Return True only if all chunks were ACKed for a stricter success definition
    return missing_acks == 0


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Simplified Network Steganography Sender')
    # Target removed, will use discovery
    # parser.add_argument('--target', '-t', required=True, help='Target IP address')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=True, help='Encryption key file (must match receiver)') # Made required
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets in seconds (default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE,
                        help=f'Chunk size in bytes (MUST be {MAX_CHUNK_SIZE})') # Fixed chunk size emphasized
    parser.add_argument('--output-dir', '-o', help='Custom base directory for session outputs')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT,
                        help=f'Timeout for waiting for ACK in seconds (default: {ACK_WAIT_TIMEOUT})')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS,
                        help=f'Maximum retransmission attempts per chunk (default: {MAX_RETRANSMISSIONS})')
    parser.add_argument('--discovery-timeout', type=int, default=60, help='Timeout for UDP discovery in seconds (default: 60)')
    return parser.parse_args()

# Define stego globally so it can be accessed in main scope after initialization
stego = None

def main():
    """Main function."""
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, MAX_CHUNK_SIZE, stego

    # Parse arguments
    args = parse_arguments()

    # Setup output directory structure
    if args.output_dir:
        OUTPUT_DIR = args.output_dir
    setup_directories() # Call early for logging

    # Log arguments (be careful with key)
    log_debug("Sender started with arguments:")
    for arg, value in vars(args).items():
         if arg == 'key':
             log_debug(f"  --{arg}: {value} (path specified)")
         else:
             log_debug(f"  --{arg}: {value}")

    # Validate chunk size (must be MAX_CHUNK_SIZE for this implementation's packet crafting)
    if args.chunk_size != MAX_CHUNK_SIZE:
        log_debug(f"Error: Invalid chunk size specified ({args.chunk_size}). Must be {MAX_CHUNK_SIZE}.")
        print(f"Error: Chunk size must be {MAX_CHUNK_SIZE} for this implementation.")
        sys.exit(1)
    chunk_size = MAX_CHUNK_SIZE # Use the fixed size


    # Set ACK timeout and max retries from args
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    log_debug(f"ACK Timeout set to: {ACK_WAIT_TIMEOUT}s")
    log_debug(f"Max Retransmissions set to: {MAX_RETRANSMISSIONS}")


    # Prepare encryption key and calculate hash
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
        sys.exit(1)


    # Choose a random TCP source port for this session (used for ACKs and discovery reply)
    sender_tcp_port = random.randint(10000, 60000)
    log_debug(f"Chosen sender TCP source port for this session: {sender_tcp_port}")

    # Create SteganographySender instance (needs TCP port)
    # `stego` is global so send_file can access it
    stego = SteganographySender(sender_tcp_port)


    # --- UDP Discovery Phase ---
    discovered_ip, discovered_tcp_port = discover_receiver(key_hash, sender_tcp_port, args.discovery_timeout)

    if not discovered_ip:
        log_debug("Receiver discovery failed. Exiting.")
        print("[FAIL] Could not discover receiver. Exiting.")
        sys.exit(1)
    else:
        log_debug(f"Discovery successful. Receiver identified: {discovered_ip}:{discovered_tcp_port}")
        print(f"[SUCCESS] Receiver located at {discovered_ip}, listening on TCP port {discovered_tcp_port}")
        # Set receiver info in the stego object (updates globals receiver_ip/receiver_port too)
        stego.set_receiver_info(discovered_ip, discovered_tcp_port)


    # --- TCP Transmission Phase ---
    # Now call send_file, which uses the globally set receiver_ip/port and the stego object
    success = send_file(
        args.input,
        key, # Pass prepared key bytes
        chunk_size, # Pass validated chunk size
        args.delay
    )

    # Exit with appropriate status
    log_debug(f"Sender finished. Success status (all ACKs received): {success}")
    print(f"\nSender finished. {'All chunks acknowledged.' if success else 'Operation completed, but some chunks may not have been acknowledged.'}")
    sys.exit(0 if success else 1) # Exit 0 only if all chunks ACKed


if __name__ == "__main__":
    main()
