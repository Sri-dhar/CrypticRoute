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
RETRANSMIT_ATTEMPTS = 5
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
    with open(DEBUG_LOG, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

class SteganographySender:
    """Simple steganography sender using only TCP with acknowledgment."""
    
    def __init__(self, target_ip):
        """Initialize the sender."""
        self.target_ip = target_ip
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
            self.ack_processing_thread.join(2)  # Wait up to 2 seconds for thread to finish
            log_debug("Stopped ACK listener thread")
            print("[THREAD] Stopped ACK listener thread")
    
    def ack_listener_thread(self):
        """Thread function to listen for and process ACK packets."""
        global stop_sniffing
        
        log_debug("ACK listener thread started")
        
        try:
            # Set up sniffing for TCP ACK packets
            filter_str = f"tcp and dst port {self.source_port}"
            log_debug(f"Sniffing for ACKs with filter: {filter_str}")
            
            # Start packet sniffing for ACKs
            sniff(
                filter=filter_str,
                prn=self.process_ack_packet,
                store=0,
                stop_filter=lambda p: stop_sniffing or self.stop_ack_processing.is_set()
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
            dport=random.randint(10000, 60000),
            seq=0x12345678,  # Fixed pattern for SYN
            window=0xDEAD,   # Special window value for handshake
            flags="S"        # SYN flag
        )
        
        return syn_packet
    
    def create_ack_packet(self):
        """Create an ACK packet to complete connection establishment."""
        global receiver_ip, receiver_port
        
        if not receiver_ip or not receiver_port:
            log_debug("Cannot create ACK - receiver information missing")
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
        
        return ack_packet
    
    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data."""
        # Ensure data is exactly 8 bytes
        if len(data) < MAX_CHUNK_SIZE:
            data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE:
            data = data[:MAX_CHUNK_SIZE]
            
        # Create random destination port for stealth
        dst_port = random.randint(10000, 60000)
        
        # Embed first 4 bytes in sequence number and last 4 in ack number
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,  # Put sequence number in window field
            flags="S",  # SYN packet
            options=[('MSS', total_chunks)]  # Store total chunks in MSS option
        )
        
        # Store checksum in ID field
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum
        
        return tcp_packet
    
    def create_completion_packet(self):
        """Create a packet signaling transmission completion."""
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000),
            window=0xFFFF,  # Special value for completion
            flags="F"  # FIN packet signals completion
        )
        return tcp_packet
    
    def process_ack_packet(self, packet):
        """Process a received ACK packet."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_ip, receiver_port
        
        # Check if it's a valid TCP packet
        if IP in packet and TCP in packet:
            # Save receiver information if not already saved
            if receiver_ip is None:
                receiver_ip = packet[IP].src
            if receiver_port is None and packet[TCP].sport != 0:
                receiver_port = packet[TCP].sport
            
            # Check for SYN-ACK packet (connection establishment)
            if not connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == 0xBEEF:  # SYN-ACK flags and special window
                log_debug("Received SYN-ACK for connection establishment")
                print("[HANDSHAKE] Received SYN-ACK response")
                
                # Store receiver info specifically from this packet
                receiver_ip = packet[IP].src
                receiver_port = packet[TCP].sport
                
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
                
                return True
            
            # Check for data chunk ACK
            if connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xCAFE:  # ACK flag and special window
                # Extract the sequence number from the ack field
                seq_num = packet[TCP].ack
                
                log_debug(f"Received ACK for chunk {seq_num}")
                self.log_ack(seq_num)
                
                # Add to acknowledged chunks
                acked_chunks.add(seq_num)
                
                # If this is the chunk we're currently waiting for, clear the wait flag
                if waiting_for_ack and seq_num == current_chunk_seq:
                    log_debug(f"Chunk {seq_num} acknowledged")
                    print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                    waiting_for_ack = False
                
                return True
        
        return False
        
    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq
        
        # Skip if this chunk has already been acknowledged
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping")
            print(f"[SKIP] Chunk {seq_num:04d} already acknowledged")
            return True
        
        # Create the packet
        packet = self.create_packet(data, seq_num, total_chunks)
        
        # Log the chunk
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
        
        # Give critical chunks more retransmission attempts
        if seq_num in [1, 4, 7]:
            max_retransmits = max_retransmits * 2
        
        start_time = time.time()
        
        while waiting_for_ack and retransmit_count < max_retransmits:
            # Wait a bit for ACK
            wait_time = 0
            while waiting_for_ack and wait_time < ACK_WAIT_TIMEOUT:
                time.sleep(0.1)
                wait_time += 0.1
                
                # Check if ACK received during sleep
                if not waiting_for_ack:
                    break
            
            # If we're still waiting for ACK, retransmit
            if waiting_for_ack:
                retransmit_count += 1
                log_debug(f"Retransmitting chunk {seq_num} (attempt {retransmit_count}/{max_retransmits})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{max_retransmits}")
                send(packet)
        
        # If we've exhausted retransmissions and still no ACK
        if waiting_for_ack:
            log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions")
            print(f"[WARNING] No ACK received for chunk {seq_num:04d} after {max_retransmits} attempts")
            waiting_for_ack = False  # Reset for next chunk
            return False
        
        # Success - chunk was acknowledged
        elapsed = time.time() - start_time
        log_debug(f"Chunk {seq_num} acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
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
    """Prepare the encryption key in correct format."""
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')
        
    # Check if it's a hex string and convert if needed
    try:
        if all(c in b'0123456789abcdefABCDEF' for c in key_data):
            hex_str = key_data.decode('ascii')
            key_data = bytes.fromhex(hex_str)
            log_debug("Converted hex key string to bytes")
            print("Converted hex key string to bytes")
    except:
        pass  # Not a hex string, use as is
    
    # Ensure key is 32 bytes (256 bits) for AES-256
    if len(key_data) < 32:
        key_data = key_data.ljust(32, b'\0')  # Pad to 32 bytes
    
    # Truncate to 32 bytes maximum
    key_data = key_data[:32]
    log_debug(f"Final key: {key_data.hex()}")
    
    # Save key for debugging
    key_file = os.path.join(DATA_DIR, "key.bin")
    with open(key_file, "wb") as f:
        f.write(key_data)
    
    return key_data

def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        # Use a fixed IV for testing/debugging
        iv = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10'
        log_debug(f"Using IV: {iv.hex()}")
        
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
            
        # Save a complete package (IV + encrypted data) for debugging
        package_file = os.path.join(DATA_DIR, "encrypted_package.bin")
        with open(package_file, "wb") as f:
            f.write(iv + encrypted_data)
            
        log_debug(f"Original data: {data.hex() if len(data) <= 32 else data[:32].hex() + '...'}")
        log_debug(f"Encrypted data: {encrypted_data.hex() if len(encrypted_data) <= 32 else encrypted_data[:32].hex() + '...'}")
            
        # Prepend IV to the encrypted data for use in decryption
        return iv + encrypted_data
    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"Encryption error: {e}")
        sys.exit(1)

def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks of specified size."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data into {len(chunks)} chunks of max size {chunk_size}")
    
    # Save chunk details for debugging
    chunk_info = {i+1: {"size": len(chunk), "data": chunk.hex()} for i, chunk in enumerate(chunks)}
    chunks_json = os.path.join(LOGS_DIR, "chunks_info.json")
    with open(chunks_json, "w") as f:
        json.dump(chunk_info, f, indent=2)
        
    return chunks

def establish_connection(stego):
    """Establish connection with the receiver using three-way handshake."""
    global connection_established, stop_sniffing
    
    log_debug("Starting connection establishment...")
    print("[HANDSHAKE] Initiating connection with receiver...")
    
    # Start ACK listener thread
    stego.start_ack_listener()
    
    # Send SYN packet
    syn_packet = stego.create_syn_packet()
    log_debug("Sending SYN packet")
    print("[HANDSHAKE] Sending SYN packet...")
    
    # Send multiple times for reliability
    for i in range(10):
        send(syn_packet)
        time.sleep(0.2)
        
        # Check if connection established during wait
        if connection_established:
            log_debug("Connection established during SYN transmission")
            print("[HANDSHAKE] Connection established successfully")
            return True
    
    # Wait for the connection to be established
    max_wait = 30  # seconds
    start_time = time.time()
    
    while not connection_established and time.time() - start_time < max_wait:
        time.sleep(0.5)
        
        # Resend SYN occasionally
        if (time.time() - start_time) % 5 < 0.5:
            log_debug("Resending SYN packet")
            print("[HANDSHAKE] Resending SYN packet...")
            send(syn_packet)
    
    # Check if connection was established
    if connection_established:
        log_debug("Connection established successfully")
        print("[HANDSHAKE] Connection established successfully")
        return True
    else:
        log_debug("Failed to establish connection")
        print("[HANDSHAKE] Failed to establish connection with receiver")
        return False

def send_file(file_path, target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt and send a file via steganography."""
    global connection_established, stop_sniffing, acked_chunks
    
    # Initialize debug log
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
    # Create a summary file with transmission parameters
    summary = {
        "timestamp": time.time(),
        "file_path": file_path,
        "target_ip": target_ip,
        "key_path": key_path,
        "chunk_size": chunk_size,
        "delay": delay
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    # Reset global variables
    acked_chunks = set()
    connection_established = False
    stop_sniffing = False
    
    # Create steganography sender
    stego = SteganographySender(target_ip)
    
    # Establish connection before sending data
    if not establish_connection(stego):
        log_debug("Aborting transmission due to connection failure")
        print("[ERROR] Aborting transmission due to connection failure")
        stego.stop_ack_listener()
        return False
    
    # Read the input file
    log_debug(f"Reading file: {file_path}")
    print(f"[FILE] Reading: {file_path}")
    file_data = read_file(file_path, 'rb')
    print(f"[FILE] Read {len(file_data)} bytes successfully")
    
    # Print the content for debugging
    try:
        text_content = file_data.decode('utf-8')
        log_debug(f"File content (as text): {text_content}")
        
        # Save the text content as a text file
        text_file = os.path.join(DATA_DIR, "original_content.txt")
        with open(text_file, "w") as f:
            f.write(text_content)
    except UnicodeDecodeError:
        log_debug(f"File content (as hex): {file_data.hex()}")
    
    # Encrypt the data if key is provided
    if key_path:
        log_debug(f"Reading encryption key from: {key_path}")
        print(f"[ENCRYPT] Reading key from: {key_path}")
        key_data = read_file(key_path, 'rb')
        key = prepare_key(key_data)
        
        log_debug("Encrypting data...")
        print(f"[ENCRYPT] Starting encryption of {len(file_data)} bytes...")
        file_data = encrypt_data(file_data, key)
        log_debug(f"Data encrypted, size: {len(file_data)} bytes")
        print(f"[ENCRYPT] Completed encryption. Result size: {len(file_data)} bytes")
    
    # Add a simple checksum to verify integrity
    file_checksum = hashlib.md5(file_data).digest()
    log_debug(f"Generated MD5 checksum: {file_checksum.hex()}")
    print(f"[CHECKSUM] Generated MD5: {file_checksum.hex()}")
    file_data_with_checksum = file_data + file_checksum
    
    # Save the checksum and final data package for debugging
    checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
    with open(checksum_file, "wb") as f:
        f.write(file_checksum)
        
    final_package_file = os.path.join(DATA_DIR, "final_data_package.bin")
    with open(final_package_file, "wb") as f:
        f.write(file_data_with_checksum)
    
    # Chunk the data
    print(f"[PREP] Splitting data into chunks of size {chunk_size} bytes...")
    chunks = chunk_data(file_data_with_checksum, chunk_size)
    total_chunks = len(chunks)
    log_debug(f"File split into {total_chunks} chunks")
    print(f"[PREP] Data split into {total_chunks} chunks")
    
    # Send "problematic" chunks first with extra attention
    problem_chunks = [1, 4, 7]
    log_debug("Sending priority chunks first...")
    print("[PRIORITY] Sending priority chunks first...")
    for seq_num in problem_chunks:
        if seq_num <= total_chunks:
            chunk = chunks[seq_num-1]
            log_debug(f"Sending priority chunk {seq_num}")
            print(f"[PRIORITY] Sending chunk {seq_num:04d}/{total_chunks:04d}")
            
            # Send with acknowledgment system
            success = stego.send_chunk(chunk, seq_num, total_chunks)
            if success:
                print(f"[PRIORITY] Successfully sent chunk {seq_num:04d}")
            else:
                print(f"[PRIORITY] Warning: Chunk {seq_num:04d} may not have been received")
    
    # Now send all chunks in order with acknowledgment
    log_debug(f"Sending data to {target_ip}...")
    print(f"[TRANSMISSION] Starting data transmission to {target_ip}...")
    print(f"[INFO] Total chunks to send: {total_chunks}")

    transmission_success = True
    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Start from 1
        
        # Skip if it's a priority chunk (already sent with special attention)
        if seq_num in problem_chunks:
            print(f"[SKIP] Chunk {seq_num:04d} (already sent as priority)")
            continue
        
        # Send the chunk with acknowledgment
        print(f"[PROGRESS] Preparing chunk {seq_num:04d}/{total_chunks:04d}")
        success = stego.send_chunk(chunk, seq_num, total_chunks)
        
        # Print completion status
        progress = (seq_num / total_chunks) * 100
        if success:
            print(f"[STATUS] Completed chunk {seq_num:04d}/{total_chunks:04d} | Progress: {progress:.2f}%")
        else:
            print(f"[WARNING] Chunk {seq_num:04d} may not have been received | Progress: {progress:.2f}%")
            transmission_success = False
            
        # Add delay between packets
        time.sleep(delay)
    
    # Send completion signal
    completion_packet = stego.create_completion_packet()
    print("[COMPLETE] Sending transmission completion signals...")
    for i in range(10):  # Send multiple times to ensure receipt
        log_debug("Sending completion signal")
        print(f"[COMPLETE] Sending signal {i+1}/10")
        send(completion_packet)
        time.sleep(0.2)
    
    # Stop the ACK listener thread
    stop_sniffing = True
    stego.stop_ack_listener()
    
    # Calculate and log statistics
    ack_rate = (len(acked_chunks) / total_chunks) * 100 if total_chunks > 0 else 0
    log_debug(f"Transmission complete! ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks})")
    print(f"[STATS] ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks} chunks acknowledged)")
    
    if transmission_success:
        log_debug("Transmission completed successfully")
        print("[COMPLETE] Transmission successfully completed!")
    else:
        log_debug("Transmission completed with some unacknowledged chunks")
        print("[COMPLETE] Transmission completed with some unacknowledged chunks")
    
    # Save session completion info
    completion_info = {
        "completed_at": time.time(),
        "total_chunks_sent": total_chunks,
        "chunks_acknowledged": len(acked_chunks),
        "ack_rate": ack_rate,
        "status": "completed" if transmission_success else "partial"
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f:
        json.dump(completion_info, f, indent=2)
    
    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Simplified Network Steganography Sender')
    parser.add_argument('--target', '-t', required=True, help='Target IP address')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', help='Encryption key file (optional)')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets in seconds (default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE, 
                        help=f'Chunk size in bytes (default: {MAX_CHUNK_SIZE})')
    parser.add_argument('--output-dir', '-o', help='Custom output directory')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT, 
                        help=f'Timeout for waiting for ACK in seconds (default: {ACK_WAIT_TIMEOUT})')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS, 
                        help=f'Maximum retransmission attempts per chunk (default: {MAX_RETRANSMISSIONS})')
    return parser.parse_args()

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup output directory structure
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS
    if args.output_dir:
        OUTPUT_DIR = args.output_dir
    setup_directories()
    
    # Set ACK timeout and max retries
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    
    # Adjust chunk size if needed
    chunk_size = min(args.chunk_size, MAX_CHUNK_SIZE)
    if args.chunk_size > MAX_CHUNK_SIZE:
        print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE} (maximum supported)")
    
    # Send the file
    success = send_file(
        args.input,
        args.target,
        args.key,
        chunk_size,
        args.delay
    )
    
    # Exit with appropriate status
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()