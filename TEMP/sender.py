#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, conf

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
RETRANSMIT_ATTEMPTS = 5

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
    """Simple steganography sender using only TCP."""
    
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
        
    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with multiple attempts."""
        packet = self.create_packet(data, seq_num, total_chunks)
        
        # Log the chunk
        self.log_chunk(seq_num, data)
        
        # Send with multiple attempts
        attempts = RETRANSMIT_ATTEMPTS if seq_num in [1, 4, 7] else 3
        
        for attempt in range(attempts):
            log_debug(f"Sending chunk {seq_num}/{total_chunks} (attempt {attempt+1}/{attempts})")
            # Detailed progress output for each attempt
            print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Attempt: {attempt+1}/{attempts} | Progress: {(seq_num / total_chunks) * 100:.2f}%")
            send(packet)
            time.sleep(0.1)
        
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

def send_file(file_path, target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt and send a file via steganography."""
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
    
    # Create steganography sender
    stego = SteganographySender(target_ip)
    
    # Send "problematic" chunks first with extra attention
    problem_chunks = [1, 4, 7]
    log_debug("Sending priority chunks first...")
    print("[PRIORITY] Sending priority chunks first...")
    for seq_num in problem_chunks:
        if seq_num <= total_chunks:
            chunk = chunks[seq_num-1]
            log_debug(f"Sending priority chunk {seq_num}")
            print(f"[PRIORITY] Sending chunk {seq_num:04d}/{total_chunks:04d}")
            
            # Send multiple times with extra care
            for repeat in range(5):
                packet = stego.create_packet(chunk, seq_num, total_chunks)
                log_debug(f"Sending chunk {seq_num} (special attempt {repeat+1}/5)")
                print(f"[PRIORITY] Chunk {seq_num:04d} attempt {repeat+1}/5")
                send(packet)
                time.sleep(0.2)
            print(f"[PRIORITY] Completed sending chunk {seq_num:04d}")
    
    # Now send all chunks in order
    log_debug(f"Sending data to {target_ip}...")
    print(f"[TRANSMISSION] Starting data transmission to {target_ip}...")
    print(f"[INFO] Total chunks to send: {total_chunks}")

    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Start from 1
        
        # Skip if it's a priority chunk (already sent with special attention)
        if seq_num in problem_chunks:
            print(f"[SKIP] Chunk {seq_num:04d} (already sent as priority)")
            continue
        
        # Send the chunk
        print(f"[PROGRESS] Preparing chunk {seq_num:04d}/{total_chunks:04d}")
        stego.send_chunk(chunk, seq_num, total_chunks)
        
        # Print completion status
        progress = (seq_num / total_chunks) * 100
        print(f"[STATUS] Completed chunk {seq_num:04d}/{total_chunks:04d} | Progress: {progress:.2f}%")
            
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
    
    log_debug("Transmission complete!")
    print("[COMPLETE] Transmission successfully completed!")
    
    # Save session completion info
    completion_info = {
        "completed_at": time.time(),
        "total_chunks_sent": total_chunks,
        "status": "completed"
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f:
        json.dump(completion_info, f, indent=2)
    
    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    
    return True

# def send_file(file_path, target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
#     """Encrypt and send a file via steganography."""
#     # Initialize debug log
#     with open(DEBUG_LOG, "w") as f:
#         f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
#     # Create a summary file with transmission parameters
#     summary = {
#         "timestamp": time.time(),
#         "file_path": file_path,
#         "target_ip": target_ip,
#         "key_path": key_path,
#         "chunk_size": chunk_size,
#         "delay": delay
#     }
#     summary_path = os.path.join(LOGS_DIR, "session_summary.json")
#     with open(summary_path, "w") as f:
#         json.dump(summary, f, indent=2)
    
#     # Read the input file
#     log_debug(f"Reading file: {file_path}")
#     print(f"Reading file: {file_path}")
#     file_data = read_file(file_path, 'rb')
#     print(f"Read {len(file_data)} bytes")
    
#     # Print the content for debugging
#     try:
#         text_content = file_data.decode('utf-8')
#         log_debug(f"File content (as text): {text_content}")
        
#         # Save the text content as a text file
#         text_file = os.path.join(DATA_DIR, "original_content.txt")
#         with open(text_file, "w") as f:
#             f.write(text_content)
#     except UnicodeDecodeError:
#         log_debug(f"File content (as hex): {file_data.hex()}")
    
#     # Encrypt the data if key is provided
#     if key_path:
#         log_debug(f"Reading encryption key from: {key_path}")
#         print(f"Reading encryption key from: {key_path}")
#         key_data = read_file(key_path, 'rb')
#         key = prepare_key(key_data)
        
#         log_debug("Encrypting data...")
#         print("Encrypting data...")
#         file_data = encrypt_data(file_data, key)
#         log_debug(f"Data encrypted, size: {len(file_data)} bytes")
#         print(f"Data encrypted, size: {len(file_data)} bytes")
    
#     # Add a simple checksum to verify integrity
#     file_checksum = hashlib.md5(file_data).digest()
#     log_debug(f"Generated MD5 checksum: {file_checksum.hex()}")
#     file_data_with_checksum = file_data + file_checksum
    
#     # Save the checksum and final data package for debugging
#     checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
#     with open(checksum_file, "wb") as f:
#         f.write(file_checksum)
        
#     final_package_file = os.path.join(DATA_DIR, "final_data_package.bin")
#     with open(final_package_file, "wb") as f:
#         f.write(file_data_with_checksum)
    
#     # Chunk the data
#     chunks = chunk_data(file_data_with_checksum, chunk_size)
#     total_chunks = len(chunks)
#     log_debug(f"File split into {total_chunks} chunks")
#     print(f"File split into {total_chunks} chunks")
    
#     # Create steganography sender
#     stego = SteganographySender(target_ip)
    
#     # Send "problematic" chunks first with extra attention
#     problem_chunks = [1, 4, 7]
#     log_debug("Sending priority chunks first...")
#     for seq_num in problem_chunks:
#         if seq_num <= total_chunks:
#             chunk = chunks[seq_num-1]
#             log_debug(f"Sending priority chunk {seq_num}")
            
#             # Send multiple times with extra care
#             for repeat in range(5):
#                 packet = stego.create_packet(chunk, seq_num, total_chunks)
#                 log_debug(f"Sending chunk {seq_num} (special attempt {repeat+1}/5)")
#                 send(packet)
#                 time.sleep(0.2)
    
#     # Now send all chunks in order
#     log_debug(f"Sending data to {target_ip}...")
#     print(f"Sending data to {target_ip}...")
#     for i, chunk in enumerate(chunks):
#         seq_num = i + 1  # Start from 1
        
#         # Skip if it's a priority chunk (already sent with special attention)
#         if seq_num in problem_chunks:
#             continue
        
#         # Send the chunk
#         stego.send_chunk(chunk, seq_num, total_chunks)
        
#         # Print progress
#         if i % 5 == 0 or i == total_chunks - 1:
#             progress = (i+1) / total_chunks * 100
#             log_debug(f"Progress: {i+1}/{total_chunks} chunks sent ({progress:.1f}%)")
#             print(f"Progress: {i+1}/{total_chunks} chunks sent ({progress:.1f}%)")
            
#         # Add delay between packets
#         time.sleep(delay)
    
#     # Send completion signal
#     completion_packet = stego.create_completion_packet()
#     for _ in range(10):  # Send multiple times to ensure receipt
#         log_debug("Sending completion signal")
#         send(completion_packet)
#         time.sleep(0.2)
    
#     log_debug("Transmission complete!")
#     print("Transmission complete!")
    
#     # Save session completion info
#     completion_info = {
#         "completed_at": time.time(),
#         "total_chunks_sent": total_chunks,
#         "status": "completed"
#     }
#     completion_path = os.path.join(LOGS_DIR, "completion_info.json")
#     with open(completion_path, "w") as f:
#         json.dump(completion_info, f, indent=2)
    
#     print(f"All session data saved to: {SESSION_DIR}")
    
#     return True

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
    return parser.parse_args()

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
    # Setup output directory structure
    global OUTPUT_DIR
    if args.output_dir:
        OUTPUT_DIR = args.output_dir
    setup_directories()
    
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