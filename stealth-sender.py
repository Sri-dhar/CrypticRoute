#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
"""

import sys
import os
import argparse
import time
import random
import hashlib
import json
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, conf

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
RETRANSMIT_ATTEMPTS = 5

# Debug log file
DEBUG_LOG = "sender_debug.log"

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
        with open("sent_chunks.json", "w") as f:
            f.write("{}")
        self.sent_chunks = {}

    def log_chunk(self, seq_num, data):
        """Save chunk data to debug file."""
        self.sent_chunks[str(seq_num)] = {
            "data": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }
        with open("sent_chunks.json", "w") as f:
            json.dump(self.sent_chunks, f, indent=2)
    
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
    
    return key_data

def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        # Use a fixed IV for testing/debugging
        iv = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10'
        log_debug(f"Using IV: {iv.hex()}")
        
        # Initialize AES cipher with key and IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Save original and encrypted data for debugging
        with open("original_data.bin", "wb") as f:
            f.write(data)
        
        with open("encrypted_data.bin", "wb") as f:
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
    with open("chunks.json", "w") as f:
        json.dump(chunk_info, f, indent=2)
        
    return chunks

def send_file(file_path, target_ip, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Encrypt and send a file via steganography."""
    # Initialize debug log
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
    # Read the input file
    log_debug(f"Reading file: {file_path}")
    print(f"Reading file: {file_path}")
    file_data = read_file(file_path, 'rb')
    print(f"Read {len(file_data)} bytes")
    
    # Print the content for debugging
    try:
        text_content = file_data.decode('utf-8')
        log_debug(f"File content (as text): {text_content}")
    except UnicodeDecodeError:
        log_debug(f"File content (as hex): {file_data.hex()}")
    
    # Encrypt the data if key is provided
    if key_path:
        log_debug(f"Reading encryption key from: {key_path}")
        print(f"Reading encryption key from: {key_path}")
        key_data = read_file(key_path, 'rb')
        key = prepare_key(key_data)
        
        log_debug("Encrypting data...")
        print("Encrypting data...")
        file_data = encrypt_data(file_data, key)
        log_debug(f"Data encrypted, size: {len(file_data)} bytes")
        print(f"Data encrypted, size: {len(file_data)} bytes")
    
    # Add a simple checksum to verify integrity
    file_checksum = hashlib.md5(file_data).digest()
    log_debug(f"Generated MD5 checksum: {file_checksum.hex()}")
    file_data = file_data + file_checksum
    
    # Save the final data package for debugging
    with open("final_data_package.bin", "wb") as f:
        f.write(file_data)
    
    # Chunk the data
    chunks = chunk_data(file_data, chunk_size)
    total_chunks = len(chunks)
    log_debug(f"File split into {total_chunks} chunks")
    print(f"File split into {total_chunks} chunks")
    
    # Create steganography sender
    stego = SteganographySender(target_ip)
    
    # Send "problematic" chunks first with extra attention
    problem_chunks = [1, 4, 7]
    log_debug("Sending priority chunks first...")
    for seq_num in problem_chunks:
        if seq_num <= total_chunks:
            chunk = chunks[seq_num-1]
            log_debug(f"Sending priority chunk {seq_num}")
            
            # Send multiple times with extra care
            for repeat in range(5):
                packet = stego.create_packet(chunk, seq_num, total_chunks)
                log_debug(f"Sending chunk {seq_num} (special attempt {repeat+1}/5)")
                send(packet)
                time.sleep(0.2)
    
    # Now send all chunks in order
    log_debug(f"Sending data to {target_ip}...")
    print(f"Sending data to {target_ip}...")
    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Start from 1
        
        # Skip if it's a priority chunk (already sent with special attention)
        if seq_num in problem_chunks:
            continue
        
        # Send the chunk
        stego.send_chunk(chunk, seq_num, total_chunks)
        
        # Print progress
        if i % 5 == 0 or i == total_chunks - 1:
            progress = (i+1) / total_chunks * 100
            log_debug(f"Progress: {i+1}/{total_chunks} chunks sent ({progress:.1f}%)")
            print(f"Progress: {i+1}/{total_chunks} chunks sent ({progress:.1f}%)")
            
        # Add delay between packets
        time.sleep(delay)
    
    # Send completion signal
    completion_packet = stego.create_completion_packet()
    for _ in range(10):  # Send multiple times to ensure receipt
        log_debug("Sending completion signal")
        send(completion_packet)
        time.sleep(0.2)
    
    log_debug("Transmission complete!")
    print("Transmission complete!")
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
    return parser.parse_args()

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
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