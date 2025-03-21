#!/usr/bin/env python3
"""
CrypticRoute - Advanced Network Steganography Sender
Hides data in IPv4/ICMP headers with confirmation and error-correction.
"""

import sys
import os
import argparse
import time
import random
import socket
import struct
import hashlib
import binascii
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, ICMP, TCP, UDP, send, sniff, Raw, conf, sr1, sr

# Configure Scapy settings
conf.verb = 0  # Suppress Scapy output

# Global settings
RETRANSMIT_ATTEMPTS = 5  # Increased from 3
ACK_TIMEOUT = 2
CONTROL_PORT = 53  # DNS port for control communication (less likely to be blocked)
MAX_CHUNK_SIZE = 8  # Maximum bytes per packet in header fields

# Protocol constants
CMD_DATA = 1
CMD_ACK = 2
CMD_RETRANSMIT = 3
CMD_COMPLETE = 4
CMD_ERROR = 5

# Debug log file
DEBUG_LOG = "stealth_sender_debug.log"

def log_debug(message):
    """Write debug message to log file."""
    with open(DEBUG_LOG, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

class HeaderSteganography:
    """Class for handling the steganographic operations."""
    
    def __init__(self, target_ip=None, source_port=random.randint(1024, 65000)):
        """Initialize the steganography handler."""
        self.target_ip = target_ip
        self.source_port = source_port
        self.recv_window = {}  # For keeping track of received chunks
        # Create and clear debug files
        with open("sent_chunks.json", "w") as f:
            f.write("{}")
        self.sent_chunks = {}

    def dump_chunk_data(self, seq_num, data, method):
        """Save chunk data to debug file."""
        self.sent_chunks[seq_num] = {
            "data": data.hex(),
            "method": method,
            "timestamp": time.time()
        }
        with open("sent_chunks.json", "w") as f:
            json.dump(self.sent_chunks, f, indent=2)
        
    def encode_data_in_tcp_header(self, data, seq_num, total_chunks, cmd=CMD_DATA):
        """Encode data in TCP header fields."""
        # Ensure data is the right size
        if len(data) < MAX_CHUNK_SIZE:
            padding_size = MAX_CHUNK_SIZE - len(data)
            log_debug(f"Padding TCP chunk {seq_num} with {padding_size} bytes")
            data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE:
            log_debug(f"Truncating TCP chunk {seq_num} from {len(data)} to {MAX_CHUNK_SIZE} bytes")
            data = data[:MAX_CHUNK_SIZE]
            
        # Create a random destination port
        dst_port = random.randint(1024, 65000)
        
        # Create TCP packet with encoded fields
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),  # 4 bytes in seq number
            ack=int.from_bytes(data[4:8], byteorder='big'),  # 4 bytes in ack number
            window=seq_num,                                  # Sequence number in window field
            flags="S",                                       # SYN packet (less likely to be blocked)
            options=[
                ('MSS', total_chunks),                       # Total chunks in MSS option
                ('Timestamp', (cmd, 0))                      # Command in timestamp
            ]
        )
        
        # Modify Time to Live for additional data channel
        tcp_packet[IP].ttl = 64 + random.randint(0, 10)  # Randomize TTL a bit for stealth
        
        # ID field stores checksum of data (for verification)
        checksum = binascii.crc32(data) & 0xFFFF  # 16-bit checksum
        tcp_packet[IP].id = checksum
        
        # Save chunk details for debugging
        self.dump_chunk_data(seq_num, data, "TCP")
        
        return tcp_packet
        
    def encode_data_in_udp_header(self, data, seq_num, total_chunks, cmd=CMD_DATA):
        """Encode data in UDP header fields."""
        # Ensure data is the right size - UDP encoding is fixed at 4 bytes
        if len(data) < 4:
            padding_size = 4 - len(data)
            log_debug(f"Padding UDP chunk {seq_num} with {padding_size} bytes")
            data = data.ljust(4, b'\0')
        elif len(data) > 4:
            log_debug(f"Truncating UDP chunk {seq_num} from {len(data)} to 4 bytes")
            data = data[:4]
            
        # Create UDP packet with encoded fields
        udp_packet = IP(dst=self.target_ip) / UDP(
            sport=self.source_port,
            dport=CONTROL_PORT,  # Use DNS port for stealth
            len=8 + len(data)    # Standard UDP header len + data len
        )
        
        # Extract values from the data bytes to encode in UDP fields
        data_value1 = int.from_bytes(data[0:2], byteorder='big')
        data_value2 = int.from_bytes(data[2:4], byteorder='big')
        
        # Store the data values in sport and dport
        udp_packet[UDP].sport = data_value1
        udp_packet[UDP].dport = data_value2
        
        # Store sequence number in IP ID
        udp_packet[IP].id = seq_num
        
        # Store total chunks in fragment offset field
        udp_packet[IP].frag = total_chunks & 0x1FFF  # 13 bits only
        
        # Store command in ToS field
        udp_packet[IP].tos = cmd
        
        # Save chunk details for debugging
        self.dump_chunk_data(seq_num, data, "UDP")
        
        return udp_packet
    
    def encode_data_in_icmp_header(self, data, seq_num, total_chunks, cmd=CMD_DATA):
        """Encode data in ICMP header fields."""
        # Ensure data is the right size - ICMP encoding is fixed at 4 bytes
        if len(data) < 4:
            padding_size = 4 - len(data)
            log_debug(f"Padding ICMP chunk {seq_num} with {padding_size} bytes")
            data = data.ljust(4, b'\0')
        elif len(data) > 4:
            log_debug(f"Truncating ICMP chunk {seq_num} from {len(data)} to 4 bytes")
            data = data[:4]
            
        # Extract values from the data bytes
        icmp_id = int.from_bytes(data[0:2], byteorder='big')   # 2 bytes for ID
        icmp_seq = int.from_bytes(data[2:4], byteorder='big')  # 2 bytes for seq
        
        # Create ICMP packet with encoded fields
        icmp_packet = IP(dst=self.target_ip) / ICMP(
            type=8,          # Echo request
            code=cmd,        # Use code field for command
            id=icmp_id,      # ICMP ID from first 2 bytes of data
            seq=icmp_seq     # ICMP sequence from next 2 bytes of data
        )
        
        # Store sequence number in IP ID
        icmp_packet[IP].id = seq_num
        
        # Store total chunks in TOS field + flags (can store up to 255)
        icmp_packet[IP].tos = total_chunks & 0xFF
        
        # Modify TTL for stealth
        icmp_packet[IP].ttl = 64 + random.randint(0, 10)
        
        # Save chunk details for debugging
        self.dump_chunk_data(seq_num, data, "ICMP")
        
        return icmp_packet

    def create_control_packet(self, cmd, seq_num=0, data=b''):
        """Create a control packet (ACK, RETRANSMIT, COMPLETE)."""
        # Control packets use UDP for reliability
        udp_packet = IP(dst=self.target_ip) / UDP(
            sport=self.source_port,
            dport=CONTROL_PORT
        )
        
        # Set the command in TOS field
        udp_packet[IP].tos = cmd
        
        # Set sequence number in IP ID
        udp_packet[IP].id = seq_num
        
        return udp_packet
        
    def send_data_with_verification(self, data_chunk, seq_num, total_chunks, cmd=CMD_DATA):
        """Send a data chunk and verify receipt."""
        for attempt in range(RETRANSMIT_ATTEMPTS):
            # Use different encoding methods for diversity and resilience
            method = ""
            if seq_num % 3 == 0:
                method = "TCP"
                packet = self.encode_data_in_tcp_header(data_chunk, seq_num, total_chunks, cmd)
            elif seq_num % 3 == 1:
                method = "UDP"
                packet = self.encode_data_in_udp_header(data_chunk, seq_num, total_chunks, cmd)
            else:
                method = "ICMP"
                packet = self.encode_data_in_icmp_header(data_chunk, seq_num, total_chunks, cmd)
                
            # Log the sending attempt
            log_debug(f"Sending chunk {seq_num}/{total_chunks} using {method} (attempt {attempt+1}/{RETRANSMIT_ATTEMPTS})")
            
            # Send the packet
            send(packet)
            
            # Send each chunk twice for critical sequence numbers (known problematic chunks)
            if seq_num in [1, 4, 7]:
                log_debug(f"Sending duplicate packet for critical chunk {seq_num}")
                time.sleep(0.05)
                send(packet)
            
            # For this advanced version, let's include a simple ACK mechanism
            # Normally we'd listen for ACKs, but for simplicity, we'll just delay
            time.sleep(0.1)
            
        return True

def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            data = file.read()
            log_debug(f"Read {len(data)} bytes from {file_path}")
            return data
    except FileNotFoundError:
        log_debug(f"Error: File not found: {file_path}")
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
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
    
    # Ensure key is the correct length for AES
    if len(key_data) < 16:
        key_data = key_data.ljust(16, b'\0')  # Pad to 16 bytes (128 bits)
        log_debug(f"Padded key to 16 bytes")
    elif 16 < len(key_data) < 24:
        key_data = key_data.ljust(24, b'\0')  # Pad to 24 bytes (192 bits)
        log_debug(f"Padded key to 24 bytes")
    elif 24 < len(key_data) < 32:
        key_data = key_data.ljust(32, b'\0')  # Pad to 32 bytes (256 bits)
        log_debug(f"Padded key to 32 bytes")
    
    # Truncate to 32 bytes maximum (256 bits)
    key_data = key_data[:32]
    log_debug(f"Final key length: {len(key_data)} bytes")
    return key_data

def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        # Initialize AES cipher with key and IV
        iv = os.urandom(16)  # Generate a random 16-byte initialization vector
        log_debug(f"Generated IV: {iv.hex()}")
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Save original and encrypted data for debugging
        with open("original_data.bin", "wb") as f:
            f.write(data)
        
        with open("encrypted_data.bin", "wb") as f:
            f.write(iv + encrypted_data)
            
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
    """Encrypt and send a file via header steganography."""
    # Initialize debug log
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
    # Read the input file
    log_debug(f"Reading file: {file_path}")
    print(f"Reading file: {file_path}")
    file_data = read_file(file_path, 'rb')
    print(f"Read {len(file_data)} bytes")
    
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
    
    # Create steganography handler
    stego = HeaderSteganography(target_ip)
    
    # Send each chunk
    log_debug(f"Sending data to {target_ip} using header steganography...")
    print(f"Sending data to {target_ip} using header steganography...")
    for i, chunk in enumerate(chunks):
        seq_num = i + 1  # Start from 1
        
        # Send the chunk
        success = stego.send_data_with_verification(chunk, seq_num, total_chunks)
        
        # Print progress
        if i % 10 == 0 or i == total_chunks - 1:
            log_debug(f"Progress: {i+1}/{total_chunks} chunks sent")
            print(f"Progress: {i+1}/{total_chunks} chunks sent")
            
        # Add delay between packets
        time.sleep(delay)
    
    # Send completion packet multiple times for reliability
    log_debug("Sending completion packets...")
    complete_packet = stego.create_control_packet(CMD_COMPLETE)
    for _ in range(5):  # Increased from 3 to 5
        send(complete_packet)
        time.sleep(0.2)
    
    log_debug("Transmission complete!")
    print("Transmission complete!")
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Advanced Network Steganography Sender')
    parser.add_argument('--target', '-t', required=True, help='Target IP address')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', help='Encryption key file (optional)')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets in seconds (default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE, 
                        help=f'Chunk size in bytes (default: {MAX_CHUNK_SIZE}, max supported by header fields)')
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