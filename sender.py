#!/usr/bin/env python3
"""
CrypticRoute - Network Steganography Sender
Hides and sends data through IPv4 packets using Scapy.
"""

import sys
import os
import argparse
import time
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, ICMP, Raw, Ether, send, conf

# Configure Scapy settings
conf.verb = 0  # Suppress Scapy output

def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def read_key(key_path):
    """Read the key file and ensure it's the correct length for AES."""
    key = read_file(key_path, 'rb')
    
    # Adjust key length if needed (truncate or pad)
    if len(key) < 16:
        # Pad to 16 bytes (128 bits)
        key = key.ljust(16, b'\0')
    elif 16 < len(key) < 24:
        # Pad to 24 bytes (192 bits)
        key = key.ljust(24, b'\0')
    elif 24 < len(key) < 32:
        # Pad to 32 bytes (256 bits)
        key = key.ljust(32, b'\0')
    
    # Truncate to 32 bytes maximum (256 bits)
    return key[:32]

def encrypt(data, key):
    """Encrypt data using AES."""
    try:
        # Initialize AES cipher with key and IV
        iv = os.urandom(16)  # Generate a random 16-byte initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Prepend IV to the encrypted data for use in decryption
        return iv + encrypted_data
    except Exception as e:
        print(f"Encryption error: {e}")
        sys.exit(1)

def chunk_data(data, chunk_size=8):
    """Split data into chunks of specified size."""
    return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]

def embed_in_ipv4(chunk, target_ip, sequence_num, total_chunks):
    """Embed data chunk in IPv4 packet and send it."""
    # Convert the chunk to bytes if it's not already
    if not isinstance(chunk, bytes):
        chunk = bytes(chunk)
    
    # Create packet with ID field containing sequence number
    # ID field is 16 bits, so we can use it to indicate chunk sequence
    packet = IP(dst=target_ip, id=sequence_num) / ICMP() / Raw(load=chunk)
    
    # ToS field (8 bits) can be used to indicate total number of chunks
    # Limited to 255 chunks with this method
    if total_chunks <= 255:
        packet[IP].tos = total_chunks
    
    # Add a small TTL variation for additional data hiding
    # This can also be used to encode information
    packet[IP].ttl = 64 + (sequence_num % 5)
    
    return packet

def send_steganographic_data(data, target_ip, chunk_size=8, delay=0.05):
    """Encrypt, chunk, and send data via IPv4 steganography."""
    # Chunk the encrypted data
    chunks = chunk_data(data, chunk_size)
    total_chunks = len(chunks)
    
    if total_chunks > 65535:
        print(f"Error: Data too large for IP ID field chunking ({total_chunks} chunks)")
        return False
    
    print(f"Sending {total_chunks} chunks to {target_ip}...")
    
    # Send each chunk in a separate packet
    for i, chunk in enumerate(chunks):
        # Sequence number starts at 1
        seq_num = i + 1
        
        # Create and send the packet
        packet = embed_in_ipv4(chunk, target_ip, seq_num, total_chunks)
        send(packet)
        
        # Print progress
        if (i + 1) % 50 == 0 or i + 1 == total_chunks:
            print(f"Progress: {i + 1}/{total_chunks} chunks sent")
        
        # Add delay between packets to avoid flooding
        time.sleep(delay)
    
    # Send end marker packet
    end_marker = IP(dst=target_ip, id=0xFFFF, tos=0xFF) / ICMP() / Raw(load=b"ENDMARKER")
    send(end_marker)
    
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Network Steganography Sender')
    parser.add_argument('--target', '-t', required=True, help='Target IP address')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=True, help='Encryption key file')
    parser.add_argument('--chunk-size', '-c', type=int, default=8, help='Chunk size in bytes (default: 8)')
    parser.add_argument('--delay', '-d', type=float, default=0.05, help='Delay between packets in seconds (default: 0.05)')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Read input file
    print(f"Reading input file: {args.input}")
    input_data = read_file(args.input, 'rb')
    print(f"Read {len(input_data)} bytes")
    
    # Read encryption key
    print(f"Reading key file: {args.key}")
    key = read_key(args.key)
    
    # Encrypt the data
    print("Encrypting data...")
    encrypted_data = encrypt(input_data, key)
    print(f"Data encrypted, total size: {len(encrypted_data)} bytes")
    
    # Send the encrypted data via IPv4 steganography
    success = send_steganographic_data(
        encrypted_data, 
        args.target, 
        chunk_size=args.chunk_size,
        delay=args.delay
    )
    
    if success:
        print("Data sent successfully!")
    else:
        print("Failed to send data!")

if __name__ == "__main__":
    main()