#!/usr/bin/env python3
"""
CrypticRoute - Network Steganography Receiver
Captures and extracts hidden data from IPv4 packets.
"""

import sys
import os
import argparse
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, ICMP, Raw, sniff, conf

# Configure Scapy settings
conf.verb = 0  # Suppress Scapy output

# Global variables to store chunks
received_chunks = {}
total_chunks = 0
start_time = 0

def read_key(key_path):
    """Read the key file and ensure it's the correct length for AES."""
    try:
        with open(key_path, 'rb') as file:
            key = file.read()
    except FileNotFoundError:
        print(f"Error: Key file not found: {key_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading key file {key_path}: {e}")
        sys.exit(1)
    
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

def decrypt(data, key):
    """Decrypt data using AES."""
    try:
        # Check if data is long enough to contain the IV
        if len(data) < 16:
            print("Error: Encrypted data is too short (missing IV)")
            return None
            
        # Extract IV from the beginning of the data
        iv = data[:16]
        encrypted_data = data[16:]
        
        # Initialize AES cipher with key and extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        return decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def packet_handler(packet):
    """Handle incoming packets with steganographic data."""
    global received_chunks, total_chunks, start_time
    
    # Check if packet has IP and ICMP layers
    if not (IP in packet and ICMP in packet):
        return
    
    # We only want ICMP echo requests (type 8)
    if packet[ICMP].type != 8:
        return
    
    # Get the IP ID field (sequence number)
    seq_num = packet[IP].id
    
    # Skip packets with seq_num 0 - potentially regular ping packets
    if seq_num == 0:
        return
    
    # Check for end marker packet
    if seq_num == 0xFFFF and Raw in packet and packet[Raw].load == b"ENDMARKER":
        print("\nReceived end marker packet. Finishing transmission.")
        # Set a flag to stop sniffing
        return True
    
    # Get total chunks from ToS field if we haven't set it yet
    if total_chunks == 0 and packet[IP].tos > 0:
        total_chunks = packet[IP].tos
        start_time = time.time()
        print(f"Detected transmission with {total_chunks} total chunks")
    
    # Extract payload if present
    if Raw in packet:
        # Store the chunk with its sequence number
        payload = bytes(packet[Raw].load)
        received_chunks[seq_num] = payload
        
        # Print progress
        chunks_received = len(received_chunks)
        if chunks_received % 50 == 0 or (total_chunks > 0 and chunks_received == total_chunks):
            if total_chunks > 0:
                progress = (chunks_received / total_chunks) * 100
                print(f"Progress: {chunks_received}/{total_chunks} chunks received ({progress:.1f}%)")
            else:
                print(f"Received {chunks_received} chunks so far")
    
    # If we've received all chunks, we can stop sniffing
    if total_chunks > 0 and len(received_chunks) >= total_chunks:
        elapsed = time.time() - start_time
        print(f"\nReceived all {total_chunks} chunks in {elapsed:.2f} seconds!")
        return True

def reassemble_data():
    """Reassemble the received chunks in correct order."""
    if not received_chunks:
        return None
    
    # Sort chunks by sequence number
    sorted_seq_nums = sorted(received_chunks.keys())
    if not sorted_seq_nums:
        return None
        
    # Verify sequence continuity
    expected_seq = sorted_seq_nums[0]
    missing_seqs = []
    
    for seq in sorted_seq_nums:
        if seq != expected_seq:
            # Found a gap
            missing_seqs.extend(range(expected_seq, seq))
        expected_seq = seq + 1
    
    if missing_seqs:
        print(f"Warning: Missing {len(missing_seqs)} sequence numbers: {missing_seqs}")
    
    # Get chunks in sequence order
    sorted_chunks = [received_chunks[seq] for seq in sorted_seq_nums]
    
    # Debug: Print chunk sizes
    print(f"Chunk sizes: {[len(chunk) for chunk in sorted_chunks]}")
    
    # Concatenate all chunks
    result = b"".join(sorted_chunks)
    print(f"Reassembled data size: {len(result)} bytes")
    
    return result

def save_to_file(data, output_path):
    """Save data to a file."""
    try:
        with open(output_path, 'wb') as file:
            file.write(data)
        print(f"Data saved to {output_path}")
        return True
    except Exception as e:
        print(f"Error saving data to {output_path}: {e}")
        return False

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Network Steganography Receiver')
    parser.add_argument('--interface', '-i', help='Network interface to listen on')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption key file')
    parser.add_argument('--timeout', '-t', type=int, default=60, help='Timeout in seconds (default: 60)')
    parser.add_argument('--filter', '-f', default="icmp", help='BPF filter for packet capture (default: icmp)')
    return parser.parse_args()

def main():
    """Main function."""
    global received_chunks, total_chunks
    
    args = parse_arguments()
    
    # Read encryption key
    print(f"Reading key file: {args.key}")
    key = read_key(args.key)
    
    # For compatibility with the provided AES_Library_With_Chunker code
    # Check if key is a hex string and convert if needed
    if all(c in '0123456789abcdefABCDEF' for c in key.decode('ascii', errors='ignore')):
        try:
            key = bytes.fromhex(key.decode('ascii'))
            print("Converted hex key string to bytes")
        except Exception as e:
            print(f"Warning: Failed to convert key as hex: {e}")
    
    # Reset global variables
    received_chunks = {}
    total_chunks = 0
    
    print(f"Listening for steganographic data on interface {args.interface or 'default'}...")
    print(f"Using filter: {args.filter}")
    print("Press Ctrl+C to stop listening prematurely")
    
    try:
        # Start packet capture
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_handler,
            store=0,
            timeout=args.timeout,
            stop_filter=lambda p: packet_handler(p) is True
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user")
    
    # Check if we captured any chunks
    if not received_chunks:
        print("No data chunks received!")
        return
    
    print(f"Received {len(received_chunks)} chunks in total")
    
    # Reassemble the data
    print("Reassembling data...")
    reassembled_data = reassemble_data()
    
    if not reassembled_data:
        print("Failed to reassemble data!")
        return
    
    # Decrypt the data
    print("Decrypting data...")
    decrypted_data = decrypt(reassembled_data, key)
    
    if not decrypted_data:
        print("Failed to decrypt data!")
        
        # Debug output in hex to help diagnose issues
        print("\nData debug (first 128 bytes in hex):")
        hex_data = reassembled_data[:128].hex()
        print(' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2)))
        return
    
    print(f"Successfully decrypted {len(decrypted_data)} bytes")
    
    # Try to decode as text and print a sample
    try:
        sample = decrypted_data[:100].decode('utf-8')
        print(f"Sample of decrypted text: {sample}")
    except UnicodeDecodeError:
        print("Decrypted data is not valid UTF-8 text")
    
    # Save to file
    save_to_file(decrypted_data, args.output)

if __name__ == "__main__":
    main()