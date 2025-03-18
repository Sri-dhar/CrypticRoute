#!/usr/bin/env python3
"""
CrypticRoute - Advanced Network Steganography Receiver
Extracts hidden data from IPv4/ICMP/TCP/UDP headers with verification.
"""

import sys
import os
import argparse
import time
import socket
import hashlib
import binascii
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, ICMP, TCP, UDP, Raw, sniff, conf, get_if_addr, send

# Configure Scapy settings
conf.verb = 0  # Suppress Scapy output

# Global settings
CONTROL_PORT = 53  # DNS port for control communication
MAX_CHUNK_SIZE = 8  # Maximum bytes per packet in header fields
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size in bytes

# Protocol constants
CMD_DATA = 1
CMD_ACK = 2
CMD_RETRANSMIT = 3
CMD_COMPLETE = 4
CMD_ERROR = 5

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0

class HeaderSteganography:
    """Class for handling the steganographic operations."""
    
    def __init__(self):
        """Initialize the steganography handler."""
        self.recv_window = {}  # For keeping track of received chunks
        
    def extract_data_from_tcp_header(self, packet):
        """Extract data from TCP header fields."""
        if IP in packet and TCP in packet:
            # Extract command from timestamp option
            cmd = None
            for option in packet[TCP].options:
                if option[0] == 'Timestamp':
                    cmd = option[1][0]  # First value in timestamp tuple is command
            
            # If not a command we recognize, ignore
            if cmd not in [CMD_DATA, CMD_COMPLETE]:
                return None, None, None, None
                
            # Extract sequence number from window field
            seq_num = packet[TCP].window
            
            # Extract total chunks from MSS option
            total_chunks = None
            for option in packet[TCP].options:
                if option[0] == 'MSS':
                    total_chunks = option[1]
            
            # Extract data from sequence and acknowledge numbers
            seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
            ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
            data = seq_bytes + ack_bytes
            
            # Extract checksum from IP ID
            checksum = packet[IP].id
            
            # Verify checksum
            calc_checksum = binascii.crc32(data) & 0xFFFF
            if checksum != calc_checksum:
                print(f"Warning: Checksum mismatch for TCP packet {seq_num}")
            
            return data, seq_num, total_chunks, cmd
        
        return None, None, None, None
    
    def extract_data_from_udp_header(self, packet):
        """Extract data from UDP header fields."""
        if IP in packet and UDP in packet:
            # Skip packets not on our control port
            if packet[UDP].dport != CONTROL_PORT:
                return None, None, None, None
                
            # Extract command from ToS field
            cmd = packet[IP].tos
            
            # If not a command we recognize, ignore
            if cmd not in [CMD_DATA, CMD_COMPLETE]:
                return None, None, None, None
                
            # Extract sequence number from IP ID
            seq_num = packet[IP].id
            
            # Extract total chunks from fragment offset field
            total_chunks = packet[IP].frag
            
            # For UDP, we've encoded limited data
            # Only using 4 bytes (combination of len and src port)
            sport_bytes = packet[UDP].sport.to_bytes(2, byteorder='big')
            len_bytes = packet[UDP].len.to_bytes(2, byteorder='big')
            data = sport_bytes + len_bytes
            
            return data, seq_num, total_chunks, cmd
            
        return None, None, None, None
    
    def extract_data_from_icmp_header(self, packet):
        """Extract data from ICMP header fields."""
        if IP in packet and ICMP in packet:
            # Only process Echo Request packets (type 8)
            if packet[ICMP].type != 8:
                return None, None, None, None
                
            # Extract command from code field
            cmd = packet[ICMP].code
            
            # If not a command we recognize, ignore
            if cmd not in [CMD_DATA, CMD_COMPLETE]:
                return None, None, None, None
                
            # Extract sequence number from IP ID
            seq_num = packet[IP].id
            
            # Extract total chunks from TOS field
            total_chunks = packet[IP].tos
            
            # Extract data from ICMP ID and sequence number
            id_bytes = packet[ICMP].id.to_bytes(2, byteorder='big')
            seq_bytes = packet[ICMP].seq.to_bytes(2, byteorder='big')
            data = id_bytes + seq_bytes
            
            return data, seq_num, total_chunks, cmd
            
        return None, None, None, None
        
    def process_packet(self, packet):
        """Process a packet to extract steganographic data."""
        global received_chunks, transmission_complete, reception_start_time, last_activity_time, highest_seq_num
        
        # Update last activity time
        last_activity_time = time.time()
        
        # Try to extract data using different methods
        data, seq_num, total_chunks, cmd = self.extract_data_from_tcp_header(packet)
        
        if data is None:
            data, seq_num, total_chunks, cmd = self.extract_data_from_udp_header(packet)
            
        if data is None:
            data, seq_num, total_chunks, cmd = self.extract_data_from_icmp_header(packet)
            
        if data is None or seq_num is None:
            return False
            
        # Process command
        if cmd == CMD_COMPLETE:
            print("Received transmission complete signal")
            transmission_complete = True
            return True
            
        # Process data chunk
        if cmd == CMD_DATA and data:
            # Skip if we already have this chunk
            if seq_num in received_chunks:
                return False
                
            # If this is the first chunk, record start time
            if len(received_chunks) == 0:
                reception_start_time = time.time()
                
            # Store the chunk
            received_chunks[seq_num] = data
            
            # Update highest sequence number seen
            if seq_num > highest_seq_num:
                highest_seq_num = seq_num
                
            # Print progress every 10 chunks or for the first chunk
            if len(received_chunks) == 1 or len(received_chunks) % 10 == 0:
                print(f"Received {len(received_chunks)} chunks so far")
                
        return False

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
            print("Converted hex key string to bytes")
    except:
        pass  # Not a hex string, use as is
    
    # Ensure key is the correct length for AES
    if len(key_data) < 16:
        key_data = key_data.ljust(16, b'\0')  # Pad to 16 bytes (128 bits)
    elif 16 < len(key_data) < 24:
        key_data = key_data.ljust(24, b'\0')  # Pad to 24 bytes (192 bits)
    elif 24 < len(key_data) < 32:
        key_data = key_data.ljust(32, b'\0')  # Pad to 32 bytes (256 bits)
    
    # Truncate to 32 bytes maximum (256 bits)
    return key_data[:32]

def decrypt_data(data, key):
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

def reassemble_data():
    """Reassemble the received chunks in correct order."""
    global received_chunks
    
    if not received_chunks:
        return None
    
    # Sort chunks by sequence number
    sorted_seq_nums = sorted(received_chunks.keys())
    
    # Check for missing chunks
    expected_seq = 1  # Start from 1
    missing_chunks = []
    
    for seq in sorted_seq_nums:
        if seq != expected_seq:
            # Found a gap
            missing_chunks.extend(range(expected_seq, seq))
        expected_seq = seq + 1
    
    if missing_chunks:
        print(f"Warning: Missing {len(missing_chunks)} chunks: {missing_chunks[:10]}...")
        
    # Get chunks in order
    sorted_chunks = [received_chunks[seq] for seq in sorted_seq_nums]
    
    # Clean chunks (remove trailing null bytes)
    cleaned_chunks = []
    for chunk in sorted_chunks:
        # If the chunk consists entirely of null bytes, keep at least one
        if all(b == 0 for b in chunk):
            cleaned_chunks.append(b'\0')
            continue
            
        # Remove trailing zeros
        cleaned_chunk = chunk.rstrip(b'\0')
        if cleaned_chunk:
            cleaned_chunks.append(cleaned_chunk)
        else:
            # If removing zeros left nothing, it was all zeros - add one back
            cleaned_chunks.append(b'\0')
    
    # Concatenate all chunks
    reassembled_data = b"".join(cleaned_chunks)
    
    return reassembled_data

def verify_data_integrity(data):
    """Verify the integrity of reassembled data using MD5 checksum."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        print("Error: Data too short to contain integrity checksum")
        return None
        
    # Extract the data and checksum
    file_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]
    
    # Calculate checksum of the data
    calculated_checksum = hashlib.md5(file_data).digest()
    
    # Compare checksums
    if calculated_checksum != received_checksum:
        print("Warning: Data integrity check failed - checksums don't match")
        print(f"Expected: {calculated_checksum.hex()}")
        print(f"Received: {received_checksum.hex()}")
        return None
        
    print("Data integrity verified successfully")
    return file_data

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

def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Receive a file via header steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time, highest_seq_num
    
    # Reset global variables
    received_chunks = {}
    transmission_complete = False
    reception_start_time = 0
    last_activity_time = time.time()
    highest_seq_num = 0
    
    # Create steganography handler
    stego = HeaderSteganography()
    
    # Prepare decryption key if provided
    key = None
    if key_path:
        print(f"Reading decryption key from: {key_path}")
        try:
            with open(key_path, 'rb') as key_file:
                key_data = key_file.read()
            key = prepare_key(key_data)
        except Exception as e:
            print(f"Error reading key file: {e}")
            return False
    
    # Start monitoring thread
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(
        target=monitor_transmission, 
        args=(stop_monitor, timeout)
    )
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Start packet capture
    print(f"Listening for steganographic data on interface {interface or 'default'}...")
    print("Press Ctrl+C to stop listening")
    
    try:
        # Start packet sniffing for all protocols we're using
        sniff(
            iface=interface,
            filter="ip and (icmp or (tcp and port not 22) or (udp and port 53))",
            prn=stego.process_packet,
            store=0,
            stop_filter=lambda p: transmission_complete
        )
    except KeyboardInterrupt:
        print("\nReceiving stopped by user")
    finally:
        stop_monitor.set()  # Signal monitor thread to stop
    
    # Check if we received any data
    if not received_chunks:
        print("No data received")
        return False
    
    # Calculate reception statistics
    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)
    
    print(f"\nReception summary:")
    print(f"- Received {chunk_count} chunks in {duration:.2f} seconds")
    print(f"- Highest sequence number seen: {highest_seq_num}")
    
    if highest_seq_num > 0 and chunk_count < highest_seq_num:
        percentage = (chunk_count / highest_seq_num) * 100
        print(f"- Packet reception rate: {percentage:.1f}%")
        print(f"- Missing approximately {highest_seq_num - chunk_count} chunks")
    
    # Reassemble the data
    print("Reassembling data...")
    reassembled_data = reassemble_data()
    
    if not reassembled_data:
        print("Failed to reassemble data")
        return False
    
    print(f"Reassembled {len(reassembled_data)} bytes of data")
    
    # Verify data integrity
    verified_data = verify_data_integrity(reassembled_data)
    if not verified_data:
        print("Warning: Proceeding with unverified data")
        verified_data = reassembled_data
    
    # Decrypt the data if key was provided
    if key:
        print("Decrypting data...")
        decrypted_data = decrypt_data(verified_data, key)
        if not decrypted_data:
            print("Decryption failed. Saving raw data instead.")
            decrypted_data = verified_data
        else:
            print(f"Successfully decrypted {len(decrypted_data)} bytes")
            
            # Try to detect text data
            try:
                sample_text = decrypted_data[:100].decode('utf-8')
                print(f"Sample of decrypted text: {sample_text}")
            except UnicodeDecodeError:
                print("Decrypted data is not text/UTF-8")
                
        # Save the decrypted data
        return save_to_file(decrypted_data, output_path)
    else:
        # Save the raw data
        return save_to_file(verified_data, output_path)

def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity and completion."""
    global last_activity_time, transmission_complete
    
    while not stop_event.is_set():
        # Check for inactivity timeout
        if time.time() - last_activity_time > timeout:
            print(f"\nInactivity timeout reached ({timeout} seconds)")
            transmission_complete = True
            break
            
        # Sleep a bit to avoid consuming CPU
        time.sleep(1)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Advanced Network Steganography Receiver')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', help='Decryption key file (optional)')
    parser.add_argument('--interface', '-i', help='Network interface to listen on')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity timeout in seconds (default: 120)')
    return parser.parse_args()

def main():
    """Main function."""
    # Parse arguments
    args = parse_arguments()
    
    # Receive the file
    success = receive_file(
        args.output,
        args.key,
        args.interface,
        args.timeout
    )
    
    # Exit with appropriate status
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
