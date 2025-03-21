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
import json
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

# Debug log file
DEBUG_LOG = "stealth_receiver_debug.log"

def log_debug(message):
    """Write debug message to log file."""
    with open(DEBUG_LOG, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

class HeaderSteganography:
    """Class for handling the steganographic operations."""
    
    def __init__(self):
        """Initialize the steganography handler."""
        self.recv_window = {}  # For keeping track of received chunks
        # Initialize debug file for received chunks
        with open("received_chunks.json", "w") as f:
            f.write("{}")
        
    def dump_received_chunk(self, seq_num, data, method):
        """Save received chunk to debug file."""
        global received_chunks
        
        # Load existing file
        try:
            with open("received_chunks.json", "r") as f:
                chunk_info = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            chunk_info = {}
        
        # Add this chunk
        chunk_info[str(seq_num)] = {
            "data": data.hex() if data else None,
            "method": method,
            "timestamp": time.time()
        }
        
        # Save back to file
        with open("received_chunks.json", "w") as f:
            json.dump(chunk_info, f, indent=2)
        
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
                log_debug(f"Warning: Checksum mismatch for TCP packet {seq_num}")
            
            # Save the received chunk data
            self.dump_received_chunk(seq_num, data, "TCP")
            
            return data, seq_num, total_chunks, cmd
        
        return None, None, None, None
    
    def extract_data_from_udp_header(self, packet):
        """Extract data from UDP header fields."""
        if IP in packet and UDP in packet:
            # Extract command from ToS field
            cmd = packet[IP].tos
            
            # If not a command we recognize, ignore
            if cmd not in [CMD_DATA, CMD_COMPLETE]:
                return None, None, None, None
                
            # Extract sequence number from IP ID
            seq_num = packet[IP].id
            
            # Extract total chunks from fragment offset field
            total_chunks = packet[IP].frag
            
            # For UDP, we need to extract data from the sport and dport
            if packet[UDP].dport == CONTROL_PORT:
                # Extract data from sport
                sport_bytes = packet[UDP].sport.to_bytes(2, byteorder='big')
                dport_bytes = packet[UDP].dport.to_bytes(2, byteorder='big')
                data = sport_bytes + bytes([0, 0])  # We don't store in dport since it's fixed
            else:
                # Both sport and dport are used for data
                sport_bytes = packet[UDP].sport.to_bytes(2, byteorder='big')
                dport_bytes = packet[UDP].dport.to_bytes(2, byteorder='big')
                data = sport_bytes + dport_bytes
            
            # Save the received chunk data
            self.dump_received_chunk(seq_num, data, "UDP")
            
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
            
            # Save the received chunk data
            self.dump_received_chunk(seq_num, data, "ICMP")
            
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
            log_debug("Received transmission complete signal")
            print("Received transmission complete signal")
            transmission_complete = True
            return True
            
        # Process data chunk
        if cmd == CMD_DATA and data:
            # Skip if we already have this chunk
            if seq_num in received_chunks:
                log_debug(f"Skipping duplicate chunk {seq_num}")
                return False
                
            # If this is the first chunk, record start time
            if len(received_chunks) == 0:
                reception_start_time = time.time()
                
            # Store the chunk
            log_debug(f"Received chunk {seq_num} (size: {len(data)})")
            received_chunks[seq_num] = data
            
            # Update highest sequence number seen
            if seq_num > highest_seq_num:
                highest_seq_num = seq_num
                
            # Print progress every 10 chunks or for the first chunk
            if len(received_chunks) == 1 or len(received_chunks) % 10 == 0:
                log_debug(f"Received {len(received_chunks)} chunks so far")
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
        
        # Save the components for debugging
        with open("extracted_iv.bin", "wb") as f:
            f.write(iv)
        
        with open("encrypted_data.bin", "wb") as f:
            f.write(encrypted_data)
            
        # Initialize AES cipher with key and extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Save decrypted data for debugging
        with open("decrypted_data.bin", "wb") as f:
            f.write(decrypted_data)
            
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
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
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks: {missing_chunks}")
        print(f"Warning: Missing {len(missing_chunks)} chunks: {missing_chunks[:10]}...")
        
    # Save diagnostic information
    chunk_info = {
        "received_chunks": len(received_chunks),
        "total_expected": highest_seq_num,
        "missing_chunks": missing_chunks,
        "received_seq_nums": sorted_seq_nums
    }
    with open("reassembly_info.json", "w") as f:
        json.dump(chunk_info, f, indent=2)
    
    # Get chunks in order
    sorted_chunks = [received_chunks[seq] for seq in sorted_seq_nums]
    
    # Clean chunks (remove trailing null bytes)
    cleaned_chunks = []
    for chunk in sorted_chunks:
        # For debugging, save each chunk before cleaning
        chunk_index = sorted_seq_nums[len(cleaned_chunks)]
        with open(f"chunk_{chunk_index}_raw.bin", "wb") as f:
            f.write(chunk)
            
        # Remove trailing zeros, but be careful with all-zero chunks
        stripped_chunk = chunk.rstrip(b'\0')
        if stripped_chunk:
            cleaned_chunks.append(stripped_chunk)
        else:
            # If it was all zeros, keep just one zero byte
            cleaned_chunks.append(b'\0')
            
        # Save the cleaned chunk
        with open(f"chunk_{chunk_index}_cleaned.bin", "wb") as f:
            f.write(cleaned_chunks[-1])
    
    # Concatenate all chunks
    reassembled_data = b"".join(cleaned_chunks)
    
    # Save the reassembled data for debugging
    with open("reassembled_data.bin", "wb") as f:
        f.write(reassembled_data)
        
    return reassembled_data

def verify_data_integrity(data):
    """Verify the integrity of reassembled data using MD5 checksum."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        log_debug("Error: Data too short to contain integrity checksum")
        print("Error: Data too short to contain integrity checksum")
        return None
        
    # Extract the data and checksum
    file_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]
    
    # Save components for debugging
    with open("data_without_checksum.bin", "wb") as f:
        f.write(file_data)
        
    with open("received_checksum.bin", "wb") as f:
        f.write(received_checksum)
    
    # Calculate checksum of the data
    calculated_checksum = hashlib.md5(file_data).digest()
    
    # Save the calculated checksum
    with open("calculated_checksum.bin", "wb") as f:
        f.write(calculated_checksum)
    
    # Compare checksums
    if calculated_checksum != received_checksum:
        log_debug("Warning: Data integrity check failed - checksums don't match")
        log_debug(f"Expected: {calculated_checksum.hex()}")
        log_debug(f"Received: {received_checksum.hex()}")
        print("Warning: Data integrity check failed - checksums don't match")
        print(f"Expected: {calculated_checksum.hex()}")
        print(f"Received: {received_checksum.hex()}")
        return None
        
    log_debug("Data integrity verified successfully")
    print("Data integrity verified successfully")
    return file_data

def save_to_file(data, output_path):
    """Save data to a file."""
    try:
        with open(output_path, 'wb') as file:
            file.write(data)
        log_debug(f"Data saved to {output_path}")
        print(f"Data saved to {output_path}")
        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"Error saving data to {output_path}: {e}")
        return False

def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Receive a file via header steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time, highest_seq_num
    
    # Initialize debug log
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Receiver Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
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
        log_debug(f"Reading decryption key from: {key_path}")
        print(f"Reading decryption key from: {key_path}")
        try:
            with open(key_path, 'rb') as key_file:
                key_data = key_file.read()
            key = prepare_key(key_data)
        except Exception as e:
            log_debug(f"Error reading key file: {e}")
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
    log_debug(f"Listening for steganographic data on interface {interface or 'default'}...")
    print(f"Listening for steganographic data on interface {interface or 'default'}...")
    print("Press Ctrl+C to stop listening")
    
    try:
        # Use a more permissive filter to capture more potential packets
        filter_str = "ip and (icmp or tcp or (udp and port 53))"
        log_debug(f"Using filter: {filter_str}")
        
        # Start packet sniffing
        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.process_packet,
            store=0,
            stop_filter=lambda p: transmission_complete
        )
    except KeyboardInterrupt:
        log_debug("\nReceiving stopped by user")
        print("\nReceiving stopped by user")
    finally:
        stop_monitor.set()  # Signal monitor thread to stop
    
    # Check if we received any data
    if not received_chunks:
        log_debug("No data received")
        print("No data received")
        return False
    
    # Calculate reception statistics
    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)
    
    log_debug(f"\nReception summary:")
    log_debug(f"- Received {chunk_count} chunks in {duration:.2f} seconds")
    log_debug(f"- Highest sequence number seen: {highest_seq_num}")
    print(f"\nReception summary:")
    print(f"- Received {chunk_count} chunks in {duration:.2f} seconds")
    print(f"- Highest sequence number seen: {highest_seq_num}")
    
    if highest_seq_num > 0 and chunk_count < highest_seq_num:
        percentage = (chunk_count / highest_seq_num) * 100
        log_debug(f"- Packet reception rate: {percentage:.1f}%")
        log_debug(f"- Missing approximately {highest_seq_num - chunk_count} chunks")
        print(f"- Packet reception rate: {percentage:.1f}%")
        print(f"- Missing approximately {highest_seq_num - chunk_count} chunks")
    
    # Reassemble the data
    log_debug("Reassembling data...")
    print("Reassembling data...")
    reassembled_data = reassemble_data()
    
    if not reassembled_data:
        log_debug("Failed to reassemble data")
        print("Failed to reassemble data")
        return False
    
    log_debug(f"Reassembled {len(reassembled_data)} bytes of data")
    print(f"Reassembled {len(reassembled_data)} bytes of data")
    
    # Verify data integrity
    verified_data = verify_data_integrity(reassembled_data)
    if not verified_data:
        log_debug("Warning: Proceeding with unverified data")
        print("Warning: Proceeding with unverified data")
        verified_data = reassembled_data
    
    # Decrypt the data if key was provided
    if key:
        log_debug("Decrypting data...")
        print("Decrypting data...")
        decrypted_data = decrypt_data(verified_data, key)
        if not decrypted_data:
            log_debug("Decryption failed. Saving raw data instead.")
            print("Decryption failed. Saving raw data instead.")
            decrypted_data = verified_data
        else:
            log_debug(f"Successfully decrypted {len(decrypted_data)} bytes")
            print(f"Successfully decrypted {len(decrypted_data)} bytes")
            
            # Try to detect text data
            try:
                sample_text = decrypted_data[:100].decode('utf-8')
                log_debug(f"Sample of decrypted text: {sample_text}")
                print(f"Sample of decrypted text: {sample_text}")
            except UnicodeDecodeError:
                log_debug("Decrypted data is not text/UTF-8")
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
            log_debug(f"\nInactivity timeout reached ({timeout} seconds)")
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