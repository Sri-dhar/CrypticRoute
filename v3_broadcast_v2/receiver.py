#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure and acknowledgment system
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
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, sniff, conf, send
import socket  # Add this to imports in both files

# Add these functions to both sender.py and receiver.py:

def calculate_key_hash(key_path):
    """Calculate hash of encryption key."""
    if not key_path:
        # If no key, use a default value
        return "NO_KEY"
    
    try:
        with open(key_path, 'rb') as key_file:
            key_data = key_file.read()
        
        # Create a hash of the key
        return hashlib.sha256(key_data).hexdigest()
    except Exception as e:
        print(f"Error calculating key hash: {e}")
        return None

# Add this function to sender.py:

def discover_receiver(key_path, broadcast_timeout=30):
    """Broadcast discovery packets and listen for responses to find receiver IP."""
    # Calculate key hash
    key_hash = calculate_key_hash(key_path)
    if not key_hash:
        print("[DISCOVERY] Failed to calculate key hash")
        log_debug("Failed to calculate key hash")
        return None
    
    # Create UDP socket for broadcasting
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(1)  # Short timeout for receiving
    
    # Create a separate socket for receiving responses
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(('', 0))  # Bind to any available port
    my_port = recv_sock.getsockname()[1]
    recv_sock.settimeout(1)  # Short timeout for receiving
    
    # Prepare discovery packet
    discovery_data = json.dumps({
        "type": "DISCOVERY",
        "key_hash": key_hash,
        "reply_port": my_port
    }).encode('utf-8')
    
    # Set broadcast address
    broadcast_addr = ('255.255.255.255', 12345)  # Use a fixed port for discovery
    
    print(f"[DISCOVERY] Broadcasting for receivers with key hash: {key_hash}")
    log_debug(f"Broadcasting discovery packets with key hash: {key_hash}")
    
    # Start time for timeout
    start_time = time.time()
    
    # Send discovery packets and listen for responses
    while time.time() - start_time < broadcast_timeout:
        try:
            # Send broadcast packet
            sock.sendto(discovery_data, broadcast_addr)
            print("[DISCOVERY] Sending broadcast packet...")
            
            # Try to receive response
            try:
                data, addr = recv_sock.recvfrom(1024)
                response = json.loads(data.decode('utf-8'))
                
                if response.get("type") == "DISCOVERY_RESPONSE" and response.get("key_hash") == key_hash:
                    receiver_ip = addr[0]
                    print(f"[DISCOVERY] Receiver found at {receiver_ip}")
                    log_debug(f"Receiver found at {receiver_ip}")
                    
                    # Close sockets
                    sock.close()
                    recv_sock.close()
                    
                    return receiver_ip
            except socket.timeout:
                # No response received, continue broadcasting
                pass
            except json.JSONDecodeError:
                # Invalid JSON received, ignore
                pass
            
            # Short delay before next broadcast
            time.sleep(1)
            
        except Exception as e:
            print(f"[DISCOVERY] Error during discovery: {e}")
            log_debug(f"Error during discovery: {e}")
    
    print("[DISCOVERY] Timed out waiting for receiver")
    log_debug("Discovery timed out")
    
    # Close sockets
    sock.close()
    recv_sock.close()
    
    return None

# Add this function to receiver.py:

def listen_for_discovery(key_path, discovery_timeout=300):
    """Listen for discovery broadcasts from sender."""
    # Calculate key hash
    key_hash = calculate_key_hash(key_path)
    if not key_hash:
        print("[DISCOVERY] Failed to calculate key hash")
        log_debug("Failed to calculate key hash")
        return False
    
    # Create UDP socket for receiving broadcasts
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 12345))  # Bind to the discovery port
    sock.settimeout(1)  # Short timeout for receiving
    
    print(f"[DISCOVERY] Listening for sender broadcasts with key hash: {key_hash}")
    log_debug(f"Listening for discovery packets with key hash: {key_hash}")
    
    # Start time for timeout
    start_time = time.time()
    
    # Listen for discovery packets
    while time.time() - start_time < discovery_timeout:
        try:
            data, addr = sock.recvfrom(1024)
            
            try:
                discovery = json.loads(data.decode('utf-8'))
                
                if discovery.get("type") == "DISCOVERY" and discovery.get("key_hash") == key_hash:
                    sender_ip = addr[0]
                    reply_port = discovery.get("reply_port")
                    
                    print(f"[DISCOVERY] Sender found at {sender_ip}")
                    log_debug(f"Sender found at {sender_ip}")
                    
                    # Prepare response
                    response_data = json.dumps({
                        "type": "DISCOVERY_RESPONSE",
                        "key_hash": key_hash
                    }).encode('utf-8')
                    
                    # Create socket for sending response
                    reply_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    
                    # Send response
                    for _ in range(5):  # Send multiple times for reliability
                        reply_sock.sendto(response_data, (sender_ip, reply_port))
                        time.sleep(0.1)
                    
                    reply_sock.close()
                    print(f"[DISCOVERY] Sent response to sender at {sender_ip}")
                    log_debug(f"Sent response to sender at {sender_ip}")
                    
                    # Set the global sender_ip variable
                    # global sender_ip
                    sender_ip = sender_ip
                    
                    sock.close()
                    return True
            except json.JSONDecodeError:
                # Invalid JSON received, ignore
                pass
                
        except socket.timeout:
            # No packet received, continue listening
            pass
        except Exception as e:
            print(f"[DISCOVERY] Error during discovery: {e}")
            log_debug(f"Error during discovery: {e}")
    
    print("[DISCOVERY] Timed out waiting for sender")
    log_debug("Discovery timed out")
    
    sock.close()
    return False
# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size in bytes

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None  # Will store the sender's IP
sender_port = None  # Will store the sender's port
ack_sent_chunks = set()  # Keep track of chunks we've acknowledged

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

class SteganographyReceiver:
    """Simple steganography receiver using only TCP with acknowledgment."""
    
    def __init__(self):
        """Initialize the receiver."""
        # Initialize debug file for received chunks
        chunks_json = os.path.join(LOGS_DIR, "received_chunks.json")
        with open(chunks_json, "w") as f:
            f.write("{}")
        self.chunks_json_path = chunks_json
        
        # Initialize values for ACK responses
        self.my_port = random.randint(10000, 60000)
        
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
        global sender_ip, sender_port
        
        if not sender_ip or not sender_port:
            log_debug("Cannot create ACK - sender information missing")
            return None
            
        # Create an ACK packet with special markers
        # Use a specific bit pattern in seq and ack fields
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port,
            dport=sender_port,
            seq=0x12345678,  # Fixed pattern to identify this as an ACK
            ack=seq_num,     # Use the ack field to specify which chunk we're acknowledging
            window=0xCAFE,   # Special window value for ACKs
            flags="A"        # ACK flag
        )
        
        return ack_packet
    
    def send_ack(self, seq_num):
        """Send an acknowledgment for a specific sequence number."""
        global ack_sent_chunks
        
        # Skip if we've already ACKed this chunk
        if seq_num in ack_sent_chunks:
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
        global sender_ip, sender_port
        
        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender information missing")
            return None
            
        # Create a SYN-ACK packet with special markers
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port,
            dport=sender_port,
            seq=0xABCDEF12,  # Fixed pattern for SYN-ACK
            ack=0x12345678,  # Fixed pattern to acknowledge SYN
            window=0xBEEF,   # Special window value for handshake
            flags="SA"       # SYN-ACK flags
        )
        
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
        global packet_counter
        
        # Increment packet counter
        packet_counter += 1
        
        # Print status for every packet or at a regular interval
        if packet_counter <= 10 or packet_counter % 10 == 0:
            print(f"[PACKET] #{packet_counter:08d} | Chunks: {len(received_chunks):04d} | Valid ratio: {valid_packet_counter}/{packet_counter}")
        
        # Call the actual processing function but don't return its value
        self.process_packet(packet)
        
        # Always return None to prevent printing
        return None
        
    def process_packet(self, packet):
        """Process a packet to extract steganographic data."""
        global received_chunks, transmission_complete, reception_start_time
        global last_activity_time, highest_seq_num, valid_packet_counter
        global connection_established, sender_ip, sender_port
        
        # Update last activity time
        last_activity_time = time.time()
        
        # Check if it's a valid TCP packet
        if IP in packet and TCP in packet:
            # Save sender information if not already saved
            if sender_ip is None:
                sender_ip = packet[IP].src
            if sender_port is None and packet[TCP].sport != 0:
                sender_port = packet[TCP].sport
            
            # Check for connection establishment (SYN packet with special window value)
            if not connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == 0xDEAD:  # SYN flag and special window
                log_debug("Received connection establishment request (SYN)")
                print("\n[HANDSHAKE] Received connection request (SYN)")
                
                # Store sender info specifically from this packet
                sender_ip = packet[IP].src
                sender_port = packet[TCP].sport
                
                # Send SYN-ACK response
                self.send_syn_ack()
                return True
                
            # Check for established connection (ACK packet with special value)
            if not connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xF00D:  # ACK flag and special window
                log_debug("Received connection confirmation (ACK)")
                print("[HANDSHAKE] Connection established with sender")
                connection_established = True
                return True
                
            # Check for completion signal (FIN flag and special window value)
            if packet[TCP].flags & 0x01 and packet[TCP].window == 0xFFFF:  # FIN flag is set and window is 0xFFFF
                log_debug("Received transmission complete signal")
                print("\n[COMPLETE] Received transmission complete signal")
                transmission_complete = True
                return True
                
            # Only process data packets if connection is established
            if not connection_established:
                return False
                
            # Extract sequence number from window field
            seq_num = packet[TCP].window
            
            # Ignore packets that don't have our data (window will be 0 or very large normally)
            if seq_num == 0 or seq_num > 10000:
                return False
                
            # Extract total chunks from MSS option
            total_chunks = None
            for option in packet[TCP].options:
                if option[0] == 'MSS':
                    total_chunks = option[1]
            
            # If we can't find total chunks, this might not be our packet
            if total_chunks is None:
                return False
                
            # We have a valid packet at this point
            valid_packet_counter += 1
            print(f"[VALID] Packet #{packet_counter} identified as steganographic data")
            
            # Extract data from sequence and acknowledge numbers
            seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
            ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
            data = seq_bytes + ack_bytes
            
            # Extract checksum from IP ID
            checksum = packet[IP].id
            
            # Verify checksum
            calc_checksum = binascii.crc32(data) & 0xFFFF
            if checksum != calc_checksum:
                log_debug(f"Warning: Checksum mismatch for packet {seq_num}")
                print(f"[CHECKSUM] Warning: Mismatch for chunk {seq_num:04d}")
            else:
                print(f"[CHECKSUM] Valid for chunk {seq_num:04d}")
            
            # Skip if we already have this chunk
            if seq_num in received_chunks:
                print(f"[DUPLICATE] Chunk {seq_num:04d} already received, skipping")
                # Still send an ACK since the sender probably didn't receive our previous ACK
                self.send_ack(seq_num)
                return False
                
            # If this is the first chunk, record start time
            if len(received_chunks) == 0:
                reception_start_time = time.time()
                print(f"[START] First chunk received, starting timer")
                
            # Store the chunk
            log_debug(f"Received chunk {seq_num} (size: {len(data)})")
            received_chunks[seq_num] = data
            
            # Log the chunk
            self.log_chunk(seq_num, data)
            
            # Send acknowledgment for this chunk
            self.send_ack(seq_num)
            
            # Update highest sequence number seen
            if seq_num > highest_seq_num:
                highest_seq_num = seq_num
                print(f"[PROGRESS] New highest sequence: {highest_seq_num:04d}")
                
            # Print detailed information for every received chunk
            if total_chunks:
                progress = (len(received_chunks) / total_chunks) * 100
                print(f"[CHUNK] Received: {seq_num:04d}/{total_chunks:04d} | Total: {len(received_chunks):04d}/{total_chunks:04d} | Progress: {progress:.2f}%")
            else:
                print(f"[CHUNK] Received: {seq_num:04d} | Total received: {len(received_chunks):04d}")
                
            return False
                
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
        
        # Save components for debugging
        iv_file = os.path.join(DATA_DIR, "extracted_iv.bin")
        with open(iv_file, "wb") as f:
            f.write(iv)
        
        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
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
            
        log_debug(f"Decrypted data: {decrypted_data.hex() if len(decrypted_data) <= 32 else decrypted_data[:32].hex() + '...'}")
        
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"Decryption error: {e}")
        return None

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
    data_file = os.path.join(DATA_DIR, "data_without_checksum.bin")
    with open(data_file, "wb") as f:
        f.write(file_data)
        
    checksum_file = os.path.join(DATA_DIR, "received_checksum.bin")
    with open(checksum_file, "wb") as f:
        f.write(received_checksum)
    
    # Calculate checksum of the data
    calculated_checksum = hashlib.md5(file_data).digest()
    
    # Save the calculated checksum
    calc_checksum_file = os.path.join(DATA_DIR, "calculated_checksum.bin")
    with open(calc_checksum_file, "wb") as f:
        f.write(calculated_checksum)
    
    # Compare checksums
    checksum_match = (calculated_checksum == received_checksum)
    
    # Save checksum comparison results
    checksum_info = {
        "expected": calculated_checksum.hex(),
        "received": received_checksum.hex(),
        "match": checksum_match
    }
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")
    with open(checksum_json, "w") as f:
        json.dump(checksum_info, f, indent=2)
    
    if not checksum_match:
        log_debug("Warning: Data integrity check failed - checksums don't match")
        log_debug(f"Expected: {calculated_checksum.hex()}")
        log_debug(f"Received: {received_checksum.hex()}")
        print("Warning: Data integrity check failed - checksums don't match")
        print(f"Expected: {calculated_checksum.hex()}")
        print(f"Received: {received_checksum.hex()}")
        
        # IMPORTANT: Return the data without the checksum even if verification fails
        # This prevents the checksum from appearing as garbage at the end of the text
        return file_data
        
    log_debug("Data integrity verified successfully")
    print("Data integrity verified successfully")
    return file_data

def reassemble_data():
    """Reassemble the received chunks in correct order."""
    global received_chunks
    
    if not received_chunks:
        return None
    
    # Sort chunks by sequence number
    print(f"[REASSEMBLY] Sorting {len(received_chunks)} chunks by sequence number...")
    sorted_seq_nums = sorted(received_chunks.keys())
    
    # Check for missing chunks
    expected_seq = 1  # Start from 1
    missing_chunks = []
    
    print("[REASSEMBLY] Checking for missing chunks...")
    for seq in sorted_seq_nums:
        if seq != expected_seq:
            # Found a gap
            missing_chunks.extend(range(expected_seq, seq))
        expected_seq = seq + 1
    
    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks: {missing_chunks}")
        print(f"[REASSEMBLY] Warning: Missing {len(missing_chunks)} chunks")
        if len(missing_chunks) <= 10:
            print(f"[REASSEMBLY] Missing chunks: {missing_chunks}")
        else:
            print(f"[REASSEMBLY] First 10 missing chunks: {missing_chunks[:10]}...")
        
    # Save diagnostic information
    print("[REASSEMBLY] Saving diagnostic information...")
    chunk_info = {
        "received_chunks": len(received_chunks),
        "total_expected": highest_seq_num,
        "missing_chunks": missing_chunks,
        "received_seq_nums": sorted_seq_nums
    }
    reassembly_file = os.path.join(LOGS_DIR, "reassembly_info.json")
    with open(reassembly_file, "w") as f:
        json.dump(chunk_info, f, indent=2)
    
    # Get chunks in order
    print("[REASSEMBLY] Processing chunks in sequence order...")
    sorted_chunks = [received_chunks[seq] for seq in sorted_seq_nums]
    
    # Clean chunks (remove trailing null bytes)
    print("[REASSEMBLY] Cleaning chunks (removing padding)...")
    cleaned_chunks = []
    for i, chunk in enumerate(sorted_chunks):
        chunk_index = sorted_seq_nums[i]
        print(f"[REASSEMBLY] Processing chunk {chunk_index:04d}/{len(sorted_chunks):04d}")
        
        # Save each raw chunk
        raw_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{chunk_index:03d}.bin")
        with open(raw_file, "wb") as f:
            f.write(chunk)
            
        # Remove trailing zeros from all chunks except the last one
        # This ensures we don't strip legitimate zeros in the final chunk
        if i < len(sorted_chunks) - 1:
            stripped_chunk = chunk.rstrip(b'\0')
            if stripped_chunk:
                cleaned_chunks.append(stripped_chunk)
            else:
                # If it was all zeros, keep just one zero byte
                cleaned_chunks.append(b'\0')
            print(f"[REASSEMBLY] Regular chunk {chunk_index:04d}: Removed trailing zeros")
        else:
            # For the last chunk, only strip trailing zeros if we're confident it's padding
            # Keep at least one null byte if the entire chunk is nulls
            if all(b == 0 for b in chunk):
                cleaned_chunks.append(b'\0')
                print(f"[REASSEMBLY] Last chunk {chunk_index:04d}: All zeros, keeping one zero byte")
            else:
                # Otherwise, be more conservative about stripping nulls from the last chunk
                # Only strip trailing nulls if there are 3 or more in a row at the end
                # This helps preserve legitimate nulls that might be part of the data
                trailing_nulls = 0
                for b in reversed(chunk):
                    if b == 0:
                        trailing_nulls += 1
                    else:
                        break
                
                if trailing_nulls >= 3:
                    # Likely padding, strip it
                    cleaned_chunks.append(chunk.rstrip(b'\0'))
                    print(f"[REASSEMBLY] Last chunk {chunk_index:04d}: Found {trailing_nulls} trailing zeros, removed")
                else:
                    # Keep the chunk as is, nulls might be legitimate
                    cleaned_chunks.append(chunk)
                    print(f"[REASSEMBLY] Last chunk {chunk_index:04d}: Keeping {trailing_nulls} trailing zeros (likely data)")
            
        # Save the cleaned chunk
        cleaned_file = os.path.join(CHUNKS_DIR, "cleaned", f"chunk_{chunk_index:03d}.bin")
        with open(cleaned_file, "wb") as f:
            f.write(cleaned_chunks[-1])
    
    # Concatenate all chunks
    print("[REASSEMBLY] Concatenating all cleaned chunks...")
    reassembled_data = b"".join(cleaned_chunks)
    
    # Save the reassembled data
    reassembled_file = os.path.join(DATA_DIR, "reassembled_data.bin")
    with open(reassembled_file, "wb") as f:
        f.write(reassembled_data)
    
    print(f"[REASSEMBLY] Completed! Total size: {len(reassembled_data)} bytes")
    return reassembled_data

def save_to_file(data, output_path):
    """Save data to a file."""
    try:
        with open(output_path, 'wb') as file:
            file.write(data)
        log_debug(f"Data saved to {output_path}")
        print(f"Data saved to {output_path}")
        
        # Copy to the data directory as well
        output_name = os.path.basename(output_path)
        output_copy = os.path.join(DATA_DIR, f"output_{output_name}")
        with open(output_copy, "wb") as f:
            f.write(data)
        
        # Try to print the content as UTF-8 text
        try:
            text_content = data.decode('utf-8')
            log_debug(f"Saved text content: {text_content}")
            print(f"Saved text content: {text_content}")
            
            # Save as text file for easy viewing
            text_file = os.path.join(DATA_DIR, "output_content.txt")
            with open(text_file, "w") as f:
                f.write(text_content)
        except UnicodeDecodeError:
            log_debug("Saved content is not valid UTF-8 text")
            print("Saved content is not valid UTF-8 text")
            
        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"Error saving data to {output_path}: {e}")
        return False

def receive_file(output_path, key_path=None, interface=None, timeout=120, discovery_timeout=300):
    """Receive a file via steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time, highest_seq_num
    global packet_counter, valid_packet_counter, connection_established, sender_ip
    
    # Listen for discovery packets from sender
    print("[DISCOVERY] Listening for sender discovery packets...")
    log_debug("Listening for sender discovery packets")
    
    discovery_success = listen_for_discovery(key_path, discovery_timeout)
    if not discovery_success:
        log_debug("No sender discovered")
        print("[DISCOVERY] No sender discovered. Continuing with passive listening...")
        # We'll continue with passive listening even if discovery fails
    else:
        print(f"[DISCOVERY] Successfully established contact with sender")
    
    # Create a summary file with reception parameters
    summary = {
        "timestamp": time.time(),
        "output_path": output_path,
        "key_path": key_path,
        "interface": interface,
        "timeout": timeout,
        "discovery_success": discovery_success
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    
    # Initialize debug log
    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Receiver Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    
    # Reset global variables
    received_chunks = {}
    transmission_complete = False
    reception_start_time = 0
    last_activity_time = time.time()
    highest_seq_num = 0
    packet_counter = 0
    valid_packet_counter = 0
    connection_established = False
    
    # Create steganography receiver
    stego = SteganographyReceiver()
    
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
        # Use a filter for TCP packets
        filter_str = "tcp"
        log_debug(f"Using filter: {filter_str}")
        
        # Start packet sniffing - use packet_handler wrapper to avoid printing return values
        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.packet_handler,  # Use the wrapper function
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
    
    # Prepare reception statistics
    stats = {
        "total_packets": packet_counter,
        "valid_packets": valid_packet_counter,
        "chunks_received": chunk_count,
        "highest_seq_num": highest_seq_num,
        "duration_seconds": duration,
        "reception_rate": (chunk_count / highest_seq_num * 100) if highest_seq_num > 0 else 0,
        "missing_chunks": (highest_seq_num - chunk_count) if highest_seq_num > 0 else 0
    }
    
    stats_file = os.path.join(LOGS_DIR, "reception_stats.json")
    with open(stats_file, "w") as f:
        json.dump(stats, f, indent=2)
    
    log_debug(f"\nReception summary:")
    log_debug(f"- Processed {packet_counter} packets total")
    log_debug(f"- Identified {valid_packet_counter} valid steganography packets")
    log_debug(f"- Received {chunk_count} unique data chunks in {duration:.2f} seconds")
    log_debug(f"- Highest sequence number seen: {highest_seq_num}")
    
    print(f"\nReception summary:")
    print(f"- Processed {packet_counter} packets total")
    print(f"- Identified {valid_packet_counter} valid steganography packets")
    print(f"- Received {chunk_count} unique data chunks in {duration:.2f} seconds")
    print(f"- Highest sequence number seen: {highest_seq_num}")
    
    if highest_seq_num > 0 and chunk_count < highest_seq_num:
        percentage = (chunk_count / highest_seq_num) * 100
        log_debug(f"- Packet reception rate: {percentage:.1f}%")
        log_debug(f"- Missing approximately {highest_seq_num - chunk_count} chunks")
        print(f"- Packet reception rate: {percentage:.1f}%")
        print(f"- Missing approximately {highest_seq_num - chunk_count} chunks")
    
    # Reassemble the data
    log_debug("Reassembling data...")
    print("[REASSEMBLY] Starting data reassembly process...")
    reassembled_data = reassemble_data()
    
    if not reassembled_data:
        log_debug("Failed to reassemble data")
        print("[REASSEMBLY] Failed to reassemble data")
        
        # Save completion info
        completion_info = {
            "completed_at": time.time(),
            "status": "failed",
            "reason": "reassembly_failed"
        }
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
            
        return False
    
    log_debug(f"Reassembled {len(reassembled_data)} bytes of data")
    print(f"[REASSEMBLY] Successfully reassembled {len(reassembled_data)} bytes of data")
    
    # Verify data integrity
    print("[VERIFY] Verifying data integrity...")
    verified_data = verify_data_integrity(reassembled_data)
    if not verified_data:
        log_debug("Warning: Using data without checksum")
        print("[VERIFY] Warning: Checksum verification failed, using data without checksum")
        # Instead of using the reassembled data with checksum, use the data portion only
        verified_data = reassembled_data[:-INTEGRITY_CHECK_SIZE]
    else:
        print(f"[VERIFY] Data integrity verified successfully ({len(verified_data)} bytes)")
    
    # Decrypt the data if key was provided
    if key:
        log_debug("Decrypting data...")
        print("[DECRYPT] Starting decryption process...")
        
        if len(verified_data) >= 16:
            print(f"[DECRYPT] Attempting to decrypt {len(verified_data)} bytes...")
            decrypted_data = decrypt_data(verified_data, key)
            if not decrypted_data:
                log_debug("Decryption failed. Saving raw data instead.")
                print("[DECRYPT] Failed! Saving raw data instead.")
                decrypted_data = verified_data
                
                # Save completion info
                completion_info = {
                    "completed_at": time.time(),
                    "status": "partial",
                    "reason": "decryption_failed"
                }
                completion_path = os.path.join(LOGS_DIR, "completion_info.json")
                with open(completion_path, "w") as f:
                    json.dump(completion_info, f, indent=2)
            else:
                log_debug(f"Successfully decrypted {len(decrypted_data)} bytes")
                print(f"[DECRYPT] Successfully decrypted {len(decrypted_data)} bytes")
                
                # Try to detect text data
                try:
                    sample_text = decrypted_data[:100].decode('utf-8')
                    log_debug(f"Sample of decrypted text: {sample_text}")
                    print(f"[DECRYPT] Sample of decrypted text: {sample_text[:30]}...")
                except UnicodeDecodeError:
                    log_debug("Decrypted data is not text/UTF-8")
                    print("[DECRYPT] Decrypted data is not text/UTF-8")
                    
                # Save completion info
                completion_info = {
                    "completed_at": time.time(),
                    "status": "completed",
                    "bytes_received": len(decrypted_data)
                }
                completion_path = os.path.join(LOGS_DIR, "completion_info.json")
                with open(completion_path, "w") as f:
                    json.dump(completion_info, f, indent=2)
        else:
            log_debug("Data too short to contain IV")
            print("[DECRYPT] Error: Data too short to contain IV")
            decrypted_data = verified_data
                
        # Save the decrypted data
        print(f"[SAVE] Saving {len(decrypted_data)} bytes to {output_path}...")
        success = save_to_file(decrypted_data, output_path)
        if success:
            print(f"[SAVE] File saved successfully")
        else:
            print(f"[SAVE] Error saving file")
    else:
        # Save the raw data
        print(f"[SAVE] Saving {len(verified_data)} bytes to {output_path}...")
        success = save_to_file(verified_data, output_path)
        if success:
            print(f"[SAVE] File saved successfully")
        else:
            print(f"[SAVE] Error saving file")
        
        # Save completion info
        completion_info = {
            "completed_at": time.time(),
            "status": "completed" if success else "failed",
            "bytes_received": len(verified_data)
        }
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
    
    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    
    return success


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
        time.sleep(0.1)


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Simplified Network Steganography Receiver')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', help='Decryption key file (optional)')
    parser.add_argument('--interface', '-i', help='Network interface to listen on')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity timeout in seconds (default: 120)')
    parser.add_argument('--output-dir', '-d', help='Custom output directory')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=300,
                        help='Timeout in seconds for listening for sender discovery (default: 300)')
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
    
    # Receive the file
    success = receive_file(
        args.output,
        args.key,
        args.interface,
        args.timeout,
        args.discovery_timeout
    )
    
    # Exit with appropriate status
    sys.exit(0 if success else 1)