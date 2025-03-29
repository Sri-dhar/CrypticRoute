#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure, acknowledgment system, and key-based discovery
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

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size
DISCOVERY_PORT = 54321 # Port for discovery probes/responses
DISCOVERY_TIMEOUT = 60 # Seconds to wait for a discovery probe initially

# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None  # Discovered sender's IP
sender_port = None  # Discovered sender's port (from SYN packet)
ack_sent_chunks = set()
discovery_sender_ip = None # IP from discovery probe
discovery_sender_port = None # Port from discovery probe
discovery_probe_received = False # Flag
receiver_key_hash_probe_expected = b'' # Derived from key
receiver_key_hash_response = b'' # Derived from key

# Output directory structure
OUTPUT_DIR = "stealth_output"
SESSION_DIR = ""
LOGS_DIR = ""
DATA_DIR = ""
CHUNKS_DIR = ""
DEBUG_LOG = ""

def setup_directories():
    """Create organized directory structure for outputs."""
    global OUTPUT_DIR, SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG

    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"receiver_session_{timestamp}")
    os.makedirs(SESSION_DIR)

    LOGS_DIR = os.path.join(SESSION_DIR, "logs")
    DATA_DIR = os.path.join(SESSION_DIR, "data")
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks")
    os.makedirs(LOGS_DIR); os.makedirs(DATA_DIR); os.makedirs(CHUNKS_DIR)
    os.makedirs(os.path.join(CHUNKS_DIR, "raw"))
    os.makedirs(os.path.join(CHUNKS_DIR, "cleaned"))

    DEBUG_LOG = os.path.join(LOGS_DIR, "receiver_debug.log")

    latest_link = os.path.join(OUTPUT_DIR, "receiver_latest")
    try:
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link):
            backup_name = f"{latest_link}_{int(time.time())}"
            os.rename(latest_link, backup_name)
            print(f"Renamed existing file to {backup_name}")
        os.symlink(SESSION_DIR, latest_link)
        print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e:
        print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    with open(DEBUG_LOG, "a") as f:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message}\n")

def derive_key_identifiers(key):
    """Derive probe and response identifiers from the key."""
    global receiver_key_hash_probe_expected, receiver_key_hash_response
    hasher = hashlib.sha256()
    hasher.update(key)
    full_hash = hasher.digest()
    receiver_key_hash_probe_expected = full_hash[:4] # Expect first 4 bytes in probe
    receiver_key_hash_response = full_hash[4:8] # Use next 4 bytes for response
    log_debug(f"Derived Expected Probe ID: {receiver_key_hash_probe_expected.hex()}")
    log_debug(f"Derived Response ID: {receiver_key_hash_response.hex()}")

class SteganographyReceiver:
    """Simple steganography receiver using TCP with acknowledgment and discovery."""

    def __init__(self):
        """Initialize the receiver."""
        chunks_json = os.path.join(LOGS_DIR, "received_chunks.json")
        with open(chunks_json, "w") as f: f.write("{}")
        self.chunks_json_path = chunks_json

        self.my_port = random.randint(10000, 60000) # Port *we* use for sending ACKs/SYN-ACKs

        acks_json = os.path.join(LOGS_DIR, "sent_acks.json")
        with open(acks_json, "w") as f: f.write("{}")
        self.acks_json_path = acks_json
        self.sent_acks = {}

    def log_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        try:
            with open(self.chunks_json_path, "r") as f: chunk_info = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): chunk_info = {}
        chunk_info[str(seq_num)] = {
            "data": data.hex(), "size": len(data), "timestamp": time.time()
        }
        with open(self.chunks_json_path, "w") as f: json.dump(chunk_info, f, indent=2)
        chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:03d}.bin")
        with open(chunk_file, "wb") as f: f.write(data)

    def log_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks[str(seq_num)] = { "timestamp": time.time() }
        with open(self.acks_json_path, "w") as f: json.dump(self.sent_acks, f, indent=2)

    # --- Discovery Response ---
    def create_discovery_response_packet(self, probe_packet):
        """Create a discovery response packet."""
        global receiver_key_hash_response
        sender_ip = probe_packet[IP].src
        sender_port = probe_packet[TCP].sport # Port the probe came from
        probe_seq = probe_packet[TCP].seq # Seq from the probe

        response_packet = IP(dst=sender_ip) / TCP(
            sport=DISCOVERY_PORT, # Respond *from* the discovery port
            dport=sender_port,    # Respond *to* the sender's source port
            flags="PF",           # PSH | FIN
            window=0xCAFE,        # Magic value 2
            seq=int.from_bytes(receiver_key_hash_response, 'big'),
            ack=probe_seq         # Acknowledge the probe's sequence number
        )
        return response_packet

    def send_discovery_response(self, probe_packet):
        """Sends the discovery response packet back to the sender."""
        response_pkt = self.create_discovery_response_packet(probe_packet)
        if response_pkt:
            log_debug(f"Sending Discovery Response to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            print(f"[DISCOVERY] Sending response to sender at {probe_packet[IP].src}")
            # Send multiple times for reliability
            for _ in range(5):
                 send(response_pkt)
                 time.sleep(0.1)

    def process_discovery_probe(self, packet):
        """Process incoming packets during discovery phase."""
        global discovery_sender_ip, discovery_sender_port, discovery_probe_received
        global receiver_key_hash_probe_expected

        if discovery_probe_received: # Already found one
             return False

        # Check for discovery probe signature: PSH|URG, Window 0xFACE, coming to DISCOVERY_PORT
        if IP in packet and TCP in packet and packet[TCP].dport == DISCOVERY_PORT \
           and packet[TCP].flags & 0x28 == 0x28 and packet[TCP].window == 0xFACE:

            probe_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery probe from {packet[IP].src}:{packet[TCP].sport}")
            log_debug(f"  Flags={packet[TCP].flags}, Window={packet[TCP].window:#x}, SeqHash={probe_hash_received.hex()}")

            # Verify key hash
            if probe_hash_received == receiver_key_hash_probe_expected:
                log_debug(f"Valid Discovery Probe received from {packet[IP].src}:{packet[TCP].sport}")
                print(f"\n[DISCOVERY] Valid probe received from sender at {packet[IP].src}")

                # Store sender info from the probe
                discovery_sender_ip = packet[IP].src
                discovery_sender_port = packet[TCP].sport # This is the port *they* will listen on for response

                # Send response
                self.send_discovery_response(packet)

                # Mark discovery as done for this phase
                discovery_probe_received = True
                return True # Signal sniff to stop
            else:
                log_debug("Probe received, but key hash mismatch.")

        return False # Continue sniffing if not the probe we want

    # --- Connection and Data Handling ---

    def create_ack_packet(self, seq_num):
        """Create an ACK packet for a specific data sequence number."""
        global sender_ip, sender_port # Should be set by now
        if not sender_ip or not sender_port:
            log_debug("Cannot create ACK - sender information missing")
            return None
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, # Send from our random port
            dport=sender_port, # Send TO the port the SYN came from
            seq=0x12345678,    # Fixed pattern
            ack=seq_num,       # Acknowledge data chunk seq num
            window=0xCAFE,     # Special window value for data ACKs
            flags="A"
        )
        return ack_packet

    def send_ack(self, seq_num):
        """Send an acknowledgment for a specific sequence number."""
        global ack_sent_chunks
        if seq_num in ack_sent_chunks: return
        ack_packet = self.create_ack_packet(seq_num)
        if not ack_packet: return

        log_debug(f"Sending ACK for chunk {seq_num} to {sender_ip}:{sender_port}")
        print(f"[ACK] Sending acknowledgment for chunk {seq_num:04d}")
        self.log_ack(seq_num)
        for _ in range(3):
            send(ack_packet)
            time.sleep(0.05)
        ack_sent_chunks.add(seq_num)

    def create_syn_ack_packet(self):
        """Create a SYN-ACK packet for connection establishment."""
        global sender_ip, sender_port # Port should be from the incoming SYN
        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender information missing")
            return None
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, # Respond from our random port
            dport=sender_port, # Respond TO the port the SYN came from
            seq=0xABCDEF12,
            ack=0x12345678 + 1 if sender_port else 0, # Ack the SYN's seq num + 1 (use actual seq from SYN when processing)
            window=0xBEEF,
            flags="SA"
        )
        return syn_ack_packet

    def send_syn_ack(self, incoming_syn_packet):
        """Send a SYN-ACK response based on an incoming SYN."""
        global sender_ip, sender_port # Update sender_port from SYN
        sender_ip = incoming_syn_packet[IP].src
        sender_port = incoming_syn_packet[TCP].sport # *** Update port based on SYN ***
        log_debug(f"Updated sender port to {sender_port} based on incoming SYN")
        print(f"[HANDSHAKE] Sender port for connection: {sender_port}")

        syn_ack_packet = self.create_syn_ack_packet()
        # Correct the ACK number based on the actual received SYN seq
        syn_ack_packet[TCP].ack = incoming_syn_packet[TCP].seq + 1

        if not syn_ack_packet: return

        log_debug(f"Sending SYN-ACK for connection establishment to {sender_ip}:{sender_port}")
        print("[HANDSHAKE] Sending SYN-ACK response")
        for _ in range(5):
            send(syn_ack_packet)
            time.sleep(0.1)

    def packet_handler(self, packet):
        """Wrapper for process_packet that handles packet counting."""
        global packet_counter
        packet_counter += 1
        if packet_counter <= 10 or packet_counter % 10 == 0:
            print(f"[PACKET] #{packet_counter:08d} | Chunks: {len(received_chunks):04d} | Valid ratio: {valid_packet_counter}/{packet_counter}", end='\r')
        self.process_packet(packet)
        return None # Prevent scapy printing

    def process_packet(self, packet):
        """Process packets for connection, data, or completion."""
        global received_chunks, transmission_complete, reception_start_time
        global last_activity_time, highest_seq_num, valid_packet_counter
        global connection_established, sender_ip, sender_port, discovery_sender_ip

        last_activity_time = time.time()

        # --- Check packet source against discovered sender IP ---
        # Allow packets only from the initially discovered sender OR if not discovered yet
        if discovery_sender_ip and IP in packet and packet[IP].src != discovery_sender_ip:
            #log_debug(f"Ignoring packet from unknown source {packet[IP].src} (expected {discovery_sender_ip})")
            return False # Ignore packets from other IPs once sender is known

        if IP in packet and TCP in packet:
            # Set sender_ip if not already set (from first valid packet)
            if sender_ip is None and discovery_sender_ip:
                 sender_ip = discovery_sender_ip # Use the discovered IP

            # Check for connection establishment (SYN packet with special window)
            # Must come from the discovered sender IP
            if not connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == 0xDEAD and packet[IP].src == sender_ip:
                log_debug(f"Received connection establishment request (SYN) from {packet[IP].src}:{packet[TCP].sport}")
                print("\n[HANDSHAKE] Received connection request (SYN)")
                self.send_syn_ack(packet) # Pass the SYN packet to extract sender port
                return True

            # Check for established connection confirmation (ACK packet with special value)
            # Must come from the discovered sender IP and *correct port* (updated by SYN-ACK)
            if not connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xF00D and packet[IP].src == sender_ip and packet[TCP].dport == self.my_port:
                 # Add check for packet[TCP].dport == self.my_port
                log_debug("Received connection confirmation (ACK)")
                print("[HANDSHAKE] Connection established with sender")
                connection_established = True
                return True

            # Check for completion signal (FIN flag and special window value)
            if connection_established and packet[TCP].flags & 0x01 and packet[TCP].window == 0xFFFF and packet[IP].src == sender_ip:
                log_debug("Received transmission complete signal")
                print("\n[COMPLETE] Received transmission complete signal")
                transmission_complete = True
                return True

            # Process data packets only if connection is established and from the sender
            if not connection_established or packet[IP].src != sender_ip:
                return False

            # --- Extract data chunk ---
            # Check if it looks like our data packet (SYN flag, MSS option)
            total_chunks = None
            if packet[TCP].flags & 0x02: # Check if it has SYN flag (our data packets use this)
                for option in packet[TCP].options:
                    if option[0] == 'MSS':
                        total_chunks = option[1]
                        break # Found MSS

            if total_chunks is not None: # Found potential data packet
                 seq_num = packet[TCP].window # Sequence number is in window field
                 if seq_num == 0 or seq_num > 60000: # Plausibility check
                      return False # Ignore packets with unlikely sequence numbers

                 valid_packet_counter += 1
                 # print(f"[VALID] Packet #{packet_counter} identified as steganographic data (Chunk {seq_num})")

                 seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
                 ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
                 data = seq_bytes + ack_bytes
                 checksum = packet[IP].id
                 calc_checksum = binascii.crc32(data) & 0xFFFF

                 if checksum != calc_checksum:
                     log_debug(f"Warning: Checksum mismatch for packet {seq_num}")
                     print(f"[CHECKSUM] Warning: Mismatch for chunk {seq_num:04d}")
                 # else: print(f"[CHECKSUM] Valid for chunk {seq_num:04d}") # Too noisy

                 if seq_num in received_chunks:
                     # print(f"[DUPLICATE] Chunk {seq_num:04d} already received, resending ACK")
                     self.send_ack(seq_num) # Resend ACK for duplicates
                     return False

                 if len(received_chunks) == 0:
                     reception_start_time = time.time()
                     print(f"[START] First chunk {seq_num} received, starting timer")

                 log_debug(f"Received chunk {seq_num} (size: {len(data)})")
                 received_chunks[seq_num] = data
                 self.log_chunk(seq_num, data)
                 self.send_ack(seq_num) # Send ACK for new chunk

                 if seq_num > highest_seq_num:
                     highest_seq_num = seq_num
                     # print(f"[PROGRESS] New highest sequence: {highest_seq_num:04d}")

                 progress = (len(received_chunks) / total_chunks) * 100 if total_chunks else 0
                 print(f"[CHUNK] Rcvd: {seq_num:04d}/{total_chunks:04d} | Total: {len(received_chunks):04d}/{total_chunks:04d} | Progress: {progress:.1f}% ", end='\r')

                 return True # Processed a valid data chunk

        return False

# --- Key Prep, Decryption, Integrity, Reassembly, Saving (Mostly Unchanged) ---

def prepare_key(key_data):
    """Prepare the decryption key and derive identifiers."""
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try:
        if all(c in b'0123456789abcdefABCDEF' for c in key_data):
            key_data = bytes.fromhex(key_data.decode('ascii'))
            log_debug("Converted hex key string to bytes")
    except: pass # Not hex

    if len(key_data) < 32: key_data = key_data.ljust(32, b'\0')
    key_data = key_data[:32]
    log_debug(f"Final key: {key_data.hex()}")

    key_file = os.path.join(DATA_DIR, "key.bin")
    with open(key_file, "wb") as f: f.write(key_data)

    # Derive identifiers needed for discovery
    derive_key_identifiers(key_data)

    return key_data

def decrypt_data(data, key):
    """Decrypt data using AES."""
    try:
        if len(data) < 16:
            log_debug("Error: Encrypted data too short (missing IV)")
            return None
        iv = data[:16]
        encrypted_data = data[16:]
        log_debug(f"Extracted IV: {iv.hex()}")
        # log_debug(f"Encrypted data size: {len(encrypted_data)} bytes")

        iv_file = os.path.join(DATA_DIR, "extracted_iv.bin")
        with open(iv_file, "wb") as f: f.write(iv)
        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        with open(encrypted_file, "wb") as f: f.write(encrypted_data)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_file = os.path.join(DATA_DIR, "decrypted_data.bin")
        with open(decrypted_file, "wb") as f: f.write(decrypted_data)
        # log_debug(f"Decrypted data size: {len(decrypted_data)}")
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"\nDecryption error: {e}")
        return None

def verify_data_integrity(data):
    """Verify MD5 checksum."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        log_debug("Error: Data too short for checksum")
        return None
    file_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]
    calculated_checksum = hashlib.md5(file_data).digest()

    checksum_match = (calculated_checksum == received_checksum)
    checksum_info = {"expected": calculated_checksum.hex(), "received": received_checksum.hex(), "match": checksum_match}
    checksum_json = os.path.join(LOGS_DIR, "checksum_verification.json")
    with open(checksum_json, "w") as f: json.dump(checksum_info, f, indent=2)

    if not checksum_match:
        log_debug("Warning: Data integrity check failed")
        log_debug(f"  Expected: {calculated_checksum.hex()}")
        log_debug(f"  Received: {received_checksum.hex()}")
        print("\nWarning: Data integrity check failed!")
        # Still return the data without checksum
        return file_data
    else:
        log_debug("Data integrity verified successfully")
        print("\nData integrity verified successfully")
        return file_data # Return data without checksum


def reassemble_data():
    """Reassemble received chunks."""
    global received_chunks
    if not received_chunks: return None

    print(f"\n[REASSEMBLY] Sorting {len(received_chunks)} chunks...")
    sorted_seq_nums = sorted(received_chunks.keys())
    expected_seq = 1
    missing_chunks = []
    for seq in sorted_seq_nums:
        if seq != expected_seq: missing_chunks.extend(range(expected_seq, seq))
        expected_seq = seq + 1

    # Check for missing chunks after the last received one, if transmission wasn't explicitly completed
    # (This logic might be flawed if highest_seq_num isn't reliable)
    # if not transmission_complete and expected_seq <= highest_seq_num:
    #     missing_chunks.extend(range(expected_seq, highest_seq_num + 1))

    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks: {missing_chunks[:20]}...")
        print(f"[REASSEMBLY] Warning: Missing {len(missing_chunks)} chunks")
        if len(missing_chunks) <= 10: print(f"[REASSEMBLY] Missing: {missing_chunks}")
        else: print(f"[REASSEMBLY] First 10 missing: {missing_chunks[:10]}...")

    chunk_info = {
        "received_chunks": len(received_chunks), "highest_seq_num": highest_seq_num,
        "missing_chunks": missing_chunks, "received_seq_nums": sorted_seq_nums
    }
    reassembly_file = os.path.join(LOGS_DIR, "reassembly_info.json")
    with open(reassembly_file, "w") as f: json.dump(chunk_info, f, indent=2)

    # Reassemble, handling potential padding (simplified logic here)
    print("[REASSEMBLY] Concatenating chunks...")
    reassembled_data = b"".join(received_chunks[seq] for seq in sorted_seq_nums)

    # Save intermediate steps (raw/cleaned chunks - skipping cleaning logic for now)
    for seq in sorted_seq_nums:
         raw_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq:03d}.bin")
         with open(raw_file, "wb") as f: f.write(received_chunks[seq])
         # Simple copy for 'cleaned' in this version
         cleaned_file = os.path.join(CHUNKS_DIR, "cleaned", f"chunk_{seq:03d}.bin")
         with open(cleaned_file, "wb") as f: f.write(received_chunks[seq])


    reassembled_file = os.path.join(DATA_DIR, "reassembled_data.bin")
    with open(reassembled_file, "wb") as f: f.write(reassembled_data)
    print(f"[REASSEMBLY] Completed! Total size: {len(reassembled_data)} bytes")
    return reassembled_data


def save_to_file(data, output_path):
    """Save data to file."""
    try:
        with open(output_path, 'wb') as file: file.write(data)
        log_debug(f"Data saved to {output_path}")
        print(f"Data saved to {output_path}")

        output_name = os.path.basename(output_path)
        output_copy = os.path.join(DATA_DIR, f"output_{output_name}")
        with open(output_copy, "wb") as f: f.write(data)

        try:
            text_content = data.decode('utf-8')
            log_debug(f"Saved text content: {text_content[:100]}...")
            print(f"Saved text content (first 100 chars): {text_content[:100]}...")
            text_file = os.path.join(DATA_DIR, "output_content.txt")
            with open(text_file, "w") as f: f.write(text_content)
        except UnicodeDecodeError:
            log_debug("Saved content is not valid UTF-8 text")
            print("Saved content is binary data.")
        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"Error saving data to {output_path}: {e}")
        return False

# --- Main Receive Logic ---

def listen_for_discovery(stego, interface, timeout=DISCOVERY_TIMEOUT):
    """Listen for discovery probe packets."""
    global discovery_probe_received
    log_debug(f"Listening for discovery probes on port {DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Listening for sender probe on UDP/{DISCOVERY_PORT} (up to {timeout}s)...") # Corrected to TCP

    discovery_probe_received = False # Reset flag
    try:
        sniff(
            iface=interface,
            filter=f"tcp and dst port {DISCOVERY_PORT}",
            prn=stego.process_discovery_probe,
            store=0,
            timeout=timeout, # Sniff only for the discovery timeout
            stop_filter=lambda p: discovery_probe_received # Stop as soon as valid probe is processed
        )
    except Exception as e:
        log_debug(f"Error during discovery sniffing: {e}")
        print(f"\nError during discovery listening: {e}")

    if discovery_probe_received:
         log_debug(f"Discovery probe processed from {discovery_sender_ip}:{discovery_sender_port}")
         return True
    else:
         log_debug("No valid discovery probe received within timeout.")
         print("\n[DISCOVERY] No sender probe received.")
         return False


def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Discover sender, receive file via steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time
    global highest_seq_num, packet_counter, valid_packet_counter, connection_established
    global sender_ip, sender_port, discovery_sender_ip, discovery_sender_port, discovery_probe_received

    # --- Initialization ---
    summary = {
        "timestamp": time.time(), "output_path": output_path, "key_path": key_path,
        "interface": interface, "activity_timeout": timeout
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f: json.dump(summary, f, indent=2)

    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Receiver Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    # Reset state
    received_chunks = {}; transmission_complete = False; reception_start_time = 0
    last_activity_time = time.time(); highest_seq_num = 0; packet_counter = 0
    valid_packet_counter = 0; connection_established = False; sender_ip = None
    sender_port = None; discovery_sender_ip = None; discovery_sender_port = None
    discovery_probe_received = False; ack_sent_chunks.clear()

    stego = SteganographyReceiver()

    # Prepare key first for discovery
    key = None
    if key_path:
        log_debug(f"Reading key from: {key_path}")
        print(f"Reading key: {key_path}")
        try:
            key_data = read_file(key_path, 'rb') # Use shared read_file helper? No, keep separate for now.
            with open(key_path, 'rb') as key_file: key_data = key_file.read()
            key = prepare_key(key_data) # Also derives identifiers
        except Exception as e:
            log_debug(f"Error reading key file: {e}")
            print(f"Error reading key file: {e}")
            return False
    else:
        print("Error: Key file is required for discovery.")
        sys.exit(1)

    # --- Discovery Phase ---
    if not listen_for_discovery(stego, interface):
        log_debug("Discovery failed. Exiting.")
        print("[ERROR] Could not discover sender. Exiting.")
        return False
    # If discovery succeeded, discovery_sender_ip is set

    # --- Main Listening Phase ---
    # Set sender_ip based on discovery before starting main sniff
    sender_ip = discovery_sender_ip
    log_debug(f"Proceeding to listen for connection/data from discovered sender: {sender_ip}")
    print(f"[INFO] Now listening for connection and data from {sender_ip}...")

    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(target=monitor_transmission, args=(stop_monitor, timeout))
    monitor_thread.daemon = True
    monitor_thread.start()

    log_debug(f"Listening for steganographic data on interface {interface or 'default'}...")
    print(f"Press Ctrl+C to stop listening for data")
    last_activity_time = time.time() # Reset activity timer before main loop

    try:
        # Filter more specifically now we know the sender IP
        filter_str = f"tcp and src host {sender_ip}"
        log_debug(f"Using main data filter: {filter_str}")
        sniff(
            iface=interface,
            filter=filter_str,
            prn=stego.packet_handler,
            store=0,
            stop_filter=lambda p: transmission_complete
        )
    except KeyboardInterrupt:
        log_debug("\nReceiving stopped by user")
        print("\nReceiving stopped by user")
    finally:
        stop_monitor.set()

    # --- Post-Reception Processing ---
    print("\n" + "="*20 + " Processing Received Data " + "="*20) # Add separator

    if not received_chunks:
        log_debug("No data received")
        print("No data chunks were received.")
        return False

    duration = time.time() - reception_start_time if reception_start_time > 0 else 0
    chunk_count = len(received_chunks)
    stats = {
        "total_packets_processed": packet_counter, "valid_data_packets": valid_packet_counter,
        "chunks_received": chunk_count, "highest_seq_num_seen": highest_seq_num,
        "duration_seconds": duration,
        "reception_rate_percent": (chunk_count / highest_seq_num * 100) if highest_seq_num > 0 else 0,
        "missing_chunks_approx": (highest_seq_num - chunk_count) if highest_seq_num > chunk_count else 0,
        "sender_ip": sender_ip, "sender_port": sender_port
    }
    stats_file = os.path.join(LOGS_DIR, "reception_stats.json")
    with open(stats_file, "w") as f: json.dump(stats, f, indent=2)

    log_debug("\nReception summary:")
    log_debug(f"- Processed {packet_counter} packets total (from sender: {sender_ip})")
    log_debug(f"- Identified {valid_packet_counter} valid data packets")
    log_debug(f"- Received {chunk_count} unique chunks in ~{duration:.2f}s")
    log_debug(f"- Highest sequence number seen: {highest_seq_num}")

    print(f"\nReception summary:")
    print(f"- Processed {packet_counter} packets total (from sender: {sender_ip})")
    print(f"- Identified {valid_packet_counter} valid data packets")
    print(f"- Received {chunk_count} unique data chunks in ~{duration:.2f}s")
    print(f"- Highest sequence number seen: {highest_seq_num}")

    if highest_seq_num > 0 and chunk_count < highest_seq_num:
        percentage = (chunk_count / highest_seq_num) * 100
        missing = highest_seq_num - chunk_count
        log_debug(f"- Reception rate: {percentage:.1f}% ({missing} missing)")
        print(f"- Reception rate: {percentage:.1f}% ({missing} missing)")


    log_debug("Reassembling data...")
    print("[REASSEMBLY] Starting data reassembly...")
    reassembled_data = reassemble_data()
    if not reassembled_data:
        log_debug("Failed to reassemble data")
        print("[REASSEMBLY] Failed!")
        completion_info = {"completed_at": time.time(), "status": "failed", "reason": "reassembly_failed"}
        completion_path = os.path.join(LOGS_DIR, "completion_info.json")
        with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
        return False
    log_debug(f"Reassembled {len(reassembled_data)} bytes")
    print(f"[REASSEMBLY] Reassembled {len(reassembled_data)} bytes")

    print("[VERIFY] Verifying data integrity...")
    verified_data = verify_data_integrity(reassembled_data)
    final_data = None
    if verified_data is None: # Checksum was present but failed
         print("[VERIFY] Checksum mismatch! Using data without checksum.")
         final_data = reassembled_data[:-INTEGRITY_CHECK_SIZE] if len(reassembled_data) > INTEGRITY_CHECK_SIZE else reassembled_data
    elif len(verified_data) == len(reassembled_data): # No checksum was found/verified (shouldn't happen if sender adds one)
         print("[VERIFY] Warning: Could not verify checksum (possibly missing?).")
         final_data = verified_data
    else: # Checksum verified and removed
         print(f"[VERIFY] Integrity OK. Data size: {len(verified_data)} bytes")
         final_data = verified_data

    # Decrypt if key was provided (key *is* required now)
    log_debug("Decrypting data...")
    print("[DECRYPT] Starting decryption...")
    decrypted_data = decrypt_data(final_data, key)
    if not decrypted_data:
        log_debug("Decryption failed. Saving raw (verified/reassembled) data instead.")
        print("[DECRYPT] Failed! Saving raw data instead.")
        decrypted_data = final_data # Fallback to pre-decryption data
        status = "partial_decryption_failed"
    else:
        log_debug(f"Successfully decrypted {len(decrypted_data)} bytes")
        print(f"[DECRYPT] Successfully decrypted {len(decrypted_data)} bytes")
        status = "completed"
        try:
            sample_text = decrypted_data[:100].decode('utf-8', errors='ignore')
            log_debug(f"Sample of decrypted text: {sample_text}")
            print(f"[DECRYPT] Sample text: {sample_text[:60]}...")
        except: pass # Ignore if still not text

    # Save final data
    print(f"[SAVE] Saving {len(decrypted_data)} bytes to {output_path}...")
    success = save_to_file(decrypted_data, output_path)
    print(f"[SAVE] File saved {'successfully' if success else 'with errors'}")

    completion_info = {
        "completed_at": time.time(),
        "status": status if success else "failed_save",
        "bytes_saved": len(decrypted_data) if success else 0
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)

    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    return success


def monitor_transmission(stop_event, timeout):
    """Monitor transmission for inactivity."""
    global last_activity_time, transmission_complete
    while not stop_event.is_set():
        if time.time() - last_activity_time > timeout:
            log_debug(f"\nInactivity timeout reached ({timeout} seconds)")
            print(f"\n\n[TIMEOUT] Inactivity timeout reached ({timeout} seconds). Stopping listening.")
            transmission_complete = True # Signal main sniff to stop
            break
        time.sleep(1) # Check every second

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Receiver with Key-Based Discovery')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption key file (REQUIRED for discovery)')
    parser.add_argument('--interface', '-i', help='Network interface to listen on')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity timeout seconds (default: 120)')
    parser.add_argument('--output-dir', '-d', help='Custom output directory')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT,
                        help=f'Timeout for initial sender discovery in seconds (default: {DISCOVERY_TIMEOUT})')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()

    global OUTPUT_DIR, DISCOVERY_TIMEOUT
    if args.output_dir: OUTPUT_DIR = args.output_dir
    setup_directories()

    DISCOVERY_TIMEOUT = args.discovery_timeout # Use argument

    success = receive_file(
        args.output,
        args.key,
        args.interface,
        args.timeout
    )

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()