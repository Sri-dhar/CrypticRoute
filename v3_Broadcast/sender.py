#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure, acknowledgment system, and key-based discovery
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
import netifaces # Added for broadcast address
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, sniff, conf, get_if_addr, get_if_hwaddr

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
RETRANSMIT_ATTEMPTS = 5
ACK_WAIT_TIMEOUT = 10  # Seconds to wait for an ACK before retransmission
MAX_RETRANSMISSIONS = 10  # Maximum number of times to retransmit a chunk
DISCOVERY_PORT = 54321 # Port for discovery probes/responses
DISCOVERY_TIMEOUT = 30 # Seconds to wait for discovery response

# Global variables for the acknowledgment system
acked_chunks = set()
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None # Discovered receiver IP
receiver_port = None # Discovered receiver port (from their response)
stop_sniffing = False
discovery_complete = False # Flag for discovery success
sender_key_hash_probe = b'' # Derived from key
sender_key_hash_response_expected = b'' # Derived from key

# Output directory structure
OUTPUT_DIR = "stealth_output"
SESSION_DIR = ""
LOGS_DIR = ""
DATA_DIR = ""
CHUNKS_DIR = ""
DEBUG_LOG = ""

def get_broadcast_address(interface=None):
    """Gets the broadcast address for a given interface."""
    try:
        if interface:
            if interface not in netifaces.interfaces():
                 log_debug(f"Error: Interface '{interface}' not found.")
                 print(f"Error: Interface '{interface}' not found. Available: {netifaces.interfaces()}")
                 return None
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                return addrs[netifaces.AF_INET][0].get('broadcast')
            else:
                log_debug(f"Warning: Interface '{interface}' has no IPv4 address.")
                return None # Fallback or error needed
        else:
            # Try to guess default interface (more complex, simplified here)
            gws = netifaces.gateways()
            default_iface = gws['default'][netifaces.AF_INET][1]
            if default_iface:
                 log_debug(f"Guessed default interface: {default_iface}")
                 addrs = netifaces.ifaddresses(default_iface)
                 if netifaces.AF_INET in addrs:
                     return addrs[netifaces.AF_INET][0].get('broadcast')
            # Fallback if default guess fails
            for iface in netifaces.interfaces():
                 addrs = netifaces.ifaddresses(iface)
                 if netifaces.AF_INET in addrs:
                     bcast = addrs[netifaces.AF_INET][0].get('broadcast')
                     # Avoid loopback
                     if bcast and not addrs[netifaces.AF_INET][0].get('addr', '').startswith('127.'):
                         log_debug(f"Using broadcast address from interface {iface}: {bcast}")
                         return bcast
        log_debug("Could not determine broadcast address.")
        print("Error: Could not determine broadcast address. Please specify an interface with -I.")
        return None
    except Exception as e:
        log_debug(f"Error getting broadcast address: {e}")
        print(f"Error getting broadcast address: {e}")
        return None # Default to limited broadcast as last resort? "255.255.255.255"


def setup_directories():
    """Create organized directory structure for outputs."""
    global OUTPUT_DIR, SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"sender_session_{timestamp}")
    os.makedirs(SESSION_DIR)

    LOGS_DIR = os.path.join(SESSION_DIR, "logs")
    DATA_DIR = os.path.join(SESSION_DIR, "data")
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks")

    os.makedirs(LOGS_DIR)
    os.makedirs(DATA_DIR)
    os.makedirs(CHUNKS_DIR)

    DEBUG_LOG = os.path.join(LOGS_DIR, "sender_debug.log")

    latest_link = os.path.join(OUTPUT_DIR, "sender_latest")
    try:
        if os.path.islink(latest_link):
            os.unlink(latest_link)
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
    # Check if DEBUG_LOG is initialized
    if not DEBUG_LOG:
        print(f"Debug log not initialized. Message: {message}")
        return
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log {DEBUG_LOG}: {e}")


def derive_key_identifiers(key):
    """Derive probe and response identifiers from the key."""
    global sender_key_hash_probe, sender_key_hash_response_expected
    hasher = hashlib.sha256()
    hasher.update(key)
    full_hash = hasher.digest()
    sender_key_hash_probe = full_hash[:4] # First 4 bytes for probe
    sender_key_hash_response_expected = full_hash[4:8] # Next 4 bytes for expected response
    log_debug(f"Derived Probe ID: {sender_key_hash_probe.hex()}")
    log_debug(f"Derived Expected Response ID: {sender_key_hash_response_expected.hex()}")

class SteganographySender:
    """Simple steganography sender using TCP with acknowledgment and discovery."""

    def __init__(self, broadcast_ip):
        """Initialize the sender."""
        # self.target_ip = target_ip # Replaced by broadcast_ip for discovery
        self.broadcast_ip = broadcast_ip
        self.source_port = random.randint(10000, 60000)
        self.target_ip = None # Will be set after discovery

        chunks_json = os.path.join(LOGS_DIR, "sent_chunks.json")
        with open(chunks_json, "w") as f: f.write("{}")
        self.sent_chunks = {}
        self.chunks_json_path = chunks_json

        acks_json = os.path.join(LOGS_DIR, "received_acks.json")
        with open(acks_json, "w") as f: f.write("{}")
        self.acks_json_path = acks_json
        self.received_acks = {}

        self.ack_processing_thread = None
        self.stop_ack_processing = threading.Event()
        self.discovery_listener_thread = None # Thread for discovery responses
        # *** FIX: Rename the event attribute ***
        self.stop_discovery_listener_event = threading.Event()

    def start_discovery_listener(self):
        """Start a thread to listen for discovery response packets."""
        self.discovery_listener_thread = threading.Thread(
            target=self.discovery_listener_thread_func
        )
        self.discovery_listener_thread.daemon = True
        # *** FIX: Use the renamed event ***
        self.stop_discovery_listener_event.clear()
        self.discovery_listener_thread.start()
        log_debug("Started Discovery Response listener thread")
        print("[THREAD] Started Discovery Response listener thread")

    def stop_discovery_listener(self): # This is the METHOD
        """Stop the discovery listener thread."""
        if self.discovery_listener_thread:
            # *** FIX: Use the renamed event ***
            self.stop_discovery_listener_event.set()
            self.discovery_listener_thread.join(2)
            log_debug("Stopped Discovery Response listener thread")
            print("[THREAD] Stopped Discovery Response listener thread")

    def discovery_listener_thread_func(self):
        """Thread function to listen for discovery response packets."""
        log_debug("Discovery Response listener thread started")
        filter_str = f"tcp and dst port {self.source_port}"
        log_debug(f"Sniffing for Discovery Response with filter: {filter_str}")
        try:
            sniff(
                filter=filter_str,
                prn=self.process_discovery_response,
                store=0,
                # *** FIX: Use the renamed event ***
                stop_filter=lambda p: self.stop_discovery_listener_event.is_set()
            )
        except Exception as e:
            log_debug(f"Error in Discovery Response listener thread: {e}")
        log_debug("Discovery Response listener thread stopped")

    def process_discovery_response(self, packet):
        """Process a received packet to check if it's our discovery response."""
        global discovery_complete, receiver_ip, receiver_port, sender_key_hash_response_expected
        if discovery_complete: # Already found receiver
             return False

        # Check for expected discovery response signature
        # PSH-FIN, Window 0xCAFE, correct key hash part
        if IP in packet and TCP in packet and packet[TCP].flags & 0x09 == 0x09 and packet[TCP].window == 0xCAFE:
            # Compare the sequence number with the expected response hash
            response_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery response from {packet[IP].src}:{packet[TCP].sport}")
            log_debug(f"  Flags={packet[TCP].flags}, Window={packet[TCP].window:#x}, SeqHash={response_hash_received.hex()}")
            if response_hash_received == sender_key_hash_response_expected:
                log_debug(f"Valid Discovery Response received from {packet[IP].src}:{packet[TCP].sport}")
                print(f"\n[DISCOVERY] Valid response received from {packet[IP].src}")
                receiver_ip = packet[IP].src
                receiver_port = packet[TCP].sport # Store the port they *sent from* (the discovery port)
                discovery_complete = True
                self.target_ip = receiver_ip # Set the target IP for subsequent comms
                # *** FIX: Use the renamed event ***
                self.stop_discovery_listener_event.set() # Stop this listener
                return True # Signal sniff to stop if needed
        return False

    def send_discovery_probe(self):
        """Sends a discovery probe packet."""
        global sender_key_hash_probe
        probe_packet = IP(dst=self.broadcast_ip) / TCP(
            sport=self.source_port,
            dport=DISCOVERY_PORT,
            flags="PU", # PSH | URG
            window=0xFACE, # Magic value 1
            seq=int.from_bytes(sender_key_hash_probe, 'big')
        )
        log_debug(f"Sending Discovery Probe to {self.broadcast_ip}:{DISCOVERY_PORT}")
        send(probe_packet)


    # --- Existing methods for ACKs, Chunks, etc. ---

    def start_ack_listener(self):
        """Start a thread to listen for ACK packets (after discovery)."""
        if not self.target_ip:
             log_debug("Cannot start ACK listener: Receiver IP not discovered yet.")
             return
        self.ack_processing_thread = threading.Thread(
            target=self.ack_listener_thread
        )
        self.ack_processing_thread.daemon = True
        self.stop_ack_processing.clear()
        self.ack_processing_thread.start()
        log_debug("Started ACK listener thread")
        print("[THREAD] Started ACK listener thread")

    def stop_ack_listener(self):
        """Stop the ACK listener thread."""
        if self.ack_processing_thread:
            self.stop_ack_processing.set()
            self.ack_processing_thread.join(2)
            log_debug("Stopped ACK listener thread")
            print("[THREAD] Stopped ACK listener thread")

    def ack_listener_thread(self):
        """Thread function to listen for and process ACK packets."""
        global stop_sniffing
        log_debug("ACK listener thread started")
        # Filter for ACKs *from the discovered receiver* on our source port
        filter_str = f"tcp and src host {self.target_ip} and dst port {self.source_port}"
        log_debug(f"Sniffing for ACKs with filter: {filter_str}")
        try:
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

        chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:03d}.bin")
        with open(chunk_file, "wb") as f: f.write(data)

    def log_ack(self, seq_num):
        """Save received ACK to debug file."""
        self.received_acks[str(seq_num)] = { "timestamp": time.time() }
        with open(self.acks_json_path, "w") as f:
            json.dump(self.received_acks, f, indent=2)

    def create_syn_packet(self):
        """Create a SYN packet for connection establishment to discovered receiver."""
        if not self.target_ip: return None # Should be discovered by now
        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            # dport=random.randint(10000, 60000), # Maybe use the discovered port? Or random? Let's try random.
            dport=receiver_port if receiver_port else random.randint(10000, 60000), # Send SYN *to the port they responded from*
            seq=0x12345678,
            window=0xDEAD,
            flags="S"
        )
        return syn_packet

    def create_ack_packet(self):
        """Create an ACK packet to complete connection establishment."""
        global receiver_ip, receiver_port # Should be set by now
        if not receiver_ip or not receiver_port:
            log_debug("Cannot create ACK - receiver information missing")
            return None
        # The receiver's SYN-ACK will come from a *different* port than the discovery port
        # We need to capture that port when processing SYN-ACK
        ack_packet = IP(dst=receiver_ip) / TCP(
            sport=self.source_port,
            dport=receiver_port, # This needs to be the port from the SYN-ACK, updated in process_ack_packet
            seq=0x87654321,
            ack=0xABCDEF12,
            window=0xF00D,
            flags="A"
        )
        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data."""
        if not self.target_ip: return None # Must have discovered receiver
        if len(data) < MAX_CHUNK_SIZE: data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE: data = data[:MAX_CHUNK_SIZE]

        dst_port = random.randint(10000, 60000) # Random destination port for data

        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,
            flags="S", # Still use SYN for data packets in this simple model
            options=[('MSS', total_chunks)]
        )
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum
        return tcp_packet

    def create_completion_packet(self):
        """Create a packet signaling transmission completion."""
        if not self.target_ip: return None
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000),
            window=0xFFFF,
            flags="F"
        )
        return tcp_packet

    def process_ack_packet(self, packet):
        """Process a received ACK or SYN-ACK packet."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_ip, receiver_port # receiver_ip already known

        # Check if it's a valid TCP packet from the receiver
        if IP in packet and TCP in packet and packet[IP].src == self.target_ip:
            # Check for SYN-ACK packet (connection establishment response)
            # Note: Receiver port might change here from the discovery port!
            if not connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == 0xBEEF:
                log_debug(f"Received SYN-ACK for connection establishment from {packet[IP].src}:{packet[TCP].sport}")
                print("[HANDSHAKE] Received SYN-ACK response")

                # IMPORTANT: Update receiver_port to the source port of the SYN-ACK
                new_receiver_port = packet[TCP].sport
                if receiver_port != new_receiver_port:
                     log_debug(f"Receiver port updated from {receiver_port} to {new_receiver_port} based on SYN-ACK")
                     print(f"[INFO] Receiver handshake port: {new_receiver_port}")
                     receiver_port = new_receiver_port # Update the port for future ACKs

                # Send final ACK to complete handshake
                ack_packet = self.create_ack_packet()
                # Correct ACK number in final handshake ACK
                if ack_packet:
                     ack_packet[TCP].ack = packet[TCP].seq + 1 # Ack the SYN-ACK's sequence number
                     log_debug("Sending final ACK to complete handshake")
                     print("[HANDSHAKE] Sending final ACK to complete connection")
                     for i in range(5):
                         send(ack_packet)
                         time.sleep(0.1)
                     connection_established = True
                     print("[HANDSHAKE] Connection established successfully")
                return True

            # Check for data chunk ACK (using the specific signature)
            if connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xCAFE:
                seq_num = packet[TCP].ack
                log_debug(f"Received ACK for chunk {seq_num} from port {packet[TCP].sport}")
                self.log_ack(seq_num)
                acked_chunks.add(seq_num)
                if waiting_for_ack and seq_num == current_chunk_seq:
                    log_debug(f"Chunk {seq_num} acknowledged")
                    print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                    waiting_for_ack = False
                return True
        return False

    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq

        if not self.target_ip:
             log_debug("Cannot send chunk: Receiver not discovered.")
             return False
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping")
            # print(f"[SKIP] Chunk {seq_num:04d} already acknowledged") # Reduce noise
            return True

        packet = self.create_packet(data, seq_num, total_chunks)
        if not packet: return False # Should not happen if discovered

        self.log_chunk(seq_num, data)
        current_chunk_seq = seq_num
        waiting_for_ack = True

        log_debug(f"Sending chunk {seq_num}/{total_chunks} to {self.target_ip}")
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:.2f}%", end='\r')
        send(packet)

        retransmit_count = 0
        max_retransmits = MAX_RETRANSMISSIONS
        start_time = time.time()

        while waiting_for_ack and retransmit_count < max_retransmits:
            wait_time = 0
            while waiting_for_ack and wait_time < ACK_WAIT_TIMEOUT:
                time.sleep(0.1)
                wait_time += 0.1
                if not waiting_for_ack: break

            if waiting_for_ack:
                retransmit_count += 1
                log_debug(f"Retransmitting chunk {seq_num} (attempt {retransmit_count}/{max_retransmits})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{max_retransmits}", end='\r')
                send(packet)

        if waiting_for_ack:
            log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions")
            print(f"\n[WARNING] No ACK received for chunk {seq_num:04d} after {max_retransmits} attempts")
            waiting_for_ack = False
            return False

        elapsed = time.time() - start_time
        log_debug(f"Chunk {seq_num} acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
        # print(f"[CONFIRMED] Chunk {seq_num:04d} successfully delivered") # Reduce noise
        return True

# --- File Reading, Encryption, Chunking (Mostly Unchanged) ---

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
    """Prepare the encryption key and derive identifiers."""
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try:
        # Check if it's a hex string *before* trying to decode
        is_hex = False
        if isinstance(key_data, bytes):
             try:
                  # Try decoding as ascii first to check if it contains only hex chars
                  hex_str = key_data.decode('ascii')
                  if all(c in '0123456789abcdefABCDEF' for c in hex_str):
                      is_hex = True
             except UnicodeDecodeError:
                  pass # Not ascii, definitely not hex string

        if is_hex:
             key_data = bytes.fromhex(hex_str)
             log_debug("Converted hex key string to bytes")

    except Exception as e:
        log_debug(f"Could not check/convert hex key: {e}")
        pass # Not hex or error occurred, use as is

    if len(key_data) < 32: key_data = key_data.ljust(32, b'\0')
    key_data = key_data[:32]
    log_debug(f"Final key: {key_data.hex()}")

    key_file = os.path.join(DATA_DIR, "key.bin")
    with open(key_file, "wb") as f: f.write(key_data)

    # Derive identifiers needed for discovery
    derive_key_identifiers(key_data)

    return key_data

def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        iv = os.urandom(16) # Use random IV for actual encryption
        log_debug(f"Using IV: {iv.hex()}")
        iv_file = os.path.join(DATA_DIR, "iv.bin")
        with open(iv_file, "wb") as f: f.write(iv)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        original_file = os.path.join(DATA_DIR, "original_data.bin")
        with open(original_file, "wb") as f: f.write(data)
        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        with open(encrypted_file, "wb") as f: f.write(encrypted_data)
        package_file = os.path.join(DATA_DIR, "encrypted_package.bin")
        with open(package_file, "wb") as f: f.write(iv + encrypted_data)

        log_debug(f"Original data size: {len(data)}")
        log_debug(f"Encrypted data size: {len(encrypted_data)}")
        return iv + encrypted_data
    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"Encryption error: {e}")
        sys.exit(1)


def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    """Split data into chunks."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data into {len(chunks)} chunks of max size {chunk_size}")
    chunk_info = {i+1: {"size": len(chunk), "data": chunk.hex()} for i, chunk in enumerate(chunks)}
    chunks_json = os.path.join(LOGS_DIR, "chunks_info.json")
    with open(chunks_json, "w") as f: json.dump(chunk_info, f, indent=2)
    return chunks

def discover_receiver(stego, timeout=DISCOVERY_TIMEOUT):
    """Broadcast probes and listen for a response."""
    global discovery_complete
    log_debug("Starting receiver discovery...")
    print(f"[DISCOVERY] Broadcasting probes on {stego.broadcast_ip}:{DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Waiting up to {timeout}s for a response...")

    stego.start_discovery_listener()
    start_time = time.time()
    probes_sent = 0
    while not discovery_complete and time.time() - start_time < timeout:
        stego.send_discovery_probe()
        probes_sent += 1
        # Wait a bit, checking frequently if discovery happened
        wait_interval = 0.1
        probe_interval = 1.0 # Send probe every second
        check_count = int(probe_interval / wait_interval)
        for _ in range(check_count):
             if discovery_complete: break
             time.sleep(wait_interval)
        if discovery_complete: break


    stego.stop_discovery_listener() # <<< Ensure method is called correctly now

    if discovery_complete:
        log_debug(f"Discovery successful after {time.time() - start_time:.2f}s. Receiver: {receiver_ip}:{receiver_port}")
        print(f"\n[DISCOVERY] Success! Found receiver at {receiver_ip}")
        return True
    else:
        log_debug(f"Discovery timed out after {timeout}s.")
        print("\n[DISCOVERY] Failed. No valid response received.")
        return False


def establish_connection(stego):
    """Establish connection with the discovered receiver."""
    global connection_established, stop_sniffing
    if not stego.target_ip:
         log_debug("Cannot establish connection: Receiver not discovered.")
         return False

    log_debug("Starting connection establishment...")
    print(f"[HANDSHAKE] Initiating connection with discovered receiver {stego.target_ip}...")

    # Start ACK listener thread (now that we know the target IP)
    stego.start_ack_listener()

    syn_packet = stego.create_syn_packet()
    if not syn_packet: return False

    log_debug("Sending SYN packet")
    # Use the receiver_port discovered (initially 54321)
    print(f"[HANDSHAKE] Sending SYN packet to {stego.target_ip}:{receiver_port}...")

    # Send SYN repeatedly, waiting for SYN-ACK (processed by ack_listener_thread)
    max_wait = 20
    start_time = time.time()
    syn_sends = 0
    while not connection_established and time.time() - start_time < max_wait:
        if syn_sends < 10 or (time.time() - start_time) % 3 < 0.2: # Send frequently initially, then less often
             log_debug(f"Sending SYN ({syn_sends+1})")
             send(syn_packet)
             syn_sends+=1
        time.sleep(0.2) # Check status often

    if connection_established:
        log_debug("Connection established successfully")
        # Handshake success message is printed in process_ack_packet
        return True
    else:
        log_debug("Failed to establish connection (no SYN-ACK received)")
        print("[HANDSHAKE] Failed to establish connection with receiver.")
        stego.stop_ack_listener() # Stop listener if handshake failed
        return False

def send_file(file_path, interface, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Discover, encrypt, and send a file via steganography."""
    global connection_established, stop_sniffing, acked_chunks, receiver_ip, receiver_port, discovery_complete

    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    # Get broadcast address for the specified or default interface
    broadcast_ip = get_broadcast_address(interface)
    if not broadcast_ip:
        print("Error: Could not determine broadcast IP. Exiting.")
        sys.exit(1)
    log_debug(f"Using broadcast address: {broadcast_ip}")

    summary = {
        "timestamp": time.time(), "file_path": file_path,
        "broadcast_ip": broadcast_ip, "interface": interface,
        "key_path": key_path, "chunk_size": chunk_size, "delay": delay
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    with open(summary_path, "w") as f: json.dump(summary, f, indent=2)

    acked_chunks = set()
    connection_established = False
    stop_sniffing = False
    receiver_ip = None
    receiver_port = None
    discovery_complete = False

    # Prepare key first to get hashes for discovery
    key = None
    if key_path:
        log_debug(f"Reading key from: {key_path}")
        print(f"[KEY] Reading key: {key_path}")
        key_data = read_file(key_path, 'rb')
        key = prepare_key(key_data) # This now also derives identifiers
    else:
        print("Error: Key file is required for discovery.")
        sys.exit(1)

    stego = SteganographySender(broadcast_ip)

    # --- Discovery Phase ---
    if not discover_receiver(stego):
        log_debug("Aborting transmission due to discovery failure")
        print("[ERROR] Aborting transmission - receiver not found.")
        return False

    # --- Connection Establishment Phase ---
    if not establish_connection(stego):
        log_debug("Aborting transmission due to connection failure")
        print("[ERROR] Aborting transmission - connection handshake failed.")
        # No need to stop ack listener, establish_connection does it on failure
        return False

    # --- Data Transmission Phase ---
    log_debug(f"Reading file: {file_path}")
    print(f"\n[FILE] Reading: {file_path}")
    file_data = read_file(file_path, 'rb')
    print(f"[FILE] Read {len(file_data)} bytes successfully")

    try:
        text_content = file_data.decode('utf-8')
        log_debug(f"File content (as text): {text_content[:100]}...")
        text_file = os.path.join(DATA_DIR, "original_content.txt")
        with open(text_file, "w") as f: f.write(text_content)
    except UnicodeDecodeError:
        log_debug(f"File content (as hex): {file_data.hex()[:100]}...")

    # Encrypt data (key already prepared)
    log_debug("Encrypting data...")
    print(f"[ENCRYPT] Starting encryption of {len(file_data)} bytes...")
    file_data = encrypt_data(file_data, key)
    log_debug(f"Data encrypted, size: {len(file_data)} bytes")
    print(f"[ENCRYPT] Completed encryption. Result size: {len(file_data)} bytes")

    file_checksum = hashlib.md5(file_data).digest()
    log_debug(f"Generated MD5 checksum: {file_checksum.hex()}")
    print(f"[CHECKSUM] Generated MD5: {file_checksum.hex()}")
    file_data_with_checksum = file_data + file_checksum

    checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
    with open(checksum_file, "wb") as f: f.write(file_checksum)
    final_package_file = os.path.join(DATA_DIR, "final_data_package.bin")
    with open(final_package_file, "wb") as f: f.write(file_data_with_checksum)

    print(f"[PREP] Splitting data into chunks of size {chunk_size} bytes...")
    chunks = chunk_data(file_data_with_checksum, chunk_size)
    total_chunks = len(chunks)
    log_debug(f"File split into {total_chunks} chunks")
    print(f"[PREP] Data split into {total_chunks} chunks")

    # --- Send Chunks ---
    log_debug(f"Sending data to discovered receiver {stego.target_ip}...")
    print(f"[TRANSMISSION] Starting data transmission to {stego.target_ip}...")
    print(f"[INFO] Total chunks to send: {total_chunks}")

    transmission_success = True
    for i, chunk in enumerate(chunks):
        seq_num = i + 1
        # Simple sending order for now, priority chunks concept removed for clarity
        # print(f"[PROGRESS] Preparing chunk {seq_num:04d}/{total_chunks:04d}") # Included in send_chunk print
        success = stego.send_chunk(chunk, seq_num, total_chunks)
        # progress = (seq_num / total_chunks) * 100 # Included in send_chunk print
        if not success:
            # print(f"\n[WARNING] Chunk {seq_num:04d} may not have been received") # Printed in send_chunk
            transmission_success = False
        # else: print(f"[STATUS] Completed chunk {seq_num:04d}/{total_chunks:04d} | Progress: {progress:.2f}%") # Reduce noise
        time.sleep(delay)

    # --- Completion ---
    print("\n[COMPLETE] Sending transmission completion signals...") # Newline after progress bar
    completion_packet = stego.create_completion_packet()
    for i in range(10):
        log_debug("Sending completion signal")
        # print(f"[COMPLETE] Sending signal {i+1}/10") # Reduce noise
        send(completion_packet)
        time.sleep(0.2)

    stop_sniffing = True # Signal ACK listener thread to stop
    stego.stop_ack_listener()

    ack_rate = (len(acked_chunks) / total_chunks) * 100 if total_chunks > 0 else 0
    log_debug(f"Transmission complete! ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks})")
    print(f"[STATS] ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks} chunks acknowledged)")

    status_msg = "successfully" if transmission_success else "with some unacknowledged chunks"
    log_debug(f"Transmission completed {status_msg}")
    print(f"[COMPLETE] Transmission completed {status_msg}!")

    completion_info = {
        "completed_at": time.time(), "total_chunks_sent": total_chunks,
        "chunks_acknowledged": len(acked_chunks), "ack_rate": ack_rate,
        "status": "completed" if transmission_success else "partial",
        "receiver_ip": receiver_ip, "receiver_port": receiver_port
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)

    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    return True

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Sender with Key-Based Discovery')
    # Removed target IP, added interface
    parser.add_argument('--interface', '-I', help='Network interface to broadcast discovery probes on (e.g., eth0, wlan0)')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=True, help='Encryption key file (REQUIRED for discovery)')
    parser.add_argument('--delay', '-d', type=float, default=0.1, help='Delay between packets in seconds (default: 0.1)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE,
                        help=f'Chunk size in bytes (default: {MAX_CHUNK_SIZE})')
    parser.add_argument('--output-dir', '-o', help='Custom output directory')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT,
                        help=f'Timeout for waiting for ACK in seconds (default: {ACK_WAIT_TIMEOUT})')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS,
                        help=f'Maximum retransmission attempts per chunk (default: {MAX_RETRANSMISSIONS})')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT,
                        help=f'Timeout for receiver discovery in seconds (default: {DISCOVERY_TIMEOUT})')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()

    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, DISCOVERY_TIMEOUT
    if args.output_dir: OUTPUT_DIR = args.output_dir
    # Setup directories early to ensure DEBUG_LOG is available
    setup_directories()

    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    DISCOVERY_TIMEOUT = args.discovery_timeout # Use argument

    chunk_size = min(args.chunk_size, MAX_CHUNK_SIZE)
    if args.chunk_size > MAX_CHUNK_SIZE:
        print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE}")

    success = send_file(
        args.input,
        args.interface, # Pass interface instead of target IP
        args.key,
        chunk_size,
        args.delay
    )

    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()