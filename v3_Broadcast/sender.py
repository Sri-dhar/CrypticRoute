#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure, acknowledgment system, key-based discovery,
length prefix, and robust completion.
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
import struct # For packing length
import netifaces # Added for broadcast address
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, send, sniff, conf, get_if_addr, get_if_hwaddr

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
# LENGTH_PREFIX_SIZE = 8 # Bytes to store the original data length (64-bit unsigned long long)
# INTEGRITY_CHECK_SIZE = 16 # MD5 checksum size

RETRANSMIT_ATTEMPTS = 5
ACK_WAIT_TIMEOUT = 10  # Seconds to wait for an ACK before retransmission
MAX_RETRANSMISSIONS = 10  # Maximum number of times to retransmit a chunk
DISCOVERY_PORT = 54321 # Port for discovery probes/responses
DISCOVERY_TIMEOUT = 30 # Seconds to wait for discovery response
POST_TRANSMISSION_DELAY = 1.0 # Seconds to wait after last ACK before sending FIN

# Global variables for the acknowledgment system
acked_chunks = set()
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None # Discovered receiver IP
receiver_port = None # Discovered receiver port (updated during handshake)
stop_sniffing = False # For ACK listener
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

# --- Utility Functions (Directory Setup, Logging, Broadcast Address) ---

def get_broadcast_address(interface=None):
    """Gets the broadcast address for a given interface."""
    try:
        if interface:
            if interface not in netifaces.interfaces():
                 log_debug(f"Error: Interface '{interface}' not found.")
                 print(f"Error: Interface '{interface}' not found. Available: {netifaces.interfaces()}")
                 return None
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                 bcast = addrs[netifaces.AF_INET][0].get('broadcast')
                 if bcast:
                     log_debug(f"Using broadcast address for interface {interface}: {bcast}")
                     return bcast
                 else:
                     log_debug(f"Warning: Interface '{interface}' has IPv4 but no broadcast address listed.")
            else:
                log_debug(f"Warning: Interface '{interface}' has no IPv4 address.")
        else: # Try to guess default
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                default_iface = gws['default'][netifaces.AF_INET][1]
                if default_iface:
                     log_debug(f"Guessed default interface: {default_iface}")
                     addrs = netifaces.ifaddresses(default_iface)
                     if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                         bcast = addrs[netifaces.AF_INET][0].get('broadcast')
                         if bcast:
                            log_debug(f"Using broadcast address for default interface {default_iface}: {bcast}")
                            return bcast
            # Fallback: Iterate interfaces
            log_debug("Default interface broadcast failed, searching all interfaces...")
            for iface in netifaces.interfaces():
                 if iface.startswith('lo'): continue
                 try:
                     addrs = netifaces.ifaddresses(iface)
                     if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                         ip_info = addrs[netifaces.AF_INET][0]
                         bcast = ip_info.get('broadcast')
                         addr = ip_info.get('addr')
                         if bcast and addr and not addr.startswith('127.'):
                             log_debug(f"Using broadcast address from interface {iface}: {bcast}")
                             return bcast
                 except ValueError: continue # Interface might have no address

        log_debug("Could not determine a suitable broadcast address automatically.")
        print("Error: Could not determine broadcast address. Please specify an interface with -I.")
        return None
    except Exception as e:
        log_debug(f"Error getting broadcast address: {e}")
        print(f"Error getting broadcast address: {e}")
        return None


def setup_directories():
    """Create organized directory structure for outputs."""
    global OUTPUT_DIR, SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"sender_session_{timestamp}")
    os.makedirs(SESSION_DIR)
    LOGS_DIR = os.path.join(SESSION_DIR, "logs"); os.makedirs(LOGS_DIR)
    DATA_DIR = os.path.join(SESSION_DIR, "data"); os.makedirs(DATA_DIR)
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks"); os.makedirs(CHUNKS_DIR)
    DEBUG_LOG = os.path.join(LOGS_DIR, "sender_debug.log")
    latest_link = os.path.join(OUTPUT_DIR, "sender_latest")
    try:
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link): os.rename(latest_link, f"{latest_link}_{int(time.time())}")
        os.symlink(SESSION_DIR, latest_link); print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e: print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    if not DEBUG_LOG: return # Avoid error if called before setup
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e: print(f"Error writing to debug log {DEBUG_LOG}: {e}")

def derive_key_identifiers(key):
    """Derive probe and response identifiers from the key."""
    global sender_key_hash_probe, sender_key_hash_response_expected
    hasher = hashlib.sha256(); hasher.update(key); full_hash = hasher.digest()
    sender_key_hash_probe = full_hash[:4]
    sender_key_hash_response_expected = full_hash[4:8]
    log_debug(f"Derived Probe ID: {sender_key_hash_probe.hex()}")
    log_debug(f"Derived Expected Response ID: {sender_key_hash_response_expected.hex()}")

# --- Steganography Sender Class ---
class SteganographySender:
    """Simple steganography sender using TCP with acknowledgment and discovery."""

    def __init__(self, broadcast_ip, interface=None):
        """Initialize the sender."""
        self.broadcast_ip = broadcast_ip
        self.interface = interface
        self.source_port = random.randint(10000, 60000)
        self.target_ip = None # Set after discovery
        try:
             self.source_ip = get_if_addr(self.interface) if self.interface else get_if_addr(conf.iface)
        except Exception:
             self.source_ip = conf.route.get_if_source(broadcast_ip)
             log_debug(f"Warning: Could not get IP for {self.interface}, using Scapy's guess: {self.source_ip}")

        log_debug(f"Sender initialized. Source IP: {self.source_ip}, Source Port: {self.source_port}, Broadcast IP: {self.broadcast_ip}, Interface: {self.interface}")

        self._init_log_file("sent_chunks.json", "{}")
        self.sent_chunks = {}
        self.chunks_json_path = os.path.join(LOGS_DIR, "sent_chunks.json")
        self._init_log_file("received_acks.json", "{}")
        self.received_acks = {}
        self.acks_json_path = os.path.join(LOGS_DIR, "received_acks.json")

        self.ack_processing_thread = None
        self.stop_ack_processing = threading.Event()
        self.discovery_listener_thread = None
        self.stop_discovery_listener_event = threading.Event() # Renamed Event

    def _init_log_file(self, filename, initial_content="{}"):
        filepath = os.path.join(LOGS_DIR, filename)
        try:
            if not os.path.exists(filepath):
                with open(filepath, "w") as f: f.write(initial_content)
        except Exception as e: log_debug(f"Failed to initialize log file {filename}: {e}")

    def _send_packet(self, packet):
        """Internal helper to send packets using the specified interface."""
        send(packet, iface=self.interface)

    # --- Discovery Methods ---
    def start_discovery_listener(self):
        if self.discovery_listener_thread and self.discovery_listener_thread.is_alive(): return
        self.discovery_listener_thread = threading.Thread(target=self.discovery_listener_thread_func, daemon=True)
        self.stop_discovery_listener_event.clear()
        self.discovery_listener_thread.start()
        log_debug("Started Discovery Response listener thread")

    def stop_discovery_listener(self):
        if self.discovery_listener_thread and self.discovery_listener_thread.is_alive():
            self.stop_discovery_listener_event.set()
            self.discovery_listener_thread.join(timeout=2)
            if self.discovery_listener_thread.is_alive(): log_debug("Warning: Discovery listener thread did not terminate cleanly.")
            else: log_debug("Stopped Discovery Response listener thread")
        self.discovery_listener_thread = None

    def discovery_listener_thread_func(self):
        log_debug("Discovery Response listener thread started")
        filter_str = f"tcp and dst port {self.source_port}"
        log_debug(f"Sniffing for Discovery Response with filter: {filter_str} on interface {self.interface or 'default'}")
        try:
            sniff(iface=self.interface, filter=filter_str, prn=self.process_discovery_response, store=0,
                  stop_filter=lambda p: self.stop_discovery_listener_event.is_set() or discovery_complete)
        except Exception as e:
            if not self.stop_discovery_listener_event.is_set(): log_debug(f"Error in Discovery Response listener thread: {e}")
        log_debug(f"Discovery Response listener thread finished.")

    def process_discovery_response(self, packet):
        global discovery_complete, receiver_ip, receiver_port, sender_key_hash_response_expected
        if discovery_complete: return False

        if IP in packet and TCP in packet and packet[IP].src != self.source_ip \
           and packet[TCP].flags & 0x09 == 0x09 and packet[TCP].window == 0xCAFE:
            response_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery response from {packet[IP].src}:{packet[TCP].sport} (Hash: {response_hash_received.hex()})")
            if response_hash_received == sender_key_hash_response_expected:
                log_debug(f"*** Valid Discovery Response received from {packet[IP].src}:{packet[TCP].sport} ***")
                print(f"\n[DISCOVERY] Valid response received from {packet[IP].src}")
                receiver_ip = packet[IP].src
                receiver_port = packet[TCP].sport # Store the discovery port they responded FROM
                discovery_complete = True
                self.target_ip = receiver_ip
                self.stop_discovery_listener_event.set() # Signal listener thread to stop
                log_debug(f"Discovery complete. Target IP: {self.target_ip}, Receiver Port (Discovery): {receiver_port}")
                return True # Signal sniff to stop
            else: log_debug("Potential response ignored: Key hash mismatch.")
        return False

    def send_discovery_probe(self):
        global sender_key_hash_probe
        if not self.broadcast_ip: log_debug("Error: Cannot send discovery probe, broadcast IP is not set."); return
        probe_packet = IP(src=self.source_ip, dst=self.broadcast_ip) / TCP(
            sport=self.source_port, dport=DISCOVERY_PORT, flags="PU", window=0xFACE,
            seq=int.from_bytes(sender_key_hash_probe, 'big'))
        # log_debug(f"Sending Discovery Probe -> {self.broadcast_ip}:{DISCOVERY_PORT}")
        self._send_packet(probe_packet)

    # --- ACK Listener Methods ---
    def start_ack_listener(self):
        if not self.target_ip: log_debug("Cannot start ACK listener: Receiver IP not discovered."); return False
        if self.ack_processing_thread and self.ack_processing_thread.is_alive(): return True
        self.stop_ack_processing.clear(); stop_sniffing = False # Reset flags
        self.ack_processing_thread = threading.Thread(target=self.ack_listener_thread, daemon=True)
        self.ack_processing_thread.start()
        log_debug("Started ACK listener thread"); return True

    def stop_ack_listener(self):
        global stop_sniffing
        stop_sniffing = True
        if self.ack_processing_thread and self.ack_processing_thread.is_alive():
            self.stop_ack_processing.set()
            self.ack_processing_thread.join(timeout=2)
            if self.ack_processing_thread.is_alive(): log_debug("Warning: ACK listener thread did not terminate cleanly.")
            else: log_debug("Stopped ACK listener thread")
        self.ack_processing_thread = None

    def ack_listener_thread(self):
        global stop_sniffing
        log_debug("ACK listener thread started")
        filter_str = f"tcp and src host {self.target_ip} and dst port {self.source_port}"
        log_debug(f"Sniffing for ACKs with filter: {filter_str} on interface {self.interface or 'default'}")
        try:
            sniff(iface=self.interface, filter=filter_str, prn=self.process_ack_packet, store=0,
                  stop_filter=lambda p: stop_sniffing or self.stop_ack_processing.is_set())
        except Exception as e:
            if not self.stop_ack_processing.is_set() and not stop_sniffing:
                log_debug(f"Error in ACK listener thread: {e}")
        log_debug(f"ACK listener thread finished.")

    # --- Logging Helpers ---
    def log_chunk(self, seq_num, data):
        log_data_hex = data.hex()[:20] + ('...' if len(data.hex()) > 20 else '')
        self.sent_chunks[str(seq_num)] = {"data_start": log_data_hex, "size": len(data), "timestamp": time.time()}
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(self.sent_chunks, f, indent=2)
            chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:04d}.bin")
            with open(chunk_file, "wb") as f: f.write(data)
        except Exception as e: log_debug(f"Error logging chunk {seq_num}: {e}")

    def log_ack(self, seq_num):
        self.received_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.received_acks, f, indent=2)
        except Exception as e: log_debug(f"Error logging ACK {seq_num}: {e}")

    # --- Packet Creation ---
    def create_syn_packet(self):
        """Create the initial SYN for the handshake."""
        global receiver_port # Use the port discovered
        if not self.target_ip: log_debug("Cannot create SYN: Target IP not set."); return None
        # Target the discovery port initially. The receiver listens broadly for this SYN.
        target_initial_port = receiver_port if receiver_port else DISCOVERY_PORT # Fallback just in case
        log_debug(f"Creating SYN packet: {self.source_ip}:{self.source_port} -> {self.target_ip}:{target_initial_port}")
        syn_packet = IP(src=self.source_ip, dst=self.target_ip) / TCP(
            sport=self.source_port, dport=target_initial_port,
            seq=0x12345678, window=0xDEAD, flags="S")
        return syn_packet

    def create_final_ack_packet(self, synack_packet):
        """Create the final ACK to complete the handshake."""
        global receiver_ip, receiver_port # Port should have been updated by SYN-ACK processing
        if not receiver_ip or not receiver_port: log_debug("Cannot create final ACK - receiver IP/Port missing"); return None
        if not synack_packet or TCP not in synack_packet: log_debug("Cannot create final ACK - invalid SYN-ACK packet"); return None
        target_handshake_port = receiver_port
        synack_seq = synack_packet[TCP].seq
        expected_ack_num = synack_seq + 1
        log_debug(f"Creating final Handshake ACK -> {receiver_ip}:{target_handshake_port} (Acking seq {synack_seq})")
        ack_packet = IP(src=self.source_ip, dst=receiver_ip) / TCP(
            sport=self.source_port, dport=target_handshake_port,
            seq=0x12345678 + 1, ack=expected_ack_num, window=0xF00D, flags="A")
        return ack_packet

    def create_data_packet(self, data, seq_num, total_chunks):
        """Create a data packet. Uses PA flags."""
        global receiver_port # Use the established handshake port
        if not self.target_ip or not receiver_port: log_debug(f"Cannot create data packet {seq_num}: Connection info missing."); return None

        # Pad chunk if needed
        if len(data) < MAX_CHUNK_SIZE: data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE: data = data[:MAX_CHUNK_SIZE]

        seq_field = int.from_bytes(data[0:4], byteorder='big')
        ack_field = int.from_bytes(data[4:8], byteorder='big')
        chunk_checksum = binascii.crc32(data) & 0xFFFF # Checksum on 8-byte chunk

        # *** FIX: Use PA flags for data ***
        tcp_packet = IP(src=self.source_ip, dst=self.target_ip, id=chunk_checksum) / TCP(
            sport=self.source_port, dport=receiver_port,
            seq=seq_field, ack=ack_field, window=seq_num,
            flags="PA", # Use PSH+ACK for data
            options=[('MSS', total_chunks)])
        return tcp_packet

    def create_completion_packet(self):
        """Create the FIN packet."""
        global receiver_port
        if not self.target_ip or not receiver_port: log_debug("Cannot create completion packet: Connection info missing."); return None
        tcp_packet = IP(src=self.source_ip, dst=self.target_ip) / TCP(
            sport=self.source_port, dport=receiver_port, window=0xFFFF, flags="F")
        log_debug(f"Created FIN completion packet -> {self.target_ip}:{receiver_port}")
        return tcp_packet

    # --- Packet Processing ---
    def process_ack_packet(self, packet):
        """Process received SYN-ACK or Data ACK."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_ip, receiver_port # receiver_ip already known (target_ip)

        if IP not in packet or TCP not in packet or packet[IP].src != self.target_ip: return False
        packet_src_port = packet[TCP].sport

        # Check for SYN-ACK (Handshake Response)
        if not connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == 0xBEEF:
            log_debug(f"Received SYN-ACK for connection establishment from {packet[IP].src}:{packet_src_port}")
            print("[HANDSHAKE] Received SYN-ACK response")

            # ** Update receiver_port to the source port of the SYN-ACK **
            if receiver_port != packet_src_port:
                 log_debug(f"Receiver connection port updated from {receiver_port} (discovery) to {packet_src_port} (handshake)")
                 print(f"[INFO] Receiver connection port confirmed: {packet_src_port}")
                 receiver_port = packet_src_port # Update global port

            # Send final ACK to complete handshake
            final_ack_packet = self.create_final_ack_packet(packet) # Pass SYN-ACK
            if final_ack_packet:
                log_debug("Sending final ACK to complete handshake")
                print("[HANDSHAKE] Sending final ACK...")
                for _ in range(5): self._send_packet(final_ack_packet); time.sleep(0.1)
                connection_established = True
                log_debug("Connection established flag SET.")
                print("[HANDSHAKE] Connection established successfully!")
            else: log_debug("Failed to create final ACK packet!")
            return True

        # Check for Data ACK
        if connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xCAFE and packet_src_port == receiver_port:
            acked_seq_num = packet[TCP].ack
            if acked_seq_num not in acked_chunks:
                # log_debug(f"Received ACK for chunk {acked_seq_num}") # Reduce noise
                print(f"[ACK] Received acknowledgment for chunk {acked_seq_num:04d}          ", end='\r')
                self.log_ack(acked_seq_num)
                acked_chunks.add(acked_seq_num)
                if waiting_for_ack and acked_seq_num == current_chunk_seq:
                    waiting_for_ack = False
            return True
        return False

    # --- Chunk Sending ---
    def send_chunk(self, data, seq_num, total_chunks):
        """Send data chunk with ACK/retransmit. Returns True on success, False on failure."""
        global waiting_for_ack, current_chunk_seq
        if not connection_established: log_debug(f"Error: Cannot send chunk {seq_num}, connection lost."); return False
        if seq_num in acked_chunks: log_debug(f"Chunk {seq_num} already acked, skipping send."); return True

        packet = self.create_data_packet(data, seq_num, total_chunks)
        if not packet: log_debug(f"Failed to create packet for chunk {seq_num}"); return False

        self.log_chunk(seq_num, data)
        current_chunk_seq = seq_num
        waiting_for_ack = True

        # log_debug(f"Sending chunk {seq_num}/{total_chunks}...") # Reduce noise
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Sent OK: {len(acked_chunks):04d} | Progress: {(len(acked_chunks) / total_chunks) * 100:.1f}%", end='\r')
        self._send_packet(packet)

        retransmit_count = 0; max_retransmits = MAX_RETRANSMISSIONS; ack_timeout = ACK_WAIT_TIMEOUT
        start_wait_time = time.time()
        while waiting_for_ack and retransmit_count <= max_retransmits:
            time_waited = time.time() - start_wait_time; time_left = ack_timeout - time_waited
            if time_left <= 0:
                retransmit_count += 1
                if retransmit_count > max_retransmits: log_debug(f"Max retransmissions ({max_retransmits}) reached for chunk {seq_num}."); break
                log_debug(f"Timeout waiting for ACK for chunk {seq_num}. Retransmitting (attempt {retransmit_count}/{max_retransmits}).")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{max_retransmits}          ", end='\r')
                self._send_packet(packet); start_wait_time = time.time(); time.sleep(0.1)
            else: time.sleep(min(0.1, time_left))

        if not waiting_for_ack:
             log_debug(f"Chunk {seq_num} successfully acknowledged.")
             return True
        else: # Failure
             log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions.")
             print(f"\n[ERROR] Failed to receive ACK for chunk {seq_num:04d} after {max_retransmits} retries.")
             waiting_for_ack = False; return False

# --- File Handling and Crypto (Unchanged from previous fix) ---
def read_file(file_path, mode='rb'):
    try:
        with open(file_path, mode) as file: data = file.read(); log_debug(f"Read {len(data)} bytes from {file_path}"); return data
    except FileNotFoundError: log_debug(f"Error: File not found: {file_path}"); print(f"Error: File not found: {file_path}"); sys.exit(1)
    except Exception as e: log_debug(f"Error reading file {file_path}: {e}"); print(f"Error reading file {file_path}: {e}"); sys.exit(1)

def prepare_key(key_data):
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try:
        is_hex = all(c in '0123456789abcdefABCDEF' for c in key_data.decode('ascii', errors='ignore'))
        if is_hex and len(key_data) % 2 == 0: key_data = bytes.fromhex(key_data.decode('ascii')); log_debug("Interpreted key data as hex string")
        else: log_debug("Key data is not hex, using raw.")
    except Exception as e: log_debug(f"Could not process key as hex ({e}), using raw.")
    orig_len = len(key_data)
    if orig_len < 32: key_data = key_data.ljust(32, b'\0')
    elif orig_len > 32: key_data = key_data[:32]
    if orig_len != 32: log_debug(f"Key size adjusted from {orig_len} to 32 bytes.")
    log_debug(f"Using final key (AES-256): {key_data.hex()}")
    try:
        with open(os.path.join(DATA_DIR, "key.bin"), "wb") as f: f.write(key_data)
    except Exception as e: log_debug(f"Failed to save key file: {e}")
    derive_key_identifiers(key_data) # Derive hashes AFTER finalizing key
    return key_data

def encrypt_data(data, key):
    try:
        iv = os.urandom(16)
        log_debug(f"Generated random IV: {iv.hex()}")
        try: # Save IV for debug
            with open(os.path.join(DATA_DIR, "iv.bin"), "wb") as f: f.write(iv)
        except Exception as e: log_debug(f"Failed to save IV file: {e}")
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor(); encrypted_data = encryptor.update(data) + encryptor.finalize()
        try: # Save encrypted data for debug
             with open(os.path.join(DATA_DIR, "encrypted_package_iv_prepended.bin"), "wb") as f: f.write(iv + encrypted_data)
        except Exception as e: log_debug(f"Failed to save encrypted package: {e}")
        log_debug(f"Encryption complete. Package size (IV+data): {len(iv + encrypted_data)}")
        return iv + encrypted_data
    except Exception as e: log_debug(f"Encryption error: {e}"); print(f"Encryption error: {e}"); sys.exit(1)

def chunk_data(data, chunk_size=MAX_CHUNK_SIZE):
    if chunk_size <= 0: log_debug("Error: Chunk size must be positive."); return []
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split {len(data)} bytes into {len(chunks)} chunks of max size {chunk_size}")
    try: # Save minimal chunk info
        chunk_info = {i+1: {"size": len(chunk)} for i, chunk in enumerate(chunks)}
        with open(os.path.join(LOGS_DIR, "chunks_info.json"), "w") as f: json.dump(chunk_info, f, indent=2)
    except Exception as e: log_debug(f"Failed to save chunk info json: {e}")
    return chunks

# --- Discovery and Connection (Unchanged from previous version) ---
def discover_receiver(stego, timeout=DISCOVERY_TIMEOUT):
    global discovery_complete, receiver_ip, receiver_port
    log_debug("Starting receiver discovery...")
    print(f"[DISCOVERY] Broadcasting probes on {stego.broadcast_ip}:{DISCOVERY_PORT} (Timeout: {timeout}s)...")
    discovery_complete = False; receiver_ip = None; receiver_port = None
    stego.start_discovery_listener()
    start_time = time.time(); probes_sent = 0; probe_interval = 1.0
    while not discovery_complete and time.time() - start_time < timeout:
        stego.send_discovery_probe(); probes_sent += 1
        wait_end_time = time.time() + probe_interval
        while time.time() < wait_end_time:
             if discovery_complete: break
             time.sleep(0.1)
        if discovery_complete: break
    stego.stop_discovery_listener()
    if discovery_complete:
        log_debug(f"Discovery successful. Receiver: {receiver_ip}:{receiver_port}"); return True
    else:
        log_debug(f"Discovery timed out after {timeout}s."); print("\n[DISCOVERY] Failed."); return False

def establish_connection(stego):
    global connection_established, stop_sniffing, receiver_port
    if not stego.target_ip: log_debug("Cannot establish connection: Receiver not discovered."); return False
    log_debug(f"Starting connection establishment to {stego.target_ip}..."); print(f"[HANDSHAKE] Initiating connection...")
    connection_established = False; stop_sniffing = False
    if not stego.start_ack_listener(): log_debug("Failed to start ACK listener."); return False
    syn_packet = stego.create_syn_packet()
    if not syn_packet: log_debug("Failed to create SYN packet."); stego.stop_ack_listener(); return False
    log_debug(f"Sending SYN packet -> {stego.target_ip}:{receiver_port}"); print(f"[HANDSHAKE] Sending SYN...")
    max_wait = 20; start_time = time.time(); syn_sends = 0; syn_interval = 1.0
    while not connection_established and time.time() - start_time < max_wait:
        if syn_sends == 0 or time.time() > start_time + (syn_sends * syn_interval):
             # log_debug(f"Sending SYN (attempt {syn_sends + 1})") # Reduce noise
             stego._send_packet(syn_packet); syn_sends += 1
        time.sleep(0.1)
    if connection_established: log_debug("Handshake successful."); return True
    else: log_debug(f"Handshake failed."); print("[HANDSHAKE] Failed (Timeout or no SYN-ACK)."); stego.stop_ack_listener(); return False

# --- Main Send Function ---
def send_file(file_path, interface, key_path=None, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Discover, encrypt, chunk, and send a file via steganography with ACK and length prefix."""
    global connection_established, stop_sniffing, acked_chunks, receiver_ip, receiver_port, discovery_complete

    with open(DEBUG_LOG, "w") as f: # Start fresh log
        f.write(f"=== CrypticRoute Sender Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(f"File: {file_path}, Interface: {interface}, Key: {key_path}, Chunk: {chunk_size}, Delay: {delay}\n")
        f.write(f"ACK Timeout: {ACK_WAIT_TIMEOUT}, Max Retries: {MAX_RETRANSMISSIONS}, Discovery Timeout: {DISCOVERY_TIMEOUT}\n")
        f.write(f"Post-Tx Delay: {POST_TRANSMISSION_DELAY}\n")

    broadcast_ip = get_broadcast_address(interface)
    if not broadcast_ip: print("Error: Could not determine broadcast IP."); sys.exit(1)
    log_debug(f"Using broadcast address: {broadcast_ip}")

    # Initialize state
    acked_chunks = set(); connection_established = False; stop_sniffing = False
    receiver_ip = None; receiver_port = None; discovery_complete = False

    # Prepare Key (Required for Discovery)
    if not key_path: print("Error: Key file (-k) is required."); sys.exit(1)
    key_data = read_file(key_path, 'rb') # Exits on error
    key = prepare_key(key_data) # Exits on error

    stego = SteganographySender(broadcast_ip, interface) # Pass interface

    # Session Summary setup
    summary = { "timestamp_start": time.time(), "file_path": file_path,
                # "target_ip": target_ip, # REMOVED - Not known yet
                "broadcast_ip": broadcast_ip, "interface": interface, "source_ip": stego.source_ip,
                "key_provided": True, "chunk_size": chunk_size, "delay_between_chunks": delay,
                "ack_timeout": ACK_WAIT_TIMEOUT, "max_retries": MAX_RETRANSMISSIONS,
                "discovery_timeout": DISCOVERY_TIMEOUT, "post_tx_delay": POST_TRANSMISSION_DELAY }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    def write_summary():
         try:
             with open(summary_path, "w") as f: json.dump(summary, f, indent=2)
         except Exception as e: log_debug(f"Failed to write session summary: {e}")
    write_summary()

    # --- Phases ---
    if not discover_receiver(stego, DISCOVERY_TIMEOUT):
        log_debug("Aborting: Discovery failed."); print("[ERROR] Aborting: Receiver not found.")
        summary["status"] = "failed_discovery"; summary["timestamp_end"] = time.time(); write_summary(); return False

    if not establish_connection(stego):
        log_debug("Aborting: Handshake failed."); print("[ERROR] Aborting: Connection handshake failed.")
        summary["status"] = "failed_handshake"; summary["receiver_ip"] = receiver_ip; summary["timestamp_end"] = time.time(); write_summary(); return False

    # --- Data Prep ---
    print(f"\n[FILE] Reading file: {file_path}")
    original_file_data = read_file(file_path, 'rb')
    print(f"[FILE] Read {len(original_file_data)} bytes")

    print(f"[ENCRYPT] Encrypting {len(original_file_data)} bytes...")
    data_to_package = encrypt_data(original_file_data, key) # Returns iv + ciphertext
    print(f"[ENCRYPT] Result size (IV+data): {len(data_to_package)} bytes")

    original_length = len(data_to_package)
    try:
        length_bytes = struct.pack('!Q', original_length)
    except struct.error as e:
        log_debug(f"Error packing length {original_length}: {e}. Aborting."); print(f"Error: File too large?"); return False

    checksum_data = length_bytes + data_to_package
    package_checksum = hashlib.md5(checksum_data).digest()
    final_data_to_send = checksum_data + package_checksum
    total_final_size = len(final_data_to_send)
    log_debug(f"Final data: [Len={length_bytes.hex()}({original_length})] + [Data={data_to_package[:10].hex()}...] + [MD5={package_checksum.hex()}] = {total_final_size} bytes")
    print(f"[CHECKSUM] Generated MD5: {package_checksum.hex()}")
    try: # Save final package for debug
        with open(os.path.join(DATA_DIR, "final_data_package_to_send.bin"), "wb") as f: f.write(final_data_to_send)
    except Exception as e: log_debug(f"Failed to save final package: {e}")

    # --- Chunk and Send ---
    print(f"[PREP] Splitting {total_final_size} bytes into chunks (size {chunk_size})...")
    chunks = chunk_data(final_data_to_send, chunk_size); total_chunks = len(chunks)
    print(f"[PREP] Data split into {total_chunks} chunks")
    if total_chunks == 0 and total_final_size > 0: # Error check
        log_debug("Error: Chunking failed."); print("[ERROR] Failed to chunk data."); stego.stop_ack_listener(); return False

    transmission_fully_acked = True; start_tx_time = time.time()
    if total_chunks > 0:
        print(f"[TRANSMISSION] Starting ({total_chunks} chunks)...")
        for i, chunk in enumerate(chunks):
            seq_num = i + 1
            if not stego.send_chunk(chunk, seq_num, total_chunks): # Abort on first failure
                transmission_fully_acked = False
                log_debug(f"Transmission aborted: Failed ACK for chunk {seq_num}."); print(f"\n[FATAL] Aborting: Failed ACK for chunk {seq_num}.")
                summary["status"] = "failed_ack_timeout"; summary["failed_chunk"] = seq_num; break # Exit loop
            if delay > 0: time.sleep(delay)
        if transmission_fully_acked: # Only print if loop finished ok
             tx_duration = time.time() - start_tx_time
             print(f"\n[TRANSMISSION] All {total_chunks} chunks acknowledged. ({tx_duration:.2f}s)")
             summary["transmission_duration_sec"] = tx_duration
    else: print("[INFO] No data chunks to send (input empty?).")

    # --- Completion ---
    if transmission_fully_acked:
        log_debug(f"Waiting {POST_TRANSMISSION_DELAY}s before FIN...")
        print(f"[COMPLETE] Waiting {POST_TRANSMISSION_DELAY}s before FIN...")
        time.sleep(POST_TRANSMISSION_DELAY)
        completion_packet = stego.create_completion_packet()
        if completion_packet:
            print("[COMPLETE] Sending FIN signal...")
            for _ in range(5): stego._send_packet(completion_packet); time.sleep(0.2)
        else: log_debug("Failed to create FIN packet.")
    else: # Don't send FIN if transmission failed
         log_debug("Skipping FIN signal due to ACK failure.")

    # --- Cleanup & Final Stats ---
    stego.stop_ack_listener()
    ack_rate = (len(acked_chunks) / total_chunks) * 100 if total_chunks > 0 else 100
    print(f"\n[STATS] ACK rate: {ack_rate:.1f}% ({len(acked_chunks)}/{total_chunks})")
    status_msg = "completed_successfully" if transmission_fully_acked else "failed_ack_timeout"
    if total_chunks == 0 and transmission_fully_acked: status_msg = "completed_empty"
    print(f"[COMPLETE] Transmission finished: {status_msg}")

    # Final Summary Update
    summary["status"] = status_msg; summary["receiver_ip"] = receiver_ip; summary["receiver_port"] = receiver_port
    summary["total_chunks_sent"] = total_chunks; summary["chunks_acknowledged"] = len(acked_chunks); summary["ack_rate"] = ack_rate
    summary["timestamp_end"] = time.time(); write_summary()
    print(f"[INFO] Session logs saved to: {SESSION_DIR}")
    return transmission_fully_acked

# --- Main Execution ---
def parse_arguments():
    parser = argparse.ArgumentParser(description='CrypticRoute - Sender with Key-Based Discovery')
    parser.add_argument('--interface', '-I', help='Network interface for discovery/sending (e.g., eth0)')
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=True, help='Encryption key file (REQUIRED)')
    parser.add_argument('--delay', '-d', type=float, default=0.05, help='Delay between sending chunks (default: 0.05s)')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE, help=f'Transport chunk size (default/max: {MAX_CHUNK_SIZE})')
    parser.add_argument('--output-dir', '-o', help='Custom base output directory')
    parser.add_argument('--ack-timeout', '-a', type=int, default=ACK_WAIT_TIMEOUT, help=f'ACK wait timeout per attempt (default: {ACK_WAIT_TIMEOUT}s)')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS, help=f'Max retransmissions per chunk (default: {MAX_RETRANSMISSIONS})')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT, help=f'Receiver discovery timeout (default: {DISCOVERY_TIMEOUT}s)')
    parser.add_argument('--post-delay', '-pd', type=float, default=POST_TRANSMISSION_DELAY, help=f'Delay after last ACK before FIN (default: {POST_TRANSMISSION_DELAY}s)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, DISCOVERY_TIMEOUT, POST_TRANSMISSION_DELAY
    if args.output_dir: OUTPUT_DIR = args.output_dir
    setup_directories() # Setup logs ASAP
    ACK_WAIT_TIMEOUT = args.ack_timeout; MAX_RETRANSMISSIONS = args.max_retries
    DISCOVERY_TIMEOUT = args.discovery_timeout; POST_TRANSMISSION_DELAY = args.post_delay
    chunk_size = min(args.chunk_size, MAX_CHUNK_SIZE)
    if args.chunk_size <= 0: print(f"Warning: Invalid chunk size. Using {MAX_CHUNK_SIZE}."); chunk_size = MAX_CHUNK_SIZE
    elif args.chunk_size > MAX_CHUNK_SIZE: print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE}.")
    if args.interface: conf.iface = args.interface; log_debug(f"Set Scapy interface: {conf.iface}")
    success = send_file(args.input, args.interface, args.key, chunk_size, args.delay)
    print(f"\nSender finished. Overall status: {'Success' if success else 'Failed'}")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()