#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Sender
With organized file output structure, acknowledgment system, AND key-based discovery
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
from scapy.all import IP, TCP, send, sniff, conf, get_if_addr # Removed get_if_hwaddr as it wasn't used

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
RETRANSMIT_ATTEMPTS = 5 # Note: This wasn't actually used in the original send_chunk logic
ACK_WAIT_TIMEOUT = 10  # Seconds to wait for an ACK before retransmission
MAX_RETRANSMISSIONS = 10  # Maximum number of times to retransmit a chunk
DISCOVERY_PORT = 54321 # Port for discovery probes/responses
DISCOVERY_TIMEOUT = 30 # Seconds to wait for discovery response

# Global variables for the acknowledgment system
acked_chunks = set()  # Set of sequence numbers that have been acknowledged
connection_established = False
waiting_for_ack = False
current_chunk_seq = 0
receiver_ip = None      # Discovered receiver IP (will be set after discovery)
receiver_port = None    # Discovered receiver port (will be set after discovery/handshake)
stop_sniffing = False   # Used for stopping ACK listener

# Global variables for Discovery
discovery_complete = False # Flag for discovery success
sender_key_hash_probe = b'' # Derived from key
sender_key_hash_response_expected = b'' # Derived from key
stop_discovery_listener_event = threading.Event() # Separate event for discovery listener

# Output directory structure
OUTPUT_DIR = "stealth_output"
SESSION_DIR = ""  # Will be set based on timestamp
LOGS_DIR = ""     # Will be set based on session dir
DATA_DIR = ""     # Will be set based on session dir
CHUNKS_DIR = ""   # Will be set based on session dir

# Debug log file
DEBUG_LOG = ""  # Will be set based on logs dir

# --- Functions Added/Modified for Discovery ---

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
                # Ensure 'broadcast' key exists before accessing
                if 'broadcast' in addrs[netifaces.AF_INET][0]:
                    return addrs[netifaces.AF_INET][0]['broadcast']
                else:
                    log_debug(f"Warning: Interface '{interface}' has IPv4 address but no broadcast address listed.")
                    # Attempt to calculate if mask is available
                    addr = addrs[netifaces.AF_INET][0].get('addr')
                    netmask = addrs[netifaces.AF_INET][0].get('netmask')
                    if addr and netmask:
                        ip_int = int(binascii.hexlify(socket.inet_aton(addr)), 16)
                        mask_int = int(binascii.hexlify(socket.inet_aton(netmask)), 16)
                        bcast_int = ip_int | (~mask_int & 0xffffffff)
                        return socket.inet_ntoa(binascii.unhexlify(f'{bcast_int:08x}'))
                    return None # Cannot determine broadcast
            else:
                log_debug(f"Warning: Interface '{interface}' has no IPv4 address.")
                return None
        else:
            # Try to guess default interface
            gws = netifaces.gateways()
            if 'default' in gws and netifaces.AF_INET in gws['default']:
                 default_iface = gws['default'][netifaces.AF_INET][1]
                 if default_iface:
                     log_debug(f"Guessed default interface: {default_iface}")
                     addrs = netifaces.ifaddresses(default_iface)
                     if netifaces.AF_INET in addrs and 'broadcast' in addrs[netifaces.AF_INET][0]:
                         return addrs[netifaces.AF_INET][0]['broadcast']
            # Fallback if default guess fails
            for iface in netifaces.interfaces():
                 addrs = netifaces.ifaddresses(iface)
                 if netifaces.AF_INET in addrs:
                     bcast = addrs[netifaces.AF_INET][0].get('broadcast')
                     addr = addrs[netifaces.AF_INET][0].get('addr', '')
                     # Avoid loopback and ensure broadcast exists
                     if bcast and not addr.startswith('127.'):
                         log_debug(f"Using broadcast address from interface {iface}: {bcast}")
                         return bcast
        log_debug("Could not determine broadcast address.")
        print("Error: Could not determine broadcast address. Please specify an interface with -I or ensure network configuration is correct.")
        return None
    except Exception as e:
        log_debug(f"Error getting broadcast address: {e}")
        print(f"Error getting broadcast address: {e}")
        return None

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

# --- Original Functions (setup_directories, log_debug) ---

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
        # Use relative path for symlink if possible for portability
        relative_session_dir = os.path.relpath(SESSION_DIR, start=OUTPUT_DIR)
        os.symlink(relative_session_dir, latest_link)
        print(f"Created symlink: {latest_link} -> {relative_session_dir}")
    except Exception as e:
        print(f"Warning: Could not create symlink: {e}")

    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    # Check if DEBUG_LOG is initialized
    if not DEBUG_LOG:
        # Fallback if called before setup_directories (e.g., during arg parsing)
        print(f"DEBUG (log not ready): {message}")
        return
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log {DEBUG_LOG}: {e}")


# --- SteganographySender Class (Merging Discovery into Original) ---

class SteganographySender:
    """Simple steganography sender using TCP with acknowledgment and discovery."""

    def __init__(self, broadcast_ip): # Changed target_ip to broadcast_ip
        """Initialize the sender."""
        self.broadcast_ip = broadcast_ip # Store broadcast IP for probes
        self.target_ip = None # Will be set after discovery succeeds
        self.source_port = random.randint(10000, 60000)

        # Create debug file paths
        chunks_json = os.path.join(LOGS_DIR, "sent_chunks.json")
        acks_json = os.path.join(LOGS_DIR, "received_acks.json")

        # Initialize tracking dictionaries and file paths
        self.sent_chunks = {}
        self.chunks_json_path = chunks_json
        self.received_acks = {}
        self.acks_json_path = acks_json

        # Create the files immediately
        try:
            with open(chunks_json, "w") as f: f.write("{}")
            with open(acks_json, "w") as f: f.write("{}")
        except IOError as e:
            log_debug(f"Error creating initial log files: {e}")
            # Decide if this is critical - maybe just log and continue

        # Initialize values for packet processing threads
        self.ack_processing_thread = None
        self.stop_ack_processing = threading.Event()
        # Add discovery listener attributes
        self.discovery_listener_thread = None
        self.stop_discovery_listener_event = threading.Event() # Separate event

    # --- Discovery Methods (Added from v2) ---

    def start_discovery_listener(self):
        """Start a thread to listen for discovery response packets."""
        self.discovery_listener_thread = threading.Thread(
            target=self.discovery_listener_thread_func
        )
        self.discovery_listener_thread.daemon = True
        self.stop_discovery_listener_event.clear() # Use the correct event
        self.discovery_listener_thread.start()
        log_debug("Started Discovery Response listener thread")
        print("[THREAD] Started Discovery Response listener thread")

    def stop_discovery_listener(self):
        """Stop the discovery listener thread."""
        if self.discovery_listener_thread:
            self.stop_discovery_listener_event.set() # Use the correct event
            # Don't join immediately if called from within the thread itself (e.g. process_discovery_response)
            # Let the discover_receiver function handle joining after timeout/success
            # self.discovery_listener_thread.join(2) # Joining here can cause deadlock
            log_debug("Signalled Discovery Response listener thread to stop")
            # print("[THREAD] Signalled Discovery Response listener thread to stop")

    def discovery_listener_thread_func(self):
        """Thread function to listen for discovery response packets."""
        global stop_sniffing # Also stop if main process signals stop
        log_debug("Discovery Response listener thread started")
        # Filter for TCP packets destined to our *source* port (where responses are expected)
        filter_str = f"tcp and dst port {self.source_port}"
        log_debug(f"Sniffing for Discovery Response with filter: {filter_str}")
        try:
            sniff(
                filter=filter_str,
                prn=self.process_discovery_response,
                store=0,
                stop_filter=lambda p: self.stop_discovery_listener_event.is_set() or stop_sniffing
            )
        except Exception as e:
            # Catch specific exceptions like socket errors if possible
            log_debug(f"Error in Discovery Response listener thread: {e}")
            print(f"\n[ERROR] Discovery listener thread error: {e}")
        finally:
             log_debug("Discovery Response listener thread stopped")


    def process_discovery_response(self, packet):
        """Process a received packet to check if it's our discovery response."""
        global discovery_complete, receiver_ip, receiver_port, sender_key_hash_response_expected
        if discovery_complete: # Already found receiver
             return False # Ignore further packets

        # Check for expected discovery response signature
        # PSH-FIN (0x09), Window 0xCAFE, correct key hash part in seq
        if IP in packet and TCP in packet and packet[TCP].flags & 0x09 == 0x09 and packet[TCP].window == 0xCAFE:
            response_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery response from {packet[IP].src}:{packet[TCP].sport}")
            log_debug(f"  Flags={packet[TCP].flags}, Window={packet[TCP].window:#x}, SeqHash={response_hash_received.hex()}")
            if response_hash_received == sender_key_hash_response_expected:
                log_debug(f"Valid Discovery Response received from {packet[IP].src}:{packet[TCP].sport}")
                print(f"\n[DISCOVERY] Valid response received from {packet[IP].src}") # Newline to avoid overwriting progress
                receiver_ip = packet[IP].src
                # IMPORTANT: This is the *discovery* port the receiver is listening on.
                # The port for *data* might change during handshake.
                receiver_port = packet[TCP].sport
                discovery_complete = True
                self.target_ip = receiver_ip # Set the target IP for subsequent comms
                self.stop_discovery_listener() # Signal this listener thread to stop
                return True # Indicate packet was processed and matched
        return False # Packet wasn't the expected discovery response

    def send_discovery_probe(self):
        """Sends a discovery probe packet using broadcast IP."""
        global sender_key_hash_probe
        probe_packet = IP(dst=self.broadcast_ip) / TCP(
            sport=self.source_port,
            dport=DISCOVERY_PORT,
            flags="PU", # PSH | URG
            window=0xFACE, # Magic value 1
            seq=int.from_bytes(sender_key_hash_probe, 'big') # Embed probe hash in seq
        )
        log_debug(f"Sending Discovery Probe to {self.broadcast_ip}:{DISCOVERY_PORT} with Seq={probe_packet[TCP].seq:#x}")
        send(probe_packet)


    # --- Original ACK Listener Methods (Modified for Discovered IP) ---

    def start_ack_listener(self):
        """Start a thread to listen for ACK packets (only after discovery)."""
        # Crucial: Only start if we have a target_ip from discovery
        if not self.target_ip:
            log_debug("Cannot start ACK listener: Receiver IP not discovered yet.")
            print("[ERROR] Cannot start ACK listener without discovered receiver.")
            return False # Indicate failure to start

        self.ack_processing_thread = threading.Thread(
            target=self.ack_listener_thread
        )
        self.ack_processing_thread.daemon = True
        self.stop_ack_processing.clear() # Use the ACK-specific event
        self.ack_processing_thread.start()
        log_debug("Started ACK listener thread")
        print("[THREAD] Started ACK listener thread")
        return True # Indicate success

    def stop_ack_listener(self):
        """Stop the ACK listener thread."""
        if self.ack_processing_thread:
            self.stop_ack_processing.set() # Use the ACK-specific event
            self.ack_processing_thread.join(2)  # Wait up to 2 seconds for thread to finish
            log_debug("Stopped ACK listener thread")
            print("[THREAD] Stopped ACK listener thread")

    def ack_listener_thread(self):
        """Thread function to listen for and process ACK packets."""
        global stop_sniffing # Main stop signal

        # Check again if target_ip is set, in case start_ack_listener logic changes
        if not self.target_ip:
            log_debug("ACK listener thread exiting: Target IP is not set.")
            return

        log_debug("ACK listener thread started")
        # Filter specifically for packets from the *discovered* receiver IP
        # and destined for our source port.
        filter_str = f"tcp and src host {self.target_ip} and dst port {self.source_port}"
        log_debug(f"Sniffing for ACKs with filter: {filter_str}")

        try:
            sniff(
                filter=filter_str,
                prn=self.process_ack_packet,
                store=0,
                # Stop if main process signals OR if the ACK-specific stop event is set
                stop_filter=lambda p: stop_sniffing or self.stop_ack_processing.is_set()
            )
        except Exception as e:
            log_debug(f"Error in ACK listener thread: {e}")
            print(f"[ERROR] ACK listener thread: {e}")
        finally:
            log_debug("ACK listener thread stopped")


    # --- Original Log Methods (Unchanged) ---

    def log_chunk(self, seq_num, data):
        """Save chunk data to debug file."""
        self.sent_chunks[str(seq_num)] = {
            "data": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }
        try:
            with open(self.chunks_json_path, "w") as f:
                json.dump(self.sent_chunks, f, indent=2)
        except IOError as e:
            log_debug(f"Error writing sent chunks log: {e}")

        # Also save the raw chunk data
        chunk_file = os.path.join(CHUNKS_DIR, f"chunk_{seq_num:03d}.bin")
        try:
            with open(chunk_file, "wb") as f:
                f.write(data)
        except IOError as e:
             log_debug(f"Error writing chunk file {chunk_file}: {e}")

    def log_ack(self, seq_num):
        """Save received ACK to debug file."""
        self.received_acks[str(seq_num)] = {
            "timestamp": time.time()
        }
        try:
            with open(self.acks_json_path, "w") as f:
                json.dump(self.received_acks, f, indent=2)
        except IOError as e:
             log_debug(f"Error writing received ACKs log: {e}")

    # --- Original Packet Creation Methods (Modified for Discovered IP) ---

    def create_syn_packet(self):
        """Create a SYN packet for connection establishment to discovered receiver."""
        # Requires self.target_ip (from discovery) and receiver_port (from discovery response)
        if not self.target_ip or receiver_port is None:
            log_debug("Cannot create SYN: Receiver IP or discovery port missing.")
            return None

        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=receiver_port, # Send SYN to the port they responded on (e.g., 54321)
            seq=0x12345678,      # Fixed pattern for SYN
            window=0xDEAD,       # Special window value for handshake
            flags="S"            # SYN flag
        )
        return syn_packet

    def create_ack_packet(self):
        """Create an ACK packet to complete connection establishment."""
        global receiver_ip, receiver_port # receiver_ip is self.target_ip

        # Requires receiver_ip and receiver_port (which might have been updated by SYN-ACK)
        if not self.target_ip or receiver_port is None:
            log_debug("Cannot create final ACK - receiver information missing")
            return None

        # Create an ACK packet with special markers
        # Destination port MUST be the one the SYN-ACK came *from*
        ack_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=receiver_port, # Use the potentially updated receiver_port
            seq=0x87654321,      # Fixed pattern for final ACK
            ack=0xABCDEF12,      # Placeholder: This *MUST* be updated based on received SYN-ACK seq
            window=0xF00D,       # Special window value for handshake completion
            flags="A"            # ACK flag
        )
        return ack_packet

    def create_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data (Sent to discovered receiver)."""
         # Requires self.target_ip
        if not self.target_ip:
            log_debug("Cannot create data packet: Receiver IP not set.")
            return None

        # Ensure data is exactly MAX_CHUNK_SIZE bytes
        if len(data) < MAX_CHUNK_SIZE:
            data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE:
            data = data[:MAX_CHUNK_SIZE]

        # Use random destination port for stealth during data transfer
        dst_port = random.randint(10000, 60000)

        # Embed first 4 bytes in sequence number and last 4 in ack number
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,  # Put sequence number in window field
            flags="S",       # SYN packet (as per original design)
            options=[('MSS', total_chunks)]  # Store total chunks in MSS option
        )

        # Store checksum in ID field (as per original design)
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum

        return tcp_packet

    def create_completion_packet(self):
        """Create a packet signaling transmission completion (Sent to discovered receiver)."""
        # Requires self.target_ip
        if not self.target_ip:
            log_debug("Cannot create completion packet: Receiver IP not set.")
            return None

        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000),
            window=0xFFFF,  # Special value for completion
            flags="F"       # FIN packet signals completion
        )
        return tcp_packet

    # --- Original ACK Processing (Modified for Handshake Port Update) ---

    def process_ack_packet(self, packet):
        """Process a received ACK/SYN-ACK packet from the discovered receiver."""
        global waiting_for_ack, current_chunk_seq, acked_chunks
        global connection_established, receiver_port # receiver_ip is self.target_ip

        # Check if it's a valid TCP packet from the *expected* discovered IP
        if IP in packet and TCP in packet and packet[IP].src == self.target_ip:

            # Check for SYN-ACK packet (connection establishment response)
            # Flags SYN(0x02) + ACK(0x10) = 0x12, Window 0xBEEF
            if not connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == 0xBEEF:
                log_debug(f"Received SYN-ACK for connection establishment from {packet[IP].src}:{packet[TCP].sport}")
                print("[HANDSHAKE] Received SYN-ACK response")

                # --- Port Update Logic ---
                # IMPORTANT: Update receiver_port to the source port of *this* SYN-ACK packet.
                # This is the port the receiver will use for the rest of *this* connection.
                new_receiver_port = packet[TCP].sport
                if receiver_port != new_receiver_port:
                     log_debug(f"Receiver port updated from {receiver_port} (discovery) to {new_receiver_port} (handshake) based on SYN-ACK")
                     print(f"[INFO] Receiver handshake port: {new_receiver_port}")
                     receiver_port = new_receiver_port # Update global for subsequent ACKs/data

                # Send final ACK to complete handshake
                ack_packet = self.create_ack_packet()
                if ack_packet:
                    # --- Correct ACK Number ---
                    # Set the ACK number to the received SYN-ACK sequence number + 1
                    syn_ack_seq = packet[TCP].seq
                    ack_packet[TCP].ack = syn_ack_seq + 1
                    log_debug(f"Sending final ACK (ack={ack_packet[TCP].ack:#x}) to complete handshake")
                    print(f"[HANDSHAKE] Sending final ACK to {self.target_ip}:{receiver_port}")

                    # Send multiple times for reliability
                    for i in range(5):
                        send(ack_packet)
                        time.sleep(0.1)

                    # Mark connection as established *after* sending final ACK
                    connection_established = True
                    print("[HANDSHAKE] Connection established successfully")

                return True # Packet processed

            # Check for data chunk ACK (using the original signature)
            # Flags ACK(0x10), Window 0xCAFE
            # Only process if connection is already established
            if connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == 0xCAFE:
                # Extract the sequence number from the ack field (as per original)
                seq_num = packet[TCP].ack

                log_debug(f"Received ACK for chunk {seq_num} from {packet[IP].src}:{packet[TCP].sport}") # Log source port
                self.log_ack(seq_num)

                # Add to acknowledged chunks
                acked_chunks.add(seq_num)

                # If this is the chunk we're currently waiting for, clear the wait flag
                if waiting_for_ack and seq_num == current_chunk_seq:
                    log_debug(f"Chunk {seq_num} acknowledged")
                    # Suppress print here, let send_chunk handle progress updates
                    # print(f"[ACK] Received acknowledgment for chunk {seq_num:04d}")
                    waiting_for_ack = False

                return True # Packet processed

        # If packet is not from target_ip or doesn't match expected patterns
        return False

    # --- Original send_chunk Method (Modified for Discovered IP) ---

    def send_chunk(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        global waiting_for_ack, current_chunk_seq

        # Requires self.target_ip
        if not self.target_ip:
             log_debug("Cannot send chunk: Receiver IP not set.")
             return False

        # Skip if this chunk has already been acknowledged
        if seq_num in acked_chunks:
            log_debug(f"Chunk {seq_num} already acknowledged, skipping")
            # print(f"[SKIP] Chunk {seq_num:04d} already acknowledged") # Can be noisy
            return True

        # Create the packet (will be sent to self.target_ip)
        packet = self.create_packet(data, seq_num, total_chunks)
        if not packet:
            log_debug(f"Failed to create packet for chunk {seq_num}")
            return False # Could not create packet

        # Log the chunk
        self.log_chunk(seq_num, data)

        # Set current chunk and waiting flag
        current_chunk_seq = seq_num
        waiting_for_ack = True

        # Initial transmission
        log_debug(f"Sending chunk {seq_num}/{total_chunks} to {self.target_ip}")
        # Use end='\r' for progress bar effect
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:.2f}%", end='\r', flush=True)
        send(packet)

        # Wait for ACK with retransmission (using original logic)
        retransmit_count = 0
        max_retransmits = MAX_RETRANSMISSIONS

        # Optional: Give critical chunks more retransmission attempts (from original)
        # if seq_num in [1, 4, 7]:
        #     max_retransmits = max_retransmits * 2

        start_time = time.time()

        while waiting_for_ack and retransmit_count < max_retransmits:
            # Wait a bit for ACK
            wait_start = time.time()
            while waiting_for_ack and (time.time() - wait_start) < ACK_WAIT_TIMEOUT:
                time.sleep(0.1)
                # Check if ACK received during sleep
                if not waiting_for_ack:
                    break # Exit inner wait loop

            # If we're still waiting for ACK after timeout, retransmit
            if waiting_for_ack:
                retransmit_count += 1
                log_debug(f"Retransmitting chunk {seq_num} to {self.target_ip} (attempt {retransmit_count}/{max_retransmits})")
                # Update progress bar during retransmit
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{max_retransmits} | Progress: {(seq_num / total_chunks) * 100:.2f}%", end='\r', flush=True)
                send(packet)

        # Check result after loops
        if waiting_for_ack:
            log_debug(f"Failed to get ACK for chunk {seq_num} after {max_retransmits} retransmissions")
            # Print warning on a new line after progress bar
            print(f"\n[WARNING] No ACK received for chunk {seq_num:04d} after {max_retransmits} attempts")
            waiting_for_ack = False  # Reset for next chunk
            return False
        else:
            # Success - chunk was acknowledged
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
            # Don't print confirmation here, progress bar implies success until warning
            # print(f"[CONFIRMED] Chunk {seq_num:04d} successfully delivered")
            return True


# --- Original File/Data Handling Functions (prepare_key Modified) ---

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
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')

    # Check if it's a hex string and convert if needed
    try:
        # More robust check for hex string
        is_hex = False
        if isinstance(key_data, bytes):
            try:
                decoded_key = key_data.decode('ascii')
                if all(c in '0123456789abcdefABCDEF' for c in decoded_key):
                    is_hex = True
            except UnicodeDecodeError:
                pass # Contains non-ASCII, so not a hex string representation

        if is_hex:
            key_data = bytes.fromhex(decoded_key)
            log_debug("Converted hex key string to bytes")
            # print("Interpreted key as hex string") # Optional user feedback
    except ValueError:
        log_debug("Key is not a valid hex string, using raw bytes.")
        pass # Not a valid hex string, use as is
    except Exception as e:
         log_debug(f"Error during hex key check/conversion: {e}")
         pass # Fallback to using raw bytes

    # Ensure key is 32 bytes (256 bits) for AES-256
    if len(key_data) < 32:
        key_data = key_data.ljust(32, b'\0')  # Pad to 32 bytes
    elif len(key_data) > 32:
        key_data = key_data[:32] # Truncate to 32 bytes

    log_debug(f"Final key (used for encryption): {key_data.hex()}")

    # Save key for debugging
    key_file = os.path.join(DATA_DIR, "key.bin")
    try:
        with open(key_file, "wb") as f:
            f.write(key_data)
    except IOError as e:
        log_debug(f"Error saving key file: {e}")

    # --- Derive Identifiers (Added) ---
    derive_key_identifiers(key_data)

    return key_data

def encrypt_data(data, key):
    """Encrypt data using AES."""
    try:
        # Use a random IV for security (as in original v1)
        iv = os.urandom(16)
        log_debug(f"Using random IV for encryption: {iv.hex()}")

        # Save IV for debugging
        iv_file = os.path.join(DATA_DIR, "iv.bin")
        try:
            with open(iv_file, "wb") as f:
                f.write(iv)
        except IOError as e:
             log_debug(f"Error saving IV file: {e}")

        # Initialize AES cipher with key and IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Save original and encrypted data for debugging
        original_file = os.path.join(DATA_DIR, "original_data.bin")
        encrypted_file = os.path.join(DATA_DIR, "encrypted_data.bin")
        package_file = os.path.join(DATA_DIR, "encrypted_package.bin")
        try:
            with open(original_file, "wb") as f: f.write(data)
            with open(encrypted_file, "wb") as f: f.write(encrypted_data)
            with open(package_file, "wb") as f: f.write(iv + encrypted_data) # Prepend IV
        except IOError as e:
             log_debug(f"Error saving debug data files: {e}")

        log_debug(f"Original data size: {len(data)}, Encrypted data size: {len(encrypted_data)}")

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
    chunk_info = {i+1: {"size": len(chunk), "data": chunk.hex() if len(chunk) <= 64 else chunk[:64].hex() + "..."}
                  for i, chunk in enumerate(chunks)} # Log only partial data for large chunks
    chunks_json = os.path.join(LOGS_DIR, "chunks_info.json")
    try:
        with open(chunks_json, "w") as f:
            json.dump(chunk_info, f, indent=2)
    except IOError as e:
         log_debug(f"Error saving chunk info log: {e}")

    return chunks


# --- Discovery and Connection Establishment Functions (Adapted from v2) ---

def discover_receiver(stego, timeout=DISCOVERY_TIMEOUT):
    """Broadcast probes and listen for a response."""
    global discovery_complete, receiver_ip, receiver_port
    log_debug("Starting receiver discovery...")
    print(f"[DISCOVERY] Broadcasting probes on {stego.broadcast_ip}:{DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Waiting up to {timeout}s for a response...", end="", flush=True) # Progress dots

    stego.start_discovery_listener()
    start_time = time.time()
    probes_sent = 0
    last_probe_time = 0
    probe_interval = 1.0 # Send probe every second

    while not discovery_complete and time.time() - start_time < timeout:
        # Send probe periodically
        current_time = time.time()
        if current_time - last_probe_time >= probe_interval:
             stego.send_discovery_probe()
             probes_sent += 1
             last_probe_time = current_time
             print(".", end="", flush=True) # Progress indicator

        # Sleep briefly to avoid busy-waiting
        time.sleep(0.1)

    # Stop the listener thread *after* the loop finishes or discovery is complete
    stego.stop_discovery_listener()
    # Ensure the thread has time to exit if it hasn't already
    if stego.discovery_listener_thread and stego.discovery_listener_thread.is_alive():
        stego.discovery_listener_thread.join(1.0) # Wait max 1 sec


    if discovery_complete:
        log_debug(f"Discovery successful after {time.time() - start_time:.2f}s. Probes sent: {probes_sent}. Receiver: {receiver_ip}:{receiver_port}")
        # Print success on a new line
        print(f"\n[DISCOVERY] Success! Found receiver at {receiver_ip} (responded on port {receiver_port})")
        return True
    else:
        log_debug(f"Discovery timed out after {timeout}s. Probes sent: {probes_sent}.")
        # Print failure on a new line
        print("\n[DISCOVERY] Failed. No valid response received.")
        # Clean up receiver info if discovery failed
        receiver_ip = None
        receiver_port = None
        stego.target_ip = None
        return False


def establish_connection(stego):
    """Establish connection with the discovered receiver using three-way handshake."""
    global connection_established, stop_sniffing # stop_sniffing used by listener

    # Check if discovery was successful (stego.target_ip should be set)
    if not stego.target_ip or receiver_port is None:
         log_debug("Cannot establish connection: Receiver not discovered or port missing.")
         print("[ERROR] Cannot establish connection - discovery must succeed first.")
         return False

    log_debug(f"Starting connection establishment with {stego.target_ip}:{receiver_port}")
    print(f"[HANDSHAKE] Initiating connection with discovered receiver {stego.target_ip}...")

    # Start ACK listener thread *now* that we know the target IP
    # This listener will handle the SYN-ACK and subsequent data ACKs
    if not stego.start_ack_listener():
        log_debug("Failed to start ACK listener thread.")
        print("[ERROR] Failed to start ACK listener during connection setup.")
        return False # Cannot proceed without ACK listener

    # Send SYN packet to the *discovered* port
    syn_packet = stego.create_syn_packet()
    if not syn_packet:
        log_debug("Failed to create SYN packet.")
        stego.stop_ack_listener() # Clean up listener if SYN fails
        return False

    log_debug(f"Sending SYN packet to {stego.target_ip}:{receiver_port}")
    print(f"[HANDSHAKE] Sending SYN packet to {stego.target_ip}:{receiver_port}...")

    # Send SYN repeatedly and wait for connection_established flag
    # The flag is set by process_ack_packet when SYN-ACK is received and final ACK sent
    max_wait = 20  # seconds for handshake
    start_time = time.time()
    syn_sends = 0
    syn_interval = 0.5 # Initial send interval
    max_syn_sends = 15 # Limit total SYN sends

    while not connection_established and time.time() - start_time < max_wait:
        # Send SYN if interval passed or first few sends
        if syn_sends < max_syn_sends and (syn_sends < 5 or (time.time() - start_time) % syn_interval < 0.1):
            log_debug(f"Sending SYN ({syn_sends+1})")
            send(syn_packet)
            syn_sends += 1
            # Increase interval slightly after initial burst
            if syn_sends == 5: syn_interval = 1.5

        time.sleep(0.1) # Check status frequently

    # Check if connection was established by the ACK listener thread
    if connection_established:
        log_debug("Connection established successfully (flag set by ACK listener)")
        # Success message is printed within process_ack_packet
        return True
    else:
        log_debug(f"Failed to establish connection (timeout: {max_wait}s, SYN sends: {syn_sends})")
        print("\n[HANDSHAKE] Failed to establish connection with receiver (no SYN-ACK received or processed).")
        # Stop the ACK listener if handshake failed
        stop_sniffing = True # Signal listener thread
        stego.stop_ack_listener()
        return False


# --- Main Send Function (Modified Workflow for Discovery) ---

def send_file(file_path, interface, key_path, chunk_size=MAX_CHUNK_SIZE, delay=0.1):
    """Discover, encrypt, and send a file via steganography."""
    global connection_established, stop_sniffing, acked_chunks, receiver_ip, receiver_port, discovery_complete

    # Initialize debug log (should already be initialized by main calling setup_directories)
    with open(DEBUG_LOG, "a") as f: # Append to log if already created
        f.write(f"\n=== CrypticRoute Sender Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

    # --- Phase 0: Preparation ---
    log_debug("Phase 0: Preparation")

    # Get broadcast address for the specified or default interface
    broadcast_ip = get_broadcast_address(interface)
    if not broadcast_ip:
        print("Error: Could not determine broadcast IP. Exiting.")
        sys.exit(1) # Critical failure
    log_debug(f"Using broadcast address: {broadcast_ip} (Interface: {interface or 'auto'})")

    # Create a summary file with transmission parameters
    summary = {
        "session_start_time": time.time(),
        "file_path": os.path.abspath(file_path),
        "interface": interface or 'auto',
        "broadcast_ip": broadcast_ip,
        "key_path": os.path.abspath(key_path) if key_path else None,
        "chunk_size": chunk_size,
        "delay_between_chunks": delay,
        "ack_timeout": ACK_WAIT_TIMEOUT,
        "max_retransmissions": MAX_RETRANSMISSIONS,
        "discovery_timeout": DISCOVERY_TIMEOUT,
    }
    summary_path = os.path.join(LOGS_DIR, "session_summary.json")
    try:
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2)
    except IOError as e:
        log_debug(f"Error writing session summary: {e}")

    # Reset global state variables for this session
    acked_chunks = set()
    connection_established = False
    stop_sniffing = False # Reset main stop signal
    receiver_ip = None
    receiver_port = None
    discovery_complete = False
    current_chunk_seq = 0
    waiting_for_ack = False

    # Prepare key first to get hashes needed for discovery
    log_debug(f"Reading key from: {key_path}")
    print(f"[KEY] Reading key: {key_path}")
    key_data = read_file(key_path, 'rb') # Key is required
    key = prepare_key(key_data) # This derives identifiers via derive_key_identifiers
    if not sender_key_hash_probe or not sender_key_hash_response_expected:
         print("Error: Failed to derive discovery identifiers from key.")
         sys.exit(1)

    # Create steganography sender instance (needs broadcast IP)
    stego = SteganographySender(broadcast_ip)

    # --- Phase 1: Discovery ---
    log_debug("Phase 1: Receiver Discovery")
    if not discover_receiver(stego, DISCOVERY_TIMEOUT):
        log_debug("Aborting transmission due to discovery failure")
        print("[ERROR] Aborting transmission - receiver not found.")
        # No listeners to stop yet
        return False # Indicate failure

    # --- Phase 2: Connection Establishment ---
    log_debug("Phase 2: Connection Establishment")
    # receiver_ip and initial receiver_port are now set globally if discovery succeeded
    # establish_connection will use them and start the ACK listener
    if not establish_connection(stego):
        log_debug("Aborting transmission due to connection failure")
        print("[ERROR] Aborting transmission - connection handshake failed.")
        # establish_connection stops the ACK listener on failure
        return False # Indicate failure

    # --- Phase 3: Data Preparation ---
    log_debug("Phase 3: Data Preparation")
    # Read the input file
    log_debug(f"Reading file: {file_path}")
    print(f"\n[FILE] Reading: {file_path}") # Newline after potential handshake messages
    file_data = read_file(file_path, 'rb')
    print(f"[FILE] Read {len(file_data)} bytes successfully")

    # Log text content if possible
    try:
        text_content = file_data.decode('utf-8', errors='ignore') # Be tolerant of non-utf8
        log_debug(f"File content (as text, max 200 chars): {text_content[:200]}{'...' if len(text_content)>200 else ''}")
        text_file = os.path.join(DATA_DIR, "original_content.txt")
        with open(text_file, "w", encoding='utf-8', errors='ignore') as f:
            f.write(text_content)
    except Exception as e: # Catch potential errors during decode/write
        log_debug(f"Could not log file as text: {e}")
        log_debug(f"File content (as hex, max 100 bytes): {file_data[:100].hex()}...")


    # Encrypt the data (using the prepared key)
    log_debug("Encrypting data...")
    print(f"[ENCRYPT] Starting encryption of {len(file_data)} bytes...")
    # encrypt_data prepends the IV
    encrypted_data_with_iv = encrypt_data(file_data, key)
    log_debug(f"Data encrypted (IV prepended), total size: {len(encrypted_data_with_iv)} bytes")
    print(f"[ENCRYPT] Completed encryption. Result size (including IV): {len(encrypted_data_with_iv)} bytes")

    # Add a simple checksum (MD5) to the *encrypted data + IV*
    file_checksum = hashlib.md5(encrypted_data_with_iv).digest()
    log_debug(f"Generated MD5 checksum for (IV + encrypted data): {file_checksum.hex()}")
    print(f"[CHECKSUM] Generated MD5 for transmitted payload: {file_checksum.hex()}")
    # Append checksum to the end
    payload_to_send = encrypted_data_with_iv + file_checksum

    # Save checksum and final payload package for debugging
    checksum_file = os.path.join(DATA_DIR, "md5_checksum.bin")
    final_package_file = os.path.join(DATA_DIR, "final_data_package.bin")
    try:
        with open(checksum_file, "wb") as f: f.write(file_checksum)
        with open(final_package_file, "wb") as f: f.write(payload_to_send)
    except IOError as e:
        log_debug(f"Error saving checksum/final package: {e}")

    # Chunk the final payload (IV + encrypted data + checksum)
    print(f"[PREP] Splitting {len(payload_to_send)} bytes of payload into chunks of size {chunk_size}...")
    chunks = chunk_data(payload_to_send, chunk_size)
    total_chunks = len(chunks)
    if total_chunks == 0:
         print("[WARNING] No data chunks to send (file might be empty or encryption failed?).")
         # Decide how to handle - maybe send completion signal anyway?
         # For now, let's continue to send completion.
    else:
        log_debug(f"Payload split into {total_chunks} chunks")
        print(f"[PREP] Payload split into {total_chunks} chunks")

    # --- Phase 4: Data Transmission ---
    log_debug("Phase 4: Data Transmission")
    if total_chunks > 0:
        print(f"[TRANSMISSION] Starting data transmission to {stego.target_ip}:{receiver_port}...")
        print(f"[INFO] Total chunks to send: {total_chunks}")

        transmission_success = True # Assume success unless a chunk fails ACK
        # Send chunks sequentially with ACK/retransmit
        for i, chunk in enumerate(chunks):
            seq_num = i + 1  # Sequence numbers start from 1

            # Send the chunk using the sender's method
            success = stego.send_chunk(chunk, seq_num, total_chunks)

            if not success:
                transmission_success = False # Mark overall transmission as potentially incomplete
                # Warning is printed inside send_chunk
                # Optional: break here if strict reliability is needed?
                # print(f"\n[ERROR] Failed to send chunk {seq_num}. Aborting.")
                # break

            # Add delay between packets (if ACK was fast, this ensures delay)
            time.sleep(delay)

        # Print final status line after loop (overwrites last progress bar)
        final_progress = (total_chunks / total_chunks) * 100 if total_chunks > 0 else 0
        status_char = "OK" if transmission_success else "PARTIAL"
        print(f"[SEND] Completed: {total_chunks:04d}/{total_chunks:04d} | Progress: {final_progress:.2f}% | Status: {status_char}   ") # Spaces to clear line

    else:
        print("[TRANSMISSION] No data chunks were generated. Skipping data sending phase.")
        transmission_success = True # No data to fail on


    # --- Phase 5: Completion ---
    log_debug("Phase 5: Sending Completion Signal")
    completion_packet = stego.create_completion_packet()
    if completion_packet:
        print("[COMPLETE] Sending transmission completion signals...")
        for i in range(10):  # Send multiple times to ensure receipt
            log_debug(f"Sending completion signal {i+1}/10 to {stego.target_ip}")
            # print(f"[COMPLETE] Sending signal {i+1}/10") # Can be noisy
            send(completion_packet)
            time.sleep(0.2)
    else:
        log_debug("Could not create completion packet (target IP likely missing).")
        print("[WARNING] Could not send completion signal.")

    # --- Phase 6: Cleanup and Stats ---
    log_debug("Phase 6: Cleanup and Statistics")
    # Stop the ACK listener thread (if it's running)
    stop_sniffing = True # Signal thread to stop if still running
    stego.stop_ack_listener()

    # Calculate and log statistics
    ack_rate = (len(acked_chunks) / total_chunks) * 100 if total_chunks > 0 else 100.0 # 100% if no chunks needed sending
    log_debug(f"Transmission complete! ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks})")
    print(f"[STATS] ACK rate: {ack_rate:.2f}% ({len(acked_chunks)}/{total_chunks} chunks acknowledged)")

    final_status = "completed_successfully"
    if total_chunks > 0 and not transmission_success:
        final_status = "completed_with_unacknowledged_chunks"
    elif total_chunks > 0 and len(acked_chunks) != total_chunks:
         # This case might happen if transmission_success stayed True but some ACKs were missed later?
         final_status = "completed_partially_acknowledged"


    log_debug(f"Transmission status: {final_status}")
    print(f"[COMPLETE] Transmission finished ({final_status}).")

    # Save session completion info
    completion_info = {
        "session_end_time": time.time(),
        "total_chunks_generated": total_chunks,
        "chunks_acknowledged": len(acked_chunks),
        "ack_rate_percent": round(ack_rate, 2),
        "final_status": final_status,
        "discovered_receiver_ip": receiver_ip,
        "final_receiver_port": receiver_port, # Port used for handshake/data ACKs
    }
    completion_path = os.path.join(LOGS_DIR, "completion_info.json")
    try:
        with open(completion_path, "w") as f:
            json.dump(completion_info, f, indent=2)
    except IOError as e:
        log_debug(f"Error writing completion info: {e}")

    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    print(f"[INFO] Latest session link: {os.path.join(OUTPUT_DIR, 'sender_latest')}")

    # Return overall success based on whether all ACKs were received (if chunks were sent)
    return final_status == "completed_successfully"


# --- Argument Parsing (Modified for Discovery) ---

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CrypticRoute - Sender with Key-Based Discovery',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults
    )
    # --- Discovery/Target ---
    parser.add_argument('--interface', '-I',
                        help='Network interface for discovery probes (e.g., eth0). If omitted, attempts to find default.')
    # --- Input/Key ---
    parser.add_argument('--input', '-i', required=True, help='Input file to send')
    parser.add_argument('--key', '-k', required=True,
                        help='Encryption key file (REQUIRED for discovery/encryption). Can be raw bytes or hex string.')
    # --- Transmission Params ---
    parser.add_argument('--delay', '-d', type=float, default=0.1,
                        help='Delay between sending data chunks in seconds.')
    parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE,
                        help=f'Payload chunk size in bytes (max: {MAX_CHUNK_SIZE}).')
    # --- Reliability/Timeouts ---
    parser.add_argument('--ack-timeout', '-at', type=int, default=ACK_WAIT_TIMEOUT,
                        help='Timeout (seconds) waiting for ACK before retransmitting a chunk.')
    parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS,
                        help='Maximum retransmission attempts per chunk.')
    parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT,
                        help='Timeout (seconds) for receiver discovery.')
    # --- Output ---
    parser.add_argument('--output-dir', '-o', default=OUTPUT_DIR,
                        help='Parent directory for session outputs.')
    return parser.parse_args()


# --- Main Execution ---

def main():
    """Main function."""
    global OUTPUT_DIR, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS, DISCOVERY_TIMEOUT

    args = parse_arguments()

    # Set output directory from arguments *before* setting up
    OUTPUT_DIR = args.output_dir
    # Setup directories early to ensure DEBUG_LOG is available for all logging
    setup_directories()
    log_debug("--- Sender Start ---")
    log_debug(f"Command line arguments: {sys.argv}")
    log_debug(f"Parsed arguments: {args}")


    # Set global timeout/retry values from arguments
    ACK_WAIT_TIMEOUT = args.ack_timeout
    MAX_RETRANSMISSIONS = args.max_retries
    DISCOVERY_TIMEOUT = args.discovery_timeout # Use argument

    # Validate and set chunk size
    chunk_size = args.chunk_size
    if chunk_size <= 0:
         log_debug(f"Invalid chunk size {chunk_size}, using default {MAX_CHUNK_SIZE}")
         print(f"Warning: Invalid chunk size ({chunk_size}), using default {MAX_CHUNK_SIZE}.")
         chunk_size = MAX_CHUNK_SIZE
    elif chunk_size > MAX_CHUNK_SIZE:
        log_debug(f"Chunk size {chunk_size} too large, reducing to {MAX_CHUNK_SIZE}")
        print(f"Warning: Chunk size reduced to {MAX_CHUNK_SIZE} (maximum supported for this encoding).")
        chunk_size = MAX_CHUNK_SIZE

    # Check if input file exists
    if not os.path.isfile(args.input):
        print(f"Error: Input file not found: {args.input}")
        log_debug(f"Input file not found: {args.input}")
        sys.exit(1)

    # Check if key file exists
    if not os.path.isfile(args.key):
        print(f"Error: Key file not found: {args.key}")
        log_debug(f"Key file not found: {args.key}")
        sys.exit(1)


    # Start the main process: Discover, Connect, Send
    try:
        success = send_file(
            args.input,
            args.interface, # Pass interface instead of target IP
            args.key,       # Key is required now
            chunk_size,
            args.delay
        )
    except KeyboardInterrupt:
        print("\n[ABORT] Keyboard interrupt received. Cleaning up...")
        log_debug("KeyboardInterrupt received.")
        # Ensure threads are signalled to stop if Ctrl+C happens mid-operation
        global stop_sniffing, stop_discovery_listener_event
        stop_sniffing = True
        stop_discovery_listener_event.set()
        # Add cleanup for SteganographySender instance if needed/possible
        success = False # Mark as unsuccessful exit
    except Exception as e:
        print(f"\n[FATAL ERROR] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
        log_debug(f"FATAL ERROR: {e}\n{traceback.format_exc()}")
        success = False


    log_debug(f"--- Sender End (Success: {success}) ---")
    # Exit with appropriate status code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    # Check for root privileges (needed for raw socket operations with Scapy)
    if os.geteuid() != 0:
        print("Error: This script requires root privileges to send/sniff packets.")
        sys.exit(1)
    main()