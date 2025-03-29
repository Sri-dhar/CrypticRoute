#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
With organized file output structure, acknowledgment system, and IP discovery
using key hash in discovery packets.
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
import socket # Added for UDP discovery
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, sniff, conf, send

# Configure Scapy settings
conf.verb = 0

# Global settings
MAX_CHUNK_SIZE = 8
INTEGRITY_CHECK_SIZE = 16  # MD5 checksum size in bytes
DISCOVERY_PORT = 54321 # UDP port for discovery (must match sender)
HASH_LEN_FOR_DISCOVERY = 16 # Use first 16 bytes (128 bits) of SHA256 hash

# Discovery Packet Prefixes
BEACON_PREFIX = b"CRYPTRT_BCN:" # Fixed prefix for sender beacon
READY_PREFIX = b"CRYPTRT_RDY:"   # Fixed prefix for receiver ready signal


# Global variables
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
total_chunks_expected = 0
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None  # Will store the discovered sender's IP
sender_port = None # Will store the sender's TCP source port
ack_sent_chunks = set()  # Keep track of chunks we've acknowledged
stop_sniffing_event = threading.Event() # Event to signal main TCP sniffing thread to stop
stop_ready_signal = threading.Event() # Event to signal stopping the READY sender loop

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

    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    SESSION_DIR = os.path.join(OUTPUT_DIR, f"receiver_session_{timestamp}")
    os.makedirs(SESSION_DIR)
    LOGS_DIR = os.path.join(SESSION_DIR, "logs"); os.makedirs(LOGS_DIR)
    DATA_DIR = os.path.join(SESSION_DIR, "data"); os.makedirs(DATA_DIR)
    CHUNKS_DIR = os.path.join(SESSION_DIR, "chunks"); os.makedirs(CHUNKS_DIR)
    os.makedirs(os.path.join(CHUNKS_DIR, "raw"))
    os.makedirs(os.path.join(CHUNKS_DIR, "cleaned"))
    DEBUG_LOG = os.path.join(LOGS_DIR, "receiver_debug.log")

    with open(DEBUG_LOG, "w") as f:
        f.write(f"=== CrypticRoute Receiver Session: {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")

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
    if not DEBUG_LOG: return
    try:
        with open(DEBUG_LOG, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log: {e}")


# Helper Function for Receiver Discovery
def check_for_tcp_syn(packet, expected_sender_ip):
    """Callback for sniff to detect the initial TCP SYN from the sender."""
    global sender_port # Need global scope to set this

    if stop_ready_signal.is_set(): return True # Already stopping

    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        # Check Source IP, SYN flag, and specific Handshake SYN Window value
        if ip_layer.src == expected_sender_ip and tcp_layer.flags & 0x02 and tcp_layer.window == 0xDEAD:
            log_debug(f"[DISCOVERY] Detected initial TCP SYN packet from sender {expected_sender_ip}:{tcp_layer.sport}")
            print(f"\n[DISCOVERY] Initial TCP SYN from sender detected!")
            if sender_port is None: # Learn sender's TCP port if not known
                sender_port = tcp_layer.sport
                log_debug(f"[DISCOVERY] Learned sender TCP port from initial SYN: {sender_port}")
            stop_ready_signal.set() # Signal the READY sender loop to stop
            return True # Tell sniff to stop
    return False # Tell sniff to continue


# Replaces the old listen_for_sender function
def discover_and_signal_ready(key_hash_hex, discovery_port, ready_interval=2, max_total_wait=120):
    """
    Listens for sender beacon (Prefix+Hash), then sends READY signal (Prefix+Hash)
    until sender's initial TCP SYN is detected. Returns the sender's IP if successful.
    """
    global sender_ip # Set the global sender_ip upon success

    try:
        full_key_hash_bytes = bytes.fromhex(key_hash_hex)
    except ValueError:
        log_debug("[DISCOVERY] Error: Invalid key_hash_hex provided.")
        return None
    if len(full_key_hash_bytes) < HASH_LEN_FOR_DISCOVERY:
        log_debug(f"[DISCOVERY] Error: Key hash too short ({len(full_key_hash_bytes)} < {HASH_LEN_FOR_DISCOVERY}).")
        return None

    truncated_hash = full_key_hash_bytes[:HASH_LEN_FOR_DISCOVERY]
    expected_beacon_payload = BEACON_PREFIX + truncated_hash
    ready_payload_to_send = READY_PREFIX + truncated_hash

    listen_sock = None
    send_sock = None
    discovered_ip = None
    start_time = time.time()

    log_debug(f"[DISCOVERY] Starting discovery. Truncated Key hash: {truncated_hash.hex()}")
    log_debug(f"[DISCOVERY] Expected Beacon Payload: {expected_beacon_payload.hex()}")
    log_debug(f"[DISCOVERY] Ready Payload to Send: {ready_payload_to_send.hex()}")
    print(f"[DISCOVERY] Listening for sender beacon on UDP port {discovery_port}...")

    try:
        # --- Phase 1: Listen for Beacon ---
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock.bind(('', discovery_port))
            log_debug(f"[DISCOVERY] Receiver socket bound to port {discovery_port} for beacon.")
        except OSError as e:
            print(f"[ERROR] Could not bind receiver to UDP port {discovery_port}: {e}")
            log_debug(f"[DISCOVERY] Failed to bind receiver UDP socket: {e}")
            if listen_sock: listen_sock.close()
            return None
        listen_sock.settimeout(1.0)

        while discovered_ip is None and (time.time() - start_time) < max_total_wait:
            try:
                data, addr = listen_sock.recvfrom(1024)
                log_debug(f"[DISCOVERY] Rcvd {len(data)} UDP bytes from {addr} while listening for beacon.")
                if data == expected_beacon_payload:
                    discovered_ip = addr[0] # Found sender!
                    print(f"\n[DISCOVERY] Valid beacon received from {discovered_ip} (port {addr[1]})!")
                    log_debug(f"[DISCOVERY] Valid beacon received from {discovered_ip}:{addr[1]}. Transitioning to READY state.")
                    break # Exit beacon loop
                # else: Ignore other packets silently

            except socket.timeout:
                log_debug("[DISCOVERY] Timeout waiting for beacon...")
                continue
            except Exception as e:
                log_debug(f"[DISCOVERY] Error receiving beacon: {e}")
                time.sleep(0.1)

        if listen_sock: listen_sock.close(); log_debug("[DISCOVERY] Closed beacon listening socket.")
        if discovered_ip is None:
            print("[DISCOVERY] Failed: Timed out waiting for sender beacon.")
            log_debug("[DISCOVERY] Failed to find sender beacon within timeout.")
            return None

        # --- Phase 2: Send READY and Sniff for TCP SYN ---
        sender_ip = discovered_ip # Set global variable now
        print(f"[DISCOVERY] Sending READY signal to {sender_ip}:{discovery_port} periodically...")
        log_debug(f"[DISCOVERY] Starting READY signal loop to {sender_ip}:{discovery_port}.")
        stop_ready_signal.clear()
        last_ready_sent_time = 0
        ready_start_time = time.time()
        # Use remaining time from max_total_wait for this phase
        max_ready_wait = max_total_wait - (time.time() - start_time)

        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Define filter string for initial TCP SYN (matching sender's create_syn_packet)
        # Use specific window value 0xDEAD
        tcp_syn_filter = f"tcp and src host {sender_ip} and tcp[tcpflags] & tcp-syn != 0 and tcp[14:2] = {0xDEAD}"
        log_debug(f"[DISCOVERY] Starting intermittent sniff for initial TCP SYN with filter: {tcp_syn_filter}")

        while not stop_ready_signal.is_set() and (time.time() - ready_start_time) < max_ready_wait :
            current_time = time.time()
            # Send READY periodically
            if current_time - last_ready_sent_time >= ready_interval:
                try:
                    bytes_sent = send_sock.sendto(ready_payload_to_send, (sender_ip, discovery_port))
                    log_debug(f"Sent READY signal ({bytes_sent} bytes) to {sender_ip}:{discovery_port}")
                    print(f"\r[DISCOVERY] Sending READY signal...", end="")
                    last_ready_sent_time = current_time
                except OSError as send_err:
                    log_debug(f"Error sending READY signal: {send_err}")
                    print(f"\n[DISCOVERY] Warning: Error sending READY signal: {send_err}")
                    time.sleep(0.5)

            # Sniff for the TCP SYN packet for a short duration without blocking READY sends
            try:
                 sniff(
                     filter=tcp_syn_filter,
                     prn=lambda pkt: check_for_tcp_syn(pkt, sender_ip), # Pass sender_ip
                     store=0,
                     count=1, # Stop sniff after finding one match
                     timeout=0.5, # Sniff briefly
                     stop_filter=lambda p: stop_ready_signal.is_set() # Allow external stop
                 )
            except ImportError as e:
                 log_debug(f"FATAL: Scapy sniffing dependency error in READY phase: {e}. Cannot detect SYN.")
                 print(f"\n[FATAL ERROR] Scapy cannot sniff packets: {e}. Cannot proceed.")
                 stop_ready_signal.set() # Stop sending READY
                 discovered_ip = None # Mark discovery as failed
                 break # Exit READY loop
            except OSError as e:
                log_debug(f"FATAL: OS error during sniff in READY phase (Permissions?): {e}")
                print(f"\n[FATAL ERROR] Cannot sniff packets (Permissions issue?): {e}. Cannot proceed.")
                stop_ready_signal.set()
                discovered_ip = None
                break
            except Exception as sniff_err:
                 log_debug(f"[DISCOVERY] Error during TCP SYN sniff attempt: {sniff_err}")
                 # Continue READY loop, maybe sniff will work next time
                 time.sleep(0.1)

        if send_sock: send_sock.close(); log_debug("[DISCOVERY] Closed READY signal sending socket.")

        # Check why loop ended
        if stop_ready_signal.is_set() and discovered_ip is not None:
            print("\n[DISCOVERY] Detected sender's TCP SYN. Stopping READY signals.")
            log_debug("[DISCOVERY] READY signal loop stopped: TCP SYN detected.")
            return discovered_ip # Success! Ready for TCP phase.
        else:
            # Loop ended due to timeout or critical sniff error
            if discovered_ip is None: # Critical error during sniff
                 print("\n[DISCOVERY] Failed: Critical error during TCP SYN sniffing.")
                 log_debug("[DISCOVERY] READY signal loop stopped: Critical sniff error.")
            else: # Timeout
                 print("\n[DISCOVERY] Failed: Timed out waiting for sender to start TCP transmission.")
                 log_debug("[DISCOVERY] READY signal loop timed out waiting for TCP SYN.")
            return None

    except KeyboardInterrupt:
        print("\n[DISCOVERY] Discovery interrupted by user.")
        log_debug("[DISCOVERY] Discovery interrupted by user.")
        if listen_sock and listen_sock.fileno() != -1: listen_sock.close()
        if send_sock and send_sock.fileno() != -1: send_sock.close()
        stop_ready_signal.set()
        return None
    except Exception as e:
         print(f"\n[DISCOVERY] An unexpected error occurred during receiver discovery: {e}")
         log_debug(f"[DISCOVERY] An unexpected error occurred during receiver discovery: {e}")
         if listen_sock and listen_sock.fileno() != -1: listen_sock.close()
         if send_sock and send_sock.fileno() != -1: send_sock.close()
         stop_ready_signal.set()
         return None

class SteganographyReceiver:
    """Simple steganography receiver using only TCP with acknowledgment."""

    def __init__(self):
        """Initialize the receiver for TCP handling."""
        self.chunks_json_path = os.path.join(LOGS_DIR, "received_chunks.json")
        self.acks_json_path = os.path.join(LOGS_DIR, "sent_acks.json")
        # Initialize/clear log files
        try:
            with open(self.chunks_json_path, "w") as f: json.dump({}, f)
            with open(self.acks_json_path, "w") as f: json.dump({}, f)
        except Exception as e: log_debug(f"Error initializing receiver log files: {e}")

        self.sent_acks = {}
        # Use a random high port for TCP source port (for SYN-ACK, Data ACKs)
        self.my_port = random.randint(10000, 60000)
        log_debug(f"Receiver TCP handler initialized. Will use TCP source port {self.my_port}.")


    def log_chunk(self, seq_num, data):
        """Save received chunk info to JSON and raw file."""
        # Load existing JSON safely
        chunk_info = {}
        try:
            if os.path.exists(self.chunks_json_path) and os.path.getsize(self.chunks_json_path) > 0:
                with open(self.chunks_json_path, "r") as f: chunk_info = json.load(f)
        except Exception as e: log_debug(f"Error reading chunks JSON: {e}")
        # Update and save JSON
        chunk_info[str(seq_num)] = { "data": data.hex(), "size": len(data), "timestamp": time.time() }
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(chunk_info, f, indent=2)
        except Exception as e: log_debug(f"Error writing chunks JSON: {e}")
        # Save raw chunk data
        try:
            chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:03d}.bin")
            with open(chunk_file, "wb") as f: f.write(data)
        except Exception as e: log_debug(f"Error writing raw chunk {seq_num}: {e}")


    def log_ack(self, seq_num):
        """Save sent ACK info to JSON log."""
        self.sent_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.sent_acks, f, indent=2)
        except Exception as e: log_debug(f"Error writing ACKs JSON: {e}")


    def create_ack_packet(self, seq_num):
        """Create a TCP ACK packet for a specific data chunk sequence number."""
        if not sender_ip or not sender_port:
            log_debug("Cannot create data ACK - sender IP or TCP Port missing")
            return None
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, dport=sender_port,
            seq=0x12345678,  # Fixed pattern for Data ACK
            ack=seq_num,     # Acknowledged chunk number
            window=0xCAFE,   # Special window for Data ACKs
            flags="A"
        )
        # log_debug(f"Created Data ACK packet for chunk {seq_num} to {sender_ip}:{sender_port}") # Verbose
        return ack_packet

    def send_ack(self, seq_num):
        """Send acknowledgment for a specific sequence number."""
        global ack_sent_chunks
        if seq_num in ack_sent_chunks:
            # log_debug(f"Already sent ACK for chunk {seq_num}, skipping.") # Maybe re-ACK? For now, skip.
            return
        ack_packet = self.create_ack_packet(seq_num)
        if not ack_packet: return

        log_debug(f"Sending ACK for chunk {seq_num}")
        print(f"\r[ACK] Sending acknowledgment for chunk {seq_num:04d}", end="")
        self.log_ack(seq_num)
        try:
            for i in range(3): # Send multiple times for reliability
                send(ack_packet)
                time.sleep(0.05)
            ack_sent_chunks.add(seq_num)
        except Exception as e:
             log_debug(f"Error sending ACK for chunk {seq_num}: {e}")
             print(f"\n[ERROR] Failed to send ACK for {seq_num}: {e}")


    def create_syn_ack_packet(self):
        """Create the TCP SYN-ACK packet for connection establishment."""
        if not sender_ip or not sender_port:
            log_debug("Cannot create SYN-ACK - sender IP or TCP Port missing")
            return None
        # Acknowledge sender's initial SYN seq (0x12345678) + 1
        syn_ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, dport=sender_port,
            seq=0xABCDEF12,      # Our initial sequence number for SYN-ACK
            ack=0x12345678 + 1,
            window=0xBEEF,       # Special window for handshake SYN-ACK
            flags="SA"
        )
        log_debug(f"Created Handshake SYN-ACK packet for {sender_ip}:{sender_port}")
        return syn_ack_packet

    def send_syn_ack(self):
        """Send SYN-ACK response for connection establishment."""
        syn_ack_packet = self.create_syn_ack_packet()
        if not syn_ack_packet: return
        log_debug("Sending Handshake SYN-ACK")
        print("\n[HANDSHAKE] Sending SYN-ACK response")
        try:
            for i in range(5): # Send multiple times
                send(syn_ack_packet)
                time.sleep(0.1)
        except Exception as e:
             log_debug(f"Error sending SYN-ACK: {e}")
             print(f"\n[ERROR] Failed to send SYN-ACK: {e}")


    def packet_handler(self, packet):
        """Wrapper for process_packet (TCP phase)."""
        global packet_counter, last_activity_time, transmission_complete

        if stop_sniffing_event.is_set(): return # Stop processing if signaled

        last_activity_time = time.time()
        packet_counter += 1

        # Basic filtering (already done by Scapy filter, but double-check)
        if not (IP in packet and TCP in packet and packet[IP].src == sender_ip):
            return

        # Print status periodically
        if packet_counter % 20 == 0 or valid_packet_counter < 5:
             progress_perc = (len(received_chunks) / total_chunks_expected * 100) if total_chunks_expected > 0 else 0
             # Ensure status fits on one line
             status_line = f"[TCP Status] Pkts Rcvd: {packet_counter:6d} | Valid Data: {valid_packet_counter:4d} | Chunks: {len(received_chunks):4d}/{total_chunks_expected:4d} ({progress_perc:3.0f}%) | Conn: {'Yes' if connection_established else 'No '}"
             print(f"\r{status_line:<80}", end="") # Pad to clear previous line

        processed_status = self.process_packet(packet)

        if processed_status == "COMPLETED":
            transmission_complete = True
            stop_sniffing_event.set()
            print("\n[INFO] Transmission complete signal received. Stopping TCP sniffer.")
            log_debug("Transmission complete signal processed. Stopping TCP sniffer.")
        elif processed_status == "HANDSHAKE_SYN":
             # Add a newline after handshake message for clarity
             print() # Move to next line after handshake SYN message


    def process_packet(self, packet):
        """Process a received TCP packet from the sender during the TCP phase."""
        global received_chunks, reception_start_time, highest_seq_num
        global valid_packet_counter, total_chunks_expected, connection_established, sender_port

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        # Learn/confirm sender's TCP source port if not already known
        if sender_port is None and tcp_layer.sport != 0:
            sender_port = tcp_layer.sport
            log_debug(f"Learned sender TCP source port {sender_port} from packet flags {tcp_layer.flags:#x}")
            print(f"\n[HANDSHAKE] Learned sender port: {sender_port}", end="") # Stay on same line if possible

        # --- Handshake Packet Handling (TCP Phase) ---
        # 1. Check for initial Handshake SYN (Should have been caught by discovery phase ideally, but handle here too)
        # Matches sender's create_syn_packet: SYN flag, specific window, specific seq
        if not connection_established and tcp_layer.flags & 0x02 and tcp_layer.window == 0xDEAD and tcp_layer.seq == 0x12345678:
            log_debug(f"Received initial Handshake SYN from {ip_layer.src}:{tcp_layer.sport}")
            print(f"\n[HANDSHAKE] Received initial connection request (SYN)", end="")

            if sender_port != tcp_layer.sport: # Update port if needed
                 log_debug(f"Handshake SYN source port {tcp_layer.sport} differs from discovery learned {sender_port}. Updating.")
                 sender_port = tcp_layer.sport
            self.send_syn_ack() # Respond
            # Do not set connection_established yet, wait for sender's final ACK
            return "HANDSHAKE_SYN" # Special status for handler wrapper

        # 2. Check for sender's final Handshake ACK
        # Matches sender's create_ack_packet: ACK flag, specific window, seq, ack
        if not connection_established and tcp_layer.flags & 0x10 and tcp_layer.window == 0xF00D \
           and tcp_layer.seq == 0x87654321 and tcp_layer.ack == (0xABCDEF12 + 1):
            log_debug(f"Received final Handshake ACK from {ip_layer.src}:{tcp_layer.sport}")
            print("\n[HANDSHAKE] Connection established with sender.")
            connection_established = True
            if reception_start_time == 0: # Record start time of actual data phase
                 reception_start_time = time.time()
                 log_debug(f"TCP Reception timer started at {reception_start_time}")
            return True

        # --- Data and Completion Packet Handling (Requires established connection) ---
        if not connection_established: return False # Ignore other packets pre-connection

        # 3. Check for transmission completion signal (FIN packet)
        # Matches sender's create_completion_packet: FIN flag, specific window
        if tcp_layer.flags & 0x01 and tcp_layer.window == 0xFFFF:
            log_debug(f"Received transmission complete signal (FIN) from {ip_layer.src}:{tcp_layer.sport}")
            return "COMPLETED" # Special status for handler wrapper

        # 4. Check for Data Packet
        # Matches sender's create_packet: SYN flag, window carries seq_num, seq/ack carry data
        is_potential_data = False
        if tcp_layer.flags & 0x02: # SYN flag check
             # Window must be positive and not a special handshake/completion value
             if tcp_layer.window > 0 and tcp_layer.window not in [0xDEAD, 0xBEEF, 0xF00D, 0xFFFF, 0xCAFE]:
                  is_potential_data = True

        if is_potential_data:
            seq_num = tcp_layer.window # Sequence number from window field
            current_total_chunks = None
            try: # Extract total chunks from MSS option
                for option in tcp_layer.options:
                    if isinstance(option, tuple) and option[0] == 'MSS':
                        current_total_chunks = option[1]; break
            except Exception as e: log_debug(f"Error parsing TCP options for chunk {seq_num}: {e}")

            if current_total_chunks is None:
                log_debug(f"Ignored potential data packet (Win={seq_num}): Missing MSS option.")
                return False # Not a valid data packet per protocol

            # Learn total expected chunks
            global total_chunks_expected
            if total_chunks_expected == 0 and current_total_chunks > 0:
                total_chunks_expected = current_total_chunks
                print(f"\n[INFO] Learned total expected chunks: {total_chunks_expected}", end="") # Stay on same line
                log_debug(f"Learned total expected chunks: {total_chunks_expected}")
            elif total_chunks_expected > 0 and current_total_chunks != total_chunks_expected:
                 log_debug(f"Warning: Packet Win={seq_num} MSS ({current_total_chunks}) differs from expected ({total_chunks_expected})")

            valid_packet_counter += 1 # Count this as a validly structured data packet

            # Extract data and checksum
            try:
                 seq_bytes = tcp_layer.seq.to_bytes(4, byteorder='big', signed=False)
                 ack_bytes = tcp_layer.ack.to_bytes(4, byteorder='big', signed=False)
                 data = seq_bytes + ack_bytes
                 checksum = ip_layer.id
            except OverflowError:
                 log_debug(f"Warning: Seq/Ack num too large in packet Win={seq_num}. Skipping.")
                 return False
            except Exception as e:
                 log_debug(f"Error extracting data/checksum for Win={seq_num}: {e}")
                 return False

            # Verify checksum
            calc_checksum = binascii.crc32(data) & 0xFFFF
            checksum_ok = (checksum == calc_checksum)
            if not checksum_ok:
                log_debug(f"Checksum MISMATCH for chunk {seq_num}. Expected={checksum:04x}, Calc={calc_checksum:04x}, Data={data.hex()}")
                print(f"\n[WARN] Checksum mismatch for chunk {seq_num:04d}!", end="")
            # else: log_debug(f"Checksum VALID for chunk {seq_num} ({checksum:04x})") # Verbose

            if seq_num in received_chunks: # Check for duplicate
                log_debug(f"Received duplicate chunk {seq_num}. Re-sending ACK.")
                print(f"\n[DUPLICATE] Chunk {seq_num:04d} received again.", end="")
                self.send_ack(seq_num) # Re-ACK
                return True # Processed as duplicate

            # Store the chunk (even if checksum failed)
            log_debug(f"Storing chunk {seq_num} (Size: {len(data)}). Checksum OK={checksum_ok}")
            received_chunks[seq_num] = data
            self.log_chunk(seq_num, data)
            self.send_ack(seq_num) # Acknowledge receipt

            if seq_num > highest_seq_num: highest_seq_num = seq_num

            # Print detailed chunk info on a new line to avoid interfering with status line
            progress = (len(received_chunks) / total_chunks_expected * 100) if total_chunks_expected > 0 else 0
            chunk_info_str = f"Received: {seq_num:04d}/{total_chunks_expected:04d} | Total Rcvd: {len(received_chunks):04d} | Progress: {progress:.1f}%"
            print(f"\n[CHUNK] {chunk_info_str} {'(Checksum OK)' if checksum_ok else '(CHECKSUM FAIL)'}", end="") # Stay on same line

            return True # Data packet processed

        # Packet from sender, connection established, but didn't match known patterns
        # log_debug(f"Ignored unexpected TCP packet. Flags={tcp_layer.flags:#x}, Win={tcp_layer.window:#x}") # Verbose
        return False


# --- Functions for key prep, decryption, integrity check, reassembly, saving ---
# --- (These remain largely unchanged from previous version) ---

def prepare_key(key_data):
    """Prepare the encryption key (32 bytes) and return bytes and SHA256 hex hash."""
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try: # Check if hex
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             key_bytes_from_hex = bytes.fromhex(key_data.decode('ascii'))
             key_data = key_bytes_from_hex
             log_debug("Interpreted key data as hex string.")
             print("Interpreted key data as hex string.")
    except ValueError: pass # Not hex

    original_len = len(key_data)
    if original_len < 32: key_data = key_data.ljust(32, b'\0')
    elif original_len > 32: key_data = key_data[:32]
    if original_len != 32: log_debug(f"Key adjusted from {original_len} bytes to 32 bytes.")

    log_debug(f"Final key bytes (for decryption): {key_data.hex()}")
    try: # Save key for debugging
        with open(os.path.join(DATA_DIR, "key.bin"), "wb") as f: f.write(key_data)
    except Exception as e: log_debug(f"Error saving key.bin: {e}")

    key_hash = hashlib.sha256(key_data).digest()
    key_hash_hex = key_hash.hex()
    log_debug(f"Key hash (SHA256 for discovery): {key_hash_hex}")
    print(f"[KEY] Key Hash (SHA256): {key_hash_hex}")
    return key_data, key_hash_hex


def decrypt_data(data, key):
    """Decrypt data using AES-256-CFB (expects IV prepended)."""
    iv_len = 16
    if len(data) < iv_len:
        log_debug(f"Decryption error: Data length ({len(data)}) < IV length ({iv_len}).")
        return None
    try:
        iv = data[:iv_len]
        encrypted_data = data[iv_len:]
        log_debug(f"Extracted IV: {iv.hex()} for decryption. Encrypted size: {len(encrypted_data)}")
        # Save components for debugging
        try:
            with open(os.path.join(DATA_DIR, "extracted_iv.bin"), "wb") as f: f.write(iv)
            with open(os.path.join(DATA_DIR, "encrypted_data_for_decryption.bin"), "wb") as f: f.write(encrypted_data)
        except Exception as e: log_debug(f"Error saving decryption debug files: {e}")

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        log_debug(f"Decryption successful. Decrypted data size: {len(decrypted_data)}")
        try: # Save decrypted data for debugging
            with open(os.path.join(DATA_DIR, "decrypted_data.bin"), "wb") as f: f.write(decrypted_data)
        except Exception as e: log_debug(f"Error saving decrypted_data.bin: {e}")
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"[DECRYPT] Error: {e}")
        return None


def verify_data_integrity(data):
    """Verify MD5 checksum (expects checksum appended). Returns (payload_data, is_valid)."""
    if len(data) < INTEGRITY_CHECK_SIZE:
        log_debug(f"Integrity check error: Data length ({len(data)}) < checksum size ({INTEGRITY_CHECK_SIZE}).")
        return None, False
    try:
        payload_data = data[:-INTEGRITY_CHECK_SIZE]
        received_checksum = data[-INTEGRITY_CHECK_SIZE:]
        log_debug(f"Verifying integrity. Payload size: {len(payload_data)}, Rcvd checksum: {received_checksum.hex()}")
        # Save components for debugging
        try:
            with open(os.path.join(DATA_DIR, "data_before_checksum_verification.bin"), "wb") as f: f.write(payload_data)
            with open(os.path.join(DATA_DIR, "received_checksum.bin"), "wb") as f: f.write(received_checksum)
        except Exception as e: log_debug(f"Error saving integrity debug files: {e}")

        calculated_checksum = hashlib.md5(payload_data).digest()
        log_debug(f"Calculated checksum: {calculated_checksum.hex()}")
        try: # Save calculated checksum
            with open(os.path.join(DATA_DIR, "calculated_checksum.bin"), "wb") as f: f.write(calculated_checksum)
        except Exception as e: log_debug(f"Error saving calculated_checksum.bin: {e}")

        checksum_match = (calculated_checksum == received_checksum)
        # Save result
        checksum_info = { "expected": calculated_checksum.hex(), "received": received_checksum.hex(), "match": checksum_match }
        try:
             with open(os.path.join(LOGS_DIR, "checksum_verification.json"), "w") as f: json.dump(checksum_info, f, indent=2)
        except Exception as e: log_debug(f"Error saving checksum_verification.json: {e}")

        if checksum_match:
             log_debug("Integrity check successful.")
             print("[VERIFY] Data integrity check successful.")
        else:
             log_debug("CHECKSUM MISMATCH!")
             print("[VERIFY] Warning: Data integrity check FAILED!")
        return payload_data, checksum_match
    except Exception as e:
         log_debug(f"Error during integrity check: {e}")
         print(f"[ERROR] Integrity check failed: {e}")
         return None, False


def reassemble_data():
    """Reassemble received chunks, check for missing ones, and remove potential padding."""
    global received_chunks, highest_seq_num, total_chunks_expected
    if not received_chunks: return None, 0

    print(f"[REASSEMBLY] Sorting {len(received_chunks)} received chunks...")
    log_debug(f"Reassembling {len(received_chunks)} chunks. Highest seq: {highest_seq_num}, Expected total: {total_chunks_expected}")
    sorted_seq_nums = sorted(received_chunks.keys())
    if not sorted_seq_nums: return None, 0

    expected_total = total_chunks_expected if total_chunks_expected > 0 else highest_seq_num
    if expected_total == 0 and sorted_seq_nums: expected_total = sorted_seq_nums[-1]

    missing_chunks_count = 0
    missing_chunks_list = []
    if expected_total > 0:
        present_chunks_set = set(sorted_seq_nums)
        for i in range(1, expected_total + 1):
            if i not in present_chunks_set:
                missing_chunks_count += 1
                if len(missing_chunks_list) < 20: missing_chunks_list.append(i)

    if missing_chunks_count > 0:
        log_debug(f"Warning: Detected {missing_chunks_count} missing chunks (Expected: {expected_total}). Sample: {missing_chunks_list}")
        print(f"[REASSEMBLY] Warning: Missing {missing_chunks_count} chunks! Sample: {missing_chunks_list}")
    else: log_debug(f"No missing chunks detected up to expected total {expected_total}.")

    try: # Save diagnostic info
        chunk_info = { "received_count": len(received_chunks), "highest_seq": highest_seq_num,
                       "expected_total_mss": total_chunks_expected, "expected_total_final": expected_total,
                       "missing_count": missing_chunks_count, "missing_sample": missing_chunks_list,
                       "received_seq_nums": sorted_seq_nums[:100] } # Limit logged sequences
        with open(os.path.join(LOGS_DIR, "reassembly_info.json"), "w") as f: json.dump(chunk_info, f, indent=2)
    except Exception as e: log_debug(f"Error saving reassembly_info.json: {e}")

    # Concatenate chunks in order
    reassembled_list = [received_chunks[seq] for seq in sorted_seq_nums]
    reassembled_data = b"".join(reassembled_list)
    log_debug(f"Raw reassembled data size: {len(reassembled_data)} bytes")
    try: # Save raw reassembled data
        with open(os.path.join(DATA_DIR, "reassembled_data_raw.bin"), "wb") as f: f.write(reassembled_data)
    except Exception as e: log_debug(f"Error saving reassembled_data_raw.bin: {e}")

    # --- Padding Removal (from end of entire reassembled data) ---
    final_data = reassembled_data
    # Remove padding only if we received the chunk matching the expected total
    if sorted_seq_nums and expected_total > 0 and sorted_seq_nums[-1] == expected_total:
         last_chunk_data = received_chunks[expected_total]
         # Assume padding if last chunk was exactly MAX_CHUNK_SIZE
         if len(last_chunk_data) == MAX_CHUNK_SIZE:
             # Find last non-null byte in the *entire* reassembled data
             last_non_null = reassembled_data.rfind(next((bytes([x]) for x in range(255,0,-1) if bytes([x]) in reassembled_data), b'\0'))

             if last_non_null != -1:
                  original_len = len(final_data)
                  final_data = reassembled_data[:last_non_null + 1]
                  stripped_count = original_len - len(final_data)
                  if stripped_count > 0:
                       log_debug(f"Stripped {stripped_count} trailing null bytes (assuming padding).")
                       print(f"[REASSEMBLY] Removed {stripped_count} potential padding bytes.")
             else: # All nulls?
                  final_data = b'\0'
                  log_debug("Warning: Reassembled data was all nulls. Kept one.")
         else: log_debug("Last chunk was < max size, no padding removal needed.")
    else: log_debug("Did not receive expected last chunk or total unknown. Skipping padding removal.")


    log_debug(f"Final reassembled data size after padding check: {len(final_data)} bytes")
    try: # Save final data
        with open(os.path.join(DATA_DIR, "reassembled_data_final.bin"), "wb") as f: f.write(final_data)
    except Exception as e: log_debug(f"Error saving reassembled_data_final.bin: {e}")

    print(f"[REASSEMBLY] Completed! Final data size: {len(final_data)} bytes")
    return final_data, missing_chunks_count


def save_to_file(data, output_path):
    """Save final data to output file."""
    if data is None:
        log_debug("Save error: Data is None."); return False
    try:
        with open(output_path, 'wb') as file: file.write(data)
        log_debug(f"Final payload data saved to {output_path} ({len(data)} bytes)")
        print(f"[SAVE] Data successfully saved to: {output_path}")
        try: # Copy to session data dir
            with open(os.path.join(DATA_DIR, f"output_{os.path.basename(output_path)}"), "wb") as f: f.write(data)
        except Exception as e: log_debug(f"Error copying output to data dir: {e}")
        try: # Try print preview
            text_content = data.decode('utf-8')
            preview = text_content[:200]
            log_debug(f"Saved content preview (UTF-8): {preview}...")
            print(f"Saved content preview:\n---\n{preview}{'...' if len(text_content) > 200 else ''}\n---")
            try: # Save text version
                 with open(os.path.join(DATA_DIR, "output_content.txt"), "w", encoding='utf-8') as f: f.write(text_content)
            except Exception as e: log_debug(f"Error saving output_content.txt: {e}")
        except UnicodeDecodeError:
            log_debug("Saved content is not valid UTF-8 text.")
            print("(Saved content is binary or non-UTF8)")
        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"[SAVE] Error saving data to {output_path}: {e}")
        return False


def monitor_transmission(stop_event, timeout):
    """Monitor TCP transmission phase for inactivity."""
    global last_activity_time, transmission_complete

    log_debug(f"TCP Monitor thread started. Inactivity timeout: {timeout}s")
    while not stop_event.is_set():
        # Check inactivity only if TCP reception has actually started
        if reception_start_time > 0 and (time.time() - last_activity_time > timeout):
            log_debug(f"TCP Inactivity timeout reached ({timeout} seconds). Signaling stop.")
            print(f"\n[TIMEOUT] TCP Inactivity timeout reached ({timeout}s). Stopping.")
            transmission_complete = True # Mark as complete due to timeout
            stop_sniffing_event.set() # Signal main TCP sniffing thread to stop
            break
        time.sleep(1) # Check every second
    log_debug("TCP Monitor thread stopped.")


def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Discover sender and receive a file via steganography."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time
    global highest_seq_num, packet_counter, valid_packet_counter, connection_established
    global sender_ip, stop_sniffing_event, total_chunks_expected, ack_sent_chunks, sender_port

    # --- Setup and Key Processing ---
    session_start_time = time.time()
    log_debug("Receiver process started.")
    summary = { "timestamp": session_start_time, "output_path": output_path, "key_path": key_path,
                "interface": interface, "timeout": timeout, "discovery_port": DISCOVERY_PORT }
    try: # Save initial summary
        with open(os.path.join(LOGS_DIR, "session_summary.json"), "w") as f: json.dump(summary, f, indent=2)
    except Exception as e: log_debug(f"Error saving initial summary: {e}")

    # Reset state variables
    received_chunks = {}; transmission_complete = False; reception_start_time = 0
    last_activity_time = time.time(); highest_seq_num = 0; total_chunks_expected = 0
    packet_counter = 0; valid_packet_counter = 0; connection_established = False
    sender_ip = None; sender_port = None; ack_sent_chunks = set()
    stop_sniffing_event.clear(); stop_ready_signal.clear()

    # Process Key File (Mandatory)
    if not key_path:
        print("[ERROR] Key file (--key) is required."); log_debug("Key file missing."); return False
    log_debug(f"Reading key from: {key_path}")
    try:
        with open(key_path, 'rb') as key_file: key_data_raw = key_file.read()
        key_bytes, key_hash_hex = prepare_key(key_data_raw)
        if not key_bytes or not key_hash_hex:
             print("[ERROR] Failed to process key file."); return False
    except FileNotFoundError:
         print(f"[ERROR] Key file not found: {key_path}"); log_debug("Key file not found."); return False
    except Exception as e:
         print(f"[ERROR] Failed reading key file: {e}"); log_debug(f"Error reading key: {e}"); return False

    # --- Discovery Phase ---
    print("--- Discovery Phase ---")
    discovered_ip = discover_and_signal_ready(key_hash_hex, DISCOVERY_PORT, max_total_wait=timeout)

    if not discovered_ip:
        print("[DISCOVERY] Failed. Aborting.")
        log_debug("Discovery/READY phase failed or timed out.")
        # Save failure status
        try:
            summary.update({"completed_at": time.time(), "status": "failed", "reason": "discovery_failed"})
            with open(os.path.join(LOGS_DIR, "completion_info.json"), "w") as f: json.dump(summary, f, indent=2)
        except Exception as e: log_debug(f"Error saving discovery failure info: {e}")
        return False
    # sender_ip global should be set by discover_and_signal_ready on success
    print(f"[INFO] Sender confirmed at {sender_ip}. Proceeding with TCP reception.")
    log_debug(f"Sender IP set to {sender_ip}. Starting main TCP sniff.")

    # --- TCP Reception Phase ---
    print("\n--- TCP Reception Phase ---")
    stego = SteganographyReceiver()
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(target=monitor_transmission, args=(stop_monitor, timeout), name="TCPMonitorThread")
    monitor_thread.daemon = True; monitor_thread.start()
    log_debug("TCP Inactivity monitor thread started.")

    print(f"Listening for TCP communication from {sender_ip}...")
    log_debug(f"Listening for TCP data from {sender_ip} on interface {interface or 'default'}...")
    print("Press Ctrl+C to stop listening manually")

    # Reset TCP specific state variables
    transmission_complete = False; reception_start_time = 0
    last_activity_time = time.time(); stop_sniffing_event.clear()

    try:
        filter_str = f"tcp and src host {sender_ip}"
        sniff(iface=interface, filter=filter_str, prn=stego.packet_handler, store=0,
              stop_filter=lambda p: stop_sniffing_event.is_set())
    except KeyboardInterrupt:
        log_debug("Sniffing stopped by user (Ctrl+C).")
        print("\n[INFO] Sniffing stopped by user.")
        transmission_complete = True; stop_sniffing_event.set()
    except ImportError as e:
         log_debug(f"FATAL: Scapy sniffing dependency error in TCP phase: {e}.")
         print(f"\n[FATAL ERROR] Scapy cannot sniff packets: {e}. Cannot proceed.")
         transmission_complete = True; stop_sniffing_event.set() # Assume failure
    except OSError as e:
         log_debug(f"FATAL: OS error during sniff in TCP phase (Permissions?): {e}")
         print(f"\n[FATAL ERROR] Cannot sniff packets (Permissions issue?): {e}.")
         transmission_complete = True; stop_sniffing_event.set()
    except Exception as e:
         log_debug(f"An error occurred during TCP packet sniffing: {e}")
         print(f"\n[ERROR] TCP Packet sniffing failed: {e}")
         transmission_complete = True; stop_sniffing_event.set()
    finally:
        stop_monitor.set(); monitor_thread.join(1.0)
        print("\n[INFO] TCP Packet sniffing stopped.")
        log_debug("TCP Packet sniffing process finished.")

    # --- Post-Reception Processing ---
    print("\n--- Post-Reception Processing ---")
    log_debug("Starting post-reception processing.")
    session_end_time = time.time()

    if not received_chunks:
        log_debug("No data chunks received during TCP phase."); print("[RESULT] No data chunks received.")
        final_status = "failed_no_chunks"
        success = False
    else:
        duration = session_end_time - reception_start_time if reception_start_time > 0 else 0
        chunk_count = len(received_chunks)
        final_expected = total_chunks_expected if total_chunks_expected > 0 else highest_seq_num
        rate = (chunk_count / final_expected * 100) if final_expected > 0 else (100 if chunk_count > 0 else 0)
        missing = (final_expected - chunk_count) if final_expected > 0 else 0
        print(f"[STATS] Rcvd {chunk_count}/{final_expected} chunks ({rate:.1f}%). Highest Seq: {highest_seq_num}. Duration: {duration:.2f}s.")

        reassembled_data, _ = reassemble_data()
        if reassembled_data is None:
            log_debug("Reassembly failed."); print("[RESULT] Failed to reassemble data.")
            final_status = "failed_reassembly"; success = False
        else:
            payload_data, checksum_ok = verify_data_integrity(reassembled_data)
            if payload_data is None:
                log_debug("Integrity check failed critically."); print("[RESULT] Failed integrity check critically.")
                final_status = "failed_integrity"; success = False
            else:
                data_to_process = payload_data
                final_data = data_to_process
                decryption_status = "not_needed"
                if key_bytes: # Decrypt if key provided
                    print("[DECRYPT] Decrypting data...")
                    decrypted_result = decrypt_data(data_to_process, key_bytes)
                    if decrypted_result is None:
                        print("[DECRYPT] Error: Decryption failed! Saving raw payload.")
                        final_data = data_to_process; decryption_status = "failed"
                    else:
                        print(f"[DECRYPT] Decryption successful. Size: {len(decrypted_result)} bytes.")
                        final_data = decrypted_result; decryption_status = "success"

                save_success = save_to_file(final_data, output_path)
                if save_success:
                     success = True # Mark overall success if saved
                     if decryption_status == "success" and checksum_ok and missing == 0: final_status = "completed_perfect"
                     elif decryption_status == "success" and checksum_ok: final_status = "completed_with_missing_chunks"
                     elif decryption_status == "success": final_status = "completed_decrypted_errors"
                     elif decryption_status == "failed": final_status = "completed_decryption_failed"
                     elif decryption_status == "not_needed" and checksum_ok and missing == 0: final_status = "completed_raw_perfect"
                     elif decryption_status == "not_needed" and checksum_ok: final_status = "completed_raw_missing_chunks"
                     else: final_status = "completed_raw_errors"
                else:
                     final_status = "failed_save"; success = False

    # Save final completion info
    try:
        stats = { "pkts_processed": packet_counter, "valid_data_pkts": valid_packet_counter,
                  "chunks_rcvd": len(received_chunks), "highest_seq": highest_seq_num,
                  "expected_total": final_expected if 'final_expected' in locals() else 0,
                  "missing_est": missing if 'missing' in locals() else -1,
                  "conn_established": connection_established, "fin_received": transmission_complete and not stop_monitor.is_set() }
        summary.update({ "completed_at": session_end_time, "status": final_status,
                         "bytes_saved": len(final_data) if 'final_data' in locals() and final_data else 0,
                         "checksum_ok": checksum_ok if 'checksum_ok' in locals() else None,
                         "decryption": decryption_status if 'decryption_status' in locals() else None,
                         **stats })
        with open(os.path.join(LOGS_DIR, "completion_info.json"), "w") as f: json.dump(summary, f, indent=2)
    except Exception as e: log_debug(f"Error saving completion info: {e}")

    print(f"\n[RESULT] Operation finished. Status: {final_status}")
    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    return success


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Receiver with Discovery')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption/Discovery key file')
    parser.add_argument('--interface', '-i', help='Network interface to listen on (Scapy syntax)')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity/Discovery timeout (s, default: 120)')
    parser.add_argument('--output-dir', '-d', help='Custom output directory for logs/data')
    parser.add_argument('--discovery-port', '-dp', type=int, default=DISCOVERY_PORT, help=f'UDP discovery port (default: {DISCOVERY_PORT})')
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()

    global OUTPUT_DIR, DISCOVERY_PORT
    if args.output_dir: OUTPUT_DIR = args.output_dir
    setup_directories()

    log_debug("Receiver starting...")
    log_debug(f"Arguments: {vars(args)}")
    DISCOVERY_PORT = args.discovery_port

    success = receive_file(
        args.output,
        args.key,
        args.interface,
        args.timeout
    )

    log_debug(f"Receiver finished. Overall success status: {success}")
    print(f"Receiver finished. {'Operation completed (check logs/status).' if success else 'Operation failed.'}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    if os.name == 'posix' and os.geteuid() != 0:
         print("Warning: Scapy requires root privileges for sniffing. Run with 'sudo'.")
    elif os.name == 'nt':
         print("Info: Ensure Npcap is installed and Python has permissions (Run as Administrator if needed).")
    main()