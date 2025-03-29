#!/usr/bin/env python3
"""
CrypticRoute - Simplified Network Steganography Receiver
V3: Listens for UDP Beacon, Initiates TCP Handshake.
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
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from scapy.all import IP, TCP, sniff, conf, send

# Configure Scapy settings
conf.verb = 0

# --- Global Settings ---
MAX_CHUNK_SIZE = 8
INTEGRITY_CHECK_SIZE = 16 # MD5
DISCOVERY_PORT = 54321
HASH_LEN_FOR_DISCOVERY = 16
BEACON_INTERVAL = 2 # How often sender broadcasts (receiver doesn't use directly)
BEACON_PREFIX = b"CRYPTRT_BCN:"
TCP_INIT_SYN_ATTEMPTS = 10 # How many times receiver sends initial SYN
TCP_INIT_SYN_INTERVAL = 0.3 # Interval between initial SYN sends

# --- Global State ---
received_chunks = {}
transmission_complete = False
reception_start_time = 0
last_activity_time = 0
highest_seq_num = 0
total_chunks_expected = 0
packet_counter = 0
valid_packet_counter = 0
connection_established = False
sender_ip = None # Learned from UDP Beacon
sender_port = None # Learned from TCP Handshake
ack_sent_chunks = set()
stop_sniffing_event = threading.Event()

# --- Output Directories ---
OUTPUT_DIR = "stealth_output"
SESSION_DIR, LOGS_DIR, DATA_DIR, CHUNKS_DIR, DEBUG_LOG = "", "", "", "", ""

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
        f.write(f"=== CrypticRoute Receiver Session (v3): {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    latest_link = os.path.join(OUTPUT_DIR, "receiver_latest")
    try: # Create symlink
        if os.path.islink(latest_link): os.unlink(latest_link)
        elif os.path.exists(latest_link): os.rename(latest_link, f"{latest_link}_{int(time.time())}")
        os.symlink(SESSION_DIR, latest_link)
        print(f"Created symlink: {latest_link} -> {SESSION_DIR}")
    except Exception as e: print(f"Warning: Could not create symlink: {e}")
    print(f"Created output directory structure at: {SESSION_DIR}")

def log_debug(message):
    """Write debug message to log file."""
    if not DEBUG_LOG: return
    try:
        with open(DEBUG_LOG, "a") as f:
            f.write(f"[{time.strftime('%H:%M:%S')}] {message}\n")
    except Exception as e: print(f"Error writing log: {e}")


# --- UDP Beacon Listener ---
def listen_for_beacon(key_hash_hex, discovery_port, max_wait_time):
    """Listens for the sender's UDP beacon and returns the sender's IP."""
    global sender_ip # Set the global variable upon success

    try:
        full_hash_bytes = bytes.fromhex(key_hash_hex)
        truncated_hash = full_hash_bytes[:HASH_LEN_FOR_DISCOVERY]
        expected_beacon_payload = BEACON_PREFIX + truncated_hash
    except Exception as e:
        log_debug(f"[DISCOVERY ERR] Failed to create expected beacon payload: {e}"); return None

    log_debug(f"[DISCOVERY] Starting discovery. Expected Beacon: {expected_beacon_payload.hex()}")
    print(f"[DISCOVERY] Listening for sender beacon on UDP port {discovery_port}...")

    listen_sock = None
    discovered_ip = None
    start_time = time.time()

    try:
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listen_sock.bind(('', discovery_port))
            log_debug(f"[DISCOVERY] Receiver socket bound to port {discovery_port} for beacon.")
        except OSError as e:
            print(f"[ERROR] Could not bind receiver to UDP port {discovery_port}: {e}"); log_debug(f"Failed bind: {e}"); return None
        listen_sock.settimeout(1.0) # Check for beacon every second

        while discovered_ip is None and (time.time() - start_time) < max_wait_time:
            try:
                print(f"\r[DISCOVERY] Waiting for beacon...", end="")
                data, addr = listen_sock.recvfrom(1024)
                log_debug(f"[DISCOVERY] Rcvd {len(data)} UDP bytes from {addr}")
                if data == expected_beacon_payload:
                    discovered_ip = addr[0] # Found it!
                    sender_ip = discovered_ip # Set global
                    print(f"\n[DISCOVERY] Valid beacon received from {sender_ip} (port {addr[1]})!")
                    log_debug(f"[DISCOVERY] Valid beacon from {sender_ip}:{addr[1]}. Discovery successful.")
                    break # Exit loop
                # else: Ignore other packets

            except socket.timeout:
                log_debug("[DISCOVERY] Timeout waiting for beacon...")
                continue # Keep listening
            except Exception as e:
                log_debug(f"[DISCOVERY] Error receiving beacon: {e}"); time.sleep(0.1)

    except KeyboardInterrupt: print("\n[DISCOVERY] Interrupted."); log_debug("Discovery interrupted.")
    except Exception as e: print(f"\n[DISCOVERY ERR] {e}"); log_debug(f"Discovery error: {e}")
    finally:
        if listen_sock: listen_sock.close(); log_debug("[DISCOVERY] Closed beacon listening socket.")

    if discovered_ip is None:
        print("\n[DISCOVERY] Failed: Timed out waiting for sender beacon.")
        log_debug("Timeout waiting for beacon.")

    return discovered_ip


class SteganographyReceiver:
    """Handles TCP communication (handshake, data, ACKs)."""

    def __init__(self):
        """Initialize receiver TCP components."""
        self.chunks_json_path = os.path.join(LOGS_DIR, "received_chunks.json")
        self.acks_json_path = os.path.join(LOGS_DIR, "sent_acks.json")
        try: # Initialize/clear log files
            with open(self.chunks_json_path, "w") as f: json.dump({}, f)
            with open(self.acks_json_path, "w") as f: json.dump({}, f)
        except Exception as e: log_debug(f"Error initializing receiver log files: {e}")
        self.sent_acks = {}
        self.my_port = random.randint(10000, 60000) # Port for outgoing TCP ACKs
        log_debug(f"Receiver TCP handler initialized. Outgoing Port: {self.my_port}.")

    # --- TCP Packet Creation Methods ---
    def create_final_ack_packet(self):
        """Create the final TCP ACK packet to complete connection establishment."""
        # This is sent by the RECEIVER in response to the sender's SYN-ACK
        if not sender_ip or not sender_port:
            log_debug("[TCP ERR] Cannot create final Handshake ACK: Sender IP/Port unknown.")
            return None
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, dport=sender_port,
            seq=0x87654321,      # Our sequence number for this ACK
            ack=0xABCDEF12 + 1,  # Acknowledge sender's SYN-ACK seq + 1
            window=0xF00D,       # Special window value for handshake completion ACK
            flags="A"
        )
        log_debug(f"Created final Handshake ACK packet for {sender_ip}:{sender_port}")
        return ack_packet

    def create_ack_packet(self, seq_num):
        """Create a TCP ACK packet for a specific data chunk sequence number."""
        if not sender_ip or not sender_port:
            log_debug("Cannot create data ACK - sender IP or TCP Port missing")
            return None
        ack_packet = IP(dst=sender_ip) / TCP(
            sport=self.my_port, dport=sender_port,
            seq=0x12345678, ack=seq_num, window=0xCAFE, flags="A"
        )
        return ack_packet

    def send_ack(self, seq_num):
        """Send acknowledgment for a specific data chunk."""
        global ack_sent_chunks
        if seq_num in ack_sent_chunks: return # Skip if already acked
        ack_packet = self.create_ack_packet(seq_num)
        if not ack_packet: return
        log_debug(f"Sending ACK for chunk {seq_num}")
        print(f"\r[ACK] Sending ack for chunk {seq_num:04d}        ", end="")
        self.log_ack(seq_num)
        try:
            for _ in range(3): send(ack_packet); time.sleep(0.05)
            ack_sent_chunks.add(seq_num)
        except Exception as e: log_debug(f"Error sending ACK {seq_num}: {e}")

    # --- Packet Processing Logic (Called by Scapy Sniff) ---
    def packet_handler(self, packet):
        """Wrapper for process_packet (TCP phase)."""
        global packet_counter, last_activity_time
        if stop_sniffing_event.is_set(): return
        last_activity_time = time.time()
        packet_counter += 1
        if not (IP in packet and TCP in packet and packet[IP].src == sender_ip): return
        # Status Printing
        if packet_counter % 20 == 0 or valid_packet_counter < 5:
             progress = (len(received_chunks) / total_chunks_expected * 100) if total_chunks_expected > 0 else 0
             status = f"[TCP Status] Pkts Rcvd: {packet_counter:6d} | Valid Data: {valid_packet_counter:4d} | Chunks: {len(received_chunks):4d}/{total_chunks_expected:4d} ({progress:3.0f}%) | Conn: {'Yes' if connection_established else 'No '}"
             print(f"\r{status:<80}", end="")
        processed_status = self.process_packet(packet)
        if processed_status == "COMPLETED":
             global transmission_complete
             transmission_complete = True; stop_sniffing_event.set()
             print("\n[INFO] Transmission complete signal received. Stopping TCP sniffer.")
             log_debug("Transmission complete signal processed. Stopping TCP sniffer.")
        elif processed_status == "HANDSHAKE_SYNACK": print() # Newline after SYNACK message

    def process_packet(self, packet):
        """Process a received TCP packet from the sender during the TCP phase."""
        global received_chunks, reception_start_time, highest_seq_num
        global valid_packet_counter, total_chunks_expected, connection_established, sender_port

        tcp_layer = packet[TCP]
        ip_layer = packet[IP]

        # Learn/confirm sender's TCP source port (expecting it from SYN-ACK)
        if sender_port is None and tcp_layer.sport != 0:
            sender_port = tcp_layer.sport
            log_debug(f"Learned sender TCP source port {sender_port} from packet flags {tcp_layer.flags:#x}")
            print(f"\n[HANDSHAKE] Learned sender port: {sender_port}", end="")

        # --- Handshake Packet Handling (Receiver expects SYN-ACK first) ---
        # 1. Check for Handshake SYN-ACK from Sender
        # Matches sender's create_syn_ack_packet: SA flags, specific seq, window, ack
        if not connection_established and tcp_layer.flags & 0x12 == 0x12 \
           and tcp_layer.window == 0xBEEF and tcp_layer.seq == 0xABCDEF12 \
           and tcp_layer.ack == (0x12345678 + 1):
            log_debug(f"Received Handshake SYN-ACK from {ip_layer.src}:{tcp_layer.sport}")
            print(f"\n[HANDSHAKE] Received SYN-ACK response from sender.", end="")

            if sender_port != tcp_layer.sport: # Update port if needed
                 log_debug(f"SYN-ACK source port {tcp_layer.sport} differs from previous {sender_port}. Updated.")
                 sender_port = tcp_layer.sport

            # Send the final Handshake ACK
            final_ack_packet = self.create_final_ack_packet()
            if final_ack_packet:
                log_debug("[TCP HANDSHAKE] Sending final ACK to complete connection.")
                print(" Sending final ACK...", end="")
                try:
                     for _ in range(5): send(final_ack_packet); time.sleep(0.1)
                     connection_established = True
                     print(" Connection established.")
                     if reception_start_time == 0: # Start timer now
                          reception_start_time = time.time()
                          log_debug(f"TCP Reception timer started at {reception_start_time}")
                     return "HANDSHAKE_SYNACK" # Special status for handler
                except Exception as e:
                     log_debug(f"Error sending final Handshake ACK: {e}")
                     print(f"\n[ERROR] Failed sending final ACK: {e}")
            else:
                 log_debug("[TCP ERR] Failed to create final Handshake ACK packet.")
            return True # Processed SYN-ACK even if final ACK failed

        # --- Data and Completion Packet Handling (Requires established connection) ---
        if not connection_established: return False # Ignore other packets pre-connection

        # 2. Check for transmission completion signal (FIN packet)
        if tcp_layer.flags & 0x01 and tcp_layer.window == 0xFFFF:
            log_debug(f"Received transmission complete signal (FIN) from {ip_layer.src}:{tcp_layer.sport}")
            return "COMPLETED"

        # 3. Check for Data Packet
        # Matches sender's create_packet: SYN flag, window=seq_num, seq/ack=data
        is_potential_data = False
        if tcp_layer.flags & 0x02: # SYN flag check
             if tcp_layer.window > 0 and tcp_layer.window not in [0xDEAD, 0xBEEF, 0xF00D, 0xFFFF, 0xCAFE]:
                  is_potential_data = True

        if is_potential_data:
            seq_num = tcp_layer.window
            current_total_chunks = None
            try: # Extract total chunks from MSS
                for opt in tcp_layer.options:
                    if isinstance(opt, tuple) and opt[0] == 'MSS': current_total_chunks = opt[1]; break
            except Exception: pass
            if current_total_chunks is None: log_debug(f"Ignored data packet (Win={seq_num}): No MSS."); return False

            global total_chunks_expected
            if total_chunks_expected == 0 and current_total_chunks > 0:
                total_chunks_expected = current_total_chunks
                print(f"\n[INFO] Learned total expected chunks: {total_chunks_expected}", end="")
                log_debug(f"Learned total expected chunks: {total_chunks_expected}")
            elif total_chunks_expected > 0 and current_total_chunks != total_chunks_expected:
                 log_debug(f"Warning: Packet Win={seq_num} MSS ({current_total_chunks}) != expected ({total_chunks_expected})")

            valid_packet_counter += 1
            try: # Extract data and checksum
                 data = tcp_layer.seq.to_bytes(4,'big') + tcp_layer.ack.to_bytes(4,'big')
                 checksum = ip_layer.id
            except Exception: log_debug(f"Error extracting data Win={seq_num}"); return False

            calc_checksum = binascii.crc32(data) & 0xFFFF # Verify checksum
            checksum_ok = (checksum == calc_checksum)
            if not checksum_ok: log_debug(f"Checksum MISMATCH chunk {seq_num}! Got={checksum:04x}, Calc={calc_checksum:04x}"); print(f"\n[WARN] Checksum fail chunk {seq_num:04d}!", end="")

            if seq_num in received_chunks: # Check duplicate
                log_debug(f"Duplicate chunk {seq_num}. Re-ACKing."); print(f"\n[DUPLICATE] Chunk {seq_num:04d}", end="")
                self.send_ack(seq_num); return True

            log_debug(f"Storing chunk {seq_num} (Size:{len(data)}). Checksum OK={checksum_ok}")
            received_chunks[seq_num] = data
            self.log_chunk(seq_num, data); self.send_ack(seq_num) # Store, Log, ACK
            if seq_num > highest_seq_num: highest_seq_num = seq_num

            prog = (len(received_chunks)/total_chunks_expected*100) if total_chunks_expected>0 else 0
            info = f"Rcvd: {seq_num:04d}/{total_chunks_expected:04d} | Total: {len(received_chunks):04d} | {prog:.1f}%"
            print(f"\n[CHUNK] {info} {' OK' if checksum_ok else ' FAIL'}", end="")
            return True # Data packet processed

        return False # Packet not processed

    # --- Logging Methods (Unchanged) ---
    def log_chunk(self, seq_num, data):
        # ... (same as previous version) ...
        chunk_info = {}
        try:
            if os.path.exists(self.chunks_json_path) and os.path.getsize(self.chunks_json_path) > 0:
                with open(self.chunks_json_path, "r") as f: chunk_info = json.load(f)
        except Exception as e: log_debug(f"Error reading chunks JSON: {e}")
        chunk_info[str(seq_num)] = { "data": data.hex(), "size": len(data), "timestamp": time.time() }
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(chunk_info, f, indent=2)
        except Exception as e: log_debug(f"Error writing chunks JSON: {e}")
        try:
            chunk_file = os.path.join(CHUNKS_DIR, "raw", f"chunk_{seq_num:03d}.bin")
            with open(chunk_file, "wb") as f: f.write(data)
        except Exception as e: log_debug(f"Error writing raw chunk {seq_num}: {e}")

    def log_ack(self, seq_num):
        # ... (same as previous version) ...
        self.sent_acks[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.sent_acks, f, indent=2)
        except Exception as e: log_debug(f"Error writing ACKs JSON: {e}")

# --- Utility Functions (Key Prep, Decrypt, Integrity, Reassemble, Save) ---
# --- (These remain unchanged from previous version) ---
def prepare_key(key_data):
    # ... (same as previous version) ...
    if isinstance(key_data, str): key_data = key_data.encode('utf-8')
    try:
        if len(key_data) % 2 == 0 and all(c in b'0123456789abcdefABCDEF' for c in key_data):
             key_data = bytes.fromhex(key_data.decode('ascii')); log_debug("Interpreted key as hex.")
    except ValueError: pass
    original_len = len(key_data)
    if original_len < 32: key_data = key_data.ljust(32, b'\0')
    elif original_len > 32: key_data = key_data[:32]
    if original_len != 32: log_debug(f"Key adjusted from {original_len} to 32 bytes.")
    log_debug(f"Final key bytes: {key_data.hex()}")
    try: # Save key
        with open(os.path.join(DATA_DIR, "key.bin"), "wb") as f: f.write(key_data)
    except Exception: pass
    key_hash = hashlib.sha256(key_data).digest(); key_hash_hex = key_hash.hex()
    log_debug(f"Key hash (SHA256): {key_hash_hex}"); print(f"[KEY] Key Hash: {key_hash_hex}")
    return key_data, key_hash_hex

def decrypt_data(data, key):
    # ... (same as previous version) ...
    iv_len = 16
    if len(data) < iv_len: log_debug(f"Decrypt ERR: Data({len(data)}) < IV({iv_len})"); return None
    try:
        iv = data[:iv_len]; encrypted_data = data[iv_len:]
        log_debug(f"Extracted IV: {iv.hex()}. Enc Size: {len(encrypted_data)}")
        try: # Save debug files
            with open(os.path.join(DATA_DIR, "extracted_iv.bin"), "wb") as f: f.write(iv)
            with open(os.path.join(DATA_DIR, "encrypted_data_for_decryption.bin"), "wb") as f: f.write(encrypted_data)
        except Exception: pass
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor(); decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        log_debug(f"Decryption OK. Decrypted size: {len(decrypted_data)}")
        try: # Save decrypted
            with open(os.path.join(DATA_DIR, "decrypted_data.bin"), "wb") as f: f.write(decrypted_data)
        except Exception: pass
        return decrypted_data
    except Exception as e: log_debug(f"Decryption error: {e}"); print(f"[DECRYPT] Error: {e}"); return None

def verify_data_integrity(data):
    # ... (same as previous version) ...
    if len(data) < INTEGRITY_CHECK_SIZE: log_debug(f"Integrity ERR: Data({len(data)}) < Checksum({INTEGRITY_CHECK_SIZE})"); return None, False
    try:
        payload = data[:-INTEGRITY_CHECK_SIZE]; rcvd_chk = data[-INTEGRITY_CHECK_SIZE:]
        log_debug(f"Integrity check. Payload: {len(payload)}, Rcvd Chk: {rcvd_chk.hex()}")
        try: # Save debug files
            with open(os.path.join(DATA_DIR, "data_before_checksum_verification.bin"), "wb") as f: f.write(payload)
            with open(os.path.join(DATA_DIR, "received_checksum.bin"), "wb") as f: f.write(rcvd_chk)
        except Exception: pass
        calc_chk = hashlib.md5(payload).digest()
        log_debug(f"Calculated checksum: {calc_chk.hex()}")
        try: # Save calculated
            with open(os.path.join(DATA_DIR, "calculated_checksum.bin"), "wb") as f: f.write(calc_chk)
        except Exception: pass
        match = (calc_chk == rcvd_chk)
        try: # Save result
             info = { "expected": calc_chk.hex(), "received": rcvd_chk.hex(), "match": match }
             with open(os.path.join(LOGS_DIR, "checksum_verification.json"), "w") as f: json.dump(info, f, indent=2)
        except Exception: pass
        if match: log_debug("Integrity OK."); print("[VERIFY] Integrity OK.")
        else: log_debug("CHECKSUM MISMATCH!"); print("[VERIFY] Warning: Integrity FAILED!")
        return payload, match
    except Exception as e: log_debug(f"Integrity check error: {e}"); print(f"[ERROR] Integrity check failed: {e}"); return None, False

def reassemble_data():
    # ... (same as previous version - minor logging tweak maybe) ...
    global received_chunks, highest_seq_num, total_chunks_expected
    if not received_chunks: return None, 0
    print(f"\n[REASSEMBLY] Sorting {len(received_chunks)} chunks...")
    log_debug(f"Reassembling {len(received_chunks)}. Highest={highest_seq_num}, Expected={total_chunks_expected}")
    sorted_seq = sorted(received_chunks.keys())
    if not sorted_seq: return None, 0
    expected_total = total_chunks_expected if total_chunks_expected > 0 else highest_seq_num
    if expected_total == 0 and sorted_seq: expected_total = sorted_seq[-1]
    missing_count, missing_list = 0, []
    if expected_total > 0:
        present = set(sorted_seq)
        for i in range(1, expected_total + 1):
            if i not in present: missing_count += 1; missing_list.append(i)
    if missing_count > 0: log_debug(f"Missing {missing_count} chunks. Sample: {missing_list[:20]}"); print(f"[REASSEMBLY] Warning: Missing {missing_count} chunks!")
    else: log_debug(f"No missing chunks detected (Expected: {expected_total}).")
    try: # Save diag
        info = { "rcvd_count": len(received_chunks), "highest": highest_seq_num,"expected_mss": total_chunks_expected, "expected_final": expected_total,"missing_count": missing_count, "missing_sample": missing_list[:20],"rcvd_seqs": sorted_seq[:100]}
        with open(os.path.join(LOGS_DIR, "reassembly_info.json"), "w") as f: json.dump(info, f, indent=2)
    except Exception: pass
    raw_data = b"".join([received_chunks[s] for s in sorted_seq])
    log_debug(f"Raw reassembled size: {len(raw_data)}")
    try: # Save raw
        with open(os.path.join(DATA_DIR, "reassembled_data_raw.bin"), "wb") as f: f.write(raw_data)
    except Exception: pass
    final_data = raw_data # Padding removal logic
    if sorted_seq and expected_total > 0 and sorted_seq[-1] == expected_total:
         last_chunk = received_chunks[expected_total]
         if len(last_chunk) == MAX_CHUNK_SIZE: # Assume padding possible
             last_non_null = raw_data.rfind(next((bytes([x]) for x in range(255,0,-1) if bytes([x]) in raw_data), b'\0'))
             if last_non_null != -1:
                  orig_len = len(final_data); final_data = raw_data[:last_non_null + 1]; stripped = orig_len - len(final_data)
                  if stripped > 0: log_debug(f"Stripped {stripped} trailing nulls."); print(f"[REASSEMBLY] Removed {stripped} padding bytes.")
             else: final_data = b'\0'; log_debug("Data all nulls?")
         else: log_debug("Last chunk < max size, no padding.")
    else: log_debug("Last chunk missing/unknown, skipping padding removal.")
    log_debug(f"Final reassembled size: {len(final_data)}")
    try: # Save final
        with open(os.path.join(DATA_DIR, "reassembled_data_final.bin"), "wb") as f: f.write(final_data)
    except Exception: pass
    print(f"[REASSEMBLY] Completed! Final size: {len(final_data)} bytes")
    return final_data, missing_count

def save_to_file(data, output_path):
    # ... (same as previous version) ...
    if data is None: log_debug("Save ERR: Data None."); return False
    try:
        with open(output_path, 'wb') as f: f.write(data)
        log_debug(f"Data saved to {output_path} ({len(data)} bytes)")
        print(f"[SAVE] Data saved to: {output_path}")
        try: # Copy to data dir
            with open(os.path.join(DATA_DIR, f"output_{os.path.basename(output_path)}"), "wb") as f: f.write(data)
        except Exception: pass
        try: # Preview
            txt = data.decode('utf-8'); preview = txt[:200]
            log_debug(f"Saved preview: {preview}..."); print(f"Preview:\n---\n{preview}{'...' if len(txt)>200 else ''}\n---")
            try: # Save text version
                 with open(os.path.join(DATA_DIR, "output_content.txt"), "w", encoding='utf-8') as f: f.write(txt)
            except Exception: pass
        except UnicodeDecodeError: log_debug("Content not UTF-8."); print("(Content is binary)")
        return True
    except Exception as e: log_debug(f"Save error: {e}"); print(f"[SAVE] Error: {e}"); return False

# --- Inactivity Monitor Thread ---
def monitor_transmission(stop_event, timeout):
    """Monitor TCP transmission phase for inactivity."""
    global last_activity_time, transmission_complete
    log_debug(f"TCP Monitor started. Timeout: {timeout}s")
    while not stop_event.is_set():
        if reception_start_time > 0 and (time.time() - last_activity_time > timeout):
            log_debug(f"TCP Inactivity timeout ({timeout}s). Signaling stop.")
            print(f"\n[TIMEOUT] TCP Inactivity timeout ({timeout}s). Stopping.")
            transmission_complete = True; stop_sniffing_event.set() # Signal main sniff loop
            break
        time.sleep(1)
    log_debug("TCP Monitor stopped.")

# --- Main Execution Logic ---
def receive_file(output_path, key_path=None, interface=None, timeout=120):
    """Discover sender via UDP beacon, initiate TCP, receive file."""
    global received_chunks, transmission_complete, reception_start_time, last_activity_time
    global highest_seq_num, packet_counter, valid_packet_counter, connection_established
    global sender_ip, stop_sniffing_event, total_chunks_expected, ack_sent_chunks, sender_port

    session_start_time = time.time()
    log_debug("Receiver process started.")
    summary = { "timestamp": session_start_time, "output_path": output_path, "key_path": key_path,
                "interface": interface, "timeout": timeout, "discovery_port": DISCOVERY_PORT }
    try: with open(os.path.join(LOGS_DIR, "session_summary.json"), "w") as f: json.dump(summary, f, indent=2)
    except Exception: pass

    # Reset state
    received_chunks={}; transmission_complete=False; reception_start_time=0; last_activity_time=time.time()
    highest_seq_num=0; total_chunks_expected=0; packet_counter=0; valid_packet_counter=0
    connection_established=False; sender_ip=None; sender_port=None; ack_sent_chunks=set()
    stop_sniffing_event.clear()

    # Process Key
    if not key_path: print("[ERROR] Key file required."); log_debug("Key missing."); return False
    log_debug(f"Reading key: {key_path}")
    try:
        with open(key_path, 'rb') as f: key_data_raw = f.read()
        key_bytes, key_hash_hex = prepare_key(key_data_raw)
        if not key_bytes or not key_hash_hex: return False
    except Exception as e: print(f"[ERROR] Reading key: {e}"); log_debug(f"Key read error: {e}"); return False

    # --- Discovery Phase: Listen for Beacon ---
    print("--- Discovery Phase ---")
    discovered_ip = listen_for_beacon(key_hash_hex, DISCOVERY_PORT, timeout)
    if not discovered_ip: # Handles timeout or error
        print("[DISCOVERY] Failed. Aborting.")
        # Save failure status
        try:
            summary.update({"completed_at": time.time(), "status": "failed", "reason": "discovery_failed"})
            with open(os.path.join(LOGS_DIR, "completion_info.json"), "w") as f: json.dump(summary, f, indent=2)
        except Exception: pass
        return False
    # sender_ip global is now set

    # --- TCP Initiation Phase (Receiver sends first SYN) ---
    print("\n--- TCP Initiation Phase ---")
    stego_receiver = SteganographyReceiver() # Init TCP handler (gets my_port)
    # Create the initial SYN packet
    initial_syn = IP(dst=sender_ip) / TCP(
        sport=stego_receiver.my_port, dport=random.randint(10000, 60000), # Dest port random
        seq=0x12345678, window=0xDEAD, flags="S"
    )
    log_debug(f"Created initial Handshake SYN for {sender_ip}")
    print(f"[HANDSHAKE] Sending initial SYN packets to {sender_ip}...")
    log_debug(f"Sending {TCP_INIT_SYN_ATTEMPTS} initial SYNs...")
    try:
        for i in range(TCP_INIT_SYN_ATTEMPTS):
            send(initial_syn)
            print(f"\r[HANDSHAKE] Sent SYN {i+1}/{TCP_INIT_SYN_ATTEMPTS}", end="")
            time.sleep(TCP_INIT_SYN_INTERVAL)
        print(" Done.")
    except Exception as e:
        print(f"\n[ERROR] Failed sending initial SYN: {e}")
        log_debug(f"Error sending initial SYN: {e}"); return False # Abort if cannot send

    # --- TCP Reception Phase ---
    print("\n--- TCP Reception Phase ---")
    stop_monitor = threading.Event()
    monitor_thread = threading.Thread(target=monitor_transmission, args=(stop_monitor, timeout), name="TCPMonitorThread")
    monitor_thread.daemon=True; monitor_thread.start()
    log_debug("TCP Inactivity monitor started.")

    print(f"Listening for TCP communication from {sender_ip}...")
    log_debug(f"Listening for TCP from {sender_ip} on interface {interface or 'default'}...")
    print("Press Ctrl+C to stop manually")

    # Reset TCP state variables before main sniff
    transmission_complete=False; reception_start_time=0; last_activity_time=time.time(); stop_sniffing_event.clear()
    connection_established=False # Reset connection status specifically

    try:
        filter_str = f"tcp and src host {sender_ip}"
        sniff(iface=interface, filter=filter_str, prn=stego_receiver.packet_handler, store=0,
              stop_filter=lambda p: stop_sniffing_event.is_set())
    except KeyboardInterrupt: log_debug("Sniff stopped by user."); print("\n[INFO] Sniffing stopped."); transmission_complete=True; stop_sniffing_event.set()
    except ImportError: log_debug("FATAL: Scapy dep error."); print("\n[FATAL] Scapy dep error."); transmission_complete=True; stop_sniffing_event.set(); success = False
    except OSError: log_debug("FATAL: Sniff OS error."); print("\n[FATAL] Sniff OS error."); transmission_complete=True; stop_sniffing_event.set(); success = False
    except Exception as e: log_debug(f"TCP Sniff error: {e}"); print(f"\n[ERROR] Sniff failed: {e}"); transmission_complete=True; stop_sniffing_event.set()
    finally:
        stop_monitor.set(); monitor_thread.join(1.0)
        print("\n[INFO] TCP Packet sniffing stopped.")
        log_debug("TCP Sniffing finished.")

    # --- Post-Reception Processing ---
    print("\n--- Post-Reception Processing ---")
    # ... (This part remains exactly the same as the previous version) ...
    log_debug("Starting post-reception processing.")
    session_end_time = time.time()
    final_status = "unknown" ; success = False ; final_data = None; checksum_ok = None; decryption_status = None; missing = -1

    if not received_chunks:
        log_debug("No data chunks received."); print("[RESULT] No data chunks received.")
        final_status = "failed_no_chunks"
    else:
        duration = session_end_time - reception_start_time if reception_start_time > 0 else 0
        chunk_count = len(received_chunks)
        final_expected = total_chunks_expected if total_chunks_expected > 0 else highest_seq_num
        rate = (chunk_count / final_expected * 100) if final_expected > 0 else (100 if chunk_count > 0 else 0)
        missing = (final_expected - chunk_count) if final_expected > 0 else 0
        print(f"[STATS] Rcvd {chunk_count}/{final_expected} chunks ({rate:.1f}%). Highest Seq: {highest_seq_num}. Duration: {duration:.2f}s.")

        reassembled_data, _ = reassemble_data()
        if reassembled_data is None: log_debug("Reassembly failed."); print("[RESULT] Failed reassembly."); final_status = "failed_reassembly"
        else:
            payload_data, checksum_ok = verify_data_integrity(reassembled_data)
            if payload_data is None: log_debug("Integrity failed critically."); print("[RESULT] Failed integrity check."); final_status = "failed_integrity"
            else:
                data_to_process = payload_data; final_data = data_to_process; decryption_status = "not_needed"
                if key_bytes: # Decrypt
                    print("[DECRYPT] Decrypting...")
                    decrypted_result = decrypt_data(data_to_process, key_bytes)
                    if decrypted_result is None: print("[DECRYPT] Error: Failed! Saving raw."); final_data = data_to_process; decryption_status = "failed"
                    else: print(f"[DECRYPT] OK. Size: {len(decrypted_result)}"); final_data = decrypted_result; decryption_status = "success"
                save_success = save_to_file(final_data, output_path)
                if save_success:
                     success = True # Overall success if saved
                     if decryption_status == "success" and checksum_ok and missing == 0: final_status = "completed_perfect"
                     elif decryption_status == "success" and checksum_ok: final_status = "completed_with_missing_chunks"
                     elif decryption_status == "success": final_status = "completed_decrypted_errors"
                     elif decryption_status == "failed": final_status = "completed_decryption_failed"
                     elif decryption_status == "not_needed" and checksum_ok and missing == 0: final_status = "completed_raw_perfect"
                     elif decryption_status == "not_needed" and checksum_ok: final_status = "completed_raw_missing_chunks"
                     else: final_status = "completed_raw_errors"
                else: final_status = "failed_save"

    # Save final completion info
    try:
        stats = { "pkts_processed": packet_counter, "valid_data_pkts": valid_packet_counter,"chunks_rcvd": len(received_chunks), "highest_seq": highest_seq_num,"expected_total": final_expected if 'final_expected' in locals() else 0,"missing_est": missing,"conn_established": connection_established, "fin_received": transmission_complete and not stop_monitor.is_set() }
        summary.update({ "completed_at": session_end_time, "status": final_status,"bytes_saved": len(final_data) if final_data else 0,"checksum_ok": checksum_ok,"decryption": decryption_status,**stats })
        with open(os.path.join(LOGS_DIR, "completion_info.json"), "w") as f: json.dump(summary, f, indent=2)
    except Exception as e: log_debug(f"Error saving completion info: {e}")

    print(f"\n[RESULT] Operation finished. Status: {final_status}")
    print(f"[INFO] All session data saved to: {SESSION_DIR}")
    return success


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='CrypticRoute - Receiver (v3 Discovery)')
    parser.add_argument('--output', '-o', required=True, help='Output file path')
    parser.add_argument('--key', '-k', required=True, help='Decryption/Discovery key file')
    parser.add_argument('--interface', '-i', help='Network interface to listen on (Scapy syntax)')
    parser.add_argument('--timeout', '-t', type=int, default=120, help='Inactivity/Discovery timeout (s, default: 120)')
    parser.add_argument('--output-dir', '-d', help='Custom output directory for logs/data')
    parser.add_argument('--discovery-port', '-dp', type=int, default=DISCOVERY_PORT, help=f'UDP discovery port (default: {DISCOVERY_PORT})')
    return parser.parse_args()


if __name__ == "__main__":
    if os.name == 'posix' and os.geteuid() != 0: print("Warning: Scapy requires root privileges. Run with 'sudo'.")
    elif os.name == 'nt': print("Info: Ensure Npcap installed & Python has Admin permissions.")
    main()