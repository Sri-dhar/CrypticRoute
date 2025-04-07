import sys
import os
import time
import hashlib
import json
import binascii
import threading
import random
from scapy.all import IP, TCP, sniff, conf, send

# Internal imports
from ..common.utils import (
    log_debug, prepare_key, decrypt_data, chunk_data, verify_data_integrity,
    save_to_file
)
from ..common.constants import (
    MAX_CHUNK_SIZE, DISCOVERY_PORT, DISCOVERY_PROBE_WINDOW,
    DISCOVERY_RESPONSE_WINDOW, SYN_WINDOW, SYN_ACK_WINDOW, FINAL_ACK_WINDOW,
    DATA_ACK_WINDOW, COMPLETION_WINDOW, IV_SIZE, INTEGRITY_CHECK_SIZE,
    RAW_CHUNKS_SUBDIR, CLEANED_CHUNKS_SUBDIR, DATA_SUBDIR, # Ensure DATA_SUBDIR is imported
    RECEIVER_SPORT_RANGE, DISCOVERY_RESPONSE_SEND_COUNT, DISCOVERY_RESPONSE_SEND_DELAY,
    DATA_ACK_SEND_COUNT, DATA_ACK_SEND_DELAY, SYN_ACK_SEND_COUNT, SYN_ACK_SEND_DELAY,
    RECEIVER_STATUS_PRINT_INTERVAL, ACK_POLL_INTERVAL # Added ACK_POLL_INTERVAL for monitor
)

# Configure Scapy settings
conf.verb = 0

# --- Receiver State (managed within the class or passed around) ---
# These were globals, now need careful handling.
# We'll use instance variables in SteganographyReceiver where possible,
# and manage others in the main receive_file_logic function.

class SteganographyReceiver:
    """Handles the core receiving logic including discovery response, handshake, and data processing."""

    def __init__(self, key_probe_id_expected, key_response_id, session_paths):
        """Initialize the receiver state."""
        self.receiver_key_hash_probe_expected = key_probe_id_expected
        self.receiver_key_hash_response = key_response_id
        self.session_paths = session_paths
        self.my_port = random.randint(*RECEIVER_SPORT_RANGE) # Port for sending ACKs/SYN-ACKs

        # State variables
        self.discovery_sender_ip = None
        self.discovery_sender_port = None
        self.discovery_probe_processed = False # Renamed from discovery_probe_received
        self.sender_ip = None # Confirmed sender IP after handshake/first data
        self.sender_port = None # Confirmed sender port after handshake/first data
        self.connection_established = False
        self.received_chunks = {} # Store received chunks {seq_num: data}
        self.ack_sent_chunks = set() # Track ACKs we have sent
        self.highest_seq_num_seen = 0 # Track highest seq num from window field
        self.total_chunks_expected = 0 # Track total chunks from MSS option

        # Debug logging setup
        self.chunks_json_path = os.path.join(session_paths['logs_dir'], "received_chunks.json")
        self.acks_json_path = os.path.join(session_paths['logs_dir'], "sent_acks.json")
        self.sent_acks_log = {} # In-memory log

        # Create log files
        try:
            with open(self.chunks_json_path, "w") as f: json.dump({}, f)
            with open(self.acks_json_path, "w") as f: json.dump({}, f)
        except IOError as e:
            log_debug(f"Error creating initial receiver log files: {e}")

        log_debug(f"Receiver initialized. Listening port (for sending): {self.my_port}")

    # --- Logging Methods ---
    def _log_received_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        # Update in-memory dict first
        self.received_chunks[seq_num] = data
        # Prepare data for JSON log (avoid logging full data directly)
        log_entry = {
            "data_hex_preview": data[:64].hex() + ("..." if len(data) > 64 else ""),
            "size": len(data),
            "timestamp": time.time()
        }
        # Load existing log, update, and save
        try:
            with open(self.chunks_json_path, "r") as f: chunk_log_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError): chunk_log_data = {}
        chunk_log_data[str(seq_num)] = log_entry
        try:
            with open(self.chunks_json_path, "w") as f: json.dump(chunk_log_data, f, indent=2)
        except IOError as e: log_debug(f"Error writing received chunks log: {e}")

        # Save raw chunk data
        raw_chunk_dir = os.path.join(self.session_paths['chunks_dir'], RAW_CHUNKS_SUBDIR)
        chunk_file = os.path.join(raw_chunk_dir, f"chunk_{seq_num:04d}.bin")
        try:
            with open(chunk_file, "wb") as f: f.write(data)
        except IOError as e: log_debug(f"Error writing raw chunk file {chunk_file}: {e}")

    def _log_sent_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks_log[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f: json.dump(self.sent_acks_log, f, indent=2)
        except IOError as e: log_debug(f"Error writing sent ACKs log: {e}")

    # --- Discovery Response Methods ---
    def _create_discovery_response_packet(self, probe_packet):
        """Create a discovery response packet."""
        sender_ip = probe_packet[IP].src
        sender_port = probe_packet[TCP].sport
        probe_seq = probe_packet[TCP].seq

        response_packet = IP(dst=sender_ip) / TCP(
            sport=DISCOVERY_PORT, # Respond *from* the well-known discovery port
            dport=sender_port,    # Respond *to* the sender's ephemeral source port
            flags="PF",           # PSH | FIN (0x09)
            window=DISCOVERY_RESPONSE_WINDOW, # Magic value
            seq=int.from_bytes(self.receiver_key_hash_response, 'big'), # Our response hash
            ack=probe_seq + 1 if probe_seq is not None else 1
        )
        log_debug(f"Created discovery response: Target={sender_ip}:{sender_port}, "
                  f"Flags={response_packet[TCP].flags}, Win={response_packet[TCP].window:#x}, "
                  f"Seq={response_packet[TCP].seq:#x}, Ack={response_packet[TCP].ack:#x}")
        return response_packet

    def _send_discovery_response(self, probe_packet):
        """Sends the discovery response packet back to the sender."""
        response_pkt = self._create_discovery_response_packet(probe_packet)
        if response_pkt:
            log_debug(f"Sending Discovery Response to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            print(f"[DISCOVERY] Sending response to sender at {probe_packet[IP].src}")
            print(f"[IP_EXCHANGE] Sending confirmation to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            for _ in range(DISCOVERY_RESPONSE_SEND_COUNT): # Send multiple times
                 send(response_pkt)
                 time.sleep(DISCOVERY_RESPONSE_SEND_DELAY)

    def process_discovery_probe(self, packet):
        """Process incoming packets during discovery phase. Returns True if valid probe processed."""
        if self.discovery_probe_processed: return False # Already processed one

        # Check for discovery probe signature: PSH|URG (0x28), Window 0xFACE, coming to DISCOVERY_PORT
        if IP in packet and TCP in packet and packet[TCP].dport == DISCOVERY_PORT \
           and packet[TCP].flags & 0x28 == 0x28 and packet[TCP].window == DISCOVERY_PROBE_WINDOW:

            probe_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery probe from {packet[IP].src}:{packet[TCP].sport}")
            log_debug(f"  Flags={int(packet[TCP].flags):#x} ({packet[TCP].flags}), Window={packet[TCP].window:#x}, SeqHash={probe_hash_received.hex()}")

            if probe_hash_received == self.receiver_key_hash_probe_expected:
                log_debug(f"Valid Discovery Probe received from {packet[IP].src}:{packet[TCP].sport}. Key hash MATCH.")
                print(f"\n[DISCOVERY] Valid probe received from sender at {packet[IP].src}")
                print(f"[IP_EXCHANGE] Sender IP identified: {packet[IP].src}:{packet[TCP].sport}")

                # Store sender info from the probe
                self.discovery_sender_ip = packet[IP].src
                self.discovery_sender_port = packet[TCP].sport

                self._send_discovery_response(packet) # Send response back
                self.discovery_probe_processed = True # Mark as processed
                return True # Signal sniff to stop (discovery successful)
            else:
                log_debug(f"Probe received from {packet[IP].src}, but key hash mismatch. Ignoring.")
        return False # Continue sniffing

    # --- Connection/Data ACK Methods ---
    def _create_data_ack_packet(self, seq_num):
        """Create an ACK packet for a specific DATA sequence number."""
        if not self.sender_ip or not self.sender_port:
            log_debug("Cannot create data ACK - sender connection info missing")
            return None
        ack_packet = IP(dst=self.sender_ip) / TCP(
            sport=self.my_port, # Send from our random port
            dport=self.sender_port,  # Send TO the port the SYN/Data came from
            seq=random.randint(0, 0xFFFFFFFF), # Random sequence number for ACK
            ack=seq_num,        # Use the ack field for the DATA chunk seq_num
            window=DATA_ACK_WINDOW, # Special window value for data ACKs
            flags="A"           # ACK flag
        )
        # log_debug(f"Created data ACK: Target={self.sender_ip}:{self.sender_port}, Ack(ChunkSeq)={ack_packet[TCP].ack}")
        return ack_packet

    def send_data_ack(self, seq_num):
        """Send an acknowledgment for a specific data sequence number."""
        if seq_num in self.ack_sent_chunks:
            # Resending on duplicate chunk received is handled in process_packet
            return

        ack_packet = self._create_data_ack_packet(seq_num)
        if not ack_packet: return

        log_debug(f"Sending ACK for data chunk {seq_num} to {self.sender_ip}:{self.sender_port}")
        # print(f"[ACK] Sending acknowledgment for chunk {seq_num}") # Can be noisy
        self._log_sent_ack(seq_num) # Log the ACK we are sending

        for _ in range(DATA_ACK_SEND_COUNT): # Send multiple times
            send(ack_packet)
            time.sleep(DATA_ACK_SEND_DELAY)
        self.ack_sent_chunks.add(seq_num) # Mark as sent

    def _create_syn_ack_packet(self, incoming_syn_packet):
        """Create a SYN-ACK packet for connection establishment."""
        if not self.sender_ip or not self.sender_port:
            log_debug("Cannot create SYN-ACK - sender connection info missing")
            return None
        syn_ack_packet = IP(dst=self.sender_ip) / TCP(
            sport=self.my_port, # Send from our random port
            dport=self.sender_port,  # Send TO the port the SYN came from
            seq=random.randint(0, 0xFFFFFFFF), # Our random SYN-ACK seq
            ack=incoming_syn_packet[TCP].seq + 1, # Acknowledge the received SYN seq + 1
            window=SYN_ACK_WINDOW, # Special window value for handshake SYN-ACK
            flags="SA"          # SYN-ACK flags
        )
        log_debug(f"Created SYN-ACK: Target={self.sender_ip}:{self.sender_port}, "
                  f"Flags={syn_ack_packet[TCP].flags}, Win={syn_ack_packet[TCP].window:#x}, "
                  f"Seq={syn_ack_packet[TCP].seq:#x}, Ack={syn_ack_packet[TCP].ack:#x}")
        return syn_ack_packet

    def _send_syn_ack(self, incoming_syn_packet):
        """Send a SYN-ACK response based on an incoming SYN."""
        syn_ack_packet = self._create_syn_ack_packet(incoming_syn_packet)
        if not syn_ack_packet: return

        log_debug(f"Sending SYN-ACK for connection establishment to {self.sender_ip}:{self.sender_port}")
        print(f"[HANDSHAKE] Sending SYN-ACK response to {self.sender_ip}:{self.sender_port}")
        for _ in range(SYN_ACK_SEND_COUNT): # Send multiple times
            send(syn_ack_packet)
            time.sleep(SYN_ACK_SEND_DELAY)

    # --- Packet Processing ---
    def process_packet(self, packet):
        """Process packets for connection, data, or completion. Returns True if transmission complete signal received."""
        # --- Phase 1: Check Source IP ---
        # Only accept packets from the discovered sender IP.
        if self.discovery_sender_ip is None:
             log_debug("Ignoring packet - discovery not yet complete.")
             return False # Should not happen if discovery runs first, but safety check
        if IP not in packet or packet[IP].src != self.discovery_sender_ip:
            # log_debug(f"Ignoring packet from non-discovered source {packet[IP].src if IP in packet else 'Unknown'}") # Can be noisy
            return False

        # --- Phase 2: Process Packet Content ---
        if TCP in packet:
            current_sender_ip = packet[IP].src # Should match discovery_sender_ip
            current_sender_port = packet[TCP].sport

            # --- Connection Establishment Handling ---
            # Check for SYN packet (Window 0xDEAD)
            if not self.connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == SYN_WINDOW:
                log_debug(f"Received connection establishment request (SYN) from {current_sender_ip}:{current_sender_port}")
                print(f"\n[HANDSHAKE] Received connection request (SYN) from {current_sender_ip}:{current_sender_port}")
                print(f"[IP_EXCHANGE] Connection request from {current_sender_ip}:{current_sender_port}")

                # Set sender IP and PORT based on this SYN packet
                self.sender_ip = current_sender_ip
                self.sender_port = current_sender_port
                log_debug(f"Set sender IP/Port for connection: {self.sender_ip}:{self.sender_port}")

                self._send_syn_ack(packet) # Send SYN-ACK response
                return False # Not complete yet

            # Check for final ACK confirming connection (Window 0xF00D, to our sending port)
            if not self.connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == FINAL_ACK_WINDOW and packet[TCP].dport == self.my_port:
                # Verify it came from the port we sent the SYN-ACK to
                if self.sender_ip == current_sender_ip and self.sender_port == current_sender_port:
                    log_debug(f"Received connection confirmation (ACK) from {current_sender_ip}:{current_sender_port}")
                    print(f"[HANDSHAKE] Connection established with sender")
                    print(f"[IP_EXCHANGE] Connection confirmed with {current_sender_ip}:{current_sender_port}")
                    self.connection_established = True
                else:
                    log_debug(f"Received final ACK-like packet but from unexpected source {current_sender_ip}:{current_sender_port} (expected {self.sender_ip}:{self.sender_port})")
                return False # Not complete yet

            # --- Completion Signal Handling ---
            # Check for FIN flag and special window (must be from established sender)
            if self.connection_established and packet[TCP].flags & 0x01 and packet[TCP].window == COMPLETION_WINDOW:
                 # Verify source IP/Port match established connection
                 if self.sender_ip == current_sender_ip and self.sender_port == current_sender_port:
                     log_debug(f"Received transmission complete signal (FIN) from {current_sender_ip}:{current_sender_port}")
                     print("\n[COMPLETE] Reception complete signal received.")
                     return True # Signal sniff loop to stop
                 else:
                     log_debug(f"Received FIN-like packet but from unexpected source {current_sender_ip}:{current_sender_port}")
                     return False # Ignore

            # --- Data Packet Handling ---
            if not self.connection_established:
                # log_debug("Ignoring packet - connection not yet established.") # Noisy
                return False

            # Check if packet structure matches data packets (SYN flag, Window=SeqNum, MSS=TotalChunks)
            seq_num = packet[TCP].window
            total_chunks = None
            if packet[TCP].flags & 0x02: # Data packets use SYN flag
                for option in packet[TCP].options:
                    if option[0] == 'MSS':
                        total_chunks = option[1]
                        break

            # Plausibility check
            if packet[TCP].flags & 0x02 and 0 < seq_num <= 65535 and total_chunks is not None:
                 # Verify source IP/Port match established connection
                 if not (self.sender_ip == current_sender_ip and self.sender_port == current_sender_port):
                      log_debug(f"Received data-like packet but from unexpected source {current_sender_ip}:{current_sender_port}")
                      return False # Ignore

                 # --- Process Data Packet ---
                 # Extract data from sequence and acknowledge numbers
                 seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
                 ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
                 data = seq_bytes + ack_bytes

                 # Extract and verify checksum from IP ID
                 checksum = packet[IP].id
                 calc_checksum = binascii.crc32(data) & 0xFFFF
                 checksum_ok = (checksum == calc_checksum)
                 if not checksum_ok:
                     log_debug(f"Warning: Checksum mismatch for packet {seq_num}. Expected {calc_checksum:#06x}, Got {checksum:#06x}")

                 # Handle duplicate chunk
                 if seq_num in self.received_chunks:
                     # log_debug(f"Duplicate chunk {seq_num} received, resending ACK.")
                     self.send_data_ack(seq_num) # Resend ACK
                     return False # Don't process duplicate further

                 # --- Process New Chunk ---
                 log_debug(f"Received chunk {seq_num} (size: {len(data)}, chksum: {'OK' if checksum_ok else 'FAIL'})")
                 self._log_received_chunk(seq_num, data) # Store and log
                 self.send_data_ack(seq_num) # Send ACK

                 # Update highest sequence number and total chunks expected
                 if seq_num > self.highest_seq_num_seen: self.highest_seq_num_seen = seq_num
                 if total_chunks > self.total_chunks_expected: self.total_chunks_expected = total_chunks # Use highest seen

                 # Print progress update
                 progress = (len(self.received_chunks) / self.total_chunks_expected) * 100 if self.total_chunks_expected else 0
                 print(f"[CHUNK] Received chunk {seq_num:04d}/{self.total_chunks_expected:04d} | Total: {len(self.received_chunks):04d}/{self.total_chunks_expected:04d} | Progress: {progress:.1f}% ", end='\r', flush=True)
                 print(f"[CHUNK] Received chunk {seq_num}/{self.total_chunks_expected} | Progress: {progress:.1f}%")

                 return False # Not complete yet

        # If packet didn't match any expected pattern
        return False

# --- Reassembly Logic ---
def reassemble_data(received_chunks_dict, highest_seq_num, logs_dir, chunks_dir, data_dir): # Added data_dir argument
    """Reassemble the received chunks in correct order, handling missing chunks."""
    if not received_chunks_dict:
        log_debug("Reassembly skipped: No chunks received.")
        return None, 0 # Return None data, 0 missing

    print(f"\n[REASSEMBLY] Sorting {len(received_chunks_dict)} received chunks...")
    sorted_seq_nums = sorted(received_chunks_dict.keys())

    # Check for missing chunks
    expected_seq = 1
    missing_chunks = []
    for seq in sorted_seq_nums:
        if seq != expected_seq:
            missing_chunks.extend(range(expected_seq, seq))
        expected_seq = seq + 1

    # Check for missing chunks *after* the last received one, up to highest seen
    last_received_seq = sorted_seq_nums[-1] if sorted_seq_nums else 0
    if expected_seq <= highest_seq_num: # highest_seq_num from window field
         log_debug(f"Checking for missing chunks between {expected_seq} and {highest_seq_num}")
         missing_chunks.extend(range(expected_seq, highest_seq_num + 1))

    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks detected. IDs (sample): {missing_chunks[:20]}...")
        print(f"[REASSEMBLY] Warning: Detected {len(missing_chunks)} missing chunks.")
        if len(missing_chunks) <= 20: print(f"[REASSEMBLY] Missing Sequence Numbers: {missing_chunks}")
        else: print(f"[REASSEMBLY] First 20 Missing Sequence Numbers: {missing_chunks[:20]}...")

    # Save diagnostic information
    chunk_info = {
        "received_chunk_count": len(received_chunks_dict),
        "highest_seq_num_seen": highest_seq_num,
        "missing_chunk_count": len(missing_chunks),
        "missing_chunks_list": missing_chunks,
        "received_seq_nums_list": sorted_seq_nums
    }
    reassembly_file = os.path.join(logs_dir, "reassembly_info.json")
    with open(reassembly_file, "w") as f: json.dump(chunk_info, f, indent=2)

    # Process chunks in order, cleaning padding
    print("[REASSEMBLY] Cleaning received chunks (removing potential padding)...")
    print(f"[PROGRESS] Processing received data | Total chunks: {len(received_chunks_dict)}")
    cleaned_chunks = []
    num_sorted = len(sorted_seq_nums)
    cleaned_chunk_dir = os.path.join(chunks_dir, CLEANED_CHUNKS_SUBDIR)

    for i, seq in enumerate(sorted_seq_nums):
        chunk = received_chunks_dict[seq]
        if i == 0 or (i + 1) % 50 == 0 or i == num_sorted - 1:
            print(f"[REASSEMBLY] Processing chunk {seq:04d} ({i+1}/{num_sorted})", end='\r', flush=True)

        # Clean padding logic (same as original)
        cleaned_chunk = chunk

        # Always strip trailing nulls unless the chunk was *only* null bytes
        if not all(b == 0 for b in chunk):
            cleaned_chunk = chunk.rstrip(b'\0')
        elif chunk: # Handle case where original chunk was b'\x00\x00...' -> keep one null
             cleaned_chunk = b'\0'
        cleaned_chunks.append(cleaned_chunk)

        # Save cleaned chunk (optional debug)
        cleaned_file = os.path.join(cleaned_chunk_dir, f"chunk_{seq:04d}.bin")
        with open(cleaned_file, "wb") as f: f.write(cleaned_chunk)

        # Save cleaned chunk
        cleaned_file = os.path.join(cleaned_chunk_dir, f"chunk_{seq:04d}.bin")
        with open(cleaned_file, "wb") as f: f.write(cleaned_chunk)

    print("\n[REASSEMBLY] Concatenating cleaned chunks...")
    reassembled_data = b"".join(cleaned_chunks)

    # Save the final reassembled data
    reassembled_file = os.path.join(data_dir, "reassembled_data.bin") # Use passed data_dir
    with open(reassembled_file, "wb") as f: f.write(reassembled_data)

    print(f"[REASSEMBLY] Completed! Final reassembled size: {len(reassembled_data)} bytes")
    return reassembled_data, len(missing_chunks)

# --- Monitor Thread ---
def monitor_transmission(stop_event, timeout, state):
    """Monitor transmission for inactivity. Updates state dict."""
    log_debug(f"Inactivity monitor started (timeout: {timeout}s).")
    while not stop_event.is_set():
        time_since_last = time.time() - state['last_activity_time']
        if time_since_last > timeout:
            log_debug(f"Inactivity timeout reached ({timeout} seconds). Stopping reception.")
            print(f"\n\n[TIMEOUT] No activity detected for {timeout} seconds. Stopping listening.")
            state['transmission_complete'] = True # Signal main sniff loop to stop
            break
        # Use ACK_POLL_INTERVAL for sleep granularity, but ensure we don't overshoot timeout
        time_to_wait = min(ACK_POLL_INTERVAL, timeout - time_since_last)
        if time_to_wait > 0: time.sleep(time_to_wait)
        else: time.sleep(ACK_POLL_INTERVAL / 2) # Small sleep if very close to timeout
    log_debug("Inactivity monitor stopped.")

# --- High-Level Workflow Function ---
def receive_file_logic(output_path, key_path, interface, inactivity_timeout, discovery_timeout, session_paths):
    """Encapsulates the main logic for discovering, receiving, and processing a file."""
    session_start_time = time.time() # Capture overall start time
    log_debug(f"--- Receiver Core Logic Start (Time: {session_start_time}) ---")
    overall_success = False
    status = "started"
    final_data_to_save = b''
    missing_chunks_count = 0
    packet_counter = 0
    valid_packet_counter = 0

    # --- Phase 0: Initialization and Key Prep ---
    log_debug("Phase 0: Initialization and Key Prep")
    # Prepare key
    log_debug(f"Reading key from: {key_path}")
    print(f"Reading key: {key_path}")
    try:
        with open(key_path, 'rb') as key_file: key_data = key_file.read()
        key, probe_id_expected, response_id = prepare_key(key_data, session_paths['data_dir'])
        if not probe_id_expected or not response_id:
             print("Error: Failed to derive discovery identifiers from key.")
             log_debug("Failed to derive key identifiers.")
             return False
    except Exception as e:
        log_debug(f"Error reading or preparing key file {key_path}: {e}")
        print(f"Error reading or preparing key file: {e}")
        return False

    # Create receiver instance
    stego = SteganographyReceiver(probe_id_expected, response_id, session_paths)

    # Shared state for monitor and packet handler
    reception_state = {
        'last_activity_time': time.time(),
        'transmission_complete': False,
        'reception_start_time': 0,
    }

    try:
        # --- Phase 1: Discovery ---
        log_debug("Phase 1: Sender Discovery")
        print(f"[DISCOVERY] Listening for sender probe on TCP/{DISCOVERY_PORT} (up to {discovery_timeout}s)...")
        try:
            sniff(
                iface=interface,
                filter=f"tcp and dst port {DISCOVERY_PORT}",
                prn=stego.process_discovery_probe,
                store=0,
                timeout=discovery_timeout,
                stop_filter=lambda p: stego.discovery_probe_processed
            )
        except Exception as e:
            log_debug(f"Error during discovery sniffing: {e}")
            print(f"\n[ERROR] An error occurred during discovery listening: {e}")
            return False

        if not stego.discovery_probe_processed:
            log_debug("Discovery failed. Exiting.")
            print("\n[DISCOVERY] No valid sender probe received within the timeout period.")
            print("[ERROR] Could not discover sender. Ensure sender is running with the correct key.")
            return False
        else:
             log_debug(f"Discovery successful. Sender identified: {stego.discovery_sender_ip}:{stego.discovery_sender_port}")
             # Success message printed within process_discovery_probe

        # --- Phase 2: Main Listening for Connection & Data ---
        log_debug(f"Phase 2: Listening for Connection/Data from {stego.discovery_sender_ip}")
        print(f"\n[INFO] Sender discovered at {stego.discovery_sender_ip}. Now listening for connection and data...")
        print(f"Listening timeout: {inactivity_timeout}s. Press Ctrl+C to stop manually.")

        # Start monitoring thread
        stop_monitor = threading.Event()
        monitor_thread = threading.Thread(target=monitor_transmission, args=(stop_monitor, inactivity_timeout, reception_state))
        monitor_thread.daemon = True
        monitor_thread.start()
        log_debug("Started inactivity monitor thread.")

        reception_state['last_activity_time'] = time.time() # Reset timer

        # Packet handler wrapper for counting
        def packet_counter_handler(packet):
            nonlocal packet_counter, valid_packet_counter
            packet_counter += 1
            reception_state['last_activity_time'] = time.time() # Update activity time

            # Record start time on first valid chunk processed inside process_packet
            if not reception_state['reception_start_time'] and stego.received_chunks:
                 reception_state['reception_start_time'] = time.time()
                 log_debug("First chunk processed, reception timer started.")

            is_complete_signal = stego.process_packet(packet)
            if is_complete_signal:
                 reception_state['transmission_complete'] = True # Signal completion

            # Update valid counter if it was a data packet (heuristic check)
            if stego.connection_established and TCP in packet and packet[TCP].flags & 0x02 and packet[TCP].window > 0:
                 # More accurate check might be needed if process_packet returns status
                 valid_packet_counter += 1 # Increment if it looks like data

            # Print status periodically
            if packet_counter <= 10 or packet_counter % RECEIVER_STATUS_PRINT_INTERVAL == 0:
                 valid_ratio_str = f"{valid_packet_counter}/{packet_counter}" if packet_counter > 0 else "0/0"
                 print(f"[SCAN] Pkts: {packet_counter:06d} | Chunks Rcvd: {len(stego.received_chunks):04d} | Valid Ratio: {valid_ratio_str}", end='\r', flush=True)

            return None # Prevent scapy summary

        try:
            filter_str = f"tcp and src host {stego.discovery_sender_ip}"
            log_debug(f"Using main sniffing filter: '{filter_str}'")
            sniff(
                iface=interface,
                filter=filter_str,
                prn=packet_counter_handler,
                store=0,
                stop_filter=lambda p: reception_state['transmission_complete']
            )
        except KeyboardInterrupt:
            log_debug("Receiving stopped by user (Ctrl+C).")
            print("\nReceiving stopped by user.")
            reception_state['transmission_complete'] = True
        except Exception as e:
             log_debug(f"Error during main sniffing loop: {e}")
             print(f"\n[ERROR] Sniffing loop failed: {e}")
             reception_state['transmission_complete'] = True
        finally:
            log_debug("Stopping inactivity monitor thread.")
            stop_monitor.set()
            if monitor_thread.is_alive(): monitor_thread.join(1.0)

        # --- Phase 3: Post-Reception Processing ---
        print("\n" + "="*20 + " Processing Received Data " + "="*20)

        if not stego.received_chunks:
            log_debug("Processing complete: No data chunks were received.")
            print("No data chunks were received during the session.")
            status = "failed_no_data"
            overall_success = False
        else:
            duration = time.time() - reception_state['reception_start_time'] if reception_state['reception_start_time'] > 0 else 0
            chunk_count = len(stego.received_chunks)
            highest_seq = stego.highest_seq_num_seen
            total_expected = stego.total_chunks_expected if stego.total_chunks_expected >= highest_seq else highest_seq # Use max seen

            # Reassemble data
            log_debug("Reassembling data...")
            print("[REASSEMBLY] Starting data reassembly process...")
            reassembled_data, missing_chunks_count = reassemble_data(
                stego.received_chunks, total_expected, session_paths['logs_dir'], session_paths['chunks_dir'], session_paths['data_dir'] # Pass data_dir
            )

            if reassembled_data is None:
                log_debug("Failed to reassemble data.")
                print("[REASSEMBLY] Failed!")
                status = "failed_reassembly"
                overall_success = False
            else:
                log_debug(f"Reassembled {len(reassembled_data)} bytes.")
                # Verify data integrity
                print("[VERIFY] Verifying data integrity...")
                verified_data, checksum_ok = verify_data_integrity(
                    reassembled_data, session_paths['logs_dir'], session_paths['data_dir']
                )

                if not checksum_ok:
                     log_debug("Integrity check failed or data too short. Using raw reassembled data.")
                     print("[VERIFY] Warning: Checksum verification failed or data too short. Proceeding with raw data.")
                     final_data_to_decrypt = verified_data # Use data before checksum
                     status = "partial_checksum_failed"
                else:
                     log_debug(f"Integrity check passed. Verified data size: {len(verified_data)} bytes.")
                     print(f"[VERIFY] Integrity check passed. Data size: {len(verified_data)} bytes")
                     final_data_to_decrypt = verified_data
                     status = "ok_integrity_checked"

                # Decrypt the data
                log_debug("Decrypting data...")
                print("[DECRYPT] Starting decryption...")
                decrypted_data = decrypt_data(final_data_to_decrypt, key, session_paths['data_dir'])

                if decrypted_data is None:
                    log_debug("Decryption failed. Saving raw (verified/reassembled) data instead.")
                    print("[DECRYPT] Failed! Saving raw data instead.")
                    final_data_to_save = final_data_to_decrypt
                    status = "failed_decryption"
                    overall_success = False # Decryption failure means overall failure
                else:
                    log_debug(f"Successfully decrypted {len(decrypted_data)} bytes.")
                    print(f"[DECRYPT] Successfully decrypted {len(decrypted_data)} bytes.")
                    final_data_to_save = decrypted_data
                    # Determine final status based on missing chunks and checksum
                    if missing_chunks_count > 0:
                        status = "completed_missing_chunks"
                        overall_success = False # Missing chunks means not fully successful
                    elif status == "partial_checksum_failed":
                         overall_success = True # Checksum fail might be acceptable? Let's say yes for now.
                         status = "completed_checksum_failed"
                    else:
                         status = "completed_successfully"
                         overall_success = True

                # Save final data
                print(f"[SAVE] Saving {len(final_data_to_save)} bytes to {output_path}...")
                save_success = save_to_file(final_data_to_save, output_path, session_paths['data_dir'])
                if not save_success:
                    status = "failed_save"
                    overall_success = False # Override success if saving fails
                else:
                     print(f"[SAVE] File saved successfully")


    except Exception as e:
         print(f"\n[FATAL ERROR] An unexpected error occurred in core logic: {e}")
         import traceback
         traceback.print_exc()
         log_debug(f"FATAL ERROR in core logic: {e}\n{traceback.format_exc()}")
         status = "failed_fatal_error"
         overall_success = False
    finally:
        # Log final stats
        session_end_time = time.time() # Capture end time for calculations
        data_transmission_duration = session_end_time - reception_state['reception_start_time'] if reception_state.get('reception_start_time', 0) > 0 else 0
        total_session_duration = session_end_time - session_start_time

        chunk_count = len(stego.received_chunks) if 'stego' in locals() else 0
        highest_seq = stego.highest_seq_num_seen if 'stego' in locals() else 0
        total_expected = stego.total_chunks_expected if 'stego' in locals() and stego.total_chunks_expected >= highest_seq else highest_seq

        reception_rate = (chunk_count / total_expected * 100) if total_expected > 0 else (100.0 if chunk_count > 0 else 0.0)

        print(f"\nReception summary:")
        print(f"- Processed {packet_counter} packets total (from sender: {stego.sender_ip if 'stego' in locals() else 'Unknown'})")
        print(f"- Identified {valid_packet_counter} valid data packets")
        print(f"- Received {chunk_count} unique data chunks") # Removed old duration print
        print(f"- Highest sequence number seen: {highest_seq}")
        print(f"- Total chunks expected (based on MSS/highest seq): {total_expected}")
        if missing_chunks_count > 0:
            print(f"- Reception rate: {reception_rate:.1f}% ({missing_chunks_count} missing)")
        # Print durations together
        print(f"- Data Transmission Duration: ~{data_transmission_duration:.2f}s")
        print(f"- Total Session Duration: ~{total_session_duration:.2f}s")

        # Save completion info
        completion_info = {
            "session_start_time": session_start_time, # Added
            "session_end_time": session_end_time,
            "status": status,
            "bytes_saved": len(final_data_to_save) if overall_success or status == "failed_decryption" else 0,
            "total_packets_processed": packet_counter,
            "valid_data_packets": valid_packet_counter,
            "chunks_received": chunk_count,
            "highest_seq_num_seen": highest_seq,
            "total_chunks_expected": total_expected,
            "missing_chunk_count": missing_chunks_count,
            "data_transmission_duration_seconds": round(data_transmission_duration, 2), # Renamed and added
            "total_session_duration_seconds": round(total_session_duration, 2), # Added
            "sender_ip_discovered": stego.discovery_sender_ip if 'stego' in locals() else None,
            "sender_ip_connected": stego.sender_ip if 'stego' in locals() else None,
            "sender_port_connected": stego.sender_port if 'stego' in locals() else None
        }
        completion_path = os.path.join(session_paths['logs_dir'], "completion_info.json")
        try:
            with open(completion_path, "w") as f: json.dump(completion_info, f, indent=2)
        except Exception as save_e:
            log_debug(f"Could not save completion info: {save_e}")

        print(f"\n[INFO] All session data saved to: {session_paths['session_dir']}")
        latest_link_path = os.path.join(os.path.dirname(session_paths['session_dir']), "receiver_latest")
        print(f"[INFO] Latest session link: {latest_link_path}")
        log_debug(f"--- Receiver Core Logic End (Status: {status}, Success: {overall_success}) ---")

    return overall_success
