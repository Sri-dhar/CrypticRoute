import sys
import os
import time
import hashlib
import json
import binascii
import threading
import random
from scapy.all import IP, TCP, sniff, conf, send
from datetime import datetime # Added for timestamp
import traceback # For detailed error logging

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
    RECEIVER_STATUS_PRINT_INTERVAL, ACK_POLL_INTERVAL # Re-added ACK_POLL_INTERVAL
)

# Configure Scapy settings
conf.verb = 0

# --- Receiver State (managed within the class or passed around) ---
class SteganographyReceiver:
    """Handles the core receiving logic including discovery response, handshake, and data processing for a single transfer segment."""

    def __init__(self, key_probe_id_expected, key_response_id, session_paths, key, update_signal=None, stop_event=None): # Added stop_event
        """Initialize the receiver state for one discovery/transfer attempt."""
        self.receiver_key_hash_probe_expected = key_probe_id_expected
        self.receiver_key_hash_response = key_response_id
        self.session_paths = session_paths
        self.stop_event = stop_event # Store the stop event
        self.key = key # Store the decryption key
        self.update_signal = update_signal # Store the optional signal emitter for GUI updates
        self.my_port = random.randint(*RECEIVER_SPORT_RANGE) # Port for sending ACKs/SYN-ACKs

        # State variables (reset implicitly by creating a new instance for each outer loop iteration)
        self.discovery_sender_ip = None
        self.discovery_sender_port = None
        self.discovery_probe_processed = False
        self.sender_ip = None
        self.sender_port = None
        self.connection_established = False
        self.received_chunks = {}
        self.ack_sent_chunks = set()
        self.highest_seq_num_seen = 0
        self.total_chunks_expected = 0
        self.reception_start_time = 0 # Track start time for this file transfer segment

        # Debug logging setup (persistent for the receiver instance)
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f") # Added microseconds
        self.chunks_json_path = os.path.join(session_paths['logs_dir'], f"received_chunks_debug_{timestamp_str}.json")
        self.acks_json_path = os.path.join(session_paths['logs_dir'], f"sent_acks_debug_{timestamp_str}.json")
        self.sent_acks_log = {} # In-memory log

        # Create log files
        try:
            os.makedirs(session_paths['logs_dir'], exist_ok=True)
            with open(self.chunks_json_path, "w") as f: json.dump({}, f)
            with open(self.acks_json_path, "w") as f: json.dump({}, f)
        except IOError as e:
            log_debug(f"Error creating receiver debug log files: {e}")

        log_debug(f"Receiver instance initialized. Listening port (for sending): {self.my_port}")

    # --- Logging Methods ---
    def _log_received_chunk(self, seq_num, data):
        """Save received chunk to debug file."""
        self.received_chunks[seq_num] = data
        log_entry = {
            "data_hex_preview": data[:64].hex() + ("..." if len(data) > 64 else ""),
            "size": len(data),
            "timestamp": time.time()
        }
        try:
            # Read existing log data safely
            try:
                with open(self.chunks_json_path, "r") as f:
                    chunk_log_data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                chunk_log_data = {}

            # Update and write back
            chunk_log_data[str(seq_num)] = log_entry
            with open(self.chunks_json_path, "w") as f:
                json.dump(chunk_log_data, f, indent=2)
        except IOError as e:
            log_debug(f"Error writing received chunks debug log: {e}")

        raw_chunk_dir = os.path.join(self.session_paths['chunks_dir'], RAW_CHUNKS_SUBDIR)
        chunk_file = os.path.join(raw_chunk_dir, f"chunk_{seq_num:04d}.bin")
        try:
            os.makedirs(raw_chunk_dir, exist_ok=True)
            with open(chunk_file, "wb") as f:
                f.write(data)
        except IOError as e:
            log_debug(f"Error writing raw chunk file {chunk_file}: {e}")

    def _log_sent_ack(self, seq_num):
        """Save sent ACK to debug file."""
        self.sent_acks_log[str(seq_num)] = { "timestamp": time.time() }
        try:
            with open(self.acks_json_path, "w") as f:
                json.dump(self.sent_acks_log, f, indent=2)
        except IOError as e:
            log_debug(f"Error writing sent ACKs debug log: {e}")

    # --- Discovery Response Methods ---
    def _create_discovery_response_packet(self, probe_packet):
        sender_ip = probe_packet[IP].src
        sender_port = probe_packet[TCP].sport
        probe_seq = probe_packet[TCP].seq
        response_packet = IP(dst=sender_ip) / TCP(
            sport=DISCOVERY_PORT, dport=sender_port, flags="PF",
            window=DISCOVERY_RESPONSE_WINDOW,
            seq=int.from_bytes(self.receiver_key_hash_response, 'big'),
            ack=probe_seq + 1 if probe_seq is not None else 1
        )
        log_debug(f"Created discovery response: Target={sender_ip}:{sender_port}, Flags={response_packet[TCP].flags}, Win={response_packet[TCP].window:#x}, Seq={response_packet[TCP].seq:#x}, Ack={response_packet[TCP].ack:#x}")
        return response_packet

    def _send_discovery_response(self, probe_packet):
        response_pkt = self._create_discovery_response_packet(probe_packet)
        if response_pkt:
            log_debug(f"Sending Discovery Response to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            print(f"[DISCOVERY] Sending response to sender at {probe_packet[IP].src}")
            print(f"[IP_EXCHANGE] Sending confirmation to {probe_packet[IP].src}:{probe_packet[TCP].sport}")
            for _ in range(DISCOVERY_RESPONSE_SEND_COUNT):
                 send(response_pkt)
                 time.sleep(DISCOVERY_RESPONSE_SEND_DELAY)

    def process_discovery_probe(self, packet):
        """Process incoming packets during discovery phase. Returns True if valid probe processed, False otherwise."""
        if self.stop_event and self.stop_event.is_set(): return True # Stop if event is set
        if self.discovery_probe_processed:
            return False # Already processed, stop filter should handle this

        if IP in packet and TCP in packet and packet[TCP].dport == DISCOVERY_PORT \
           and packet[TCP].flags & 0x28 == 0x28 and packet[TCP].window == DISCOVERY_PROBE_WINDOW:
            probe_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery probe from {packet[IP].src}:{packet[TCP].sport}")
            log_debug(f"  Flags={int(packet[TCP].flags):#x} ({packet[TCP].flags}), Window={packet[TCP].window:#x}, SeqHash={probe_hash_received.hex()}")

            if probe_hash_received == self.receiver_key_hash_probe_expected:
                log_debug(f"Valid Discovery Probe received from {packet[IP].src}:{packet[TCP].sport}. Key hash MATCH.")
                print(f"\n[DISCOVERY] Valid probe received from sender at {packet[IP].src}")
                print(f"[IP_EXCHANGE] Sender IP identified: {packet[IP].src}:{packet[TCP].sport}")
                self.discovery_sender_ip = packet[IP].src
                self.discovery_sender_port = packet[TCP].sport
                self._send_discovery_response(packet)
                self.discovery_probe_processed = True
                return True # Signal discovery sniff to stop
            else:
                log_debug(f"Probe received from {packet[IP].src}, but key hash mismatch. Ignoring.")
                return False # Explicitly return False if hash mismatch

        # Explicitly return False if packet didn't match discovery criteria
        return False

    # --- Connection/Data ACK Methods ---
    def _create_data_ack_packet(self, seq_num):
        if not self.sender_ip or not self.sender_port: return None
        ack_packet = IP(dst=self.sender_ip) / TCP(
            sport=self.my_port, dport=self.sender_port,
            seq=random.randint(0, 0xFFFFFFFF), ack=seq_num,
            window=DATA_ACK_WINDOW, flags="A"
        )
        return ack_packet

    def send_data_ack(self, seq_num):
        if self.stop_event and self.stop_event.is_set(): return # Don't send if stopping
        if seq_num in self.ack_sent_chunks: return
        ack_packet = self._create_data_ack_packet(seq_num)
        if not ack_packet: return
        log_debug(f"Sending ACK for data chunk {seq_num} to {self.sender_ip}:{self.sender_port}")
        self._log_sent_ack(seq_num)
        for _ in range(DATA_ACK_SEND_COUNT):
            send(ack_packet)
            time.sleep(DATA_ACK_SEND_DELAY)
        self.ack_sent_chunks.add(seq_num)

    def _create_syn_ack_packet(self, incoming_syn_packet):
        if not self.sender_ip or not self.sender_port: return None
        syn_ack_packet = IP(dst=self.sender_ip) / TCP(
            sport=self.my_port, dport=self.sender_port,
            seq=random.randint(0, 0xFFFFFFFF), ack=incoming_syn_packet[TCP].seq + 1,
            window=SYN_ACK_WINDOW, flags="SA"
        )
        log_debug(f"Created SYN-ACK: Target={self.sender_ip}:{self.sender_port}, Flags={syn_ack_packet[TCP].flags}, Win={syn_ack_packet[TCP].window:#x}, Seq={syn_ack_packet[TCP].seq:#x}, Ack={syn_ack_packet[TCP].ack:#x}")
        return syn_ack_packet

    def _send_syn_ack(self, incoming_syn_packet):
        if self.stop_event and self.stop_event.is_set(): return # Don't send if stopping
        syn_ack_packet = self._create_syn_ack_packet(incoming_syn_packet)
        if not syn_ack_packet: return
        log_debug(f"Sending SYN-ACK for connection establishment to {self.sender_ip}:{self.sender_port}")
        print(f"[HANDSHAKE] Sending SYN-ACK response to {self.sender_ip}:{self.sender_port}")
        for _ in range(SYN_ACK_SEND_COUNT):
            send(syn_ack_packet)
            time.sleep(SYN_ACK_SEND_DELAY)

    # --- Data Processing and Saving (triggered by FIN) ---
    def _process_and_save_received_data(self):
        """Reassembles, verifies, decrypts, and saves the currently received data."""
        processing_start_time = time.time()
        log_debug("FIN received, starting post-reception processing...")
        print("\n" + "="*20 + " Processing Received Data Segment " + "="*20)

        if not self.received_chunks:
            log_debug("Processing skipped: No data chunks received for this segment.")
            print("No data chunks received for this segment.")
            return # Nothing to process

        current_chunks = self.received_chunks.copy() # Process the completed segment
        current_total_expected = self.total_chunks_expected if self.total_chunks_expected >= self.highest_seq_num_seen else self.highest_seq_num_seen
        current_reception_start_time = self.reception_start_time

        log_debug("Reassembling data segment...")
        print("[REASSEMBLY] Starting data reassembly process...")
        reassembled_data, missing_chunks_count = reassemble_data(
            current_chunks, current_total_expected, self.session_paths['logs_dir'], self.session_paths['chunks_dir'], self.session_paths['data_dir']
        )

        final_data_to_save = b''
        segment_status = "processing"
        segment_success = False
        saved_txt_filepath = None # Track the saved file path

        if reassembled_data is None:
            log_debug("Failed to reassemble data segment.")
            print("[REASSEMBLY] Failed!")
            segment_status = "failed_reassembly"
        else:
            log_debug(f"Reassembled {len(reassembled_data)} bytes for segment.")
            print("[VERIFY] Verifying data integrity...")
            verified_data, checksum_ok = verify_data_integrity(
                reassembled_data, self.session_paths['logs_dir'], self.session_paths['data_dir']
            )

            if not checksum_ok:
                 log_debug("Integrity check failed or data too short. Using raw reassembled data for segment.")
                 print("[VERIFY] Warning: Checksum verification failed or data too short. Proceeding with raw data.")
                 final_data_to_decrypt = verified_data
                 segment_status = "partial_checksum_failed"
            else:
                 log_debug(f"Integrity check passed. Verified data size: {len(verified_data)} bytes.")
                 print(f"[VERIFY] Integrity check passed. Data size: {len(verified_data)} bytes")
                 final_data_to_decrypt = verified_data
                 segment_status = "ok_integrity_checked"

            log_debug("Decrypting data segment...")
            print("[DECRYPT] Starting decryption...")
            decrypted_data = decrypt_data(final_data_to_decrypt, self.key, self.session_paths['data_dir'])

            if decrypted_data is None:
                log_debug("Decryption failed. Saving raw (verified/reassembled) data segment instead.")
                print("[DECRYPT] Failed! Saving raw data instead.")
                final_data_to_save = final_data_to_decrypt
                segment_status = "failed_decryption"
                segment_success = False
            else:
                log_debug(f"Successfully decrypted {len(decrypted_data)} bytes for segment.")
                print(f"[DECRYPT] Successfully decrypted {len(decrypted_data)} bytes.")
                final_data_to_save = decrypted_data
                if missing_chunks_count > 0:
                    segment_status = "completed_missing_chunks"
                    segment_success = False
                elif segment_status == "partial_checksum_failed":
                     segment_success = True
                     segment_status = "completed_checksum_failed"
                else:
                     segment_status = "completed_successfully"
                     segment_success = True

            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename_bin = f"received_{timestamp_str}.bin"
            output_filepath_bin = os.path.join(self.session_paths['data_dir'], output_filename_bin)
            output_filename_txt = f"received_{timestamp_str}.txt"
            output_filepath_txt = os.path.join(self.session_paths['data_dir'], output_filename_txt)

            print(f"[SAVE] Saving {len(final_data_to_save)} bytes to {output_filename_bin} and {output_filename_txt}...")
            save_success_bin = save_to_file(final_data_to_save, output_filepath_bin, self.session_paths['data_dir'])
            save_success_txt = save_to_file(final_data_to_save, output_filepath_txt, self.session_paths['data_dir'])

            if not save_success_bin or not save_success_txt:
                segment_status = "failed_save"
                segment_success = False
                log_debug(f"Failed to save segment. BIN success: {save_success_bin}, TXT success: {save_success_txt}")
                print(f"[SAVE] Error saving file segment!")
            else:
                 print(f"[SAVE] File segment saved successfully to {output_filename_bin} and {output_filename_txt}")
                 saved_txt_filepath = output_filepath_txt # Store path if save was successful

        processing_end_time = time.time()
        duration = processing_end_time - current_reception_start_time if current_reception_start_time > 0 else 0
        log_debug(f"Segment processing finished. Status: {segment_status}, Success: {segment_success}, Duration: {duration:.2f}s")
        print(f"Segment processing complete. Status: {segment_status}")
        print("="*50)

        # Emit signal for GUI update if successful and signal exists
        if segment_success and saved_txt_filepath and self.update_signal:
            try:
                log_debug(f"Emitting signal for GUI update with path: {saved_txt_filepath}")
                self.update_signal.emit(saved_txt_filepath)
            except Exception as e:
                log_debug(f"Error emitting GUI update signal: {e}")


    # --- Packet Processing ---
    def process_packet(self, packet, shared_state):
        """
        Process packets for connection, data, or completion.
        Updates shared_state['last_activity_time'].
        Returns True if FIN processed, False otherwise.
        """
        if self.stop_event and self.stop_event.is_set(): return True # Signal inner loop to stop

        # Update activity time whenever a relevant packet is processed by this handler
        shared_state['last_activity_time'] = time.time()

        # --- Phase 1: Check Source IP ---
        if self.discovery_sender_ip is None:
             log_debug("Ignoring packet - discovery not yet complete for this instance.")
             return False
        if IP not in packet or packet[IP].src != self.discovery_sender_ip:
            return False

        # --- Phase 2: Process Packet Content ---
        if TCP in packet:
            current_sender_ip = packet[IP].src
            current_sender_port = packet[TCP].sport

            # --- Connection Establishment Handling ---
            if not self.connection_established and packet[TCP].flags & 0x02 and packet[TCP].window == SYN_WINDOW:
                log_debug(f"Received connection establishment request (SYN) from {current_sender_ip}:{current_sender_port}")
                print(f"\n[HANDSHAKE] Received connection request (SYN) from {current_sender_ip}:{current_sender_port}")
                print(f"[IP_EXCHANGE] Connection request from {current_sender_ip}:{current_sender_port}")
                self.sender_ip = current_sender_ip
                self.sender_port = current_sender_port
                log_debug(f"Set sender IP/Port for connection: {self.sender_ip}:{self.sender_port}")
                self._send_syn_ack(packet)
                return False # Continue sniffing

            if not self.connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == FINAL_ACK_WINDOW and packet[TCP].dport == self.my_port:
                if self.sender_ip == current_sender_ip and self.sender_port == current_sender_port:
                    log_debug(f"Received connection confirmation (ACK) from {current_sender_ip}:{current_sender_port}")
                    print(f"[HANDSHAKE] Connection established with sender")
                    print(f"[IP_EXCHANGE] Connection confirmed with {current_sender_ip}:{current_sender_port}")
                    self.connection_established = True
                else:
                    log_debug(f"Received final ACK-like packet but from unexpected source {current_sender_ip}:{current_sender_port}")
                return False # Continue sniffing

            # --- Completion Signal Handling (FIN) --- Trigger processing and signal stop for *inner* loop ---
            if self.connection_established and packet[TCP].flags & 0x01 and packet[TCP].window == COMPLETION_WINDOW:
                 if self.sender_ip == current_sender_ip and self.sender_port == current_sender_port:
                     log_debug(f"Received transmission complete signal (FIN) from {current_sender_ip}:{current_sender_port}.")
                     print("\n[COMPLETE] Reception complete signal received. Processing data segment...")
                     self._process_and_save_received_data()
                     # No reset needed here, new instance handles it.
                     print(f"\n[INFO] Segment processed. Restarting discovery for potential next transmission...")
                     return True # Signal inner sniff loop to stop and outer loop to restart
                 else:
                     log_debug(f"Received FIN-like packet but from unexpected source {current_sender_ip}:{current_sender_port}. Ignoring.")
                     return False # Ignore and continue sniffing

            # --- Data Packet Handling ---
            if not self.connection_established:
                return False

            seq_num = packet[TCP].window
            total_chunks = None
            if packet[TCP].flags & 0x02:
                for option in packet[TCP].options:
                    if option[0] == 'MSS':
                        total_chunks = option[1]
                        break

            if packet[TCP].flags & 0x02 and 0 < seq_num <= 65535 and total_chunks is not None:
                 if not (self.sender_ip == current_sender_ip and self.sender_port == current_sender_port):
                      log_debug(f"Received data-like packet but from unexpected source {current_sender_ip}:{current_sender_port}")
                      return False

                 if not self.received_chunks and not self.reception_start_time:
                     self.reception_start_time = time.time()
                     log_debug(f"First chunk ({seq_num}) of new segment received, reception timer started.")

                 seq_bytes = packet[TCP].seq.to_bytes(4, byteorder='big')
                 ack_bytes = packet[TCP].ack.to_bytes(4, byteorder='big')
                 data = seq_bytes + ack_bytes
                 checksum = packet[IP].id
                 calc_checksum = binascii.crc32(data) & 0xFFFF
                 checksum_ok = (checksum == calc_checksum)
                 if not checksum_ok:
                     log_debug(f"Warning: Checksum mismatch for packet {seq_num}. Expected {calc_checksum:#06x}, Got {checksum:#06x}")

                 if seq_num in self.received_chunks:
                     self.send_data_ack(seq_num)
                     return False

                 log_debug(f"Received chunk {seq_num} (size: {len(data)}, chksum: {'OK' if checksum_ok else 'FAIL'})")
                 self._log_received_chunk(seq_num, data)
                 self.send_data_ack(seq_num)

                 if seq_num > self.highest_seq_num_seen: self.highest_seq_num_seen = seq_num
                 if total_chunks > self.total_chunks_expected: self.total_chunks_expected = total_chunks

                 progress = (len(self.received_chunks) / self.total_chunks_expected) * 100 if self.total_chunks_expected else 0
                 print(f"[CHUNK] Received chunk {seq_num:04d}/{self.total_chunks_expected:04d} | Total: {len(self.received_chunks):04d}/{self.total_chunks_expected:04d} | Progress: {progress:.1f}% ", end='\r', flush=True)

                 return False # Continue sniffing

        # If packet didn't match any expected pattern
        return False

# --- Reassembly Logic (Helper for _process_and_save_received_data) ---
def reassemble_data(received_chunks_dict, highest_seq_num, logs_dir, chunks_dir, data_dir):
    """Reassemble the received chunks in correct order, handling missing chunks."""
    if not received_chunks_dict:
        log_debug("Reassembly skipped: No chunks received.")
        return None, 0

    print(f"\n[REASSEMBLY] Sorting {len(received_chunks_dict)} received chunks...")
    sorted_seq_nums = sorted(received_chunks_dict.keys())

    expected_seq = 1
    missing_chunks = []
    for seq in sorted_seq_nums:
        if seq != expected_seq:
            missing_chunks.extend(range(expected_seq, seq))
        expected_seq = seq + 1

    last_received_seq = sorted_seq_nums[-1] if sorted_seq_nums else 0
    if expected_seq <= highest_seq_num:
         log_debug(f"Checking for missing chunks between {expected_seq} and {highest_seq_num}")
         missing_chunks.extend(range(expected_seq, highest_seq_num + 1))

    if missing_chunks:
        log_debug(f"Warning: Missing {len(missing_chunks)} chunks detected. IDs (sample): {missing_chunks[:20]}...")
        print(f"[REASSEMBLY] Warning: Detected {len(missing_chunks)} missing chunks.")
        if len(missing_chunks) <= 20: print(f"[REASSEMBLY] Missing Sequence Numbers: {missing_chunks}")
        else: print(f"[REASSEMBLY] First 20 Missing Sequence Numbers: {missing_chunks[:20]}...")

    chunk_info = {
        "received_chunk_count": len(received_chunks_dict),
        "highest_seq_num_seen": highest_seq_num,
        "missing_chunk_count": len(missing_chunks),
        "missing_chunks_list": missing_chunks,
        "received_seq_nums_list": sorted_seq_nums
    }
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f") # Added microseconds
    reassembly_file = os.path.join(logs_dir, f"reassembly_info_{timestamp_str}.json")
    try: # Wrap file writing in try/except
        with open(reassembly_file, "w") as f: json.dump(chunk_info, f, indent=2)
    except IOError as e:
        log_debug(f"Error writing reassembly info file {reassembly_file}: {e}")


    print("[REASSEMBLY] Cleaning received chunks (removing potential padding)...")
    print(f"[PROGRESS] Processing received data | Total chunks: {len(received_chunks_dict)}")
    cleaned_chunks = []
    num_sorted = len(sorted_seq_nums)
    cleaned_chunk_dir = os.path.join(chunks_dir, CLEANED_CHUNKS_SUBDIR)
    os.makedirs(cleaned_chunk_dir, exist_ok=True)

    for i, seq in enumerate(sorted_seq_nums):
        chunk = received_chunks_dict[seq]
        if i == 0 or (i + 1) % 50 == 0 or i == num_sorted - 1:
            print(f"[REASSEMBLY] Processing chunk {seq:04d} ({i+1}/{num_sorted})", end='\r', flush=True)

        cleaned_chunk = chunk
        if not all(b == 0 for b in chunk):
            cleaned_chunk = chunk.rstrip(b'\0')
        elif chunk:
             cleaned_chunk = b'\0'
        cleaned_chunks.append(cleaned_chunk)

        cleaned_file = os.path.join(cleaned_chunk_dir, f"chunk_{seq:04d}.bin")
        try: # Wrap file writing in try/except
            with open(cleaned_file, "wb") as f: f.write(cleaned_chunk)
        except IOError as e:
            log_debug(f"Error writing cleaned chunk file {cleaned_file}: {e}")


    print("\n[REASSEMBLY] Concatenating cleaned chunks...")
    reassembled_data = b"".join(cleaned_chunks)

    reassembled_file = os.path.join(data_dir, f"reassembled_data_{timestamp_str}.bin")
    try: # Wrap file writing in try/except
        with open(reassembled_file, "wb") as f: f.write(reassembled_data)
    except IOError as e:
        log_debug(f"Error writing reassembled data file {reassembled_file}: {e}")


    print(f"[REASSEMBLY] Completed! Final reassembled size: {len(reassembled_data)} bytes")
    return reassembled_data, len(missing_chunks)

# --- Monitor Thread ---
def monitor_inactivity(stop_event, timeout, shared_state): # Use stop_event directly
    """Monitors for inactivity during data reception."""
    log_debug(f"Inactivity monitor started (timeout: {timeout}s).")
    while not stop_event.is_set(): # Check the passed stop_event
        # Ensure last_activity_time exists before checking
        last_activity = shared_state.get('last_activity_time')
        if last_activity is None: # Should not happen after monitor starts, but safety check
             time.sleep(ACK_POLL_INTERVAL)
             continue

        time_since_last = time.time() - last_activity
        if time_since_last > timeout:
            log_debug(f"Inactivity timeout reached ({timeout} seconds). Signaling stop.")
            print(f"\n\n[TIMEOUT] No activity detected for {timeout} seconds. Restarting discovery...")
            shared_state['stop_due_to_timeout'] = True # Signal main sniff loop to stop
            break # Exit monitor thread

        # Check more frequently than the timeout itself
        time_to_wait = min(ACK_POLL_INTERVAL, timeout - time_since_last + 0.1) # Add buffer
        if time_to_wait <= 0: time_to_wait = ACK_POLL_INTERVAL / 2 # Prevent negative/zero sleep

        # Use stop_event.wait for efficient sleeping interruptible by the main thread
        if stop_event.wait(timeout=time_to_wait): # Use stop_event.wait
            break # Stop event was set, exit loop

    log_debug("Inactivity monitor stopped.")


# --- High-Level Workflow Function ---
def receive_file_logic(output_path, key_path, interface, timeout, discovery_timeout, session_paths, update_signal=None, stop_event=None): # Added stop_event
    """
    Encapsulates the main logic for discovering and continuously receiving file segments.
    The 'timeout' parameter defines inactivity timeout during data reception.
    The 'discovery_timeout' is currently unused but kept for CLI compatibility.
    'update_signal' is an optional PyQt signal for GUI updates.
    """
    session_start_time = time.time()
    log_debug(f"--- Receiver Core Logic Start (Time: {session_start_time}) ---")
    packet_counter = 0 # Overall counter for the entire run
    valid_packet_counter = 0 # Overall counter
    segment_counter = 0 # Count processed segments

    # --- Phase 0: Key Prep (Done once) ---
    log_debug("Phase 0: Initialization and Key Prep")
    print(f"Reading key: {key_path}")
    try:
        with open(key_path, 'rb') as key_file: key_data = key_file.read()
        key, probe_id_expected, response_id = prepare_key(key_data, session_paths['data_dir'])
        if not key or not probe_id_expected or not response_id:
             print("Error: Failed to derive key or discovery identifiers from key.")
             log_debug("Failed to derive key or key identifiers.")
             return False
    except Exception as e:
        log_debug(f"Error reading or preparing key file {key_path}: {e}")
        print(f"Error reading or preparing key file: {e}")
        return False

    # --- Outer Loop: Handles Discovery and Listening for each segment ---
    stopped_externally = False # Primarily for Ctrl+C detection now
    while not stopped_externally and not (stop_event and stop_event.is_set()): # Check event here
        segment_counter += 1
        log_debug(f"--- Starting Receiver Loop Iteration {segment_counter} ---")
        fin_processed_this_iteration = False
        timed_out_this_iteration = False

        # Create a new receiver instance with fresh state for this iteration
        # Pass the update_signal and stop_event down to the instance
        stego = SteganographyReceiver(probe_id_expected, response_id, session_paths, key, update_signal, stop_event) # Pass event

        # Shared state for this iteration (monitor thread and packet handler)
        shared_state = {
            'last_activity_time': time.time(), # Initialize for monitor start
            'stop_due_to_timeout': False
        }

        monitor_thread = None
        # stop_monitor_event = threading.Event() # Removed, use main stop_event

        try:
            # --- Phase 1: Discovery (No Timeout) ---
            log_debug(f"Iteration {segment_counter}: Phase 1: Sender Discovery")
            print(f"\n[DISCOVERY] Listening indefinitely for sender probe on TCP/{DISCOVERY_PORT}... Iteration: {segment_counter}")
            print(f"Press Ctrl+C to stop.")
            try:
                sniff(
                    iface=interface,
                    filter=f"tcp and dst port {DISCOVERY_PORT}",
                    prn=stego.process_discovery_probe,
                    store=0,
                    stop_filter=lambda p: stego.discovery_probe_processed or stopped_externally or (stop_event and stop_event.is_set()) # Check event
                )
            except KeyboardInterrupt:
                 log_debug("Discovery stopped by user (Ctrl+C).")
                 print("\nDiscovery stopped by user.")
                 stopped_externally = True
                 continue # Go to outer finally block
            except Exception as e:
                log_debug(f"Error during discovery sniffing: {e}")
                print(f"\n[ERROR] An error occurred during discovery listening: {e}")
                stopped_externally = True # Treat discovery error as fatal
                continue # Go to outer finally block

            # Check if stopped after discovery sniff
            if stop_event and stop_event.is_set():
                log_debug("Exiting loop due to external stop event after discovery.")
                stopped_externally = True # Signal outer loop to stop cleanly
                continue

            # If sniff stopped due to Ctrl+C before probe was processed
            if not stego.discovery_probe_processed and stopped_externally:
                 log_debug("Exiting loop due to external stop during discovery (Ctrl+C).")
                 continue # Go to outer finally block

            # If sniff finished but no probe was processed (should only happen on error/Ctrl+C now)
            if not stego.discovery_probe_processed:
                 log_debug("Discovery sniff ended unexpectedly without processing a probe. Exiting.")
                 print("\n[ERROR] Discovery ended unexpectedly. Exiting.")
                 stopped_externally = True # Treat as fatal
                 continue # Go to outer finally block

            # --- Phase 2: Main Listening Loop (with Inactivity Timeout) ---
            log_debug(f"Discovery successful. Sender identified: {stego.discovery_sender_ip}:{stego.discovery_sender_port}")
            log_debug(f"Iteration {segment_counter}: Phase 2: Listening for Connection/Data from {stego.discovery_sender_ip}")
            print(f"\n[INFO] Sender discovered at {stego.discovery_sender_ip}. Now listening for connection and data (Inactivity timeout: {timeout}s)...")

            # Start inactivity monitor thread using the main stop_event
            shared_state['last_activity_time'] = time.time() # Reset timer before starting monitor
            monitor_thread = threading.Thread(target=monitor_inactivity, args=(stop_event, timeout, shared_state)) # Use main stop_event
            monitor_thread.daemon = True
            monitor_thread.start()
            log_debug("Started inactivity monitor thread.")

            # Packet handler wrapper
            def packet_counter_handler(packet):
                nonlocal packet_counter, valid_packet_counter
                packet_counter += 1
                # Pass shared state to update last_activity_time
                processed_fin = stego.process_packet(packet, shared_state)
                if processed_fin:
                    nonlocal fin_processed_this_iteration
                    fin_processed_this_iteration = True # Set flag for stop_filter

                if stego.connection_established and TCP in packet and packet[TCP].flags & 0x02 and packet[TCP].window > 0:
                     valid_packet_counter += 1

                if packet_counter <= 10 or packet_counter % RECEIVER_STATUS_PRINT_INTERVAL == 0:
                     print(f"[SCAN] Total Pkts: {packet_counter:06d} | Valid Pkts: {valid_packet_counter:06d} | Current Segment Chunks: {len(stego.received_chunks):04d}", end='\r', flush=True)
                return None

            # Inner sniffing loop - stops on FIN, Ctrl+C, error, or timeout
            try:
                filter_str = f"tcp and src host {stego.discovery_sender_ip}"
                log_debug(f"Using main sniffing filter: '{filter_str}'")
                sniff(
                    iface=interface,
                    filter=filter_str,
                    prn=packet_counter_handler,
                    store=0,
                    # Stop if FIN processed OR external stop OR timeout signaled OR stop_event set
                    stop_filter=lambda p: fin_processed_this_iteration or stopped_externally or shared_state['stop_due_to_timeout'] or (stop_event and stop_event.is_set()) # Check event
                )
            except KeyboardInterrupt:
                log_debug("Receiving stopped by user (Ctrl+C).")
                print("\nReceiving stopped by user.")
                stopped_externally = True # Signal outer loop to stop
            except Exception as e:
                 log_debug(f"Error during main sniffing loop: {e}")
                 print(f"\n[ERROR] Sniffing loop failed: {e}")
                 # Don't set stopped_externally, allow outer loop to continue after stopping monitor
            finally:
                log_debug(f"Inner sniffing loop for iteration {segment_counter} ended.")
                # Stop the monitor thread cleanly (it uses the main stop_event now, so just join)
                # stop_monitor_event.set() # Removed
                if monitor_thread and monitor_thread.is_alive():
                    log_debug("Waiting for monitor thread to stop...")
                    monitor_thread.join(1.0) # Wait briefly
                    if monitor_thread.is_alive():
                         log_debug("Monitor thread did not stop quickly.")

                # Determine why the loop stopped *after* stopping the monitor
                if stop_event and stop_event.is_set():
                    log_debug("Inner loop stopped due to external stop event.")
                    stopped_externally = True # Ensure outer loop stops
                elif shared_state['stop_due_to_timeout']:
                    timed_out_this_iteration = True
                    log_debug("Inner loop stopped due to inactivity timeout.")
                    # Message already printed by monitor thread
                elif fin_processed_this_iteration:
                    log_debug("Inner loop stopped because FIN was processed.")
                elif stopped_externally: # This now only means Ctrl+C
                    log_debug("Inner loop stopped due to external signal (Ctrl+C).")
                else:
                    # This case handles errors caught by the inner try/except or other unexpected stops
                    log_debug("Inner loop stopped due to error or unknown reason. Restarting discovery.")
                    print("\n[WARN] Data reception stopped unexpectedly. Restarting discovery...")

        except Exception as outer_e:
            # Catch errors happening before the inner loop (e.g., instance creation)
            print(f"\n[FATAL ERROR] An unexpected error occurred in outer loop: {outer_e}")
            traceback.print_exc()
            log_debug(f"FATAL ERROR in outer loop: {outer_e}\n{traceback.format_exc()}")
            stopped_externally = True # Exit outer loop

        # Cleanly stop monitor if outer loop exception occurred before stopping it
        finally: # This finally is for the outer try block
             # Monitor uses main stop_event, just ensure thread is joined if it was started
             if monitor_thread and monitor_thread.is_alive():
                  log_debug("Ensuring monitor thread is joined after outer loop exception/completion.")
                  monitor_thread.join(0.5)


    # --- Post-Outer-Loop Cleanup / Final Stats ---
    print("\n" + "="*20 + " Receiver Stopped " + "="*20)
    session_end_time = time.time()
    total_session_duration = session_end_time - session_start_time

    print(f"\nOverall Session Summary:")
    print(f"- Total Run Duration: ~{total_session_duration:.2f}s")
    print(f"- Processed {segment_counter} discovery/listening iteration(s).")
    print(f"- Processed {packet_counter} packets total.")
    print(f"- Identified {valid_packet_counter} potential valid data packets.")

    print(f"\n[INFO] Session logs and potentially saved data segments are in: {session_paths['session_dir']}")
    latest_link_path = os.path.join(os.path.dirname(session_paths['session_dir']), "receiver_latest")
    print(f"[INFO] Latest session link: {latest_link_path}")
    log_debug(f"--- Receiver Core Logic Stopped ---")

    # Determine success based on how it stopped
    if stopped_externally and not (stop_event and stop_event.is_set()): # Stopped by Ctrl+C
        log_debug(f"Receiver logic finished due to Ctrl+C after {segment_counter} segments. Returning True.")
        return segment_counter > 0 # True if at least one segment started/finished
    else: # Stopped by event, timeout, or error
        log_debug(f"Receiver logic finished due to stop_event, timeout, or error. Returning False.")
        return False
