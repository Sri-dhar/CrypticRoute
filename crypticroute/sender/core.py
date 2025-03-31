import sys
import os
import time
import random
import hashlib
import json
import binascii
import threading
from scapy.all import IP, TCP, send, sniff, conf

# Internal imports
from ..common.utils import log_debug, read_file, prepare_key, encrypt_data, chunk_data
from ..common.network import get_broadcast_address
from ..common.constants import (
    MAX_CHUNK_SIZE, DISCOVERY_PORT, DISCOVERY_PROBE_WINDOW,
    DISCOVERY_RESPONSE_WINDOW, SYN_WINDOW, SYN_ACK_WINDOW, FINAL_ACK_WINDOW,
    DATA_ACK_WINDOW, COMPLETION_WINDOW, IV_SIZE, INTEGRITY_CHECK_SIZE
)

# Configure Scapy settings
conf.verb = 0

class SteganographySender:
    """Handles the core sending logic including discovery, handshake, and data transfer."""

    def __init__(self, broadcast_ip, source_port, key_probe_id, key_response_id, session_paths, ack_timeout, max_retries):
        """Initialize the sender state."""
        self.broadcast_ip = broadcast_ip
        self.source_port = source_port
        self.sender_key_hash_probe = key_probe_id
        self.sender_key_hash_response_expected = key_response_id
        self.session_paths = session_paths
        self.ack_timeout = ack_timeout
        self.max_retries = max_retries

        # State variables (previously globals)
        self.target_ip = None
        self.receiver_port = None # Port receiver responds *from* during discovery/handshake
        self.discovery_complete = False
        self.connection_established = False
        self.acked_chunks = set()
        self.waiting_for_ack = False
        self.current_chunk_seq = 0
        self.stop_sniffing_event = threading.Event() # Unified stop event

        # Listener threads
        self.discovery_listener_thread = None
        self.ack_listener_thread = None

        # Debug logging setup
        self.chunks_json_path = os.path.join(session_paths['logs_dir'], "sent_chunks.json")
        self.acks_json_path = os.path.join(session_paths['logs_dir'], "received_acks.json")
        self.sent_chunks_log = {} # In-memory log for JSON dump
        self.received_acks_log = {} # In-memory log for JSON dump

        # Create the log files immediately
        try:
            with open(self.chunks_json_path, "w") as f: json.dump({}, f)
            with open(self.acks_json_path, "w") as f: json.dump({}, f)
        except IOError as e:
            log_debug(f"Error creating initial sender log files: {e}")

    # --- Logging Methods ---
    def _log_sent_chunk(self, seq_num, data):
        """Save chunk data to debug file."""
        self.sent_chunks_log[str(seq_num)] = {
            "data_hex": data.hex(),
            "size": len(data),
            "timestamp": time.time()
        }
        try:
            with open(self.chunks_json_path, "w") as f:
                json.dump(self.sent_chunks_log, f, indent=2)
        except IOError as e:
            log_debug(f"Error writing sent chunks log: {e}")

        # Also save the raw chunk data
        chunk_file = os.path.join(self.session_paths['chunks_dir'], f"chunk_{seq_num:04d}.bin")
        try:
            with open(chunk_file, "wb") as f:
                f.write(data)
        except IOError as e:
             log_debug(f"Error writing chunk file {chunk_file}: {e}")

    def _log_received_ack(self, seq_num):
        """Save received ACK to debug file."""
        self.received_acks_log[str(seq_num)] = {
            "timestamp": time.time()
        }
        try:
            with open(self.acks_json_path, "w") as f:
                json.dump(self.received_acks_log, f, indent=2)
        except IOError as e:
             log_debug(f"Error writing received ACKs log: {e}")

    # --- Discovery Methods ---
    def start_discovery_listener(self):
        """Start a thread to listen for discovery response packets."""
        if self.discovery_listener_thread and self.discovery_listener_thread.is_alive():
            log_debug("Discovery listener already running.")
            return
        self.discovery_listener_thread = threading.Thread(
            target=self._discovery_listener_thread_func, daemon=True
        )
        self.stop_sniffing_event.clear() # Ensure stop flag is clear
        self.discovery_listener_thread.start()
        log_debug("Started Discovery Response listener thread")
        print("[THREAD] Started Discovery Response listener thread")

    def _discovery_listener_thread_func(self):
        """Thread function to listen for discovery response packets."""
        log_debug("Discovery Response listener thread started")
        filter_str = f"tcp and dst port {self.source_port}"
        log_debug(f"Sniffing for Discovery Response with filter: {filter_str}")
        try:
            sniff(
                filter=filter_str,
                prn=self._process_discovery_response,
                store=0,
                stop_filter=lambda p: self.stop_sniffing_event.is_set()
            )
        except Exception as e:
            log_debug(f"Error in Discovery Response listener thread: {e}")
            print(f"\n[ERROR] Discovery listener thread error: {e}")
        finally:
             log_debug("Discovery Response listener thread stopped")

    def _process_discovery_response(self, packet):
        """Process a received packet to check if it's our discovery response."""
        if self.discovery_complete: return # Already found

        # Check for expected discovery response signature (PSH-FIN, Window 0xCAFE, correct key hash)
        if IP in packet and TCP in packet and packet[TCP].flags & 0x09 == 0x09 and packet[TCP].window == DISCOVERY_RESPONSE_WINDOW:
            response_hash_received = packet[TCP].seq.to_bytes(4, 'big')
            log_debug(f"Received potential discovery response from {packet[IP].src}:{packet[TCP].sport}")
            log_debug(f"  Flags={packet[TCP].flags}, Window={packet[TCP].window:#x}, SeqHash={response_hash_received.hex()}")

            if response_hash_received == self.sender_key_hash_response_expected:
                log_debug(f"Valid Discovery Response received from {packet[IP].src}:{packet[TCP].sport}")
                print(f"\n[DISCOVERY] Valid response received from {packet[IP].src}")
                print(f"[IP_EXCHANGE] Receiver IP discovered: {packet[IP].src}")

                self.target_ip = packet[IP].src
                self.receiver_port = packet[TCP].sport # Port they responded *from*
                self.discovery_complete = True
                self.stop_sniffing_event.set() # Signal listener thread to stop
                return # Packet processed and matched
        return # Packet wasn't the expected discovery response

    def send_discovery_probe(self):
        """Sends a discovery probe packet using broadcast IP."""
        probe_packet = IP(dst=self.broadcast_ip) / TCP(
            sport=self.source_port,
            dport=DISCOVERY_PORT,
            flags="PU", # PSH | URG
            window=DISCOVERY_PROBE_WINDOW,
            seq=int.from_bytes(self.sender_key_hash_probe, 'big')
        )
        log_debug(f"Sending Discovery Probe to {self.broadcast_ip}:{DISCOVERY_PORT} with Seq={probe_packet[TCP].seq:#x}")
        send(probe_packet)

    # --- ACK Listener Methods ---
    def start_ack_listener(self):
        """Start a thread to listen for ACK packets (only after discovery)."""
        if not self.target_ip:
            log_debug("Cannot start ACK listener: Receiver IP not discovered yet.")
            print("[ERROR] Cannot start ACK listener without discovered receiver.")
            return False

        if self.ack_listener_thread and self.ack_listener_thread.is_alive():
            log_debug("ACK listener already running.")
            return True

        self.ack_listener_thread = threading.Thread(
            target=self._ack_listener_thread_func, daemon=True
        )
        self.stop_sniffing_event.clear() # Ensure stop flag is clear for this listener
        self.ack_listener_thread.start()
        log_debug("Started ACK listener thread")
        print("[THREAD] Started ACK listener thread")
        return True

    def stop_listener_threads(self):
        """Stop all running listener threads."""
        log_debug("Signalling listener threads to stop...")
        self.stop_sniffing_event.set()
        time.sleep(0.1) # Give threads a moment to see the event

        if self.discovery_listener_thread and self.discovery_listener_thread.is_alive():
            log_debug("Joining discovery listener thread...")
            self.discovery_listener_thread.join(1.0)
            if self.discovery_listener_thread.is_alive():
                log_debug("Warning: Discovery listener thread did not exit cleanly.")
            else:
                log_debug("Discovery listener thread stopped.")
            self.discovery_listener_thread = None

        if self.ack_listener_thread and self.ack_listener_thread.is_alive():
            log_debug("Joining ACK listener thread...")
            self.ack_listener_thread.join(1.0)
            if self.ack_listener_thread.is_alive():
                log_debug("Warning: ACK listener thread did not exit cleanly.")
            else:
                log_debug("ACK listener thread stopped.")
            self.ack_listener_thread = None
        log_debug("Finished stopping listener threads.")


    def _ack_listener_thread_func(self):
        """Thread function to listen for and process ACK packets."""
        if not self.target_ip:
            log_debug("ACK listener thread exiting: Target IP is not set.")
            return

        log_debug("ACK listener thread started")
        filter_str = f"tcp and src host {self.target_ip} and dst port {self.source_port}"
        log_debug(f"Sniffing for ACKs with filter: {filter_str}")

        try:
            sniff(
                filter=filter_str,
                prn=self._process_ack_packet,
                store=0,
                stop_filter=lambda p: self.stop_sniffing_event.is_set()
            )
        except Exception as e:
            log_debug(f"Error in ACK listener thread: {e}")
            print(f"[ERROR] ACK listener thread: {e}")
        finally:
            log_debug("ACK listener thread stopped")

    def _process_ack_packet(self, packet):
        """Process a received ACK/SYN-ACK packet from the discovered receiver."""
        # Check if it's a valid TCP packet from the *expected* discovered IP
        if IP in packet and TCP in packet and packet[IP].src == self.target_ip:

            # --- SYN-ACK Handling ---
            # Check for SYN-ACK packet (SYN(0x02) + ACK(0x10) = 0x12, Window 0xBEEF)
            if not self.connection_established and packet[TCP].flags & 0x12 == 0x12 and packet[TCP].window == SYN_ACK_WINDOW:
                log_debug(f"Received SYN-ACK for connection establishment from {packet[IP].src}:{packet[TCP].sport}")
                print(f"[HANDSHAKE] Received SYN-ACK response from {packet[IP].src}:{packet[TCP].sport}")
                print(f"[IP_EXCHANGE] Confirmed connection with {packet[IP].src}:{packet[TCP].sport}")

                # IMPORTANT: Update receiver_port to the source port of *this* SYN-ACK packet.
                new_receiver_port = packet[TCP].sport
                if self.receiver_port != new_receiver_port:
                     log_debug(f"Receiver port updated from {self.receiver_port} (discovery) to {new_receiver_port} (handshake) based on SYN-ACK")
                     print(f"[INFO] Receiver handshake port: {new_receiver_port}")
                     self.receiver_port = new_receiver_port # Update instance variable

                # Send final ACK to complete handshake
                ack_packet = self._create_final_ack_packet(packet[TCP].seq) # Pass SYN-ACK seq
                if ack_packet:
                    log_debug(f"Sending final ACK (ack={ack_packet[TCP].ack:#x}) to complete handshake")
                    print(f"[HANDSHAKE] Sending final ACK")
                    for _ in range(5): # Send multiple times for reliability
                        send(ack_packet)
                        time.sleep(0.1)
                    self.connection_established = True # Mark connection established *after* sending final ACK
                    print(f"[HANDSHAKE] Connection established")
                return # Packet processed

            # --- Data ACK Handling ---
            # Check for data chunk ACK (Flags ACK(0x10), Window 0xCAFE)
            # Only process if connection is already established
            if self.connection_established and packet[TCP].flags & 0x10 and packet[TCP].window == DATA_ACK_WINDOW:
                seq_num = packet[TCP].ack # Sequence number is in the ack field

                log_debug(f"Received ACK for chunk {seq_num} from {packet[IP].src}:{packet[TCP].sport}")
                self._log_received_ack(seq_num)
                self.acked_chunks.add(seq_num)

                # If this is the chunk we're currently waiting for, clear the wait flag
                if self.waiting_for_ack and seq_num == self.current_chunk_seq:
                    log_debug(f"Chunk {seq_num} acknowledged")
                    print(f"[ACK] Received acknowledgment for chunk {seq_num}")
                    print(f"[CONFIRMED] Chunk {seq_num} successfully delivered")
                    self.waiting_for_ack = False
                return # Packet processed
        return # Packet not from target or doesn't match

    # --- Packet Creation Methods ---
    def _create_syn_packet(self):
        """Create a SYN packet for connection establishment to discovered receiver."""
        if not self.target_ip or self.receiver_port is None:
            log_debug("Cannot create SYN: Receiver IP or discovery port missing.")
            return None
        syn_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=self.receiver_port, # Send SYN to the port they responded on
            seq=random.randint(0, 0xFFFFFFFF), # Use random initial sequence number
            window=SYN_WINDOW,
            flags="S"
        )
        log_debug(f"Created SYN packet: Target={self.target_ip}:{self.receiver_port}, Seq={syn_packet[TCP].seq:#x}")
        return syn_packet

    def _create_final_ack_packet(self, syn_ack_seq):
        """Create an ACK packet to complete connection establishment."""
        if not self.target_ip or self.receiver_port is None:
            log_debug("Cannot create final ACK - receiver information missing")
            return None
        ack_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=self.receiver_port, # Use the potentially updated receiver_port
            seq=random.randint(0, 0xFFFFFFFF), # Can be anything, but let's make it random
            ack=syn_ack_seq + 1, # Acknowledge the received SYN-ACK sequence number + 1
            window=FINAL_ACK_WINDOW,
            flags="A"
        )
        log_debug(f"Created Final ACK packet: Target={self.target_ip}:{self.receiver_port}, Ack={ack_packet[TCP].ack:#x}")
        return ack_packet

    def _create_data_packet(self, data, seq_num, total_chunks):
        """Create a TCP packet with embedded data."""
        if not self.target_ip:
            log_debug("Cannot create data packet: Receiver IP not set.")
            return None

        # Ensure data is exactly MAX_CHUNK_SIZE bytes
        if len(data) < MAX_CHUNK_SIZE:
            data = data.ljust(MAX_CHUNK_SIZE, b'\0')
        elif len(data) > MAX_CHUNK_SIZE:
            data = data[:MAX_CHUNK_SIZE]

        dst_port = random.randint(10000, 60000) # Use random destination port

        # Embed data in sequence and ack numbers, seq_num in window
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=dst_port,
            seq=int.from_bytes(data[0:4], byteorder='big'),
            ack=int.from_bytes(data[4:8], byteorder='big'),
            window=seq_num,
            flags="S", # SYN flag used for data packets in original design
            options=[('MSS', total_chunks)] # Store total chunks in MSS option
        )

        # Store checksum in IP ID field
        checksum = binascii.crc32(data) & 0xFFFF
        tcp_packet[IP].id = checksum
        # log_debug(f"Created Data packet: SeqNum={seq_num}, Target={self.target_ip}:{dst_port}, TCP_Seq={tcp_packet[TCP].seq:#x}, TCP_Ack={tcp_packet[TCP].ack:#x}, IP_ID={checksum:#x}")
        return tcp_packet

    def _create_completion_packet(self):
        """Create a packet signaling transmission completion."""
        if not self.target_ip:
            log_debug("Cannot create completion packet: Receiver IP not set.")
            return None
        tcp_packet = IP(dst=self.target_ip) / TCP(
            sport=self.source_port,
            dport=random.randint(10000, 60000),
            window=COMPLETION_WINDOW,
            flags="F" # FIN packet signals completion
        )
        log_debug(f"Created Completion packet: Target={self.target_ip}")
        return tcp_packet

    # --- Send Chunk Method ---
    def send_chunk_with_ack(self, data, seq_num, total_chunks):
        """Send a data chunk with acknowledgment and retransmission."""
        if not self.target_ip:
             log_debug("Cannot send chunk: Receiver IP not set.")
             return False

        if seq_num in self.acked_chunks:
            # log_debug(f"Chunk {seq_num} already acknowledged, skipping") # Can be noisy
            return True

        packet = self._create_data_packet(data, seq_num, total_chunks)
        if not packet:
            log_debug(f"Failed to create packet for chunk {seq_num}")
            return False

        self._log_sent_chunk(seq_num, data) # Log the chunk being sent

        self.current_chunk_seq = seq_num
        self.waiting_for_ack = True
        retransmit_count = 0

        log_debug(f"Sending chunk {seq_num}/{total_chunks} to {self.target_ip}")
        print(f"[SEND] Chunk: {seq_num:04d}/{total_chunks:04d} | Progress: {(seq_num / total_chunks) * 100:.2f}%", end='\r', flush=True)
        print(f"[PROGRESS] Sending chunk {seq_num}/{total_chunks} | Progress: {(seq_num / total_chunks) * 100:.1f}%")
        send(packet) # Initial transmission

        start_time = time.time()
        while self.waiting_for_ack and retransmit_count < self.max_retries:
            wait_start = time.time()
            while self.waiting_for_ack and (time.time() - wait_start) < self.ack_timeout:
                time.sleep(0.1) # Wait for ACK
                if not self.waiting_for_ack: break # ACK received

            if self.waiting_for_ack: # Timeout occurred
                retransmit_count += 1
                log_debug(f"Retransmitting chunk {seq_num} to {self.target_ip} (attempt {retransmit_count}/{self.max_retries})")
                print(f"[RETRANSMIT] Chunk {seq_num:04d} | Attempt: {retransmit_count}/{self.max_retries} | Progress: {(seq_num / total_chunks) * 100:.2f}%", end='\r', flush=True)
                print(f"[PACKET] Retransmitting chunk {seq_num} | {retransmit_count}/{self.max_retries}")
                send(packet)

        if self.waiting_for_ack: # Failed after all retries
            log_debug(f"Failed to get ACK for chunk {seq_num} after {self.max_retries} retransmissions")
            print(f"\n[WARNING] No ACK received for chunk {seq_num:04d} after {self.max_retries} attempts")
            self.waiting_for_ack = False # Reset for next chunk
            return False
        else: # Success
            elapsed = time.time() - start_time
            log_debug(f"Chunk {seq_num} acknowledged after {retransmit_count} retransmissions ({elapsed:.2f}s)")
            return True

# --- High-Level Workflow Functions ---

def discover_receiver(stego, timeout):
    """Broadcast probes and listen for a response."""
    log_debug("Starting receiver discovery...")
    print(f"[DISCOVERY] Broadcasting probes on {stego.broadcast_ip}:{DISCOVERY_PORT}...")
    print(f"[DISCOVERY] Waiting up to {timeout}s for a response...", end="", flush=True)

    stego.start_discovery_listener()
    start_time = time.time()
    probes_sent = 0
    last_probe_time = 0
    probe_interval = 1.0

    while not stego.discovery_complete and time.time() - start_time < timeout:
        current_time = time.time()
        if current_time - last_probe_time >= probe_interval:
             stego.send_discovery_probe()
             probes_sent += 1
             last_probe_time = current_time
             print(".", end="", flush=True)
        time.sleep(0.1) # Avoid busy-waiting

    # Stop the listener thread *after* the loop finishes or discovery is complete
    stego.stop_listener_threads() # Use the unified stop method

    if stego.discovery_complete:
        log_debug(f"Discovery successful after {time.time() - start_time:.2f}s. Probes sent: {probes_sent}. Receiver: {stego.target_ip}:{stego.receiver_port}")
        print(f"\n[DISCOVERY] Success! Found receiver at {stego.target_ip} (responded on port {stego.receiver_port})")
        return True
    else:
        log_debug(f"Discovery timed out after {timeout}s. Probes sent: {probes_sent}.")
        print("\n[DISCOVERY] Failed. No valid response received.")
        stego.target_ip = None # Ensure target_ip is None if discovery failed
        stego.receiver_port = None
        return False

def establish_connection(stego, timeout=20):
    """Establish connection with the discovered receiver using three-way handshake."""
    if not stego.target_ip or stego.receiver_port is None:
         log_debug("Cannot establish connection: Receiver not discovered or port missing.")
         print("[ERROR] Cannot establish connection - discovery must succeed first.")
         return False

    log_debug(f"Starting connection establishment with {stego.target_ip}:{stego.receiver_port}")
    print(f"[HANDSHAKE] Initiating connection with discovered receiver {stego.target_ip}...")
    print(f"[IP_EXCHANGE] Connecting to receiver at {stego.target_ip}:{stego.receiver_port}")

    # Start ACK listener thread (handles SYN-ACK and data ACKs)
    if not stego.start_ack_listener():
        log_debug("Failed to start ACK listener thread.")
        print("[ERROR] Failed to start ACK listener during connection setup.")
        return False

    # Send SYN packet to the *discovered* port
    syn_packet = stego._create_syn_packet()
    if not syn_packet:
        log_debug("Failed to create SYN packet.")
        stego.stop_listener_threads() # Clean up listener
        return False

    log_debug(f"Sending SYN packet to {stego.target_ip}:{stego.receiver_port}")
    print(f"[HANDSHAKE] Sending SYN packet to {stego.target_ip}:{stego.receiver_port}...")

    # Send SYN repeatedly and wait for connection_established flag (set by _process_ack_packet)
    start_time = time.time()
    syn_sends = 0
    syn_interval = 0.5
    max_syn_sends = 15

    while not stego.connection_established and time.time() - start_time < timeout:
        if syn_sends < max_syn_sends and (syn_sends < 5 or (time.time() - start_time) % syn_interval < 0.1):
            log_debug(f"Sending SYN ({syn_sends+1})")
            send(syn_packet)
            syn_sends += 1
            if syn_sends == 5: syn_interval = 1.5
        time.sleep(0.1)

    if stego.connection_established:
        log_debug("Connection established successfully (flag set by ACK listener)")
        # Success message printed within _process_ack_packet
        return True
    else:
        log_debug(f"Failed to establish connection (timeout: {timeout}s, SYN sends: {syn_sends})")
        print("\n[HANDSHAKE] Failed to establish connection with receiver (no SYN-ACK received or processed).")
        stego.stop_listener_threads() # Stop the ACK listener
        return False

def send_file_logic(file_path, interface, key_path, chunk_size, delay, ack_timeout, max_retries, discovery_timeout, session_paths):
    """Encapsulates the main logic for discovering, connecting, and sending a file."""
    log_debug("--- Sender Core Logic Start ---")
    overall_success = False # Track overall outcome

    # --- Phase 0: Preparation ---
    log_debug("Phase 0: Preparation")
    broadcast_ip = get_broadcast_address(interface)
    if not broadcast_ip:
        print("Error: Could not determine broadcast IP. Exiting.")
        return False # Critical failure

    log_debug(f"Using broadcast address: {broadcast_ip} (Interface: {interface or 'auto'})")

    # Prepare key and derive identifiers
    log_debug(f"Reading key from: {key_path}")
    print(f"[KEY] Reading key: {key_path}")
    key_data = read_file(key_path, 'rb')
    if not key_data: return False # read_file handles exit on error

    key, probe_id, response_id = prepare_key(key_data, session_paths['data_dir'])
    if not probe_id or not response_id:
         print("Error: Failed to derive discovery identifiers from key.")
         log_debug("Failed to derive key identifiers.")
         return False

    # Create sender instance
    stego = SteganographySender(
        broadcast_ip=broadcast_ip,
        source_port=random.randint(10000, 60000),
        key_probe_id=probe_id,
        key_response_id=response_id,
        session_paths=session_paths,
        ack_timeout=ack_timeout,
        max_retries=max_retries
    )

    try:
        # --- Phase 1: Discovery ---
        log_debug("Phase 1: Receiver Discovery")
        if not discover_receiver(stego, discovery_timeout):
            log_debug("Aborting transmission due to discovery failure")
            print("[ERROR] Aborting transmission - receiver not found.")
            return False

        # --- Phase 2: Connection Establishment ---
        log_debug("Phase 2: Connection Establishment")
        if not establish_connection(stego):
            log_debug("Aborting transmission due to connection failure")
            print("[ERROR] Aborting transmission - connection handshake failed.")
            # establish_connection stops listeners on failure
            return False

        # --- Phase 3: Data Preparation ---
        log_debug("Phase 3: Data Preparation")
        log_debug(f"Reading file: {file_path}")
        print(f"\n[FILE] Reading: {file_path}")
        file_data = read_file(file_path, 'rb')
        if not file_data: return False # read_file handles exit on error
        print(f"[FILE] Read {len(file_data)} bytes successfully")

        log_debug("Encrypting data...")
        print(f"[ENCRYPT] Starting encryption of {len(file_data)} bytes...")
        encrypted_data_with_iv = encrypt_data(file_data, key, session_paths['data_dir'])
        if encrypted_data_with_iv is None:
            print("[ERROR] Encryption failed.")
            return False
        log_debug(f"Data encrypted (IV prepended), total size: {len(encrypted_data_with_iv)} bytes")
        print(f"[ENCRYPT] Completed encryption. Result size (including IV): {len(encrypted_data_with_iv)} bytes")

        file_checksum = hashlib.md5(encrypted_data_with_iv).digest()
        log_debug(f"Generated MD5 checksum for (IV + encrypted data): {file_checksum.hex()}")
        print(f"[CHECKSUM] Generated MD5 for transmitted payload: {file_checksum.hex()}")
        payload_to_send = encrypted_data_with_iv + file_checksum

        # Save checksum and final payload package for debugging
        checksum_file = os.path.join(session_paths['data_dir'], "md5_checksum.bin")
        final_package_file = os.path.join(session_paths['data_dir'], "final_data_package.bin")
        try:
            with open(checksum_file, "wb") as f: f.write(file_checksum)
            with open(final_package_file, "wb") as f: f.write(payload_to_send)
        except IOError as e:
            log_debug(f"Error saving checksum/final package: {e}")

        print(f"[PREP] Splitting {len(payload_to_send)} bytes of payload into chunks of size {chunk_size}...")
        chunks = chunk_data(payload_to_send, chunk_size, session_paths['logs_dir'])
        total_chunks = len(chunks)
        if total_chunks == 0:
             print("[WARNING] No data chunks to send (file might be empty or encryption failed?).")
        else:
            log_debug(f"Payload split into {total_chunks} chunks")
            print(f"[PREP] Data split into {total_chunks} chunks")

        # --- Phase 4: Data Transmission ---
        log_debug("Phase 4: Data Transmission")
        transmission_successful_chunks = 0
        if total_chunks > 0:
            print(f"[TRANSMISSION] Starting data transmission to {stego.target_ip}:{stego.receiver_port}...")
            print(f"[INFO] Total chunks to send: {total_chunks}")

            for i, chunk_data_bytes in enumerate(chunks):
                seq_num = i + 1
                success = stego.send_chunk_with_ack(chunk_data_bytes, seq_num, total_chunks)
                if success:
                    transmission_successful_chunks += 1
                else:
                    # Optional: break here if strict reliability is needed?
                    log_debug(f"Failed to get ACK for chunk {seq_num}, continuing...")
                    # print(f"\n[ERROR] Failed to send chunk {seq_num}. Aborting.")
                    # break
                time.sleep(delay) # Add delay

            # Final status line
            final_progress = (transmission_successful_chunks / total_chunks) * 100 if total_chunks > 0 else 100.0
            status_char = "OK" if transmission_successful_chunks == total_chunks else "PARTIAL"
            print(f"[SEND] Completed: {transmission_successful_chunks:04d}/{total_chunks:04d} | Progress: {final_progress:.2f}% | Status: {status_char}   ")
            print(f"[PROGRESS] Completed {transmission_successful_chunks}/{total_chunks} chunks | Progress: {final_progress:.1f}%")
        else:
            print("[TRANSMISSION] No data chunks were generated. Skipping data sending phase.")
            transmission_successful_chunks = 0 # Ensure it's 0

        # --- Phase 5: Completion ---
        log_debug("Phase 5: Sending Completion Signal")
        completion_packet = stego._create_completion_packet()
        if completion_packet:
            print("[COMPLETE] Sending transmission completion signals...")
            for i in range(10):
                log_debug(f"Sending completion signal {i+1}/10 to {stego.target_ip}")
                send(completion_packet)
                time.sleep(0.2)
        else:
            log_debug("Could not create completion packet.")
            print("[WARNING] Could not send completion signal.")

        # Determine overall success based on ACKs
        overall_success = (total_chunks == 0 or transmission_successful_chunks == total_chunks)

    except KeyboardInterrupt:
        print("\n[ABORT] Keyboard interrupt received during core logic. Cleaning up...")
        log_debug("KeyboardInterrupt received in core logic.")
        overall_success = False
    except Exception as e:
        print(f"\n[FATAL ERROR] An unexpected error occurred in core logic: {e}")
        import traceback
        traceback.print_exc()
        log_debug(f"FATAL ERROR in core logic: {e}\n{traceback.format_exc()}")
        overall_success = False
    finally:
        # --- Phase 6: Cleanup ---
        log_debug("Phase 6: Cleanup")
        stego.stop_listener_threads() # Ensure listeners are stopped

        # Log final stats
        ack_rate = (len(stego.acked_chunks) / total_chunks) * 100 if total_chunks > 0 else 100.0
        final_status = "unknown"
        if overall_success:
            final_status = "completed_successfully"
        elif total_chunks > 0 and transmission_successful_chunks > 0:
             final_status = "completed_partially_acknowledged"
        elif stego.connection_established:
             final_status = "failed_during_transmission"
        elif stego.discovery_complete:
             final_status = "failed_during_handshake"
        else:
             final_status = "failed_during_discovery"


        log_debug(f"Transmission status: {final_status}")
        print(f"[STATS] Final ACK rate: {ack_rate:.2f}% ({len(stego.acked_chunks)}/{total_chunks} chunks acknowledged)")
        print(f"[COMPLETE] Sender process finished with status: {final_status}")

        # Save session completion info
        completion_info = {
            "session_end_time": time.time(),
            "total_chunks_generated": total_chunks,
            "chunks_acknowledged": len(stego.acked_chunks),
            "ack_rate_percent": round(ack_rate, 2),
            "final_status": final_status,
            "discovered_receiver_ip": stego.target_ip,
            "final_receiver_port": stego.receiver_port,
        }
        completion_path = os.path.join(session_paths['logs_dir'], "completion_info.json")
        try:
            with open(completion_path, "w") as f:
                json.dump(completion_info, f, indent=2)
        except IOError as e:
            log_debug(f"Error writing completion info: {e}")

        print(f"[INFO] All session data saved to: {session_paths['session_dir']}")
        latest_link_path = os.path.join(os.path.dirname(session_paths['session_dir']), "sender_latest") # Reconstruct link path
        print(f"[INFO] Latest session link: {latest_link_path}")
        log_debug(f"--- Sender Core Logic End (Success: {overall_success}) ---")

    return overall_success
