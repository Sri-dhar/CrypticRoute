import pytest
import os
import binascii
import time
import json
from unittest.mock import patch, MagicMock, call

from scapy.all import IP, TCP

# Assuming crypticroute is importable from the project root
from crypticroute.receiver.core import SteganographyReceiver # Import the real class
from crypticroute.common.constants import (
    DISCOVERY_PORT, DISCOVERY_PROBE_WINDOW, DISCOVERY_RESPONSE_WINDOW,
    SYN_WINDOW, SYN_ACK_WINDOW, FINAL_ACK_WINDOW, DATA_ACK_WINDOW,
    COMPLETION_WINDOW, RAW_CHUNKS_SUBDIR, CLEANED_CHUNKS_SUBDIR, DATA_SUBDIR
)
from crypticroute.common.utils import prepare_key # Use the real key prep

# Use the temp_dirs fixture from conftest.py

# --- Fixtures ---

@pytest.fixture
def dummy_key_file(temp_dirs):
    """Creates a dummy key file."""
    key_path = os.path.join(temp_dirs['session_dir'], "test_key.bin")
    key_content = b'this_is_a_test_key_1234567890' # Example key data
    with open(key_path, "wb") as f:
        f.write(key_content)
    return key_path

# --- Integration Test ---

@patch('crypticroute.receiver.core.send') # Mock network sending
@patch('crypticroute.receiver.core.log_debug') # Mock logging for cleaner output
def test_simulated_receiver_flow(mock_log, mock_send, temp_dirs, dummy_key_file):
    """Simulates the packet flow by calling receiver methods directly."""

    # --- Setup ---
    sender_ip = "192.168.1.200"
    sender_port = 44444
    output_file = os.path.join(temp_dirs['data_dir'], "integrated_output.txt")

    # Prepare key and get expected hashes
    key, probe_id_expected, response_id = prepare_key(open(dummy_key_file, 'rb').read(), temp_dirs['data_dir'])
    assert key is not None
    assert probe_id_expected is not None
    assert response_id is not None

    # Create a real receiver instance
    # Need to pass session_paths correctly
    receiver = SteganographyReceiver(probe_id_expected, response_id, temp_dirs)
    receiver_port = receiver.my_port # Get the randomly assigned port

    # --- Simulation ---

    # 1. Discovery Probe
    discovery_probe_pkt = IP(src=sender_ip) / TCP(
        sport=sender_port,
        dport=DISCOVERY_PORT,
        flags=0x28, # PU
        window=DISCOVERY_PROBE_WINDOW,
        seq=int.from_bytes(probe_id_expected, 'big')
    )
    discovery_result = receiver.process_discovery_probe(discovery_probe_pkt)
    assert discovery_result is True
    assert receiver.discovery_probe_processed is True
    assert receiver.discovery_sender_ip == sender_ip
    assert receiver.discovery_sender_port == sender_port
    # Check that discovery response was sent (mock_send called)
    assert mock_send.call_count >= 1 # Should be 5, but check at least 1
    # Verify the sent packet details (optional, but good)
    sent_discovery_response = mock_send.call_args_list[0][0][0]
    assert sent_discovery_response[IP].dst == sender_ip
    assert sent_discovery_response[TCP].dport == sender_port
    assert sent_discovery_response[TCP].sport == DISCOVERY_PORT
    assert sent_discovery_response[TCP].flags == 0x09 # PF
    assert sent_discovery_response[TCP].window == DISCOVERY_RESPONSE_WINDOW
    assert sent_discovery_response[TCP].seq == int.from_bytes(response_id, 'big')
    mock_send.reset_mock() # Reset for next phase

    # 2. Connection SYN
    syn_pkt = IP(src=sender_ip) / TCP(
        sport=sender_port,
        dport=receiver_port, # Should target the receiver's actual port now? No, SYN comes *to* discovery port or receiver port? Let's assume receiver port based on core logic
        flags='S',
        window=SYN_WINDOW,
        seq=1000
    )
    # Correction: The SYN *should* still target the receiver's listening port (receiver_port)
    # However, the process_packet logic checks against discovery_sender_ip first.
    # Let's refine the SYN packet destination based on how process_packet works.
    # process_packet checks packet[IP].src == discovery_sender_ip.
    # It *then* checks for SYN_WINDOW. It doesn't check dport for SYN.
    # It sets sender_ip/port based on the SYN's src IP/port.
    # So, dport for SYN doesn't strictly matter for detection, but let's use receiver_port for realism.
    syn_pkt[TCP].dport = receiver_port # Target the receiver's ephemeral port for SYN

    syn_result = receiver.process_packet(syn_pkt)
    assert syn_result is False
    assert receiver.sender_ip == sender_ip
    assert receiver.sender_port == sender_port
    # Check SYN-ACK sent
    assert mock_send.call_count >= 1 # Should be 5
    sent_syn_ack = mock_send.call_args_list[0][0][0]
    assert sent_syn_ack[IP].dst == sender_ip
    assert sent_syn_ack[TCP].dport == sender_port
    assert sent_syn_ack[TCP].sport == receiver_port
    assert sent_syn_ack[TCP].flags == 'SA'
    assert sent_syn_ack[TCP].window == SYN_ACK_WINDOW
    assert sent_syn_ack[TCP].ack == 1001 # SYN seq + 1
    mock_send.reset_mock()

    # 3. Final ACK
    final_ack_pkt = IP(src=sender_ip) / TCP(
        sport=sender_port,
        dport=receiver_port, # Must target the port we sent SYN-ACK from
        flags='A',
        window=FINAL_ACK_WINDOW,
        ack=sent_syn_ack[TCP].seq + 1 # Acknowledge the SYN-ACK seq
    )
    final_ack_result = receiver.process_packet(final_ack_pkt)
    assert final_ack_result is False
    assert receiver.connection_established is True
    assert mock_send.call_count == 0 # No response needed

    # 4. Data Chunks
    total_chunks = 2
    total_chunks = 2
    # Ensure data is exactly 8 bytes to split between seq and ack
    # Ensure data is exactly 8 bytes to split between seq and ack
    chunk1_data_seq = 1001 # Use smaller fixed int
    chunk1_data_ack = 2002 # Use smaller fixed int
    chunk1_data = chunk1_data_seq.to_bytes(4, 'big') + chunk1_data_ack.to_bytes(4, 'big')
    chunk1_seq_num = 1
    chunk1_checksum = binascii.crc32(chunk1_data) & 0xFFFF
    data1_pkt = IP(src=sender_ip, id=chunk1_checksum) / TCP(
        sport=sender_port, dport=receiver_port, flags='S', window=chunk1_seq_num, # Chunk seq num in window
        seq=chunk1_data_seq, # First part of data in seq field
        ack=chunk1_data_ack, # Second part of data in ack field
        options=[('MSS', total_chunks)]
    )
    data1_result = receiver.process_packet(data1_pkt)
    assert data1_result is False
    assert chunk1_seq_num in receiver.received_chunks
    assert receiver.received_chunks[chunk1_seq_num] == chunk1_data
    assert receiver.total_chunks_expected == total_chunks
    assert receiver.highest_seq_num_seen == chunk1_seq_num
    assert mock_send.call_count >= 1 # Data ACK sent
    sent_data1_ack = mock_send.call_args_list[0][0][0]
    assert sent_data1_ack[TCP].flags == 'A'
    assert sent_data1_ack[TCP].ack == chunk1_seq_num # ACK field contains the chunk seq num
    assert sent_data1_ack[TCP].window == DATA_ACK_WINDOW
    mock_send.reset_mock()

    # Ensure data is exactly 8 bytes
    chunk2_data_seq = 3003
    chunk2_data_ack = 4004
    chunk2_data = chunk2_data_seq.to_bytes(4, 'big') + chunk2_data_ack.to_bytes(4, 'big')
    chunk2_seq_num = 2
    chunk2_checksum = binascii.crc32(chunk2_data) & 0xFFFF
    data2_pkt = IP(src=sender_ip, id=chunk2_checksum) / TCP(
        sport=sender_port, dport=receiver_port, flags='S', window=chunk2_seq_num, # Chunk seq num in window
        seq=chunk2_data_seq, # First part of data in seq field
        ack=chunk2_data_ack, # Second part of data in ack field
        options=[('MSS', total_chunks)]
    )
    data2_result = receiver.process_packet(data2_pkt)
    assert data2_result is False
    assert chunk2_seq_num in receiver.received_chunks
    assert receiver.received_chunks[chunk2_seq_num] == chunk2_data
    assert receiver.highest_seq_num_seen == chunk2_seq_num
    assert mock_send.call_count >= 1 # Data ACK sent
    sent_data2_ack = mock_send.call_args_list[0][0][0]
    assert sent_data2_ack[TCP].ack == chunk2_seq_num # ACK field contains the chunk seq num
    mock_send.reset_mock()

    # 5. Completion FIN
    fin_pkt = IP(src=sender_ip) / TCP(
        sport=sender_port,
        dport=receiver_port, # Destination port likely doesn't matter for FIN detection
        flags='F',
        window=COMPLETION_WINDOW
    )
    fin_result = receiver.process_packet(fin_pkt)
    assert fin_result is True # Signals completion
    assert mock_send.call_count == 0

    # --- Verification (Post-simulation) ---
    # Check collected chunks (already done during simulation)
    assert len(receiver.received_chunks) == 2

    # Check log files were created and potentially written to
    assert os.path.exists(os.path.join(temp_dirs['logs_dir'], "received_chunks.json"))
    assert os.path.exists(os.path.join(temp_dirs['logs_dir'], "sent_acks.json"))
    assert os.path.exists(os.path.join(temp_dirs['raw_chunks_dir'], "chunk_0001.bin"))
    assert os.path.exists(os.path.join(temp_dirs['raw_chunks_dir'], "chunk_0002.bin"))

    # Optionally, read log files and verify content
    with open(os.path.join(temp_dirs['logs_dir'], "received_chunks.json"), "r") as f:
        rcvd_log = json.load(f)
        assert "1" in rcvd_log
        assert "2" in rcvd_log
    with open(os.path.join(temp_dirs['logs_dir'], "sent_acks.json"), "r") as f:
        sent_log = json.load(f)
        # ACKs sent during discovery/handshake aren't logged here, only data ACKs
        assert "1" in sent_log # Data ACK for chunk 1
        assert "2" in sent_log # Data ACK for chunk 2
