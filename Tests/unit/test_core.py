import pytest
import os
import json
import binascii
from unittest.mock import patch, MagicMock, mock_open, call
from scapy.all import IP, TCP, Ether # Import necessary Scapy layers

# Assuming crypticroute is importable from the project root
from crypticroute.receiver.core import reassemble_data, SteganographyReceiver, receive_file_logic
from crypticroute.common.constants import (
    DISCOVERY_PORT, DISCOVERY_PROBE_WINDOW, DISCOVERY_RESPONSE_WINDOW,
    SYN_WINDOW, SYN_ACK_WINDOW, FINAL_ACK_WINDOW, DATA_ACK_WINDOW,
    COMPLETION_WINDOW, RAW_CHUNKS_SUBDIR, CLEANED_CHUNKS_SUBDIR, DATA_SUBDIR
)
from crypticroute.common.utils import log_debug # Mock or capture log_debug if needed
import threading
import time

# --- Fixtures ---

# temp_dirs fixture is now in conftest.py

@pytest.fixture
def mock_receiver_instance(temp_dirs):
    """Creates a mocked SteganographyReceiver instance."""
    key_probe_id = b'\xde\xad\xbe\xef'
    key_response_id = b'\xca\xfe\xba\xbe'
    mock_session_paths = {
        'logs_dir': temp_dirs['logs_dir'],
        'chunks_dir': temp_dirs['chunks_dir'],
        'data_dir': temp_dirs['data_dir'],
        'session_dir': os.path.dirname(temp_dirs['logs_dir'])
    }
    # Use mock_open directly here as the fixture needs the instance
    # conftest fixture handles initial log file creation now.
    receiver = SteganographyReceiver(key_probe_id, key_response_id, mock_session_paths)

    receiver.sender_ip = "192.168.1.100"
    receiver.sender_port = 54321
    receiver.my_port = 12345
    receiver.connection_established = False
    return receiver, temp_dirs

# --- Tests for reassemble_data ---

def test_reassemble_data_empty(temp_dirs):
    data, missing = reassemble_data({}, 0, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data is None
    assert missing == 0
    # Fix 1: reassembly_info.json is NOT created when no chunks are received
    assert not os.path.exists(os.path.join(temp_dirs['logs_dir'], "reassembly_info.json"))

def test_reassemble_data_single_chunk(temp_dirs):
    chunks = {1: b"single_chunk"}
    data, missing = reassemble_data(chunks, 1, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data == b"single_chunk"
    assert missing == 0
    assert os.path.exists(os.path.join(temp_dirs['data_dir'], "reassembled_data.bin"))
    assert os.path.exists(os.path.join(temp_dirs['cleaned_chunks_dir'], "chunk_0001.bin"))
    with open(os.path.join(temp_dirs['cleaned_chunks_dir'], "chunk_0001.bin"), "rb") as f:
        assert f.read() == b"single_chunk"
    # Check reassembly info is created
    assert os.path.exists(os.path.join(temp_dirs['logs_dir'], "reassembly_info.json"))


def test_reassemble_data_multiple_chunks_ordered(temp_dirs):
    chunks = {1: b"part1", 2: b"part2", 3: b"part3"}
    data, missing = reassemble_data(chunks, 3, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data == b"part1part2part3"
    assert missing == 0
    assert os.path.exists(os.path.join(temp_dirs['logs_dir'], "reassembly_info.json"))

def test_reassemble_data_multiple_chunks_unordered(temp_dirs):
    chunks = {3: b"part3", 1: b"part1", 2: b"part2"}
    data, missing = reassemble_data(chunks, 3, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data == b"part1part2part3"
    assert missing == 0
    assert os.path.exists(os.path.join(temp_dirs['logs_dir'], "reassembly_info.json"))

def test_reassemble_data_missing_chunks_middle(temp_dirs):
    chunks = {1: b"part1", 3: b"part3"}
    data, missing = reassemble_data(chunks, 3, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data == b"part1part3"
    assert missing == 1
    reassembly_info_path = os.path.join(temp_dirs['logs_dir'], "reassembly_info.json")
    assert os.path.exists(reassembly_info_path)
    with open(reassembly_info_path, "r") as f:
        info = json.load(f)
        assert info["missing_chunk_count"] == 1
        assert info["missing_chunks_list"] == [2]

def test_reassemble_data_missing_chunks_end(temp_dirs):
    chunks = {1: b"part1", 2: b"part2"}
    data, missing = reassemble_data(chunks, 3, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data == b"part1part2"
    assert missing == 1
    reassembly_info_path = os.path.join(temp_dirs['logs_dir'], "reassembly_info.json")
    assert os.path.exists(reassembly_info_path)
    with open(reassembly_info_path, "r") as f:
        info = json.load(f)
        assert info["missing_chunk_count"] == 1
        assert info["missing_chunks_list"] == [3]

def test_reassemble_data_padding_removal(temp_dirs):
    chunks = {
        1: b"data1\0\0\0",
        2: b"data2",
        3: b"\0\0\0\0",
        4: b"data4\0\0\0\0"
    }
    data, missing = reassemble_data(chunks, 4, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    assert data == b"data1data2\0data4"
    assert missing == 0
    with open(os.path.join(temp_dirs['cleaned_chunks_dir'], "chunk_0001.bin"), "rb") as f: assert f.read() == b"data1"
    with open(os.path.join(temp_dirs['cleaned_chunks_dir'], "chunk_0003.bin"), "rb") as f: assert f.read() == b"\0"
    with open(os.path.join(temp_dirs['cleaned_chunks_dir'], "chunk_0004.bin"), "rb") as f: assert f.read() == b"data4"
    assert os.path.exists(os.path.join(temp_dirs['logs_dir'], "reassembly_info.json"))

# --- Tests for SteganographyReceiver ---

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open) # Mock file open globally for these tests
@patch('crypticroute.receiver.core.log_debug')
def test_receiver_init(mock_log, mock_file_open, mock_send, temp_dirs):
    key_probe = b'probe'
    key_resp = b'resp'
    # Init should attempt to create log files
    receiver = SteganographyReceiver(key_probe, key_resp, temp_dirs)

    assert receiver.receiver_key_hash_probe_expected == key_probe
    assert receiver.receiver_key_hash_response == key_resp
    assert receiver.session_paths == temp_dirs
    assert 10000 <= receiver.my_port <= 60000
    # Check log file creation attempts via mock_open
    # Note: conftest now creates these, so init doesn't need to. Let's remove this check.
    # expected_calls = [
    #     call(os.path.join(temp_dirs['logs_dir'], "received_chunks.json"), "w"),
    #     call().__enter__(), call().write('{}'), call().__exit__(None, None, None),
    #     call(os.path.join(temp_dirs['logs_dir'], "sent_acks.json"), "w"),
    #     call().__enter__(), call().write('{}'), call().__exit__(None, None, None)
    # ]
    # mock_file_open.assert_has_calls(expected_calls, any_order=False)
    # Check that __init__ *did* try to open the files in write mode, even if they exist.
    # mock_open intercepts these calls.
    expected_calls = [
        call(os.path.join(temp_dirs['logs_dir'], "received_chunks.json"), "w"),
        call(os.path.join(temp_dirs['logs_dir'], "sent_acks.json"), "w"),
    ]
    # Check if these specific calls were made among all calls to mock_file_open
    mock_file_open.assert_has_calls(expected_calls, any_order=True)


@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_create_discovery_response(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    probe_packet = IP(src="1.2.3.4") / TCP(sport=1111, seq=100)
    response_pkt = receiver._create_discovery_response_packet(probe_packet)
    assert response_pkt is not None
    assert response_pkt[IP].dst == "1.2.3.4"
    assert response_pkt[TCP].sport == DISCOVERY_PORT
    assert response_pkt[TCP].dport == 1111
    assert response_pkt[TCP].flags == 0x09 # PF
    assert response_pkt[TCP].window == DISCOVERY_RESPONSE_WINDOW
    assert response_pkt[TCP].seq == int.from_bytes(receiver.receiver_key_hash_response, 'big')
    assert response_pkt[TCP].ack == 101

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_send_discovery_response(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    probe_packet = IP(src="1.2.3.4") / TCP(sport=1111, seq=100)
    receiver._send_discovery_response(probe_packet)
    assert mock_send.call_count == 5
    sent_packet = mock_send.call_args[0][0]
    assert sent_packet[IP].dst == "1.2.3.4"
    assert sent_packet[TCP].seq == int.from_bytes(receiver.receiver_key_hash_response, 'big')

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_process_discovery_probe_valid(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    valid_probe = IP(src="5.6.7.8") / TCP(
        sport=2222, dport=DISCOVERY_PORT, flags=0x28, window=DISCOVERY_PROBE_WINDOW,
        seq=int.from_bytes(receiver.receiver_key_hash_probe_expected, 'big')
    )
    result = receiver.process_discovery_probe(valid_probe)
    assert result is True
    assert receiver.discovery_probe_processed is True
    assert receiver.discovery_sender_ip == "5.6.7.8"
    assert receiver.discovery_sender_port == 2222
    assert mock_send.call_count == 5

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_process_discovery_probe_invalid_hash(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    invalid_probe = IP(src="5.6.7.8") / TCP(
        sport=2222, dport=DISCOVERY_PORT, flags=0x28, window=DISCOVERY_PROBE_WINDOW,
        seq=int.from_bytes(b'xxxx', 'big')
    )
    result = receiver.process_discovery_probe(invalid_probe)
    assert result is False
    assert receiver.discovery_probe_processed is False
    assert mock_send.call_count == 0

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_process_discovery_probe_wrong_flags_window(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    wrong_flags = IP(src="5.6.7.8") / TCP(
        sport=2222, dport=DISCOVERY_PORT, flags=0x02, window=DISCOVERY_PROBE_WINDOW,
        seq=int.from_bytes(receiver.receiver_key_hash_probe_expected, 'big')
    )
    wrong_window = IP(src="5.6.7.8") / TCP(
        sport=2222, dport=DISCOVERY_PORT, flags=0x28, window=0x1234,
        seq=int.from_bytes(receiver.receiver_key_hash_probe_expected, 'big')
    )
    assert receiver.process_discovery_probe(wrong_flags) is False
    assert receiver.process_discovery_probe(wrong_window) is False
    assert receiver.discovery_probe_processed is False
    assert mock_send.call_count == 0

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_create_data_ack(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    seq_num_to_ack = 123
    ack_pkt = receiver._create_data_ack_packet(seq_num_to_ack)
    assert ack_pkt is not None
    assert ack_pkt[IP].dst == receiver.sender_ip
    assert ack_pkt[TCP].sport == receiver.my_port
    assert ack_pkt[TCP].dport == receiver.sender_port
    assert ack_pkt[TCP].flags == 'A'
    assert ack_pkt[TCP].window == DATA_ACK_WINDOW
    assert ack_pkt[TCP].ack == seq_num_to_ack

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_send_data_ack(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, temp_dirs = mock_receiver_instance
    seq_num_to_ack = 456
    receiver.send_data_ack(seq_num_to_ack)
    assert mock_send.call_count == 3
    sent_packet = mock_send.call_args[0][0]
    assert sent_packet[TCP].ack == seq_num_to_ack
    assert seq_num_to_ack in receiver.ack_sent_chunks
    # Check sent_acks.json write attempt
    mock_file.assert_any_call(os.path.join(temp_dirs['logs_dir'], "sent_acks.json"), "w")

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_create_syn_ack(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    syn_packet = IP(src=receiver.sender_ip) / TCP(sport=receiver.sender_port, seq=1000, flags='S')
    syn_ack_pkt = receiver._create_syn_ack_packet(syn_packet)
    assert syn_ack_pkt is not None
    assert syn_ack_pkt[IP].dst == receiver.sender_ip
    assert syn_ack_pkt[TCP].sport == receiver.my_port
    assert syn_ack_pkt[TCP].dport == receiver.sender_port
    assert syn_ack_pkt[TCP].flags == 'SA'
    assert syn_ack_pkt[TCP].window == SYN_ACK_WINDOW
    assert syn_ack_pkt[TCP].ack == 1001

@patch('crypticroute.receiver.core.send')
@patch('crypticroute.receiver.core.log_debug')
def test_send_syn_ack(mock_log, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    syn_packet = IP(src=receiver.sender_ip) / TCP(sport=receiver.sender_port, seq=2000, flags='S')
    receiver._send_syn_ack(syn_packet)
    assert mock_send.call_count == 5
    sent_packet = mock_send.call_args[0][0]
    assert sent_packet[TCP].flags == 'SA'
    assert sent_packet[TCP].ack == 2001

# --- Tests for process_packet ---

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_process_packet_ignore_wrong_source(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    receiver.discovery_sender_ip = "1.1.1.1"
    packet = IP(src="2.2.2.2") / TCP()
    result = receiver.process_packet(packet)
    assert result is False
    assert mock_send.call_count == 0

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_process_packet_receive_syn(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    receiver.discovery_sender_ip = "192.168.1.100"
    syn_packet = IP(src="192.168.1.100") / TCP(
        sport=54321, flags='S', window=SYN_WINDOW, seq=3000
    )
    result = receiver.process_packet(syn_packet)
    assert result is False
    assert receiver.sender_ip == "192.168.1.100"
    assert receiver.sender_port == 54321
    assert mock_send.call_count == 5
    sent_packet = mock_send.call_args[0][0]
    assert sent_packet[TCP].flags == 'SA'
    assert sent_packet[TCP].ack == 3001

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_process_packet_receive_final_ack(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    receiver.discovery_sender_ip = "192.168.1.100"
    receiver.sender_ip = "192.168.1.100"
    receiver.sender_port = 54321
    # Simulate SYN-ACK was sent (doesn't matter what seq it had for this test)
    final_ack_packet = IP(src="192.168.1.100") / TCP(
        sport=54321, dport=receiver.my_port, flags='A', window=FINAL_ACK_WINDOW, ack=101
    )
    result = receiver.process_packet(final_ack_packet)
    assert result is False
    assert receiver.connection_established is True
    assert mock_send.call_count == 0

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_process_packet_receive_data_chunk(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, temp_dirs = mock_receiver_instance
    receiver.discovery_sender_ip = "192.168.1.100"
    receiver.sender_ip = "192.168.1.100"
    receiver.sender_port = 54321
    receiver.connection_established = True

    seq_num = 1
    total_chunks = 10
    # Ensure data is exactly 8 bytes
    data_part1 = b'abcd'
    data_part2 = b'efgh'
    full_data = data_part1 + data_part2
    checksum = binascii.crc32(full_data) & 0xFFFF

    data_packet = IP(src="192.168.1.100", id=checksum) / TCP(
        sport=54321, dport=receiver.my_port, flags='S', window=seq_num,
        seq=int.from_bytes(data_part1, 'big'), ack=int.from_bytes(data_part2, 'big'),
        options=[('MSS', total_chunks)]
    )
    result = receiver.process_packet(data_packet)
    assert result is False
    assert seq_num in receiver.received_chunks
    assert receiver.received_chunks[seq_num] == full_data
    assert receiver.highest_seq_num_seen == seq_num
    assert receiver.total_chunks_expected == total_chunks
    assert mock_send.call_count == 3
    sent_packet = mock_send.call_args[0][0]
    assert sent_packet[TCP].flags == 'A'
    assert sent_packet[TCP].ack == seq_num

    # Fix 2: Check mock_file calls instead of os.path.exists
    mock_file.assert_any_call(os.path.join(temp_dirs['logs_dir'], "received_chunks.json"), "w")
    mock_file.assert_any_call(os.path.join(temp_dirs['raw_chunks_dir'], f"chunk_{seq_num:04d}.bin"), "wb")
    mock_file.assert_any_call(os.path.join(temp_dirs['logs_dir'], "sent_acks.json"), "w")

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_process_packet_receive_duplicate_data(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    receiver.discovery_sender_ip = "192.168.1.100"
    receiver.sender_ip = "192.168.1.100"
    receiver.sender_port = 54321
    receiver.connection_established = True

    seq_num = 5
    total_chunks = 10
    data_part1 = b'ijkl'
    data_part2 = b'mnop'
    full_data = data_part1 + data_part2
    checksum = binascii.crc32(full_data) & 0xFFFF

    data_packet = IP(src="192.168.1.100", id=checksum) / TCP(
        sport=54321, dport=receiver.my_port, flags='S', window=seq_num,
        seq=int.from_bytes(data_part1, 'big'), ack=int.from_bytes(data_part2, 'big'),
        options=[('MSS', total_chunks)]
    )

    # Process first time - ACK is sent
    receiver.process_packet(data_packet)
    assert seq_num in receiver.received_chunks
    assert mock_send.call_count == 3
    first_chunk_data = receiver.received_chunks[seq_num]
    # Add to ack_sent_chunks manually as send_data_ack does
    receiver.ack_sent_chunks.add(seq_num)
    mock_send.reset_mock()

    # Process second time (duplicate)
    result = receiver.process_packet(data_packet)
    assert result is False
    assert receiver.received_chunks[seq_num] == first_chunk_data # Data not overwritten
    # The ACK is *not* resent because it was already logged in ack_sent_chunks
    assert mock_send.call_count == 0 # ACK not resent

@patch('crypticroute.receiver.core.send')
@patch('builtins.open', new_callable=mock_open)
@patch('crypticroute.receiver.core.log_debug')
def test_process_packet_receive_completion_signal(mock_log, mock_file, mock_send, mock_receiver_instance):
    receiver, _ = mock_receiver_instance
    receiver.discovery_sender_ip = "192.168.1.100"
    receiver.sender_ip = "192.168.1.100"
    receiver.sender_port = 54321
    receiver.connection_established = True
    completion_packet = IP(src="192.168.1.100") / TCP(
        sport=54321, dport=receiver.my_port, flags='F', window=COMPLETION_WINDOW
    )
    result = receiver.process_packet(completion_packet)
    assert result is True
    assert mock_send.call_count == 0

# --- Tests for receive_file_logic (Refactored) ---

# Mock dependencies for receive_file_logic tests
@patch('crypticroute.receiver.core.SteganographyReceiver')
@patch('crypticroute.receiver.core.prepare_key')
@patch('crypticroute.receiver.core.sniff') # Mock sniff to control its behavior
@patch('crypticroute.receiver.core.reassemble_data')
@patch('crypticroute.receiver.core.verify_data_integrity')
@patch('crypticroute.receiver.core.decrypt_data')
@patch('crypticroute.receiver.core.save_to_file')
@patch('crypticroute.receiver.core.threading.Thread') # Mock the thread itself
@patch('crypticroute.receiver.core.time.sleep') # Mock sleep in monitor
@patch('builtins.open', new_callable=mock_open, read_data=b'test_key_data') # Mock key file open
@patch('crypticroute.receiver.core.log_debug')
def test_receive_logic_success_flow(
    mock_log, mock_file_open, mock_sleep, mock_thread_class, mock_save, mock_decrypt,
    mock_verify, mock_reassemble, mock_sniff, mock_prepare_key, mock_receiver_class,
    temp_dirs
):
    # --- Mock Setup ---
    mock_key = b'1234567890123456'
    mock_probe_id = b'probe'
    mock_resp_id = b'resp'
    mock_prepare_key.return_value = (mock_key, mock_probe_id, mock_resp_id)

    # Mock SteganographyReceiver instance
    mock_stego_instance = MagicMock()
    mock_receiver_class.return_value = mock_stego_instance

    # --- Configure Mock Instance State for Success ---
    mock_stego_instance.discovery_probe_processed = True # Simulate discovery success
    mock_stego_instance.discovery_sender_ip = "10.0.0.1" # Simulate discovered IP
    mock_stego_instance.discovery_sender_port = 9876
    # Simulate data received during the (mocked) main sniff loop
    mock_stego_instance.received_chunks = {1: b'raw1', 2: b'raw2'}
    mock_stego_instance.total_chunks_expected = 2
    mock_stego_instance.highest_seq_num_seen = 2
    # Ensure sender_ip is set if discovery was successful
    mock_stego_instance.sender_ip = "10.0.0.1"

    # --- Configure Mock Sniff Behavior ---
    # Make sniff do nothing, relying on pre-set mock_stego_instance state
    mock_sniff.side_effect = [None, None] # Called twice, does nothing each time

    # --- Mock Post-Processing Functions ---
    mock_reassembled_data = b'reassembled_raw'
    mock_reassemble.return_value = (mock_reassembled_data, 0) # No missing chunks
    mock_verified_data = b'verified_data'
    mock_verify.return_value = (mock_verified_data, True) # Checksum OK
    mock_decrypted_data = b'final_decrypted_data'
    mock_decrypt.return_value = mock_decrypted_data
    mock_save.return_value = True # Save successful

    # Mock threading.Thread
    mock_thread_instance = MagicMock()
    mock_thread_class.return_value = mock_thread_instance

    # --- Execute ---
    output_file = os.path.join(temp_dirs['data_dir'], "output.txt")
    key_file = "dummy_key.key"
    result = receive_file_logic(output_file, key_file, "eth0", 10, 5, temp_dirs)

    # --- Assert ---
    assert result is True # Overall success

    # --- Assert Mocks ---
    mock_file_open.assert_any_call(key_file, 'rb')
    mock_prepare_key.assert_called_once()
    mock_receiver_class.assert_called_once_with(mock_probe_id, mock_resp_id, temp_dirs)
    # Sniff is called twice: once for discovery, once for main listen
    assert mock_sniff.call_count == 2
    mock_thread_class.assert_called_once()
    mock_thread_instance.start.assert_called_once()
    mock_thread_instance.join.assert_called_once()

    # Check post-processing calls
    expected_total = max(mock_stego_instance.total_chunks_expected, mock_stego_instance.highest_seq_num_seen)
    mock_reassemble.assert_called_once_with(mock_stego_instance.received_chunks, expected_total, temp_dirs['logs_dir'], temp_dirs['chunks_dir'], temp_dirs['data_dir'])
    mock_verify.assert_called_once_with(mock_reassembled_data, temp_dirs['logs_dir'], temp_dirs['data_dir'])
    mock_decrypt.assert_called_once_with(mock_verified_data, mock_key, temp_dirs['data_dir'])
    mock_save.assert_called_once_with(mock_decrypted_data, output_file, temp_dirs['data_dir'])

    # Check completion log write attempt
    completion_log_path = os.path.join(temp_dirs['logs_dir'], "completion_info.json")
    mock_file_open.assert_any_call(completion_log_path, "w")


@patch('crypticroute.receiver.core.SteganographyReceiver')
@patch('crypticroute.receiver.core.prepare_key')
@patch('crypticroute.receiver.core.sniff') # Mock sniff to control its behavior
@patch('crypticroute.receiver.core.threading.Thread')
@patch('crypticroute.receiver.core.time.sleep')
@patch('builtins.open', new_callable=mock_open, read_data=b'test_key_data')
@patch('crypticroute.receiver.core.log_debug')
def test_receive_logic_discovery_timeout(
    mock_log, mock_file_open, mock_sleep, mock_thread_class, mock_sniff, mock_prepare_key, mock_receiver_class,
    temp_dirs
):
    # --- Mock Setup ---
    mock_prepare_key.return_value = (b'key', b'probe', b'resp')

    # --- Mock Receiver Instance State for Timeout ---
    mock_stego_instance = MagicMock()
    mock_stego_instance.discovery_probe_processed = False # Discovery fails
    # Set default integer values for attributes accessed in finally block
    mock_stego_instance.total_chunks_expected = 0
    mock_stego_instance.highest_seq_num_seen = 0
    mock_stego_instance.received_chunks = {}
    mock_stego_instance.sender_ip = None # Ensure sender_ip is None if discovery fails
    mock_receiver_class.return_value = mock_stego_instance

    # --- Mock Sniff Behavior for Timeout ---
    # Sniff for discovery runs but doesn't set discovery_probe_processed to True
    mock_sniff.side_effect = [None] # Only called once for discovery

    # --- Execute ---
    result = receive_file_logic("out.txt", "key.key", "eth0", 10, 5, temp_dirs)

    # --- Assert ---
    assert result is False # Should fail due to discovery timeout
    mock_sniff.assert_called_once() # Only discovery sniff called
    mock_thread_class.assert_not_called() # Monitor thread not started
    # Check completion log write attempt
    completion_log_path = os.path.join(temp_dirs['logs_dir'], "completion_info.json")
    mock_file_open.assert_any_call(completion_log_path, "w")


@patch('crypticroute.receiver.core.SteganographyReceiver')
@patch('crypticroute.receiver.core.prepare_key')
@patch('crypticroute.receiver.core.sniff') # Mock sniff
@patch('crypticroute.receiver.core.reassemble_data')
@patch('crypticroute.receiver.core.verify_data_integrity')
@patch('crypticroute.receiver.core.decrypt_data')
@patch('crypticroute.receiver.core.save_to_file')
@patch('crypticroute.receiver.core.threading.Thread')
@patch('crypticroute.receiver.core.time.sleep')
@patch('builtins.open', new_callable=mock_open, read_data=b'test_key_data')
@patch('crypticroute.receiver.core.log_debug')
def test_receive_logic_decryption_fail(
    mock_log, mock_file_open, mock_sleep, mock_thread_class, mock_save, mock_decrypt,
    mock_verify, mock_reassemble, mock_sniff, mock_prepare_key, mock_receiver_class,
    temp_dirs
):
    # --- Mock Setup ---
    mock_key = b'1234567890123456'
    mock_probe_id = b'probe'
    mock_resp_id = b'resp'
    mock_prepare_key.return_value = (mock_key, mock_probe_id, mock_resp_id)

    # --- Mock Receiver Instance State for Decryption Fail ---
    mock_stego_instance = MagicMock()
    mock_stego_instance.discovery_probe_processed = True # Discovery succeeds
    mock_stego_instance.discovery_sender_ip = "10.0.0.1"
    mock_stego_instance.discovery_sender_port = 9876
    mock_stego_instance.received_chunks = {1: b'raw1'}
    mock_stego_instance.total_chunks_expected = 1
    mock_stego_instance.highest_seq_num_seen = 1
    mock_stego_instance.sender_ip = "10.0.0.1" # Set sender IP
    mock_receiver_class.return_value = mock_stego_instance

    # --- Mock Sniff Behavior ---
    mock_sniff.side_effect = [None, None] # Discovery and main loop complete

    # --- Mock Post-Processing ---
    mock_reassembled_data = b'reassembled_raw'
    mock_reassemble.return_value = (mock_reassembled_data, 0)
    mock_verified_data = b'verified_data'
    mock_verify.return_value = (mock_verified_data, True) # Checksum OK
    mock_decrypt.return_value = None # Simulate decryption failure
    mock_save.return_value = True # Assume save succeeds

    # Mock threading.Thread
    mock_thread_instance = MagicMock()
    mock_thread_class.return_value = mock_thread_instance

    # --- Execute ---
    output_file = os.path.join(temp_dirs['data_dir'], "output.txt")
    result = receive_file_logic(output_file, "key.key", "eth0", 10, 5, temp_dirs)

    # --- Assert ---
    assert result is False # Overall failure due to decryption
    mock_reassemble.assert_called_once()
    mock_verify.assert_called_once()
    mock_decrypt.assert_called_once()
    # Check that the *verified* (but not decrypted) data was saved
    mock_save.assert_called_once_with(mock_verified_data, output_file, temp_dirs['data_dir'])
    # Check completion log write attempt
    completion_log_path = os.path.join(temp_dirs['logs_dir'], "completion_info.json")
    mock_file_open.assert_any_call(completion_log_path, "w")


@patch('crypticroute.receiver.core.SteganographyReceiver')
@patch('crypticroute.receiver.core.prepare_key')
@patch('crypticroute.receiver.core.sniff') # Mock sniff
@patch('crypticroute.receiver.core.reassemble_data')
@patch('crypticroute.receiver.core.verify_data_integrity') # Mock verify
@patch('crypticroute.receiver.core.decrypt_data') # Mock decrypt
@patch('crypticroute.receiver.core.save_to_file') # Mock save
@patch('crypticroute.receiver.core.threading.Thread')
@patch('crypticroute.receiver.core.time.sleep')
@patch('builtins.open', new_callable=mock_open, read_data=b'test_key_data')
@patch('crypticroute.receiver.core.log_debug')
def test_receive_logic_missing_chunks(
    mock_log, mock_file_open, mock_sleep, mock_thread_class, mock_save, mock_decrypt,
    mock_verify, mock_reassemble, mock_sniff, mock_prepare_key, mock_receiver_class,
    temp_dirs
):
    # --- Mock Setup ---
    mock_key, mock_probe_id, mock_resp_id = b'key', b'probe', b'resp'
    mock_prepare_key.return_value = (mock_key, mock_probe_id, mock_resp_id)

    # --- Mock Receiver Instance State ---
    mock_stego_instance = MagicMock()
    mock_stego_instance.discovery_probe_processed = True
    mock_stego_instance.discovery_sender_ip = "10.0.0.1"
    mock_stego_instance.discovery_sender_port = 9876
    mock_stego_instance.received_chunks = {1: b'raw1', 3: b'raw3'} # Chunk 2 missing
    mock_stego_instance.total_chunks_expected = 3
    mock_stego_instance.highest_seq_num_seen = 3
    mock_stego_instance.sender_ip = "10.0.0.1" # Set sender IP
    mock_receiver_class.return_value = mock_stego_instance

    # --- Mock Sniff Behavior ---
    mock_sniff.side_effect = [None, None] # Discovery and main loop complete

    # --- Mock Post-Processing ---
    mock_reassembled_data = b'reassembled_partial'
    # Simulate reassemble detecting missing chunks
    mock_reassemble.return_value = (mock_reassembled_data, 1) # 1 missing chunk
    # Assume downstream functions work correctly with partial data
    mock_verified_data = b'verified_partial'
    mock_verify.return_value = (mock_verified_data, True)
    mock_decrypted_data = b'decrypted_partial'
    mock_decrypt.return_value = mock_decrypted_data
    mock_save.return_value = True

    # Mock threading.Thread
    mock_thread_instance = MagicMock()
    mock_thread_class.return_value = mock_thread_instance

    # --- Execute ---
    output_file = os.path.join(temp_dirs['data_dir'], "output.txt")
    result = receive_file_logic(output_file, "key.key", "eth0", 10, 5, temp_dirs)

    # --- Assert ---
    assert result is False # Overall failure because chunks were missing
    mock_reassemble.assert_called_once()
    mock_verify.assert_called_once()
    mock_decrypt.assert_called_once()
    mock_save.assert_called_once_with(mock_decrypted_data, output_file, temp_dirs['data_dir'])
    # Check completion status indicates missing chunks (via log file check ideally)
    completion_log_path = os.path.join(temp_dirs['logs_dir'], "completion_info.json")
    mock_file_open.assert_any_call(completion_log_path, "w")
