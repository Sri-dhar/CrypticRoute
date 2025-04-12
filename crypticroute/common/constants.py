# Shared constants for CrypticRoute
# Values are loaded from config.toml if present, otherwise defaults are used.

from crypticroute.config_loader import get_config

# Network settings
MAX_CHUNK_SIZE = get_config('network', 'max_chunk_size', 8)
DISCOVERY_PORT = get_config('network', 'discovery_port', 54321)
DISCOVERY_TIMEOUT_SENDER = get_config('network', 'discovery_timeout_sender', 30) # Default sender discovery timeout
DISCOVERY_TIMEOUT_RECEIVER = get_config('network', 'discovery_timeout_receiver', 60) # Default receiver discovery timeout
ACK_WAIT_TIMEOUT = get_config('network', 'ack_wait_timeout', 10)
MAX_RETRANSMISSIONS = get_config('network', 'max_retransmissions', 10)

# Handshake/Packet Signatures (Keep consistent with original logic)
# Note: config_loader converts hex strings from TOML back to integers
SYN_WINDOW = get_config('network', 'syn_window', 0xDEAD)
SYN_ACK_WINDOW = get_config('network', 'syn_ack_window', 0xBEEF)
FINAL_ACK_WINDOW = get_config('network', 'final_ack_window', 0xF00D)
DATA_ACK_WINDOW = get_config('network', 'data_ack_window', 0xCAFE)
COMPLETION_WINDOW = get_config('network', 'completion_window', 0xFFFF)
DISCOVERY_PROBE_WINDOW = get_config('network', 'discovery_probe_window', 0xFACE)
DISCOVERY_RESPONSE_WINDOW = get_config('network', 'discovery_response_window', 0xCAFE) # Note: Same as DATA_ACK in original

# Transmission Parameters
FINAL_ACK_RETRANSMISSIONS = get_config('transmission', 'final_ack_retransmissions', 5)
FINAL_ACK_DELAY = get_config('transmission', 'final_ack_delay', 0.1)
# Convert list from TOML to tuple
_data_dport_range_list = get_config('transmission', 'data_dport_range', [10000, 60000])
DATA_DPORT_RANGE = tuple(_data_dport_range_list) if isinstance(_data_dport_range_list, list) and len(_data_dport_range_list) == 2 else (10000, 60000)
_completion_dport_range_list = get_config('transmission', 'completion_dport_range', [10000, 60000])
COMPLETION_DPORT_RANGE = tuple(_completion_dport_range_list) if isinstance(_completion_dport_range_list, list) and len(_completion_dport_range_list) == 2 else (10000, 60000)
ACK_POLL_INTERVAL = get_config('transmission', 'ack_poll_interval', 0.1) # How often sender checks if ACK arrived
DISCOVERY_PROBE_INTERVAL = get_config('transmission', 'discovery_probe_interval', 1.0) # Seconds between sender discovery probes
CONNECTION_TIMEOUT = get_config('transmission', 'connection_timeout', 20) # Seconds sender waits for SYN-ACK
SYN_RETRANSMIT_INTERVAL_INITIAL = get_config('transmission', 'syn_retransmit_interval_initial', 0.5) # Initial seconds between SYN retransmits
MAX_SYN_SENDS = get_config('transmission', 'max_syn_sends', 15) # Max SYN packets sender will send before giving up
SYN_RETRANSMIT_INTERVAL_LATER = get_config('transmission', 'syn_retransmit_interval_later', 1.5) # Seconds between SYN retransmits after the first few
COMPLETION_SEND_COUNT = get_config('transmission', 'completion_send_count', 10) # How many times sender sends completion packet
COMPLETION_SEND_DELAY = get_config('transmission', 'completion_send_delay', 0.2) # Seconds between sender completion packets
# Convert list from TOML to tuple
_sender_sport_range_list = get_config('transmission', 'sender_sport_range', [10000, 60000])
SENDER_SPORT_RANGE = tuple(_sender_sport_range_list) if isinstance(_sender_sport_range_list, list) and len(_sender_sport_range_list) == 2 else (10000, 60000)
_receiver_sport_range_list = get_config('transmission', 'receiver_sport_range', [10000, 60000])
RECEIVER_SPORT_RANGE = tuple(_receiver_sport_range_list) if isinstance(_receiver_sport_range_list, list) and len(_receiver_sport_range_list) == 2 else (10000, 60000)
DISCOVERY_RESPONSE_SEND_COUNT = get_config('transmission', 'discovery_response_send_count', 5) # How many times receiver sends discovery response
DISCOVERY_RESPONSE_SEND_DELAY = get_config('transmission', 'discovery_response_send_delay', 0.1) # Seconds between receiver discovery responses
DATA_ACK_SEND_COUNT = get_config('transmission', 'data_ack_send_count', 3) # How many times receiver sends data ACK
DATA_ACK_SEND_DELAY = get_config('transmission', 'data_ack_send_delay', 0.05) # Seconds between receiver data ACKs
SYN_ACK_SEND_COUNT = get_config('transmission', 'syn_ack_send_count', 5) # How many times receiver sends SYN-ACK
SYN_ACK_SEND_DELAY = get_config('transmission', 'syn_ack_send_delay', 0.1) # Seconds between receiver SYN-ACKs
RECEIVER_STATUS_PRINT_INTERVAL = get_config('transmission', 'receiver_status_print_interval', 50) # Print receiver status every N packets

# Encryption/Integrity
AES_KEY_SIZE = get_config('security', 'aes_key_size', 32) # Bytes (for AES-256)
IV_SIZE = get_config('security', 'iv_size', 16) # Bytes (for AES CFB)
INTEGRITY_CHECK_SIZE = get_config('security', 'integrity_check_size', 32) # Bytes (SHA-256 checksum)

# Output directories
DEFAULT_OUTPUT_DIR = get_config('output', 'default_output_dir', "stealth_output")
SENDER_SESSION_PREFIX = get_config('output', 'sender_session_prefix', "sender_session")
RECEIVER_SESSION_PREFIX = get_config('output', 'receiver_session_prefix', "receiver_session")
LOGS_SUBDIR = get_config('output', 'logs_subdir', "logs")
DATA_SUBDIR = get_config('output', 'data_subdir', "data")
CHUNKS_SUBDIR = get_config('output', 'chunks_subdir', "chunks")
RAW_CHUNKS_SUBDIR = get_config('output', 'raw_chunks_subdir', "raw")
CLEANED_CHUNKS_SUBDIR = get_config('output', 'cleaned_chunks_subdir', "cleaned")
LATEST_SENDER_LINK = get_config('output', 'latest_sender_link', "sender_latest")
LATEST_RECEIVER_LINK = get_config('output', 'latest_receiver_link', "receiver_latest")
