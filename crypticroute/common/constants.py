# Shared constants for CrypticRoute

# Network settings
MAX_CHUNK_SIZE = 8
DISCOVERY_PORT = 54321
DISCOVERY_TIMEOUT_SENDER = 30 # Default sender discovery timeout
DISCOVERY_TIMEOUT_RECEIVER = 60 # Default receiver discovery timeout
ACK_WAIT_TIMEOUT = 10
MAX_RETRANSMISSIONS = 10

# Handshake/Packet Signatures (Keep consistent with original logic)
SYN_WINDOW = 0xDEAD
SYN_ACK_WINDOW = 0xBEEF
FINAL_ACK_WINDOW = 0xF00D
DATA_ACK_WINDOW = 0xCAFE
COMPLETION_WINDOW = 0xFFFF
DISCOVERY_PROBE_WINDOW = 0xFACE
DISCOVERY_RESPONSE_WINDOW = 0xCAFE # Note: Same as DATA_ACK in original

# Transmission Parameters
FINAL_ACK_RETRANSMISSIONS = 5
FINAL_ACK_DELAY = 0.1
DATA_DPORT_RANGE = (10000, 60000) # Range for random destination ports for data packets
COMPLETION_DPORT_RANGE = (10000, 60000) # Range for random destination ports for completion packets
ACK_POLL_INTERVAL = 0.1 # How often sender checks if ACK arrived
DISCOVERY_PROBE_INTERVAL = 1.0 # Seconds between sender discovery probes
CONNECTION_TIMEOUT = 20 # Seconds sender waits for SYN-ACK
SYN_RETRANSMIT_INTERVAL_INITIAL = 0.5 # Initial seconds between SYN retransmits
MAX_SYN_SENDS = 15 # Max SYN packets sender will send before giving up
SYN_RETRANSMIT_INTERVAL_LATER = 1.5 # Seconds between SYN retransmits after the first few
COMPLETION_SEND_COUNT = 10 # How many times sender sends completion packet
COMPLETION_SEND_DELAY = 0.2 # Seconds between sender completion packets
SENDER_SPORT_RANGE = (10000, 60000) # Range for random source port for sender
RECEIVER_SPORT_RANGE = (10000, 60000) # Range for random source port for receiver ACKs/SYN-ACKs
DISCOVERY_RESPONSE_SEND_COUNT = 5 # How many times receiver sends discovery response
DISCOVERY_RESPONSE_SEND_DELAY = 0.1 # Seconds between receiver discovery responses
DATA_ACK_SEND_COUNT = 3 # How many times receiver sends data ACK
DATA_ACK_SEND_DELAY = 0.05 # Seconds between receiver data ACKs
SYN_ACK_SEND_COUNT = 5 # How many times receiver sends SYN-ACK
SYN_ACK_SEND_DELAY = 0.1 # Seconds between receiver SYN-ACKs
RECEIVER_STATUS_PRINT_INTERVAL = 50 # Print receiver status every N packets

# Encryption/Integrity
AES_KEY_SIZE = 32 # Bytes (for AES-256)
IV_SIZE = 16 # Bytes (for AES CFB)
INTEGRITY_CHECK_SIZE = 32 # Bytes (SHA-256 checksum)

# Output directories
DEFAULT_OUTPUT_DIR = "stealth_output"
SENDER_SESSION_PREFIX = "sender_session"
RECEIVER_SESSION_PREFIX = "receiver_session"
LOGS_SUBDIR = "logs"
DATA_SUBDIR = "data"
CHUNKS_SUBDIR = "chunks"
RAW_CHUNKS_SUBDIR = "raw"
CLEANED_CHUNKS_SUBDIR = "cleaned"
LATEST_SENDER_LINK = "sender_latest"
LATEST_RECEIVER_LINK = "receiver_latest"
