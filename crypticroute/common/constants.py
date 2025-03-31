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

# Encryption/Integrity
AES_KEY_SIZE = 32 # Bytes (for AES-256)
IV_SIZE = 16 # Bytes (for AES CFB)
INTEGRITY_CHECK_SIZE = 16 # Bytes (MD5 checksum)

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
