import os
import time
import datetime
import json
import hashlib
import binascii
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .constants import (
    AES_KEY_SIZE, IV_SIZE, INTEGRITY_CHECK_SIZE,
    LOGS_SUBDIR, DATA_SUBDIR, CHUNKS_SUBDIR, RAW_CHUNKS_SUBDIR, CLEANED_CHUNKS_SUBDIR
)

# --- Logging ---

DEBUG_LOG_PATH = None # Module-level variable to store the log path

def set_debug_log_path(path):
    """Sets the path for the debug log file."""
    global DEBUG_LOG_PATH
    DEBUG_LOG_PATH = path

def log_debug(message):
    """Write debug message to the configured log file."""
    if not DEBUG_LOG_PATH:
        print(f"DEBUG (log not configured): {message}")
        return
    try:
        with open(DEBUG_LOG_PATH, "a") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"Error writing to debug log {DEBUG_LOG_PATH}: {e}")

# --- Directory Setup ---

def setup_directories(base_output_dir, session_prefix, latest_link_name):
    """Create organized directory structure for outputs and return paths."""
    paths = {}
    if not os.path.exists(base_output_dir):
        os.makedirs(base_output_dir)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    paths['session_dir'] = os.path.join(base_output_dir, f"{session_prefix}_{timestamp}")
    os.makedirs(paths['session_dir'])

    paths['logs_dir'] = os.path.join(paths['session_dir'], LOGS_SUBDIR)
    paths['data_dir'] = os.path.join(paths['session_dir'], DATA_SUBDIR)
    paths['chunks_dir'] = os.path.join(paths['session_dir'], CHUNKS_SUBDIR)

    os.makedirs(paths['logs_dir'])
    os.makedirs(paths['data_dir'])
    os.makedirs(paths['chunks_dir'])

    # Create subdirs for receiver chunks if needed (harmless for sender)
    os.makedirs(os.path.join(paths['chunks_dir'], RAW_CHUNKS_SUBDIR), exist_ok=True)
    os.makedirs(os.path.join(paths['chunks_dir'], CLEANED_CHUNKS_SUBDIR), exist_ok=True)

    paths['debug_log_path'] = os.path.join(paths['logs_dir'], f"{session_prefix}_debug.log")
    set_debug_log_path(paths['debug_log_path']) # Configure logging

    latest_link = os.path.join(base_output_dir, latest_link_name)
    try:
        if os.path.islink(latest_link):
            os.unlink(latest_link)
        elif os.path.exists(latest_link):
            # Use a more unique backup name
            backup_name = f"{latest_link}_{timestamp}_{int(time.time())}"
            os.rename(latest_link, backup_name)
            print(f"Renamed existing file/link to {backup_name}")
        # Use relative path for symlink if possible for portability
        relative_session_dir = os.path.relpath(paths['session_dir'], start=base_output_dir)
        os.symlink(relative_session_dir, latest_link)
        print(f"Created symlink: {latest_link} -> {relative_session_dir}")
    except Exception as e:
        print(f"Warning: Could not create/update symlink '{latest_link}': {e}")

    print(f"Created output directory structure at: {paths['session_dir']}")
    log_debug(f"Initialized directory structure in {paths['session_dir']}")
    return paths

# --- File Handling ---

def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            data = file.read()
            log_debug(f"Read {len(data)} bytes from {file_path}")
            return data
    except Exception as e:
        log_debug(f"Error reading file {file_path}: {e}")
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1) # Exit if critical file read fails

def save_to_file(data, output_path, data_dir):
    """Save data to a file and optionally log text content."""
    try:
        with open(output_path, 'wb') as file:
            file.write(data)
        log_debug(f"Data saved to {output_path}")
        print(f"Data saved to {output_path}")

        # Copy to the data directory as well
        output_name = os.path.basename(output_path)
        output_copy = os.path.join(data_dir, f"output_{output_name}")
        with open(output_copy, "wb") as f:
            f.write(data)

        # Try to print/save as text
        try:
            text_content = data.decode('utf-8', errors='ignore')
            log_debug(f"Saved text content (sample): {text_content[:100]}...")
            print(f"Saved content appears to be text (sample): {text_content[:60]}...")
            text_file = os.path.join(data_dir, "output_content.txt")
            with open(text_file, "w", encoding='utf-8', errors='ignore') as f:
                f.write(text_content)
        except Exception as e:
            log_debug(f"Content is not valid UTF-8 text or failed to save as text: {e}")
            print("Saved content is binary data or could not be saved as text.")

        return True
    except Exception as e:
        log_debug(f"Error saving data to {output_path}: {e}")
        print(f"Error saving data to {output_path}: {e}")
        return False

# --- Key Handling & Derivation ---

def derive_key_identifiers(key):
    """Derive probe and response identifiers from the key."""
    hasher = hashlib.sha256()
    hasher.update(key)
    full_hash = hasher.digest()
    # Sender uses first 4 for probe, next 4 for expected response
    # Receiver expects first 4 in probe, uses next 4 for its response
    probe_id = full_hash[:4]
    response_id = full_hash[4:8]
    log_debug(f"Derived Probe ID component: {probe_id.hex()}")
    log_debug(f"Derived Response ID component: {response_id.hex()}")
    return probe_id, response_id

def prepare_key(key_data, data_dir):
    """Prepare the encryption key, derive identifiers, and save debug info."""
    # If it's a string, convert to bytes
    if isinstance(key_data, str):
        key_data = key_data.encode('utf-8')

    # Check if it's a hex string and convert if needed
    try:
        is_hex = False
        if isinstance(key_data, bytes):
            try:
                decoded_key = key_data.decode('ascii')
                # Check if all characters are valid hex digits
                if all(c in '0123456789abcdefABCDEF' for c in decoded_key):
                    # Ensure even length for hex conversion
                    if len(decoded_key) % 2 == 0:
                        is_hex = True
            except UnicodeDecodeError:
                pass # Contains non-ASCII, so not a hex string representation

        if is_hex:
            key_data = bytes.fromhex(decoded_key)
            log_debug("Converted hex key string to bytes")
    except ValueError:
        log_debug("Key is not a valid hex string, using raw bytes.")
    except Exception as e:
         log_debug(f"Error during hex key check/conversion: {e}")

    # Ensure key is correct size for AES-256
    if len(key_data) < AES_KEY_SIZE:
        key_data = key_data.ljust(AES_KEY_SIZE, b'\0')  # Pad
    elif len(key_data) > AES_KEY_SIZE:
        key_data = key_data[:AES_KEY_SIZE] # Truncate

    log_debug(f"Final key (used for encryption/decryption): {key_data.hex()}")

    # Save key for debugging
    key_file = os.path.join(data_dir, "key.bin")
    try:
        with open(key_file, "wb") as f:
            f.write(key_data)
    except IOError as e:
        log_debug(f"Error saving key file: {e}")

    # Derive identifiers
    probe_id, response_id = derive_key_identifiers(key_data)

    return key_data, probe_id, response_id

# --- Encryption & Decryption ---

def encrypt_data(data, key, data_dir):
    """Encrypt data using AES-CFB and prepend IV."""
    try:
        iv = os.urandom(IV_SIZE)
        log_debug(f"Using random IV for encryption: {iv.hex()}")

        # Save IV for debugging
        iv_file = os.path.join(data_dir, "iv.bin")
        try:
            with open(iv_file, "wb") as f: f.write(iv)
        except IOError as e:
             log_debug(f"Error saving IV file: {e}")

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        # Save original and encrypted data for debugging
        original_file = os.path.join(data_dir, "original_data.bin")
        encrypted_file = os.path.join(data_dir, "encrypted_data.bin")
        package_file = os.path.join(data_dir, "encrypted_package.bin") # IV + Encrypted
        try:
            with open(original_file, "wb") as f: f.write(data)
            with open(encrypted_file, "wb") as f: f.write(encrypted_data)
            with open(package_file, "wb") as f: f.write(iv + encrypted_data) # Prepend IV
        except IOError as e:
             log_debug(f"Error saving debug data files: {e}")

        log_debug(f"Original data size: {len(data)}, Encrypted data size: {len(encrypted_data)}")
        return iv + encrypted_data
    except Exception as e:
        log_debug(f"Encryption error: {e}")
        print(f"Encryption error: {e}")
        return None # Indicate failure

def decrypt_data(data_with_iv, key, data_dir):
    """Extract IV and decrypt data using AES-CFB."""
    try:
        if len(data_with_iv) < IV_SIZE:
            log_debug("Error: Encrypted data too short (missing IV)")
            print("Error: Encrypted data too short (missing IV)")
            return None
        iv = data_with_iv[:IV_SIZE]
        encrypted_data = data_with_iv[IV_SIZE:]
        log_debug(f"Extracted IV: {iv.hex()}")
        log_debug(f"Encrypted data size: {len(encrypted_data)} bytes")

        # Save components for debugging
        iv_file = os.path.join(data_dir, "extracted_iv.bin")
        with open(iv_file, "wb") as f: f.write(iv)
        encrypted_file = os.path.join(data_dir, "encrypted_data.bin") # Overwrites sender's if exists
        with open(encrypted_file, "wb") as f: f.write(encrypted_data)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_file = os.path.join(data_dir, "decrypted_data.bin")
        with open(decrypted_file, "wb") as f: f.write(decrypted_data)
        log_debug(f"Decrypted data size: {len(decrypted_data)}")
        return decrypted_data
    except Exception as e:
        log_debug(f"Decryption error: {e}")
        print(f"\nDecryption error: {e}")
        return None

# --- Data Handling & Integrity ---

def chunk_data(data, chunk_size, logs_dir):
    """Split data into chunks of specified size."""
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    log_debug(f"Split data into {len(chunks)} chunks of max size {chunk_size}")

    # Save chunk details for debugging
    chunk_info = {
        i+1: {
            "size": len(chunk),
            "data_hex_preview": chunk[:64].hex() + ("..." if len(chunk) > 64 else "")
        } for i, chunk in enumerate(chunks)
    }
    chunks_json = os.path.join(logs_dir, "chunks_info.json")
    try:
        with open(chunks_json, "w") as f:
            json.dump(chunk_info, f, indent=2)
    except IOError as e:
         log_debug(f"Error saving chunk info log: {e}")

    return chunks

def verify_data_integrity(data, logs_dir, data_dir):
    """Verify and remove trailing SHA-256 checksum. Returns (data_without_checksum, checksum_ok)."""
    if len(data) <= INTEGRITY_CHECK_SIZE:
        log_debug(f"Error: Data too short ({len(data)} bytes) to contain integrity checksum ({INTEGRITY_CHECK_SIZE} bytes)")
        print("Error: Data too short to contain integrity checksum")
        return data, False # Return original data, mark as failed

    file_data = data[:-INTEGRITY_CHECK_SIZE]
    received_checksum = data[-INTEGRITY_CHECK_SIZE:]

    # Save components for debugging
    data_file = os.path.join(data_dir, "data_without_checksum.bin")
    with open(data_file, "wb") as f: f.write(file_data)
    checksum_file = os.path.join(data_dir, "received_sha256_checksum.bin")
    with open(checksum_file, "wb") as f: f.write(received_checksum)

    calculated_checksum = hashlib.sha256(file_data).digest()
    calc_checksum_file = os.path.join(data_dir, "calculated_sha256_checksum.bin")
    with open(calc_checksum_file, "wb") as f: f.write(calculated_checksum)

    checksum_match = (calculated_checksum == received_checksum)

    checksum_info = {
        "expected_sha256": calculated_checksum.hex(),
        "received_sha256": received_checksum.hex(),
        "match": checksum_match
    }
    checksum_json = os.path.join(logs_dir, "checksum_verification.json")
    with open(checksum_json, "w") as f: json.dump(checksum_info, f, indent=2)

    if not checksum_match:
        log_debug("Warning: Data integrity check failed - checksums don't match")
        log_debug(f"  Expected: {calculated_checksum.hex()}")
        log_debug(f"  Received: {received_checksum.hex()}")
        print("\nWarning: Data integrity check failed!")
        # Return the data *without* the bad checksum
        return file_data, False
    else:
        log_debug("Data integrity verified successfully")
        print("\nData integrity verified successfully")
        # Return data *without* the verified checksum
        return file_data, True
