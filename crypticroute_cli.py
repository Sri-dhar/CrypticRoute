#!/usr/bin/env python3
"""
CrypticRoute - Combined Command Line Interface (Sender & Receiver)
"""

import sys
import os
import argparse
import traceback

# Ensure the package directory is in the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    from crypticroute.common.utils import setup_directories, log_debug
    from crypticroute.common.constants import (
        MAX_CHUNK_SIZE, DEFAULT_OUTPUT_DIR, SENDER_SESSION_PREFIX, RECEIVER_SESSION_PREFIX,
        LATEST_SENDER_LINK, LATEST_RECEIVER_LINK, ACK_WAIT_TIMEOUT, MAX_RETRANSMISSIONS,
        DISCOVERY_TIMEOUT_SENDER, DISCOVERY_TIMEOUT_RECEIVER
    )
    from crypticroute.sender.core import send_file_logic
    from crypticroute.receiver.core import receive_file_logic
except ImportError as e:
    print(f"Error importing CrypticRoute modules: {e}")
    print("Please ensure the script is run from the project root directory or the crypticroute package is installed.")
    sys.exit(1)

def parse_arguments():
    """Parse command line arguments for the combined CLI."""
    parser = argparse.ArgumentParser(
        description='CrypticRoute - Combined Sender/Receiver CLI',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='mode', required=True, help='Operating mode')

    # --- Sender Subparser ---
    sender_parser = subparsers.add_parser('sender', help='Run in sender mode', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # Input/Key
    sender_parser.add_argument('--input', '-i', required=True, help='Input file to send')
    sender_parser.add_argument('--key', '-k', required=True,
                               help='Encryption key file (REQUIRED for discovery/encryption). Can be raw bytes or hex string.')
    # Network/Discovery
    sender_parser.add_argument('--interface', '-I',
                               help='Network interface for discovery probes (e.g., eth0). If omitted, attempts to find default.')
    # Transmission Params
    sender_parser.add_argument('--delay', '-d', type=float, default=0.1,
                               help='Delay between sending data chunks in seconds.')
    sender_parser.add_argument('--chunk-size', '-c', type=int, default=MAX_CHUNK_SIZE,
                               help=f'Payload chunk size in bytes (max: {MAX_CHUNK_SIZE}).')
    # Reliability/Timeouts
    sender_parser.add_argument('--ack-timeout', '-at', type=int, default=ACK_WAIT_TIMEOUT,
                               help='Timeout (seconds) waiting for ACK before retransmitting a chunk.')
    sender_parser.add_argument('--max-retries', '-r', type=int, default=MAX_RETRANSMISSIONS,
                               help='Maximum retransmission attempts per chunk.')
    sender_parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT_SENDER,
                               help='Timeout (seconds) for receiver discovery.')
    # Output
    sender_parser.add_argument('--output-dir', '-o', default=DEFAULT_OUTPUT_DIR,
                               help='Parent directory for session outputs.')

    # --- Receiver Subparser ---
    receiver_parser = subparsers.add_parser('receiver', help='Run in receiver mode', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    receiver_parser.add_argument('--output', '-o', required=True, help='Output file path for received data')
    receiver_parser.add_argument('--key', '-k', required=True,
                                 help='Decryption key file (REQUIRED for discovery/decryption)')
    receiver_parser.add_argument('--interface', '-i',
                                 help='Network interface to listen on (e.g., eth0). If omitted, Scapy attempts default.')
    # Inactivity Timeout: It sets a duration in seconds for which 
    # the receiver will wait without receiving any relevant packets
    # from the sender after the initial discovery and connection phase has begun.
    receiver_parser.add_argument('--timeout', '-t', type=int, default=120,
                                 help='Inactivity timeout in seconds (stops listening if no packets received).')
    receiver_parser.add_argument('--output-dir', '-d', default=DEFAULT_OUTPUT_DIR,
                                 help='Parent directory for session outputs.')
    receiver_parser.add_argument('--discovery-timeout', '-dt', type=int, default=DISCOVERY_TIMEOUT_RECEIVER,
                                 help='Timeout (seconds) for initial sender discovery phase.')

    return parser.parse_args()

def main():
    """Main function for the combined CLI."""
    # Check for root privileges early
    if os.geteuid() != 0:
        print("Error: This script requires root privileges to send/sniff packets.")
        sys.exit(1)

    args = parse_arguments()

    # Setup directories and logging based on mode
    session_prefix = SENDER_SESSION_PREFIX if args.mode == 'sender' else RECEIVER_SESSION_PREFIX
    latest_link = LATEST_SENDER_LINK if args.mode == 'sender' else LATEST_RECEIVER_LINK
    output_dir_arg = args.output_dir # Both subparsers use --output-dir, but receiver also has -d alias

    try:
        session_paths = setup_directories(output_dir_arg, session_prefix, latest_link)
    except Exception as e:
        print(f"Error setting up output directories: {e}")
        sys.exit(1)

    log_debug(f"--- CrypticRoute CLI Start (Mode: {args.mode}) ---")
    log_debug(f"Command line arguments: {sys.argv}")
    log_debug(f"Parsed arguments: {args}")
    log_debug(f"Session paths: {session_paths}")

    success = False
    try:
        if args.mode == 'sender':
            # Validate chunk size for sender
            chunk_size = args.chunk_size
            if chunk_size <= 0 or chunk_size > MAX_CHUNK_SIZE:
                print(f"Warning: Invalid chunk size ({chunk_size}). Using {MAX_CHUNK_SIZE} bytes.")
                log_debug(f"Chunk size adjusted from {chunk_size} to {MAX_CHUNK_SIZE}")
                chunk_size = MAX_CHUNK_SIZE

            # Check file existence for sender
            if not os.path.isfile(args.input):
                print(f"Error: Input file not found: {args.input}")
                log_debug(f"Input file not found: {args.input}")
                sys.exit(1)
            if not os.path.isfile(args.key):
                print(f"Error: Key file not found: {args.key}")
                log_debug(f"Key file not found: {args.key}")
                sys.exit(1)

            success = send_file_logic(
                file_path=args.input,
                interface=args.interface,
                key_path=args.key,
                chunk_size=chunk_size,
                delay=args.delay,
                ack_timeout=args.ack_timeout,
                max_retries=args.max_retries,
                discovery_timeout=args.discovery_timeout,
                session_paths=session_paths
            )

        elif args.mode == 'receiver':
            # Check key file existence for receiver
            if not os.path.isfile(args.key):
                print(f"Error: Key file not found: {args.key}")
                log_debug(f"Key file not found: {args.key}")
                sys.exit(1)

            success = receive_file_logic(
                output_path=args.output,
                key_path=args.key,
                interface=args.interface,
                timeout=args.timeout, # Corrected argument name
                discovery_timeout=args.discovery_timeout,
                session_paths=session_paths
            )

    except PermissionError:
         print("\n[ERROR] Permission denied during sniffing. Please ensure the script is run as root or with necessary capabilities.")
         log_debug("PermissionError caught during sniffing.")
         success = False # Ensure failure exit code
    except KeyboardInterrupt:
        print("\n[ABORT] Keyboard interrupt received in CLI. Exiting.")
        log_debug("KeyboardInterrupt received in CLI.")
        # Core logic's finally block should handle cleanup
    except Exception as e:
        print(f"\n[FATAL CLI ERROR] An unexpected error occurred: {e}")
        traceback.print_exc()
        log_debug(f"FATAL CLI ERROR: {e}\n{traceback.format_exc()}")
    finally:
        log_debug(f"--- CrypticRoute CLI End (Mode: {args.mode}, Overall Success: {success}) ---")
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
