#!/usr/bin/env python3

import sys
from scapy.all import sniff, IP, UDP, IPOption_Timestamp, Raw # Added Raw
import binascii
import math
# Removed signal and threading imports
import threading # Keep threading only for Event

LISTEN_PORT = 11234
EXPECTED_OPTIONS = 5
BITS_PER_OPTION = 4
CHUNK_BITS = EXPECTED_OPTIONS * BITS_PER_OPTION

# Define the End-of-Transmission marker (must match sender)
EOT_MARKER = '0' * CHUNK_BITS

# Global variables
all_received_bits = ""
packets_received = 0 # Counter for received packets
reception_start_time = None # Time first relevant packet received (matching filter)
first_data_packet_time = None # Time first packet with valid data bits received
reception_end_time = None # Time EOT received or sniff stopped
# Event to signal sniffing to stop
sniff_stop_event = threading.Event()


def bits_to_string(bits):
    """Converts a string of bits back to an ASCII string."""
    # Ensure the bit string length is a multiple of 8
    num_chars = math.ceil(len(bits) / 8)
    padded_bits = bits.ljust(num_chars * 8, '0')
    byte_array = bytearray()
    for i in range(0, len(padded_bits), 8):
        byte = padded_bits[i:i+8]
        try:
            byte_array.append(int(byte, 2))
        except ValueError:
            # Handle cases where a byte might not be valid if padding was excessive
            # or data was corrupted. For this example, we'll skip invalid bytes.
            print(f"[!] Skipping invalid byte sequence: {byte}")
            continue

    # Attempt to decode as UTF-8, replacing errors
    # Handle potential errors if bits don't form valid UTF-8
    try:
        return byte_array.decode('utf-8', errors='replace')
    except UnicodeDecodeError:
        print("[!] Error decoding bytes to UTF-8.")
        return "[Decoding Error]"

# Removed timer functions (reset_inactivity_timer, stop_sniffing)

def packet_handler(packet):
    """Processes sniffed packets to extract covert data."""
    global all_received_bits, sniff_stop_event, packets_received, reception_start_time, first_data_packet_time, reception_end_time

    # Check if stop event is already set (e.g., by previous EOT)
    if sniff_stop_event.is_set():
        return

    if packet.haslayer(IP) and packet.haslayer(UDP):
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        # Check if it's the correct destination port and has IP options
        if udp_layer.dport == LISTEN_PORT and ip_layer.options:
            if reception_start_time is None: # Record time of first valid packet
                reception_start_time = time.time()

            packets_received += 1 # Increment packet counter here
            # Optional: Log the raw payload to see chunk number
            payload_str = ""
            if packet.haslayer(Raw):
                try:
                    payload_str = f" (Payload: {packet.getlayer(Raw).load.decode('utf-8', errors='ignore')})"
                except Exception:
                    payload_str = " (Payload: <undecodable>)"
            print(f"\n[*] Received packet from {ip_layer.src}{payload_str}")

            current_chunk_bits = ""
            options_valid = False

            # Check if options are parsed as IPOption_Timestamp
            # or as Raw bytes (more likely)
            if isinstance(ip_layer.options, list) and len(ip_layer.options) > 0:
                 # Handle case where Scapy might still parse *some* options
                 # This part is less likely to be hit with Raw sender but kept for robustness
                 timestamp_options = [opt for opt in ip_layer.options if isinstance(opt, IPOption_Timestamp)]
                 if len(timestamp_options) == EXPECTED_OPTIONS:
                     print(f"[+] Found {len(timestamp_options)} parsed timestamp options (IPOption_Timestamp).")
                     options_valid = True
                     for i, option in enumerate(timestamp_options):
                         try:
                             # Convert parsed option back to bytes to reliably get overflow
                             option_bytes = bytes(option)
                             if len(option_bytes) == 8:
                                 # According to IP Timestamp Option format:
                                 # Byte 0: Type (0x44)
                                 # Byte 1: Length (8)
                                 # Byte 2: Pointer (5)
                                 # Byte 3: Overflow (upper 4 bits) + Flag (lower 4 bits)
                                 overflow_flag_byte = option_bytes[3]
                                 overflow_val = overflow_flag_byte >> 4 # Extract upper 4 bits
                                 flag_val = overflow_flag_byte & 0x0F # Extract lower 4 bits

                             # Optional: Add check for flag_val == 0 if needed
                             # if flag_val == 0:
                             bits = format(overflow_val, f'0{BITS_PER_OPTION}b')
                             current_chunk_bits += bits
                             # print(f"  - Option {i+1}: RawByte[3]={hex(overflow_flag_byte)}, Overflow={overflow_val} -> Bits='{bits}'") # Less verbose
                             # else:
                             #     print(f"  - Option {i+1}: Parsed but skipped (unexpected flag value: {flag_val})")
                             #     current_chunk_bits += '?' * BITS_PER_OPTION
                         except Exception as e:
                             print(f"  - Option {i+1}: Error processing parsed option: {e}")
                             current_chunk_bits += '?' * BITS_PER_OPTION
                         except Exception as e:
                             print(f"  - Option {i+1}: Error processing parsed option: {e}")
                             extracted_bits += '?' * BITS_PER_OPTION
                 # Check if options were passed as Raw bytes
                 elif len(ip_layer.options) == 1 and isinstance(ip_layer.options[0], Raw):
                     raw_options_data = ip_layer.options[0].load
                     expected_len = EXPECTED_OPTIONS * 8 # 8 bytes per option
                     print(f"[+] Found Raw IP options data ({len(raw_options_data)} bytes).")
                     if len(raw_options_data) == expected_len:
                         options_valid = True
                         for i in range(EXPECTED_OPTIONS):
                             option_chunk = raw_options_data[i*8:(i+1)*8]
                             opt_type = option_chunk[0]
                             opt_len = option_chunk[1]
                             opt_ptr = option_chunk[2]
                             overflow_flag_byte = option_chunk[3]

                             # Validate the structure we expect from the sender
                             if opt_type == 0x44 and opt_len == 8 and opt_ptr == 5:
                                 overflow_val = overflow_flag_byte >> 4 # Extract upper 4 bits
                                 bits = format(overflow_val, f'0{BITS_PER_OPTION}b')
                                 current_chunk_bits += bits
                                 # print(f"  - Raw Option {i+1}: Overflow={overflow_val} -> Bits='{bits}'") # Less verbose
                             else:
                                 print(f"  - Raw Option {i+1}: Skipped (unexpected format: type={hex(opt_type)}, len={opt_len}, ptr={opt_ptr})")
                                 current_chunk_bits += '?' * BITS_PER_OPTION
                     else:
                         print(f"[!] Raw options data has unexpected length: {len(raw_options_data)} bytes (expected {expected_len}). Skipping.")
                 else:
                     print(f"[!] Unexpected options format found: {type(ip_layer.options)}. Skipping.")

            # Process extracted bits for this chunk if options were valid
            if options_valid:
                # Record time of first valid data packet *before* checking EOT
                if first_data_packet_time is None and len(current_chunk_bits) == CHUNK_BITS and '?' not in current_chunk_bits:
                    first_data_packet_time = time.time()

                if len(current_chunk_bits) == CHUNK_BITS and '?' not in current_chunk_bits:
                    # Check if the received chunk is the EOT marker
                    if current_chunk_bits == EOT_MARKER:
                        reception_end_time = time.time() # Record time EOT received
                        print(f"[+] EOT marker received: {current_chunk_bits}")
                        print("[*] Stopping sniff...")
                        sniff_stop_event.set() # Signal sniff to stop
                    else:
                        # It's a regular data chunk
                        print(f"[+] Extracted chunk bits: {current_chunk_bits}")
                        all_received_bits += current_chunk_bits
                elif '?' in current_chunk_bits:
                    print(f"[!] Incomplete data in chunk: {current_chunk_bits}")
                    # Decide how to handle incomplete chunks, e.g., add placeholders or discard
                    # For now, add placeholders to maintain length consistency if possible
                    all_received_bits += current_chunk_bits.replace('?', '0') # Or discard chunk
                else:
                    print(f"[!] Extracted unexpected number of bits in chunk: {len(current_chunk_bits)}. Skipping chunk.")
            elif not options_valid and isinstance(ip_layer.options, list) and len(ip_layer.options) > 0 :
                 print(f"[!] Could not process IP options found in this packet.")

        # else: # Packet on wrong port or without options
            # print(".", end="", flush=True) # Reduce noise
            pass

import time # Add time import

def main():
    global all_received_bits, packets_received, reception_start_time, first_data_packet_time, reception_end_time # Ensure we clear previous runs
    all_received_bits = ""
    packets_received = 0
    reception_start_time = None
    first_data_packet_time = None
    reception_end_time = None
    sniff_stop_event.clear() # Ensure event is clear at start

    print(f"[*] Starting receiver...")
    print(f"[*] Listening for UDP packets on port {LISTEN_PORT}")
    print("[*] Waiting for covert message chunks...")
    print(f"[*] Will stop upon receiving EOT marker ({EOT_MARKER}).")
    print("[*] Note: This requires root/administrator privileges to sniff packets.")

    # Removed timer start

    try:
        # Sniff until the stop event is set by the EOT marker detection
        sniff(filter=f"udp and dst port {LISTEN_PORT}",
              prn=packet_handler,
              stop_filter=lambda p: sniff_stop_event.is_set(), # Stop when event is set
              store=0)
    except PermissionError:
        print(f"\n[!] Error: Sniffing packets requires root/administrator privileges.")
        print(f"[*] Try running: sudo {sys.argv[0]}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred during sniffing: {e}")
    # Removed finally block with timer cancellation

    # --- Sniffing finished ---
    # If sniffing stopped but EOT wasn't the reason (e.g., manual interrupt), record end time now
    if reception_end_time is None and reception_start_time is not None: # Avoid setting end time if no packets were ever received
        reception_end_time = time.time()

    total_sniffing_duration = 0
    if reception_start_time and reception_end_time:
        total_sniffing_duration = reception_end_time - reception_start_time

    data_transmission_duration = 0
    if first_data_packet_time and reception_end_time:
         data_transmission_duration = reception_end_time - first_data_packet_time

    print("\n" + "="*30)
    print("[*] Reception Summary:")
    print(f"[*]   Total packets received (matching filter): {packets_received}")
    print(f"[*]   Total covert bits extracted: {len(all_received_bits)}")

    # Print Data Transmission Duration
    if first_data_packet_time:
        print(f"[*]   Data Transmission Duration: {data_transmission_duration:.4f} seconds (First data packet to EOT/stop)")
    else:
        print("[*]   Data Transmission Duration: N/A (No valid data packets received)")

    # Print Total Sniffing Duration
    if reception_start_time:
        print(f"[*]   Total Sniffing Duration: {total_sniffing_duration:.4f} seconds (First matching packet to EOT/stop)")
    else:
        print("[*]   Total Sniffing Duration: N/A (No matching packets received)")

    print(f"[*]   Accumulated bits: {all_received_bits}")

    if all_received_bits:
        final_message = "[Decoding Error]" # Default in case of error
        try:
            # Attempt to decode the accumulated bits
            # Note: Padding on the last chunk might result in extra null chars or errors
            # depending on the original message length.
            final_message = bits_to_string(all_received_bits)
        except Exception as e:
            print(f"[!] Error decoding final bits: {e}")
            # Keep the default error message

        # Always print the result (either decoded message or error placeholder)
        print(f"[*] Final Decoded Message (approx): {final_message}")

        # Always attempt to save the result to a file
        output_filename = "received_message.txt"
        try:
            with open(output_filename, "w", encoding="utf-8") as f:
                f.write(final_message)
            print(f"[*] Message saved to: {output_filename}")
        except IOError as e:
            print(f"[!] Error saving message to file {output_filename}: {e}")
    else:
        print("[*] No covert data bits were successfully extracted.")
    print("="*30)


if __name__ == "__main__":
    main()
