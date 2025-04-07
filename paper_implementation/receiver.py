#!/usr/bin/env python3

import sys
from scapy.all import sniff, IP, UDP, IPOption_Timestamp, Raw # Added Raw
import binascii
import math
import signal # For timeout handling
import threading # For timeout handling

LISTEN_PORT = 11234
EXPECTED_OPTIONS = 5
BITS_PER_OPTION = 4
CHUNK_BITS = EXPECTED_OPTIONS * BITS_PER_OPTION # Renamed TOTAL_BITS

# Global variable to store accumulated bits across packets
all_received_bits = ""
# Timer to detect end of transmission (inactivity)
inactivity_timer = None
TIMEOUT_SECONDS = 2.0 # Stop sniffing after 2 seconds of inactivity
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

def reset_inactivity_timer():
    """Resets the inactivity timer."""
    global inactivity_timer
    if inactivity_timer:
        inactivity_timer.cancel()
    inactivity_timer = threading.Timer(TIMEOUT_SECONDS, stop_sniffing)
    inactivity_timer.start()

def stop_sniffing():
    """Signals the sniffing process to stop."""
    global sniff_stop_event
    print(f"\n[*] No packets received for {TIMEOUT_SECONDS} seconds. Stopping sniff.")
    sniff_stop_event.set()


def packet_handler(packet):
    """Processes sniffed packets to extract covert data."""
    global all_received_bits
    reset_inactivity_timer() # Reset timer on packet arrival

    if packet.haslayer(IP) and packet.haslayer(UDP):
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        # Check if it's the correct destination port and has IP options
        if udp_layer.dport == LISTEN_PORT and ip_layer.options:
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
                if len(current_chunk_bits) == CHUNK_BITS and '?' not in current_chunk_bits:
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

def main():
    print(f"[*] Starting receiver...")
    print(f"[*] Listening for UDP packets on port {LISTEN_PORT}")
    print("[*] Waiting for covert message chunks...")
    print(f"[*] Will stop after {TIMEOUT_SECONDS} seconds of inactivity.")
    print("[*] Note: This requires root/administrator privileges to sniff packets.")

    # Start the initial inactivity timer
    reset_inactivity_timer()

    try:
        # Sniff until the stop event is set by the timer
        sniff(filter=f"udp and dst port {LISTEN_PORT}",
              prn=packet_handler,
              stop_filter=lambda p: sniff_stop_event.is_set(),
              store=0)
    except PermissionError:
        print(f"\n[!] Error: Sniffing packets requires root/administrator privileges.")
        print(f"[*] Try running: sudo {sys.argv[0]}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred during sniffing: {e}")
    finally:
        # Ensure timer is cancelled on exit
        if inactivity_timer:
            inactivity_timer.cancel()

    # --- Sniffing finished ---
    print("\n" + "="*30)
    print("[*] Sniffing complete.")
    print(f"[*] Total bits received: {len(all_received_bits)}")
    print(f"[*] Accumulated bits: {all_received_bits}")

    if all_received_bits:
        try:
            # Attempt to decode the accumulated bits
            # Note: Padding on the last chunk might result in extra null chars or errors
            # depending on the original message length.
            final_message = bits_to_string(all_received_bits)
            print(f"[*] Final Decoded Message (approx): {final_message}")
        except Exception as e:
            print(f"[!] Error decoding final bits: {e}")
    else:
        print("[*] No covert data bits were successfully extracted.")
    print("="*30)


if __name__ == "__main__":
    main()
