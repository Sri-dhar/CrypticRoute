#!/usr/bin/env python3

import sys
from scapy.all import sniff, IP, UDP, IPOption_Timestamp, Raw # Added Raw
import binascii
import math

LISTEN_PORT = 11234
EXPECTED_OPTIONS = 5
BITS_PER_OPTION = 4
TOTAL_BITS = EXPECTED_OPTIONS * BITS_PER_OPTION

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
    return byte_array.decode('utf-8', errors='replace')


def packet_handler(packet):
    """Processes sniffed packets to extract covert data."""
    if packet.haslayer(IP) and packet.haslayer(UDP):
        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)

        # Check if it's the correct destination port and has IP options
        if udp_layer.dport == LISTEN_PORT and ip_layer.options:
            print(f"\n[*] Received packet from {ip_layer.src} on port {udp_layer.dport}")
            extracted_bits = ""
            options_valid = False

            # Check if options are parsed as IPOption_Timestamp (less likely now)
            # or as Raw bytes (more likely)
            if isinstance(ip_layer.options, list) and len(ip_layer.options) > 0:
                 # Handle case where Scapy might still parse *some* options
                 # This part is less likely to be hit with Raw sender but kept for robustness
                 timestamp_options = [opt for opt in ip_layer.options if isinstance(opt, IPOption_Timestamp)]
                 if len(timestamp_options) == EXPECTED_OPTIONS:
                     print(f"[+] Found {len(timestamp_options)} parsed timestamp options (IPOption_Timestamp).")
                     options_valid = True
                     for i, option in enumerate(timestamp_options):
                         if option.length == 8 and option.flag == 0:
                             overflow_val = option.overflow # Scapy might parse this if it recognizes the structure
                             bits = format(overflow_val, f'0{BITS_PER_OPTION}b')
                             extracted_bits += bits
                             print(f"  - Option {i+1}: Overflow={overflow_val} -> Bits='{bits}'")
                         else:
                             print(f"  - Option {i+1}: Parsed but skipped (unexpected format: length={option.length}, flag={option.flag})")
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
                                 extracted_bits += bits
                                 print(f"  - Raw Option {i+1}: Overflow={overflow_val} -> Bits='{bits}'")
                             else:
                                 print(f"  - Raw Option {i+1}: Skipped (unexpected format: type={hex(opt_type)}, len={opt_len}, ptr={opt_ptr})")
                                 extracted_bits += '?' * BITS_PER_OPTION
                     else:
                         print(f"[!] Raw options data has unexpected length: {len(raw_options_data)} bytes (expected {expected_len}). Skipping.")
                 else:
                     print(f"[!] Unexpected options format found: {type(ip_layer.options)}. Skipping.")

            # Process extracted bits if options were valid
            if options_valid:
                if len(extracted_bits) == TOTAL_BITS and '?' not in extracted_bits:
                    print(f"\n[*] Extracted {TOTAL_BITS} bits: {extracted_bits}")
                    try:
                        decoded_message = bits_to_string(extracted_bits)
                        print(f"[*] Decoded message (approx): {decoded_message}")
                    except Exception as e:
                        print(f"[!] Error decoding bits to string: {e}")
                elif '?' in extracted_bits:
                    print(f"\n[!] Incomplete data extracted due to unexpected option format: {extracted_bits}")
                else:
                    print(f"\n[!] Extracted unexpected number of bits: {len(extracted_bits)}. Skipping.")
            elif not options_valid and isinstance(ip_layer.options, list) and len(ip_layer.options) > 0 :
                 # Only print skipping message if options were present but not processable
                 print(f"[!] Could not process IP options found. Skipping packet.")

        # else:
            # print(".", end="", flush=True) # Indicate non-matching packet received (e.g., wrong port)

def main():
    print(f"[*] Starting receiver...")
    print(f"[*] Listening for UDP packets on port {LISTEN_PORT}")
    print("[*] Waiting for covert message...")
    print("Note: This requires root/administrator privileges to sniff packets.")

    try:
        # Sniff indefinitely for UDP packets on the specified port
        sniff(filter=f"udp and dst port {LISTEN_PORT}", prn=packet_handler, store=0)
    except PermissionError:
        print(f"\n[!] Error: Sniffing packets requires root/administrator privileges.")
        print(f"[*] Try running: sudo {sys.argv[0]}")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
