#!/usr/bin/env python3

import sys
from scapy.all import sniff, IP, UDP, IPOption_Timestamp
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

            timestamp_options = [opt for opt in ip_layer.options if isinstance(opt, IPOption_Timestamp)]

            if len(timestamp_options) == EXPECTED_OPTIONS:
                print(f"[+] Found {len(timestamp_options)} timestamp options.")
                extracted_bits = ""
                for i, option in enumerate(timestamp_options):
                    # Ensure the option format matches what sender created (length 8, flag 0)
                    if option.length == 8 and option.flag == 0:
                        overflow_val = option.overflow
                        # Format as 4 bits (e.g., 5 -> '0101')
                        bits = format(overflow_val, f'0{BITS_PER_OPTION}b')
                        extracted_bits += bits
                        print(f"  - Option {i+1}: Overflow={overflow_val} -> Bits='{bits}'")
                    else:
                        print(f"  - Option {i+1}: Skipped (unexpected format: length={option.length}, flag={option.flag})")
                        extracted_bits += '?' * BITS_PER_OPTION # Indicate missing data

                if len(extracted_bits) == TOTAL_BITS and '?' not in extracted_bits:
                    print(f"\n[*] Extracted {TOTAL_BITS} bits: {extracted_bits}")
                    try:
                        # Attempt to decode the bits back to a string
                        decoded_message = bits_to_string(extracted_bits)
                        print(f"[*] Decoded message (approx): {decoded_message}")
                    except Exception as e:
                        print(f"[!] Error decoding bits to string: {e}")
                elif '?' in extracted_bits:
                     print(f"\n[!] Incomplete data extracted due to unexpected option format: {extracted_bits}")
                else:
                    print(f"\n[!] Extracted unexpected number of bits: {len(extracted_bits)}")

            else:
                print(f"[!] Expected {EXPECTED_OPTIONS} timestamp options, but found {len(timestamp_options)}. Skipping.")
        # else:
            # print(".", end="", flush=True) # Indicate non-matching packet received

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
