#!/usr/bin/env python3

import sys
from scapy.all import IP, UDP, send, Raw # Removed IPOption_Timestamp
import binascii
import traceback # Add traceback import

def bits_to_int(bits):
    """Converts a string of bits to an integer."""
    if not bits:
        return 0
    return int(bits, 2)

def string_to_bits(s):
    """Converts an ASCII string to a string of bits."""
    return ''.join(format(ord(c), '08b') for c in s)

def create_timestamp_option_bytes(data_bits):
    """Creates raw bytes for 5 IP timestamp options with data in overflow."""
    if len(data_bits) != 20:
        raise ValueError("Data must be exactly 20 bits long for this implementation.")

    all_option_bytes = b''
    for i in range(5):
        chunk = data_bits[i*4:(i+1)*4]
        overflow_val = bits_to_int(chunk)
        flag_val = 0 # As per paper and implementation attempt

        # Calculate the byte containing overflow (upper 4 bits) and flag (lower 4 bits)
        overflow_flag_byte = (overflow_val << 4) | flag_val

        # Construct the option bytes:
        # Type (0x44), Length (8), Pointer (5), Overflow+Flag, Timestamp (0)
        option_bytes = bytes([
            0x44,  # Option Type: Timestamp
            8,     # Option Length: Minimal for flag=0 (1 timestamp slot)
            5,     # Pointer: Minimal value
            overflow_flag_byte, # Combined Overflow (bits 7-4) and Flag (bits 3-0)
            0, 0, 0, 0 # Dummy 32-bit timestamp value
        ])
        all_option_bytes += option_bytes
    return all_option_bytes

def main():
    if len(sys.argv) != 3:
        print(f"Usage: sudo {sys.argv[0]} <receiver_ip> <secret_message>")
        print("Note: Secret message will be truncated/padded to fit 20 bits.")
        sys.exit(1)

    receiver_ip = sys.argv[1]
    secret_message = sys.argv[2]
    dest_port = 11234 # Port used in the paper

    print(f"[*] Sending to {receiver_ip}:{dest_port}")
    print(f"[*] Original message: {secret_message}")

    # Convert message to bits and ensure it's 20 bits long
    message_bits = string_to_bits(secret_message)
    if len(message_bits) > 20:
        message_bits = message_bits[:20]
        print("[!] Message truncated to 20 bits.")
    elif len(message_bits) < 20:
        padding = '0' * (20 - len(message_bits))
        message_bits += padding
        print("[!] Message padded to 20 bits.")

    print(f"[*] Sending bits: {message_bits}")

    try:
        # Create raw bytes for the options
        raw_options = create_timestamp_option_bytes(message_bits)

        # Craft the packet: IP layer with raw options, UDP layer, optional raw payload
        ip_layer = IP(dst=receiver_ip, options=Raw(load=raw_options))
        udp_layer = UDP(dport=dest_port, sport=12345) # Random source port
        # Add some dummy payload if needed, though not strictly necessary for the technique
        payload = Raw(load="Covert Packet")

        packet = ip_layer / udp_layer / payload
        # packet.show() # Uncomment to see packet structure

        send(packet, verbose=0)
        print("[+] Packet sent successfully.")

    except ValueError as e:
        print(f"[!] Error: {e}")
    except PermissionError:
        print("[!] Error: Sending packets requires root/administrator privileges.")
        print(f"[*] Try running: sudo {sys.argv[0]} {receiver_ip} \"{secret_message}\"")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        print("--- Traceback ---")
        traceback.print_exc()
        print("---------------")

if __name__ == "__main__":
    main()
