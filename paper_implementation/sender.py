#!/usr/bin/env python3

import sys
from scapy.all import IP, UDP, IPOption_Timestamp, send, Raw
import binascii

def bits_to_int(bits):
    """Converts a string of bits to an integer."""
    if not bits:
        return 0
    return int(bits, 2)

def string_to_bits(s):
    """Converts an ASCII string to a string of bits."""
    return ''.join(format(ord(c), '08b') for c in s)

def create_timestamp_options(data_bits):
    """Creates a list of 5 IPOption_Timestamp objects with data in overflow."""
    if len(data_bits) != 20:
        raise ValueError("Data must be exactly 20 bits long for this implementation.")

    options = []
    for i in range(5):
        chunk = data_bits[i*4:(i+1)*4]
        overflow_val = bits_to_int(chunk)

        # Create a timestamp option
        # Type=68 (0x44), Length=8 (minimum for flag 0), Pointer=5 (minimum)
        # Flag=0 (timestamps only), Overflow=covert data
        # We add a dummy timestamp value (0) as Scapy might require it for length 8.
        # Note: The paper's approach of 5 separate options is unusual.
        # A single option holding 5 timestamps would normally have length 24.
        # We follow the paper's description of 5 distinct options.
        option = IPOption_Timestamp(
            copy_flag=0,
            optclass=2, # Debugging and Measurement
            option=4,   # Timestamp
            length=8,   # Minimal length for flag=0 (includes one timestamp slot)
            pointer=5,  # Minimal pointer value
            overflow=overflow_val,
            flag=0,     # Timestamps only
            timestamps=[0] # Dummy timestamp to satisfy length 8
        )
        options.append(option)
    return options

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
        timestamp_options = create_timestamp_options(message_bits)

        # Craft the packet: IP layer with options, UDP layer, optional raw payload
        ip_layer = IP(dst=receiver_ip, options=timestamp_options)
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

if __name__ == "__main__":
    main()
