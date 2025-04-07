#!/usr/bin/env python3

import sys
import time # Added for delay
from scapy.all import IP, UDP, send, Raw
import binascii
import traceback

# Define the End-of-Transmission marker (20 bits)
EOT_MARKER = '0' * 20

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
        print(f"Usage: sudo {sys.argv[0]} <receiver_ip> <input_file_path>")
        print(f"Example: sudo {sys.argv[0]} 192.168.1.100 message.txt")
        sys.exit(1)

    receiver_ip = sys.argv[1]
    input_file_path = sys.argv[2]
    dest_port = 11234 # Port used in the paper
    chunk_size = 20 # Bits per packet
    delay_between_packets = 0.1 # Seconds

    # Read the secret message from the file
    try:
        with open(input_file_path, 'r', encoding='utf-8') as f:
            secret_message = f.read()
        print(f"[*] Read message from: {input_file_path}")
    except FileNotFoundError:
        print(f"[!] Error: Input file not found at '{input_file_path}'")
        sys.exit(1)
    except IOError as e:
        print(f"[!] Error reading input file '{input_file_path}': {e}")
        sys.exit(1)

    print(f"[*] Sending to {receiver_ip}:{dest_port}")
    # print(f"[*] Original message: {secret_message}") # Maybe too long to print

    # Convert the entire message to bits
    message_bits = string_to_bits(secret_message)
    total_bits = len(message_bits)
    print(f"[*] Total bits to send: {total_bits}")

    packets_sent = 0
    start_time = None # Initialize start time
    try:
        for i in range(0, total_bits, chunk_size):
            if start_time is None: # Record time just before sending the first packet
                start_time = time.time()

            chunk = message_bits[i:i+chunk_size]

            # Pad the last chunk if necessary
            if len(chunk) < chunk_size:
                padding = '0' * (chunk_size - len(chunk))
                chunk += padding
                print(f"[*] Padding last chunk: {padding}")

            print(f"\n[*] Preparing chunk {packets_sent + 1}: {chunk}")

            # Create raw bytes for the options for this chunk
            try:
                 raw_options = create_timestamp_option_bytes(chunk)
            except ValueError as e:
                 print(f"[!] Error creating options for chunk {packets_sent + 1}: {e}")
                 continue # Skip this chunk if options can't be made (shouldn't happen with padding)


            # Craft the packet: IP layer with raw options, UDP layer, optional raw payload
            # Add packet sequence number in payload for potential reordering handling (optional)
            payload_content = f"Chunk {packets_sent + 1}"
            ip_layer = IP(dst=receiver_ip, options=Raw(load=raw_options))
            udp_layer = UDP(dport=dest_port, sport=12345) # Random source port
            payload = Raw(load=payload_content)

            packet = ip_layer / udp_layer / payload
            # packet.show() # Uncomment to see packet structure

            send(packet, verbose=0)
            print(f"[+] Chunk {packets_sent + 1} sent successfully.")
            packets_sent += 1
            time.sleep(delay_between_packets) # Add a small delay

        # Send the EOT marker packet
        print(f"\n[*] Sending EOT marker: {EOT_MARKER}")
        try:
            raw_options_eot = create_timestamp_option_bytes(EOT_MARKER)
            ip_layer_eot = IP(dst=receiver_ip, options=Raw(load=raw_options_eot))
            udp_layer_eot = UDP(dport=dest_port, sport=12345)
            payload_eot = Raw(load="EOT")
            packet_eot = ip_layer_eot / udp_layer_eot / payload_eot
            send(packet_eot, verbose=0)
            print("[+] EOT marker sent successfully.")
            packets_sent += 1
        except Exception as e:
            print(f"[!] Error sending EOT marker: {e}")
        finally:
            end_time = time.time() # Record end time
            print("--- Traceback ---")
            traceback.print_exc()
            print("---------------")


        total_time = end_time - start_time
        print("\n" + "="*30)
        print("[*] Transmission Summary:")
        print(f"[*]   Total bits intended: {total_bits}")
        print(f"[*]   Total packets sent (including EOT): {packets_sent}")
        print(f"[*]   Total transmission time: {total_time:.4f} seconds")
        print("="*30)

    except ValueError as e: # Catch potential errors during option creation
        print(f"[!] Error: {e}")
    except PermissionError:
        print("[!] Error: Sending packets requires root/administrator privileges.")
        print(f"[*] Try running: sudo {sys.argv[0]} {receiver_ip} {input_file_path}")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        print("--- Traceback ---")
        traceback.print_exc()
        print("---------------")

if __name__ == "__main__":
    main()
