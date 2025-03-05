import sys
import os
import socket
import subprocess
import argparse
from scapy.all import *

def read_key_file(key_file):
    """Read encryption key from a file"""
    try:
        with open(key_file, 'r') as f:
            key = f.read().strip()
        return key
    except FileNotFoundError:
        print(f"Error: Key file '{key_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading key file: {str(e)}")
        sys.exit(1)

def decrypt_file(encrypted_file, output_file, key):
    """Decrypt the file using the AES encryption binary"""
    try:
        aes_binary = "./aes_encrypt"  # Adjust path as needed
        
        result = subprocess.run(
            [aes_binary, "-d", encrypted_file, output_file, key],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Decryption failed: {result.stderr}")
            return False
        
        print(f"Successfully decrypted {encrypted_file} to {output_file}")
        return True
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        return False

def is_zero_chunk(data):
    """Check if the data is all zeros"""
    return all(byte == 0 for byte in data)

def receive_and_decode_packets(interface, key_file, output_file, count=100, filter_ip=None):
    """
    Sniff packets with IP options and reconstruct the hidden message between all-zero markers.
    """
    received_chunks = []
    collecting = False  # Flag to indicate when to start/stop collecting data
    
    print(f"Sniffing for packets with IP options on {interface}...")
    print("Waiting for initial all-zero packet to start collection...")
    
    packet_filter = "ip[0] & 0x0f > 5"  # Packets with IP options
    if filter_ip:
        packet_filter += f" and host {filter_ip}"
    
    def extract_options(packet):
        nonlocal collecting, received_chunks
        print(f"[DEBUG] Packet received: {packet.summary()}")
        
        if IP in packet and packet[IP].options:
            print(f"[DEBUG] IP Options found: {packet[IP].options}")
            for option in packet[IP].options:
                try:
                    print(f"[DEBUG] Option details: {option}")
                    if hasattr(option, 'value') and len(option.value) > 4:
                        data = option.value[4:]  # Skip header bytes
                        print(f"[DEBUG] Option data: {data.hex()}")
                        
                        if is_zero_chunk(data):
                            if not collecting:
                                print("Received initial all-zero packet. Starting data collection.")
                                collecting = True
                            elif collecting and received_chunks:  # Ensure we have data before stopping
                                print("Received final all-zero packet. Stopping data collection.")
                                collecting = False
                                return True
                        elif collecting:
                            hex_chunk = ' '.join(f'{byte:02x}' for byte in data)
                            received_chunks.append(hex_chunk)
                            print(f"Received chunk: {hex_chunk}")
                except Exception as e:
                    print(f"[DEBUG] Error parsing option: {e}")
        return False

    try:
        # Sniff until stopped by the final zero packet or count is reached
        packets = sniff(
            iface=interface,
            filter=packet_filter,
            prn=lambda p: extract_options(p),
            stop_filter=lambda p: extract_options(p),  # Stop when extract_options returns True
            count=count
        )
        print(f"Finished sniffing. Captured {len(packets)} packets with IP options.")
        
        # Reconstruct the encrypted file if we received any chunks
        if received_chunks:
            received_encrypted = 'received_encrypted.bin'
            with open(received_encrypted, 'wb') as outfile:
                for chunk in received_chunks:
                    outfile.write(bytes.fromhex(chunk.replace(' ', '')))
            
            # Read key and attempt decryption
            try:
                key = read_key_file(key_file)
                if decrypt_file(received_encrypted, output_file, key):
                    print(f"Successfully decrypted and saved to {output_file}")
                else:
                    print("Decryption failed.")
            except Exception as e:
                print(f"Decryption error: {e}")
        else:
            print("No data chunks received between markers.")
        
        return received_chunks
    except Exception as e:
        print(f"Error sniffing packets: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description='Encrypted Steganographic Packet Receiver with Zero Markers')
    parser.add_argument('--interface', default='wlan0', help='Network interface to sniff on')
    parser.add_argument('--key-file', default='key.txt', help='Path to decryption key file')
    parser.add_argument('--output-file', default='received_output.txt', help='Path to save decrypted output')
    parser.add_argument('--count', type=int, default=100, help='Maximum number of packets to capture')
    parser.add_argument('--filter-ip', help='Optional IP address to filter')
    
    args = parser.parse_args()
    
    receive_and_decode_packets(
        interface=args.interface,
        key_file=args.key_file,
        output_file=args.output_file,
        count=args.count,
        filter_ip=args.filter_ip
    )

def print_port():
    # Create a temporary socket to get the port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        
        print(f"Program is running on port: {port}")
        return port
    
    except Exception as e:
        print(f"Error getting port: {e}")
        return None 

if __name__ == "__main__":
    print_port()
    main()
    
    '''python receiver.py --interface wlan0 --output-file received.txt'''