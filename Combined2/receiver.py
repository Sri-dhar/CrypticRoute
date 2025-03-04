import sys
import os
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

def receive_and_decode_packets(interface, key_file, output_file, count=100, filter_ip=None):
    """
    Sniff packets with IP options and reconstruct the hidden message.
    """
    received_chunks = []
    
    print(f"Sniffing for packets with IP options on {interface}...")
    
    packet_filter = "ip[0] & 0x0f > 5"  # Packets with IP options
    if filter_ip:
        packet_filter += f" and host {filter_ip}"
    
    def extract_options(packet):
        if IP in packet and packet[IP].options:
            for option in packet[IP].options:
                try:
                    if hasattr(option, 'value') and len(option.value) > 4:
                        data = option.value[4:]  # Skip header bytes
                        hex_chunk = ' '.join(f'{byte:02x}' for byte in data)
                        received_chunks.append(hex_chunk)
                        print(f"Received chunk: {hex_chunk}")
                except Exception as e:
                    print(f"  Error parsing option: {e}")
    
    try:
        packets = sniff(iface=interface, filter=packet_filter, prn=extract_options, count=count)
        print(f"Finished sniffing. Captured {len(packets)} packets with IP options.")
        
        # Reconstruct the encrypted file
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
        
        return received_chunks
    except Exception as e:
        print(f"Error sniffing packets: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description='Encrypted Steganographic Packet Receiver')
    parser.add_argument('--interface', default='eth0', help='Network interface to sniff on')
    parser.add_argument('--key-file', default='key.txt', help='Path to decryption key file')
    parser.add_argument('--output-file', default='received_output.txt', help='Path to save decrypted output')
    parser.add_argument('--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('--filter-ip', help='Optional IP address to filter')
    
    args = parser.parse_args()
    
    receive_and_decode_packets(
        interface=args.interface,
        key_file=args.key_file,
        output_file=args.output_file,
        count=args.count,
        filter_ip=args.filter_ip
    )

if __name__ == "__main__":
    main()
    
    '''python receiver.py --interface eth0 --output-file received.txt'''