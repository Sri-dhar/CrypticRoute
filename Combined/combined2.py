import sys
import os
import subprocess
import argparse
import shutil
from scapy.all import *
import binascii
import math

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

def encrypt_file(input_file, encrypted_file, key):
    """Encrypt the input file using the AES encryption binary"""
    try:
        aes_binary = "./../AES_withInput/aes_encrypt"
        
        if not os.path.exists(aes_binary):
            print(f"Error: AES encryption binary not found at {aes_binary}")
            sys.exit(1)
        
        result = subprocess.run(
            [aes_binary, "-e", input_file, encrypted_file, key],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Encryption failed: {result.stderr}")
            sys.exit(1)
        
        print(f"Successfully encrypted {input_file} to {encrypted_file}")
        return True
    except Exception as e:
        print(f"Error during encryption: {str(e)}")
        sys.exit(1)

def chunk_file_to_packets(input_file, chunk_size=30):
    """
    Reads an encrypted file and splits its contents into packet-sized chunks.
    
    Args:
        input_file (str): Path to the encrypted file
        chunk_size (int): Size of each chunk for IP options
        
    Returns:
        list: List of packet chunks
    """
    try:
        with open(input_file, 'rb') as infile:
            chunks = []
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                hex_chunk = ' '.join(f'{byte:02x}' for byte in chunk)
                chunks.append(hex_chunk)
        
        return chunks
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during chunking: {str(e)}")
        sys.exit(1)

def encode_chunk_to_ip_options(chunk):
    """
    Encode a hex chunk into IP options format using the Timestamp option.
    
    Args:
        chunk (str): Hex chunk to encode
        
    Returns:
        bytes: IP options with encoded chunk
    """
    data_bytes = bytes.fromhex(chunk)
    opt_type = 0x44  # Timestamp
    opt_pointer = 5  # Standard value
    opt_overflow_flags = 0
    opt_len = 4 + len(data_bytes)  # 4 bytes header + data
    
    option = bytes([opt_type, opt_len, opt_pointer, opt_overflow_flags]) + data_bytes
    padding_needed = (4 - (len(option) % 4)) % 4  # Pad to multiple of 4
    if padding_needed > 0:
        option += b'\x00' * padding_needed
    
    return option

def send_encrypted_chunks(target_ip, port, chunks, cover_data="Normal traffic"):
    """
    Send encrypted chunks hidden in IP options of UDP packets.
    
    Args:
        target_ip (str): Target IP address
        port (int): Destination port
        chunks (list): List of hex chunks to send
        cover_data (str): Cover text for packet payload
    """
    if ":" in target_ip:
        print("Error: IP Options are only available in IPv4, not IPv6")
        return
    
    try:
        for i, chunk in enumerate(chunks):
            option_bytes = encode_chunk_to_ip_options(chunk)
            
            # Create IP packet with UDP
            packet = IP(dst=target_ip, options=IPOption(bytes(option_bytes)))/UDP(dport=port)/Raw(load=f"{cover_data} Packet {i+1}")
            send(packet, verbose=0)
            
            print(f"Sent packet {i+1}/{len(chunks)} with {len(option_bytes)} bytes of option data")
            print(f"  Data sample: {chunk[:20]}...")
        
        print(f"\nEncrypted steganographic transmission complete.")
    except Exception as e:
        print(f"Error sending packets: {e}")

def receive_and_decode_packets(interface, count=100, filter_ip=None):
    """
    Sniff packets with IP options and reconstruct the hidden message.
    
    Args:
        interface (str): Network interface to sniff on
        count (int): Number of packets to capture
        filter_ip (str): Optional IP to filter on
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
            with open('received_encrypted.bin', 'wb') as outfile:
                for chunk in received_chunks:
                    outfile.write(bytes.fromhex(chunk.replace(' ', '')))
            print("Reconstructed encrypted file: received_encrypted.bin")
        
        return received_chunks
    except Exception as e:
        print(f"Error sniffing packets: {e}")

def decrypt_file(encrypted_file, output_file, key):
    """Decrypt the file using the AES decryption binary"""
    try:
        aes_binary = "./../AES_withInput/aes_encrypt"
        
        result = subprocess.run(
            [aes_binary, "-d", encrypted_file, output_file, key],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"Decryption failed: {result.stderr}")
            sys.exit(1)
        
        print(f"Successfully decrypted {encrypted_file} to {output_file}")
        return True
    except Exception as e:
        print(f"Error during decryption: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Encrypted Steganographic Packet Transmission')
    parser.add_argument('mode', choices=['send', 'receive'], help='Mode of operation')
    parser.add_argument('--input-file', default='input.txt', help='Input file for sending (default: input.txt)')
    parser.add_argument('--output-file', default='output.txt', help='Output file for receiving (default: output.txt)')
    parser.add_argument('--key-file', default='key.txt', help='Encryption key file (default: key.txt)')
    parser.add_argument('--target-ip', default='10.1.6.214', help='Target IP for sending (default: 10.1.6.214)')
    parser.add_argument('--port', type=int, default=53, help='Destination port (default: 53)')
    parser.add_argument('--interface', default='eth0', help='Network interface for receiving (default: eth0)')
    
    args = parser.parse_args()
    
    if args.mode == 'send':
        # Encryption Pipeline
        temp_dir = 'temp'
        os.makedirs(temp_dir, exist_ok=True)
        
        encrypted_file = os.path.join(temp_dir, 'encrypted.bin')
        
        # Read encryption key
        key = read_key_file(args.key_file)
        
        # Encrypt input file
        encrypt_file(args.input_file, encrypted_file, key)
        
        # Chunk and send packets
        chunks = chunk_file_to_packets(encrypted_file)
        send_encrypted_chunks(args.target_ip, args.port, chunks)
        
    elif args.mode == 'receive':
        # Receive and reconstruct
        received_chunks = receive_and_decode_packets(
            args.interface, 
            filter_ip=args.target_ip
        )
        
        if received_chunks:
            # Decrypt received file
            received_encrypted = 'received_encrypted.bin'
            key = read_key_file(args.key_file)
            decrypt_file(received_encrypted, args.output_file, key)

if __name__ == "__main__":
    main()

'''
Sending Usage:
python script.py send --input-file input.txt --target-ip 10.1.6.214

Receiving Usage:
python script.py receive --interface eth0
'''