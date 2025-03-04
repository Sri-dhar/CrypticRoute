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

def encrypt_file(input_file, encrypted_file, key):
    """Encrypt the input file using the AES encryption binary"""
    try:
        aes_binary = "./aes_encrypt"  # Adjust path as needed
        
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

def main():
    parser = argparse.ArgumentParser(description='Encrypted Steganographic Packet Sender')
    parser.add_argument('--input-file', default='input.txt', help='Input file to send')
    parser.add_argument('--key-file', default='key.txt', help='Encryption key file')
    parser.add_argument('--target-ip', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=53, help='Destination port')
    
    args = parser.parse_args()
    
    # Create temp directory
    temp_dir = 'temp'
    os.makedirs(temp_dir, exist_ok=True)
    
    # Paths for temporary files
    encrypted_file = os.path.join(temp_dir, 'encrypted.bin')
    
    # Read encryption key
    key = read_key_file(args.key_file)
    
    # Encrypt input file
    encrypt_file(args.input_file, encrypted_file, key)
    
    # Chunk and send packets
    chunks = chunk_file_to_packets(encrypted_file)
    send_encrypted_chunks(args.target_ip, args.port, chunks)

if __name__ == "__main__":
    main()
    
    '''## Usage

### Sender
```bash
python sender.py --input-file message.txt --target-ip 10.0.0.1 --port 53'''