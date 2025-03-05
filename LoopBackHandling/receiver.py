import sys
import os
import hashlib
from scapy.all import *
from scapy.layers.inet import IP, UDP
import subprocess

def read_file(file_path: str) -> str:
    """Read content from a file."""
    with open(file_path, 'r') as file:
        content = file.read().strip()
    with open('receiver_read_output.txt', 'a') as f:
        f.write(f"Read from {file_path}: {content}\n")
    return content

def write_to_file(file_path: str, data: str) -> None:
    """Write data to a file."""
    with open(file_path, 'w') as file:
        file.write(data)
    with open('receiver_write_output.txt', 'a') as f:
        f.write(f"Wrote to {file_path}: {data}\n")

def compute_hash(key: str) -> str:
    """Compute SHA256 hash of the key."""
    hash_value = hashlib.sha256(key.encode()).hexdigest()
    with open('receiver_hash_output.txt', 'a') as f:
        f.write(f"SHA256 hash of key: {hash_value}\n")
    return hash_value

def get_bits(hash_str: str, start: int, length: int) -> str:
    """Extract specific bits from the hash."""
    binary = bin(int(hash_str, 16))[2:].zfill(256)
    bits = binary[start:start+length]
    with open('receiver_bits_output.txt', 'a') as f:
        f.write(f"Extracted bits (start={start}, length={length}): {bits}\n")
    return bits

def decrypt_message(encrypted_file: str, key: str) -> str:
    """Decrypt the data using AES binary."""
    subprocess.run(['./aes_encrypt', '-d', encrypted_file, 'decrypted_temp.txt', key], check=True)
    # Read as binary to avoid UTF-8 decoding issues, then decode as latin1 if needed
    with open('decrypted_temp.txt', 'rb') as f:
        decrypted_data = f.read()
    with open('receiver_decryption_output.txt', 'a') as f:
        f.write(f"Decrypted data (raw bytes): {decrypted_data}\n")
    # Try to decode as UTF-8, fallback to raw bytes if it fails
    try:
        return decrypted_data.decode('utf-8')
    except UnicodeDecodeError:
        return decrypted_data.decode('latin1')  # Or return bytes if text isn’t needed

def reverse_chunk_file(input_file: str, output_file: str) -> None:
    """Reverse chunk the received data using reverseFileChunker.py."""
    subprocess.run(['python', 'reverseFileChunker.py', input_file, output_file], check=True)
    with open('receiver_reversed_output.txt', 'a') as f:
        with open(output_file, 'r') as reversed_f:
            f.write(f"Reversed data in {output_file}:\n{reversed_f.read()}\n")

def receive_packets(interface: str, src_ip: str, dst_ip: str, port: int, start_bits: str, end_bits: str) -> list:
    """Receive and filter UDP packets based on IPs and port."""
    chunks = []
    sniff_filter = f"udp and src host {src_ip} and dst host {dst_ip} and src port {port} and dst port {port}"
    print(f"Listening with filter: {sniff_filter}")
    
    # Calculate total packets: start + data + end
    with open('chunked_output.txt', 'r') as f:
        chunk_count = len([line for line in f if line.strip()])
    total_packets = chunk_count + 2  # Start + data + end
    
    # Capture all packets at once
    packets = sniff(iface=interface, filter=sniff_filter, count=total_packets, timeout=20)
    
    connection_established = False
    
    for packet in packets:
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode('latin1')
            with open('receiver_packet_output.txt', 'a') as f:
                f.write(f"Received packet: src={packet[IP].src}, dst={packet[IP].dst}, data={data}\n")
            if data == start_bits and not connection_established:
                print("Connection established")
                connection_established = True
            elif data == end_bits and connection_established:
                print("Connection ended")
                break
            elif connection_established and data != start_bits and data != end_bits:
                chunks.append(data)  # Append all data packets after connection is established
    
    return chunks

def main():
    """Main function to orchestrate the receiver's tasks."""
    if len(sys.argv) != 5:
        print("Usage: python receiver.py <interface> <src_ip> <dst_ip> <port>")
        sys.exit(1)

    interface = sys.argv[1]
    src_ip = sys.argv[2]
    dst_ip = sys.argv[3]
    port = int(sys.argv[4])

    # Read key and compute hash
    key = read_file('key.txt')
    hash_value = compute_hash(key)
    start_bits = get_bits(hash_value, 0, 10)  # First 10 bits
    end_bits = get_bits(hash_value, -10, 10)  # Last 10 bits

    print(f"Receiver running on port {port}")
    print("Waiting for connection establishment...")

    # Receive packets
    chunks = receive_packets(interface, src_ip, dst_ip, port, start_bits, end_bits)

    # Write received chunks to file
    with open('received_chunks.txt', 'w') as f:
        for chunk in chunks:
            f.write(f"{chunk}\n")
    print(f"Received {len(chunks)} data packets")

    # Reverse chunk and decrypt
    reverse_chunk_file('received_chunks.txt', 'reversed_output.txt')
    decrypted_message = decrypt_message('reversed_output.txt', key)
    print("Decrypted message:", decrypted_message)

if __name__ == "__main__":
    main()