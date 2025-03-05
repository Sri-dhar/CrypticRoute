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
    with open('sender_read_output.txt', 'a') as f:
        f.write(f"Read from {file_path}: {content}\n")
    return content

def write_to_file(file_path: str, data: str) -> None:
    """Write data to a file."""
    with open(file_path, 'w') as file:
        file.write(data)
    with open('sender_write_output.txt', 'a') as f:
        f.write(f"Wrote to {file_path}: {data}\n")

def compute_hash(key: str) -> str:
    """Compute SHA256 hash of the key."""
    hash_value = hashlib.sha256(key.encode()).hexdigest()
    with open('sender_hash_output.txt', 'a') as f:
        f.write(f"SHA256 hash of key: {hash_value}\n")
    return hash_value

def get_bits(hash_str: str, start: int, length: int) -> str:
    """Extract specific bits from the hash."""
    binary = bin(int(hash_str, 16))[2:].zfill(256)
    bits = binary[start:start+length]
    with open('sender_bits_output.txt', 'a') as f:
        f.write(f"Extracted bits (start={start}, length={length}): {bits}\n")
    return bits

def encrypt_message(message: str, key: str) -> bytes:
    """Encrypt the message using AES binary."""
    write_to_file('message_temp.txt', message)
    subprocess.run(['./aes_encrypt', '-e', 'message_temp.txt', 'encrypted_temp.txt', key], check=True)
    with open('encrypted_temp.txt', 'rb') as f:
        encrypted_data = f.read()
    with open('sender_encryption_output.txt', 'a') as f:
        f.write(f"Encrypted data (raw bytes): {encrypted_data}\n")
    return encrypted_data

def chunk_file(input_file: str, output_file: str, chunk_size: int) -> None:
    """Chunk the encrypted data using fileChunker.py."""
    subprocess.run(['python', 'fileChunker.py', input_file, output_file, str(chunk_size)], check=True)
    with open('sender_chunk_output.txt', 'a') as f:
        with open(output_file, 'r') as chunk_f:
            f.write(f"Chunked data in {output_file}:\n{chunk_f.read()}\n")

def send_packet(src_ip: str, dst_ip: str, port: int, data: str, interface: str) -> None:
    """Send a packet with data in the Raw layer using UDP."""
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=port, dport=port) / Raw(load=data)
    send(packet, iface=interface, verbose=0)
    with open('sender_packet_output.txt', 'a') as f:
        f.write(f"Sent packet: src={src_ip}, dst={dst_ip}, sport={port}, dport={port}, data={data}\n")

def main():
    """Main function to orchestrate the sender's tasks."""
    if len(sys.argv) != 6:
        print("Usage: python sender.py <interface> <src_ip> <dst_ip> <port> <chunk_size>")
        sys.exit(1)

    interface = sys.argv[1]
    src_ip = sys.argv[2]
    dst_ip = sys.argv[3]
    port = int(sys.argv[4])
    chunk_size = int(sys.argv[5])

    # Read key and message
    key = read_file('key.txt')
    message = read_file('message.txt')

    # Compute hash and extract bits for connection
    hash_value = compute_hash(key)
    start_bits = get_bits(hash_value, 0, 10)  # First 10 bits
    end_bits = get_bits(hash_value, -10, 10)  # Last 10 bits

    # Encrypt the message
    encrypted_data = encrypt_message(message, key)
    write_to_file('encrypted_data.txt', encrypted_data.decode('latin1'))

    # Chunk the encrypted data
    chunk_file('encrypted_data.txt', 'chunked_output.txt', chunk_size)

    # Read chunks
    with open('chunked_output.txt', 'r') as f:
        chunks = [chunk.strip() for chunk in f.readlines()]

    # Send connection establishment packet
    send_packet(src_ip, dst_ip, port, start_bits, interface)
    print("Sent connection establishment packet")

    # Send data packets
    for chunk in chunks:
        send_packet(src_ip, dst_ip, port, chunk, interface)
    print(f"Sent {len(chunks)} data packets")

    # Send connection termination packet
    send_packet(src_ip, dst_ip, port, end_bits, interface)
    print("Sent connection termination packet")

    print(f"Sender running on port {port}")

if __name__ == "__main__":
    main()