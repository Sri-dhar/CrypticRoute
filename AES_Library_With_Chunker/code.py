#!/usr/bin/env python3
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def read_file(file_path, mode='rb'):
    """Read a file and return its contents."""
    try:
        with open(file_path, mode) as file:
            return file.read()
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        sys.exit(1)

def read_key(key_path):
    """Read the key file and ensure it's the correct length for AES."""
    key = read_file(key_path, 'rb')
    
    # Adjust key length if needed (truncate or pad)
    if len(key) < 16:
        # Pad to 16 bytes (128 bits)
        key = key.ljust(16, b'\0')
    elif 16 < len(key) < 24:
        # Pad to 24 bytes (192 bits)
        key = key.ljust(24, b'\0')
    elif 24 < len(key) < 32:
        # Pad to 32 bytes (256 bits)
        key = key.ljust(32, b'\0')
    
    # Truncate to 32 bytes maximum (256 bits)
    return key[:32]

def to_binary_string(data):
    """Convert bytes to a string of 0s and 1s."""
    binary = ''
    for byte in data:
        binary += format(byte, '08b')
    return binary

def from_binary_string(binary_str):
    """Convert a string of 0s and 1s back to bytes."""
    # First remove any whitespace or non-binary characters
    binary_str = ''.join(c for c in binary_str if c in '01')
    
    # Ensure the binary string length is a multiple of 8
    if len(binary_str) % 8 != 0:
        padding = '0' * (8 - (len(binary_str) % 8))
        binary_str += padding
    
    # Convert to bytes
    bytes_data = bytearray()
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        bytes_data.append(int(byte, 2))
    
    return bytes(bytes_data)

def chunk_binary(binary_str, chunk_size):
    """Chunk the binary string into specified bit-length groups."""
    chunked = ''
    for i in range(0, len(binary_str), chunk_size):
        chunk = binary_str[i:i+chunk_size]
        chunked += chunk
        if i + chunk_size < len(binary_str):
            chunked += ' '
    return chunked

def reverse_chunk(chunked_str):
    """Remove spaces to get continuous binary string."""
    return chunked_str.replace(' ', '')

def encrypt(data, key):
    """Encrypt data using AES."""
    try:
        # Initialize AES cipher with key and IV
        iv = os.urandom(16)  # Generate a random 16-byte initialization vector
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        # Prepend IV to the encrypted data for use in decryption
        return iv + encrypted_data
    except Exception as e:
        print(f"Encryption error: {e}")
        sys.exit(1)

def decrypt(data, key):
    """Decrypt data using AES."""
    try:
        # Check if data is long enough to contain the IV
        if len(data) < 16:
            print("Error: Encrypted data is too short (missing IV)")
            sys.exit(1)
            
        # Extract IV from the beginning of the data
        iv = data[:16]
        encrypted_data = data[16:]
        
        # Initialize AES cipher with key and extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the data
        return decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        print(f"Decryption error: {e}")
        sys.exit(1)

def main():
    """Main function to parse arguments and perform encryption/decryption."""
    # Check if enough arguments are provided
    if len(sys.argv) < 5:
        print("Usage:")
        print("  code input.txt -e key.txt encrypted.txt")
        print("  code encrypted.txt -d key.txt cipher.txt")
        print("  code input.txt -e key.txt encrypted.txt -chunk=8")
        print("  code encrypted.txt -d key.txt decrypted.txt")
        return
    
    input_file = sys.argv[1]
    
    # Determine operation mode
    if sys.argv[2] == '-e':
        operation = 'encrypt'
    elif sys.argv[2] == '-d':
        operation = 'decrypt'
    else:
        print("Invalid operation. Use -e for encryption or -d for decryption.")
        return
    
    key_file = sys.argv[3]
    output_file = sys.argv[4]
    
    # Check for chunking option
    chunk_size = None
    for arg in sys.argv[5:]:
        if arg.startswith('-chunk='):
            try:
                chunk_size = int(arg.split('=')[1])
                if chunk_size <= 0:
                    print("Chunk size must be a positive integer.")
                    return
            except (ValueError, IndexError):
                print("Invalid chunk size. Use -chunk=N where N is a positive integer.")
                return
    
    # Read the key
    key = read_key(key_file)
    
    try:
        if operation == 'encrypt':
            # Read input file
            input_data = read_file(input_file, 'rb')
            
            # Encrypt the data
            encrypted_data = encrypt(input_data, key)
            
            # Convert to binary string
            binary_result = to_binary_string(encrypted_data)
            
            # Apply chunking if specified
            if chunk_size:
                binary_result = chunk_binary(binary_result, chunk_size)
            
            # Write to output file
            with open(output_file, 'w') as file:
                file.write(binary_result)
                
            print(f"Encryption successful. Output written to {output_file}")
                
        elif operation == 'decrypt':
            # Read input file (expecting binary text)
            binary_str = read_file(input_file, 'r')
            
            # Check if the input is chunked
            if ' ' in binary_str:
                binary_str = reverse_chunk(binary_str)
            
            # Convert binary string to bytes
            input_data = from_binary_string(binary_str)
            
            # Decrypt the data
            decrypted_data = decrypt(input_data, key)
            
            # Write to output file
            with open(output_file, 'wb') as file:
                file.write(decrypted_data)
                
            print(f"Decryption successful. Output written to {output_file}")
            
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()