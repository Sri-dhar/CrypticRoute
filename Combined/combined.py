import sys
import os
import subprocess
import argparse
import shutil

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

def chunk_file(input_file, output_file, chunk_size=8):
    """
    Reads a file and splits its contents into chunks of specified size,
    writing each chunk on a new line in the output file.
    """
    try:
        with open(input_file, 'rb') as infile:
            with open(output_file, 'w') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    hex_string = ' '.join(f'{byte:02x}' for byte in chunk)
                    if len(chunk) < chunk_size:
                        padding = ' ' * (chunk_size - len(chunk)) * 3
                        outfile.write(f"{hex_string}{padding} \n")
                    else:
                        outfile.write(f"{hex_string}\n")
        print(f"Successfully chunked {input_file} into {output_file}")
        return True
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when accessing files")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during chunking: {str(e)}")
        sys.exit(1)

def reverse_chunk_file(input_file, output_file):
    """
    Reads a file containing hex values in chunks (one chunk per line)
    and converts them back to the original binary content.
    """
    try:
        with open(input_file, 'r') as infile:
            with open(output_file, 'wb') as outfile:
                for line in infile:
                    hex_values = line.strip().split()
                    for hex_val in hex_values:
                        try:
                            if hex_val and not hex_val.isspace():
                                byte_val = int(hex_val, 16)
                                outfile.write(bytes([byte_val]))
                        except ValueError:
                            print(f"Warning: Skipping invalid hex value '{hex_val}'")
                            continue
        print(f"Successfully reversed chunked file {input_file} into {output_file}")
        return True
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied when accessing files")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during reverse chunking: {str(e)}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Encrypt, chunk, reverse chunk, and decrypt a file')
    parser.add_argument('input_file', help='Path to the input file to be processed')
    parser.add_argument('output_file', help='Path to the final output file')
    parser.add_argument('--chunk-size', type=int, default=8, help='Size of chunks in bytes (default: 8)')
    parser.add_argument('--key-file', default='key.txt', help='Path to the file containing the encryption key (default: key.txt)')
    parser.add_argument('--keep-temp', action='store_true', help='Keep temporary files after processing')
    args = parser.parse_args()

    temp_dir = 'temp'
    os.makedirs(temp_dir, exist_ok=True)
    
    encrypted_file = os.path.join(temp_dir, 'encrypted.bin')
    chunked_file = os.path.join(temp_dir, 'chunked.txt')
    unchunked_file = os.path.join(temp_dir, 'unchunked.bin')
    chunks_file = 'chunks.txt'  # This will be saved in the main directory
    
    key = read_key_file(args.key_file)
    print(f"Read encryption key from {args.key_file}")
    
    encrypt_file(args.input_file, encrypted_file, key)
    
    chunk_file(encrypted_file, chunked_file, args.chunk_size)
    
    try:
        shutil.copy2(chunked_file, chunks_file)
        print(f"\nChunked data has been saved to {chunks_file}")
    except Exception as e:
        print(f"\nWarning: Could not save chunks to {chunks_file}: {str(e)}")
    
    print(f"\nChunked file contents (preview):")
    try:
        with open(chunks_file, 'r') as f:
            chunked_content = f.read()
            print(chunked_content[:100] + "..." if len(chunked_content) > 100 else chunked_content)
            print()
    except Exception as e:
        print(f"Could not read chunked file: {str(e)}")
        print()
    
    reverse_chunk_file(chunked_file, unchunked_file)
    
    decrypt_file(unchunked_file, args.output_file, key)
    
    print("\nComplete Pipeline Execution:")
    print(f"1. Encrypted {args.input_file} → {encrypted_file}")
    print(f"2. Chunked {encrypted_file} → {chunked_file} (chunk size: {args.chunk_size})")
    print(f"3. Saved chunks to {chunks_file}")
    print(f"4. Reversed chunks from {chunked_file} → {unchunked_file}")
    print(f"5. Decrypted {unchunked_file} → {args.output_file}")
    print(f"\nFinal output saved to: {args.output_file}")
    print(f"Chunked data saved to: {chunks_file}")
    
    if not args.keep_temp:
        try:
            for file in [encrypted_file, chunked_file, unchunked_file]:
                if os.path.exists(file):
                    os.remove(file)
            if not os.listdir(temp_dir):
                os.rmdir(temp_dir)
            print("\nTemporary files removed")
        except Exception as e:
            print(f"\nWarning: Could not remove some temporary files: {str(e)}")
    else:
        print("\nTemporary files kept as requested")

if __name__ == "__main__":
    main()
    
'''
python combined.py input.txt output.txt --key-file key.txt --chunk-size 9
'''