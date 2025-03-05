import sys

def reverse_chunk_file(input_file: str, output_file: str):
    """
    Reads a file containing hex values in chunks (one chunk per line)
    and converts them back to the original binary/text content.
    Args:
        input_file (str): Path to the input file with hex chunks
        output_file (str): Path to the output file where original content will be written
    """
    try:
        with open(input_file, 'r') as infile:
            with open(output_file, 'wb') as outfile:
                for line in infile:
                    # Strip whitespace and split by spaces to get individual hex values
                    hex_values = line.strip().split()
                    # Convert each hex value to its byte representation
                    for hex_val in hex_values:
                        try:
                            # Skip empty strings or whitespace
                            if hex_val and not hex_val.isspace():
                                byte_val = int(hex_val, 16)
                                outfile.write(bytes([byte_val]))
                        except ValueError:
                            # Skip non-hex values
                            print(f"Warning: Skipping invalid hex value '{hex_val}'")
                            continue
        print(f"Successfully reversed {input_file} into {output_file}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
    except PermissionError:
        print(f"Error: Permission denied when accessing files")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

def main():
    # Check if correct number of arguments is provided
    if len(sys.argv) != 3:
        print("Usage: python script_name.py input_file output_file")
        sys.exit(1)
    
    # Get input and output file names from command line arguments
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Execute the reverse chunking
    reverse_chunk_file(input_file, output_file)

if __name__ == "__main__":
    main()
    
    
# python reverseFileChunker.py chunked_output.txt reversed_output.txt