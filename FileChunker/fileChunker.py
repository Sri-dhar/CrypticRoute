import sys

def chunk_file(input_file: str, output_file: str, chunk_size: int = 8):
    """
    Reads a file and splits its contents into chunks of specified size,
    writing each chunk on a new line in the output file.
    Args:
        input_file (str): Path to the input file
        output_file (str): Path to the output file
        chunk_size (int): Size of each chunk in bytes (default: 8)
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
                        # outfile.write(f"{hex_string}{padding} (partial chunk)\n")
                        outfile.write(f"{hex_string}{padding} \n")
                    else:
                        outfile.write(f"{hex_string}\n")
        print(f"Successfully processed {input_file} into {output_file}")
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
    except PermissionError:
        print(f"Error: Permission denied when accessing files")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

def main():
    # Check if the minimum number of arguments is provided
    if len(sys.argv) < 3:
        print("Usage: python script_name.py input_file output_file [chunk_size]")
        sys.exit(1)
    
    # Get input and output file names from command line arguments
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Get optional chunk size argument
    chunk_size = 22  # default
    if len(sys.argv) >= 4:
        try:
            chunk_size = int(sys.argv[3])
        except ValueError:
            print("Error: chunk_size must be an integer")
            sys.exit(1)
    
    # Execute the chunking
    chunk_file(input_file, output_file, chunk_size)

if __name__ == "__main__":
    main()
    
    
# python fileChunker.py test_input.txt chunked_output.txt 16
# here 16 is the optional parameter for block size, default is 8