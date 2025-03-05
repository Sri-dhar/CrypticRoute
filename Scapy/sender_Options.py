from scapy.all import *
import sys
import binascii
import math

def encode_message_to_ip_options(message):
    """
    Encode a message into IP options format.
    
    The IP options field allows for several option types:
    - 0x44: Timestamp (most useful for steganography)
    - 0x83: Loose Source Routing
    - 0x89: Strict Source Routing
    - etc.
    
    We'll use the Timestamp option (type 0x44) as it's less suspicious
    and allows for variable length data.
    
    Args:
        message (str): Message to encode in IP options
        
    Returns:
        list: List of IP options ready to use with Scapy
    """
    # Calculate how many packets we need
    # Each IP option can contain around 36 bytes maximum (40 bytes total options
    # minus option headers)
    chunk_size = 30  # Conservative value to avoid issues
    chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
    result = []
    
    for i, chunk in enumerate(chunks):
        # Convert chunk to bytes
        data_bytes = chunk.encode('utf-8')
        
        # For Timestamp option:
        # - First byte: Option type (0x44 for Timestamp)
        # - Second byte: Option length (including these two bytes)
        # - Third byte: Pointer (where to start, usually 5)
        # - Fourth byte: Overflow and flags (we use 0)
        # - Rest: Our hidden data disguised as timestamp values
        
        # Create the option
        opt_type = 0x44  # Timestamp
        opt_pointer = 5  # Standard value
        opt_overflow_flags = 0
        
        # Total option length: 4 bytes header + data
        opt_len = 4 + len(data_bytes)
        
        # Build the option
        option = bytes([opt_type, opt_len, opt_pointer, opt_overflow_flags]) + data_bytes
        
        # Padding if needed to make total length multiple of 4
        padding_needed = (4 - (len(option) % 4)) % 4
        if padding_needed > 0:
            option += b'\x00' * padding_needed
            
        result.append(option)
    
    return result

def send_options_steganography(target_ip, port, message):
    """
    Send packets with a message hidden in IP options field
    
    Args:
        target_ip (str): The target IP address
        port (int): The destination port
        message (str): The message to hide in IP options
    """
    # Validate target IP is IPv4 (IP options field is IPv4-specific)
    if ":" in target_ip:
        print("Error: IP Options are only available in IPv4, not IPv6")
        return
        
    # Encode the message into options chunks
    options_chunks = encode_message_to_ip_options(message)
    
    print(f"Encoding message '{message}' into {len(options_chunks)} packets")
    
    # The actual message sent in packets will be innocuous
    cover_data = "This is normal traffic."
    
    try:
        # Send a packet for each chunk of the hidden message
        for i, option_bytes in enumerate(options_chunks):
            # Convert bytes to raw format for Scapy
            raw_option = struct.unpack('!' + 'B'*len(option_bytes), option_bytes)
            
            # Create the IP packet with options
            packet = IP(dst=target_ip, options=IPOption(bytes(option_bytes)))/TCP(dport=port)/Raw(load=f"{cover_data} Packet {i+1}")
            
            # Send the packet
            send(packet, verbose=0)
            
            # For display purposes, show a sample of the hidden data
            display_bytes = option_bytes[4:12] if len(option_bytes) > 12 else option_bytes[4:]
            try:
                display_text = display_bytes.decode('utf-8', errors='replace')
            except:
                display_text = repr(display_bytes)
                
            print(f"Sent packet {i+1}/{len(options_chunks)} with {len(option_bytes)} bytes of option data")
            print(f"  Data sample: {display_text}...")
            
        print(f"\nSteganographic message transmission complete.")
        print(f"To decode, capture packets and extract IP options field data.")
        
    except Exception as e:
        print(f"Error: {e}")

def receive_and_decode_packets(interface, count=10, filter_ip=None):
    """
    Sniff packets with IP options and attempt to decode hidden messages
    
    Args:
        interface (str): Network interface to sniff on
        count (int): Number of packets to capture
        filter_ip (str): Optional IP to filter on
    """
    print(f"Sniffing for packets with IP options on {interface}...")
    
    # Build filter
    packet_filter = "ip[0] & 0x0f > 5"  # Only packets with IP options
    if filter_ip:
        packet_filter += f" and host {filter_ip}"
    
    # Function to process each captured packet
    def extract_options(packet):
        print(packet.summary())
        # Print the options field of packets
        if IP in packet and packet[IP].options:
            print(f"Packet from {packet[IP].src} to {packet[IP].dst}")
            for option in packet[IP].options:
                try:
                    # Try to extract data from option (assuming timestamp option format)
                    if hasattr(option, 'value') and len(option.value) > 4:
                        data = option.value[4:]  # Skip the header bytes
                    try:
                        print(f"  Decoded: {data.decode('utf-8', errors='replace')}")
                    except:
                        print(f"  Raw data: {data}")
                except Exception as e:
                    print(f"  Error parsing option: {e}")
        if IP in packet and packet[IP].options:
            print(f"Packet from {packet[IP].src} to {packet[IP].dst}")
            for option in packet[IP].options:
                try:
                    # Try to extract data from option (assuming timestamp option format)
                    if hasattr(option, 'value') and len(option.value) > 4:
                        data = option.value[4:]  # Skip the header bytes
                        try:
                            print(f"  Decoded: {data.decode('utf-8', errors='replace')}")
                        except:
                            print(f"  Raw data: {data}")
                except Exception as e:
                    print(f"  Error parsing option: {e}")
    
    # Sniff packets
    try:
        packets = sniff(iface=interface, filter=packet_filter, prn=extract_options, count=count)
        print(f"Finished sniffing. Captured {len(packets)} packets with IP options.")
    except Exception as e:
        print(f"Error sniffing packets: {e}")

def print_port():
    # Create a temporary socket to get the port
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', 0))
        port = sock.getsockname()[1]
        sock.close()
        
        print(f"Program is running on port: {port}")
        return port
    
    except Exception as e:
        print(f"Error getting port: {e}")
        return None 

if __name__ == "__main__":
    
    print_port()
    
    # Default values
    target_ip = "127.0.0.1"  # Replace with your target IP
    target_port = 20             # Replace with your target port
    secret_message = "This is a hidden message using IP options steganography. Much more data can be hidden this way compared to TTL."
    mode = "send"                # "send" or "receive"
    interface = "wlan0"           # For receive mode
    
    # Command line usage (optional)
    if len(sys.argv) >= 2:
        mode = sys.argv[1].lower()
        
        if mode == "send" and len(sys.argv) >= 5:
            target_ip = sys.argv[2]
            target_port = int(sys.argv[3])
            secret_message = sys.argv[4]
            send_options_steganography(target_ip, target_port, secret_message)
            
        elif mode == "receive" and len(sys.argv) >= 3:
            interface = sys.argv[2]
            count = int(sys.argv[3]) if len(sys.argv) > 3 else 10
            filter_ip = sys.argv[4] if len(sys.argv) > 4 else None
            receive_and_decode_packets(interface, count, filter_ip)
            
        else:
            print("Usage:")
            print("  For sending: python script.py send <target_ip> <port> \"<secret_message>\"")
            print("  For receiving: python script.py receive <interface> [count] [filter_ip]")
    else:
        # Default execution
        send_options_steganography(target_ip, target_port, secret_message)