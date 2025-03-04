from scapy.all import *
import sys
import binascii
import math

def encode_message_to_ip_options(message):
    """
    Encode a message into IP options format using the Timestamp option (type 0x44).
    
    Args:
        message (str): Message to encode in IP options
        
    Returns:
        list: List of IP options ready to use with Scapy
    """
    chunk_size = 30  # Conservative value to fit within 40-byte IP options limit
    chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
    result = []
    
    for chunk in chunks:
        data_bytes = chunk.encode('utf-8')
        opt_type = 0x44  # Timestamp
        opt_pointer = 5  # Standard value
        opt_overflow_flags = 0
        opt_len = 4 + len(data_bytes)  # 4 bytes header + data
        
        option = bytes([opt_type, opt_len, opt_pointer, opt_overflow_flags]) + data_bytes
        padding_needed = (4 - (len(option) % 4)) % 4  # Pad to multiple of 4
        if padding_needed > 0:
            option += b'\x00' * padding_needed
            
        result.append(option)
    
    return result

def send_options_steganography(target_ip, port, message):
    """
    Send packets with a message hidden in IP options field using UDP.
    
    Args:
        target_ip (str): The target IP address
        port (int): The destination port
        message (str): The message to hide in IP options
    """
    if ":" in target_ip:
        print("Error: IP Options are only available in IPv4, not IPv6")
        return
        
    options_chunks = encode_message_to_ip_options(message)
    print(f"Encoding message '{message}' into {len(options_chunks)} packets")
    
    cover_data = "This is normal traffic."
    
    try:
        for i, option_bytes in enumerate(options_chunks):
            # Create IP packet with UDP instead of TCP
            packet = IP(dst=target_ip, options=IPOption(bytes(option_bytes)))/UDP(dport=port)/Raw(load=f"{cover_data} Packet {i+1}")
            send(packet, verbose=0)
            
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
    Sniff packets with IP options and attempt to decode hidden messages.
    
    Args:
        interface (str): Network interface to sniff on
        count (int): Number of packets to capture
        filter_ip (str): Optional IP to filter on
    """
    print(f"Sniffing for packets with IP options on {interface}...")
    
    packet_filter = "ip[0] & 0x0f > 5"  # Packets with IP options
    if filter_ip:
        packet_filter += f" and host {filter_ip}"
    
    def extract_options(packet):
        if IP in packet and packet[IP].options:
            print(f"Packet from {packet[IP].src} to {packet[IP].dst}")
            for option in packet[IP].options:
                try:
                    if hasattr(option, 'value') and len(option.value) > 4:
                        data = option.value[4:]  # Skip header bytes
                        try:
                            print(f"  Decoded: {data.decode('utf-8', errors='replace')}")
                        except:
                            print(f"  Raw data: {data}")
                except Exception as e:
                    print(f"  Error parsing option: {e}")
    
    try:
        packets = sniff(iface=interface, filter=packet_filter, prn=extract_options, count=count)
        print(f"Finished sniffing. Captured {len(packets)} packets with IP options.")
    except Exception as e:
        print(f"Error sniffing packets: {e}")

if __name__ == "__main__":
    # Updated default values
    target_ip = "10.1.6.214"  # Replace with your target IP
    target_port = 53              # Changed to 53 (DNS) for UDP
    secret_message = "This is a hidden message using IP options steganography. Much more data can be hidden this way compared to TTL."
    mode = "send"                 # "send" or "receive"
    interface = "eth0"            # For receive mode
    
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
        send_options_steganography(target_ip, target_port, secret_message)