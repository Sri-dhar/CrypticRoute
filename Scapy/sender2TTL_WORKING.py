from scapy.all import *
import sys
import random
import binascii

def encode_message_in_ttl(message):
    """
    Encode a text message into TTL values
    - Each character is converted to its ASCII value
    - This value is used as the TTL (with modulo 255 if needed)
    
    Args:
        message (str): The message to encode
    
    Returns:
        list: List of TTL values
    """
    return [ord(c) % 255 for c in message]

def send_steganographic_packets(target_ip, port, message, ipv6=False):
    """
    Send packets with message encoded in TTL values
    
    Args:
        target_ip (str): The target IP address
        port (int): The destination port
        message (str): The message to hide in TTL values
        ipv6 (bool): Whether to use IPv6 instead of IPv4
    """
    # Convert message to TTL values
    ttl_values = encode_message_in_ttl(message)
    print(f"Encoding message '{message}' into {len(ttl_values)} packets")
    print(f"TTL values: {ttl_values}")
    
    # The actual message sent in packets will be innocuous
    cover_data = "This is normal traffic."
    
    # Prepare for IPv6 if requested
    if ipv6:
        if ":" not in target_ip:
            print("Error: You specified IPv6 mode but provided an IPv4 address")
            return
        ip_layer = IPv6(dst=target_ip, hlim=64)  # hlim is IPv6's equivalent of TTL
    else:
        if ":" in target_ip:
            print("Error: You specified IPv4 mode but provided an IPv6 address")
            return
        ip_layer = IP(dst=target_ip, ttl=64)  # Default TTL, will be changed per packet
    
    try:
        # Send a packet for each character in the hidden message
        for i, ttl_value in enumerate(ttl_values):
            # Build the packet with the specified TTL value
            if ipv6:
                # For IPv6, use hlim instead of ttl
                packet = IPv6(dst=target_ip, hlim=ttl_value)/TCP(dport=port)/Raw(load=f"{cover_data} Packet {i+1}")
            else:
                packet = IP(dst=target_ip, ttl=ttl_value)/TCP(dport=port)/Raw(load=f"{cover_data} Packet {i+1}")
            
            # Send the packet
            send(packet, verbose=0)
            print(f"Sent packet {i+1}/{len(ttl_values)} with TTL={ttl_value} ({chr(ttl_value) if 32 <= ttl_value <= 126 else '?'})")
            
        print(f"\nSteganographic message transmission complete.")
        print(f"To decode, capture packets and extract TTL values.")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Default values
    target_ip = "192.168.242.241"  # Replace with your target IP
    target_port = 80             # Replace with your target port
    secret_message = "HIDDEN"    # Replace with your secret message
    use_ipv6 = False             # Set to True for IPv6
    
    # Command line usage (optional)
    if len(sys.argv) >= 4:
        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        secret_message = sys.argv[3]
        if len(sys.argv) > 4:
            use_ipv6 = sys.argv[4].lower() in ('true', 'yes', '1')
    
    send_steganographic_packets(target_ip, target_port, secret_message, use_ipv6)