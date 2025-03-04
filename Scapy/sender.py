from scapy.all import *
import sys

def send_data_to_ip(target_ip, port, data, count=1):
    """
    Send custom data to a specific IP address and port using Scapy.
    
    Args:
        target_ip (str): The target IP address
        port (int): The destination port
        data (str): The data payload to send
        count (int): Number of packets to send
    """
    try:
        # Create an IP packet directed to the target
        ip = IP(dst=target_ip)
        
        # Create a TCP packet directed to the specified port
        tcp = TCP(dport=port)
        
        # Combine into a single packet with data payload
        packet = ip/tcp/Raw(load=data)
        
        print(f"Sending {count} packet(s) to {target_ip}:{port}")
        
        # Send the packets one by one
        for i in range(count):
            # Send the packet and store the answer
            response = sr1(packet, timeout=2, verbose=1)
            
            # Check if we received a response
            if response:
                print(f"\nReceived response for packet {i+1}:")
                response.show()
            else:
                print(f"\nNo response received for packet {i+1}.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Example usage
    target_ip = "192.168.242.241"  # Replace with your target IP
    target_port = 80              # Replace with your target port
    message = "Hello from Scapy!" # Replace with your message
    
    send_data_to_ip(target_ip, target_port, message)
    
    # For command-line usage (optional)
    if len(sys.argv) >= 4:
        target_ip = sys.argv[1]
        target_port = int(sys.argv[2])
        message = sys.argv[3]
        count = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        send_data_to_ip(target_ip, target_port, message, count)