from scapy.all import *
import time

def get_own_ip():
    """Get the IP address of this machine"""
    return get_if_addr(conf.iface)

def handle_broadcast_packet(packet):
    """Handle received broadcast packet and send ACK"""
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode()
        
        # Check if this is our expected format
        if raw_data.startswith("HELLO:"):
            sender_ip = packet[IP].src
            own_ip = get_own_ip()
            
            print(f"Received broadcast from {sender_ip}")
            print(f"My IP: {own_ip}")
            print(f"Sender IP: {sender_ip}")
            
            # Create and send acknowledgment packet
            ack_packet = (
                IP(dst=sender_ip) /
                UDP(sport=5000, dport=12345) /
                Raw(load=f"ACK:{own_ip}")
            )
            
            print(f"Sending acknowledgment to {sender_ip}")
            send(ack_packet, verbose=0)
            
            return True
    return False

def receiver():
    own_ip = get_own_ip()
    print(f"Receiver started with IP: {own_ip}")
    print("Listening for broadcast messages...")
    
    try:
        # Sniff for packets, stopping when we receive a valid broadcast and send ACK
        sniff(
            filter=f"udp and dst port 5000", 
            timeout=60,
            count=1,
            prn=handle_broadcast_packet,
            stop_filter=handle_broadcast_packet
        )
    except KeyboardInterrupt:
        print("Receiver stopped by user")

if __name__ == "__main__":
    receiver()