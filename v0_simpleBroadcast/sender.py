from scapy.all import *
import time

def get_own_ip():
    """Get the IP address of this machine"""
    return get_if_addr(conf.iface)

def handle_ack_packet(packet):
    """Handle received ACK packet"""
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(Raw):
        raw_data = packet[Raw].load.decode()
        if raw_data.startswith("ACK:"):
            receiver_ip = packet[IP].src
            own_ip = get_own_ip()
            print(f"Received acknowledgment from {receiver_ip}")
            print(f"My IP: {own_ip}")
            print(f"Receiver IP: {receiver_ip}")
            return True
    return False

def sender():
    own_ip = get_own_ip()
    print(f"Sender started with IP: {own_ip}")
    
    # Create a broadcast packet with a unique message
    broadcast_packet = (
        IP(dst="255.255.255.255") / 
        UDP(sport=12345, dport=5000) / 
        Raw(load=f"HELLO:{own_ip}")
    )
    
    print(f"Broadcasting message: HELLO:{own_ip}")
    
    # Send the broadcast packet a few times
    for _ in range(5):
        send(broadcast_packet, verbose=0)
        time.sleep(1)
    
    print("Waiting for acknowledgment...")
    
    # Set up a sniffer to capture the ACK
    try:
        # Sniff for packets, stopping when we receive a valid ACK
        sniff(
            filter=f"udp and dst port 12345 and src not {own_ip}", 
            timeout=30, 
            count=1, 
            prn=handle_ack_packet, 
            stop_filter=handle_ack_packet
        )
    except KeyboardInterrupt:
        print("Sender stopped by user")

if __name__ == "__main__":
    sender()