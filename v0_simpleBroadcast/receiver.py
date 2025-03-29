from scapy.all import *
import time

def get_own_ip():
    """Get the IP address of this machine"""
    # Get all interfaces and their IPs
    interfaces = get_if_list()
    for iface in interfaces:
        if iface != "lo" and get_if_addr(iface) != "0.0.0.0":
            print(f"Using interface {iface} with IP {get_if_addr(iface)}")
            return iface, get_if_addr(iface)
    # Fall back to conf.iface
    print(f"Using default interface {conf.iface} with IP {get_if_addr(conf.iface)}")
    return conf.iface, get_if_addr(conf.iface)

def handle_broadcast_packet(packet):
    """Handle received broadcast packet and send ACK"""
    try:
        # Print raw packet for debugging
        print("\nReceived packet:")
        print(packet.summary())
        
        if packet.haslayer(UDP) and packet.haslayer(IP):
            print(f"UDP packet from {packet[IP].src}:{packet[UDP].sport} to port {packet[UDP].dport}")
            
            # Check if Raw layer exists
            if packet.haslayer(Raw):
                data = packet[Raw].load
                print(f"Raw data: {data}")
                
                try:
                    # Try to decode as string
                    raw_data = data.decode('utf-8', errors='ignore')
                    print(f"Decoded data: {raw_data}")
                    
                    # Even if it doesn't have our prefix, we'll send an ACK
                    # since we see the packet in Wireshark
                    sender_ip = packet[IP].src
                    own_ip = my_ip
                    
                    print(f"Sending acknowledgment to {sender_ip}")
                    
                    # Create and send acknowledgment packet
                    ack_packet = (
                        IP(dst=sender_ip) /
                        UDP(sport=5000, dport=12345) /
                        Raw(load=f"ACK:{own_ip}")
                    )
                    
                    send(ack_packet, iface=my_iface, verbose=1)
                    
                    print(f"My IP: {own_ip}")
                    print(f"Sender IP: {sender_ip}")
                    
                    return True
                except Exception as e:
                    print(f"Error decoding data: {e}")
    except Exception as e:
        print(f"Error processing packet: {e}")
    
    return False

def packet_callback(packet):
    """Simple callback to print packets and send ACK for any UDP packet on port 5000"""
    print("\nPacket detected:")
    print(packet.summary())
    
    if UDP in packet and packet[UDP].dport == 5000:
        sender_ip = packet[IP].src
        print(f"UDP to port 5000 from {sender_ip}")
        
        # Send ACK
        ack_packet = (
            IP(dst=sender_ip) /
            UDP(sport=5000, dport=12345) /
            Raw(load=f"ACK:{my_ip}")
        )
        
        print(f"Sending acknowledgment to {sender_ip}")
        send(ack_packet, iface=my_iface, verbose=1)
        
        print(f"My IP: {my_ip}")
        print(f"Sender IP: {sender_ip}")
        return True
    
    return False

# Global variables to store interface and IP
my_iface, my_ip = get_own_ip()

def receiver():
    print(f"Receiver started with IP: {my_ip}")
    print(f"Listening for broadcast messages on interface {my_iface}...")
    
    try:
        # Use a very simple filter - just capture all UDP packets on port 5000
        print("Starting packet capture...")
        sniff(
            iface=my_iface,
            filter="udp port 5000",
            prn=packet_callback,
            store=0,
            timeout=120  # Increase timeout to 2 minutes
        )
    except KeyboardInterrupt:
        print("Receiver stopped by user")
    except Exception as e:
        print(f"Error in sniffing: {e}")

if __name__ == "__main__":
    conf.verbose = 1  # Enable Scapy verbose mode
    receiver()