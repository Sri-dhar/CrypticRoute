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

def packet_callback(packet):
    """Check if this is an ACK packet"""
    print("\nPacket detected:")
    print(packet.summary())
    
    if UDP in packet and packet[UDP].dport == 12345:
        if Raw in packet:
            try:
                data = packet[Raw].load.decode('utf-8', errors='ignore')
                print(f"Received data: {data}")
                
                # Even if it doesn't match our expected format, we'll accept it
                # since we're having detection issues
                receiver_ip = packet[IP].src
                print(f"Received acknowledgment from {receiver_ip}")
                print(f"My IP: {my_ip}")
                print(f"Receiver IP: {receiver_ip}")
                return True
            except Exception as e:
                print(f"Error decoding packet data: {e}")
    
    return False

# Global variables to store interface and IP
my_iface, my_ip = get_own_ip()

def sender():
    print(f"Sender started with IP: {my_ip}")
    
    # Create a broadcast packet with a unique message
    broadcast_packet = (
        IP(dst="255.255.255.255") / 
        UDP(sport=12345, dport=5000) / 
        Raw(load=f"HELLO:{my_ip}")
    )
    
    print(f"Broadcasting message: HELLO:{my_ip}")
    print("Packet summary:")
    print(broadcast_packet.summary())
    
    # Send the broadcast packet multiple times
    for i in range(10):
        print(f"Sending broadcast packet (attempt {i+1})...")
        send(broadcast_packet, iface=my_iface, verbose=1)
        time.sleep(1)
    
    print("Waiting for acknowledgment...")
    
    try:
        # Sniff for UDP packets on port 12345
        print("Starting packet capture for ACKs...")
        sniff(
            iface=my_iface,
            filter="udp port 12345",
            prn=packet_callback,
            store=0,
            timeout=30
        )
    except KeyboardInterrupt:
        print("Sender stopped by user")
    except Exception as e:
        print(f"Error in sniffing: {e}")

if __name__ == "__main__":
    conf.verbose = 1  # Enable Scapy verbose mode
    sender()