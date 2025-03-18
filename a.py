# ===== Sender Laptop Code =====
from scapy.all import *
import time

# Replace with the public IP of the receiving laptop
DESTINATION_IP = "xxx.xxx.xxx.xxx"  
# Choose a port not blocked by firewalls
DESTINATION_PORT = 12345  

def send_packet(message):
    # Create IP packet with custom payload
    packet = IP(dst=DESTINATION_IP)/UDP(dport=DESTINATION_PORT)/Raw(load=message)
    
    # Send the packet
    send(packet, verbose=0)
    print(f"Sent: {message}")

# Example usage
if __name__ == "__main__":
    while True:
        message = input("Enter message to send (or 'exit' to quit): ")
        if message.lower() == 'exit':
            break
        send_packet(message.encode())
        time.sleep(1)  # Prevent flooding


# ===== Receiver Laptop Code =====
from scapy.all import *

# The port you're listening on
PORT = 12345

def packet_callback(packet):
    if packet.haslayer(UDP) and packet.haslayer(Raw):
        if packet[UDP].dport == PORT:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            print(f"Received from {packet[IP].src}: {payload}")

def start_sniffing():
    print(f"Listening for packets on port {PORT}...")
    # Set filter to only capture UDP packets on your specified port
    sniff(filter=f"udp port {PORT}", prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()