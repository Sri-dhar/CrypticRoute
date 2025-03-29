import socket

def receiver():
    # Get own IP by connecting to an external server (doesn't send any data)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    own_ip = s.getsockname()[0]
    s.close()
    
    # Create socket for receiving broadcast
    receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    receive_socket.bind(('0.0.0.0', 5000))  # Bind to all interfaces
    
    print("Listening for broadcast messages...")
    receive_socket.settimeout(60)  # Set timeout to 60 seconds
    
    try:
        # Wait for broadcast from sender
        data, addr = receive_socket.recvfrom(1024)
        sender_message = data.decode()
        print(f"Received: {sender_message}")
        
        # Parse sender IP and port from the message
        sender_info = sender_message.split("from ")[1]
        sender_ip, sender_port = sender_info.split(":")
        sender_port = int(sender_port)
        
        # Send acknowledgment
        print(f"Sending acknowledgment to {sender_ip}:{sender_port}")
        ack_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ack_socket.settimeout(30)  # Set timeout to 30 seconds
        
        try:
            # Connect to sender and send acknowledgment
            ack_socket.connect((sender_ip, sender_port))
            ack_message = f"ACK from {own_ip}"
            ack_socket.send(ack_message.encode())
            
            # Print IP addresses
            print(f"My IP: {own_ip}")
            print(f"Sender IP: {sender_ip}")
        except (socket.timeout, ConnectionRefusedError) as e:
            print(f"Failed to connect to sender: {e}")
        finally:
            ack_socket.close()
    except socket.timeout:
        print("No broadcast message received within the timeout period.")
    
    # Clean up
    receive_socket.close()

if __name__ == "__main__":
    receiver()