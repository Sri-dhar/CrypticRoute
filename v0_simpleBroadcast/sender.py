import socket
import time

def sender():
    # Get own IP by connecting to an external server (doesn't send any data)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    own_ip = s.getsockname()[0]
    s.close()
    
    # Create UDP socket for broadcasting
    broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # Create TCP socket for receiving acknowledgment
    ack_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ack_socket.bind(('0.0.0.0', 12345))  # Bind to all interfaces
    ack_socket.listen(1)
    
    # Broadcast message repeatedly (in case the receiver isn't ready)
    message = f"HELLO from {own_ip}:12345"
    print(f"Broadcasting message: {message}")
    
    # Send broadcast a few times to ensure reception
    for _ in range(5):
        broadcast_socket.sendto(message.encode(), ('<broadcast>', 5000))
        time.sleep(1)
    
    print("Waiting for acknowledgment...")
    ack_socket.settimeout(30)  # Set timeout to 30 seconds
    
    try:
        # Wait for connection from receiver
        conn, addr = ack_socket.accept()
        receiver_ip = addr[0]
        
        # Receive acknowledgment
        data = conn.recv(1024).decode()
        print(f"Received acknowledgment: {data}")
        
        # Print IP addresses
        print(f"My IP: {own_ip}")
        print(f"Receiver IP: {receiver_ip}")
        
        # Close connection
        conn.close()
    except socket.timeout:
        print("No acknowledgment received within the timeout period.")
    
    # Clean up
    ack_socket.close()
    broadcast_socket.close()

if __name__ == "__main__":
    sender()