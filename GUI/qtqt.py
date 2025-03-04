import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                               QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                               QPushButton, QFileDialog, QTextEdit, QComboBox)
from PySide6.QtCore import Qt

# Mock core steganography module (replace with your actual implementation)
class StegoCore:
    def send_data(self, target_ip, target_port, file_path, key):
        return f"Sending data to {target_ip}:{target_port} from {file_path} with key {key}"

    def receive_data(self, listen_port, save_path, key):
        return f"Receiving data on port {listen_port}, saving to {save_path} with key {key}"

class StegoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Steganography Tool")
        self.setGeometry(100, 100, 800, 600)
        
        # Initialize core steganography module
        self.stego_core = StegoCore()
        
        # Output log (moved up to initialize before tab creation)
        self.log = QTextEdit(self)
        self.log.setReadOnly(True)
        
        # Create tab widget
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        
        # Add tabs
        self.tabs.addTab(self.create_sender_tab(), "Send")
        self.tabs.addTab(self.create_receiver_tab(), "Receive")
        self.tabs.addTab(self.create_config_tab(), "Settings")
        
    def create_sender_tab(self):
        sender_tab = QWidget()
        layout = QVBoxLayout()
        
        # Target IP and Port
        layout.addWidget(QLabel("Target IP:Port"))
        self.target_input = QLineEdit("192.168.1.10:5555")
        layout.addWidget(self.target_input)
        
        # File selection
        layout.addWidget(QLabel("Data File"))
        self.file_input = QLineEdit()
        file_btn = QPushButton("Browse")
        file_btn.clicked.connect(self.select_file)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(file_btn)
        layout.addLayout(file_layout)
        
        # Encryption key
        layout.addWidget(QLabel("Encryption Key"))
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.key_input)
        
        # Send button
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self.send_data)
        layout.addWidget(send_btn)
        
        # Log area
        layout.addWidget(self.log)
        
        sender_tab.setLayout(layout)
        return sender_tab
    
    def create_receiver_tab(self):
        receiver_tab = QWidget()
        layout = QVBoxLayout()
        
        # Listening port
        layout.addWidget(QLabel("Listen Port"))
        self.listen_port = QLineEdit("5555")
        layout.addWidget(self.listen_port)
        
        # Save file
        layout.addWidget(QLabel("Save To"))
        self.save_input = QLineEdit()
        save_btn = QPushButton("Browse")
        save_btn.clicked.connect(self.select_save_file)
        save_layout = QHBoxLayout()
        save_layout.addWidget(self.save_input)
        save_layout.addWidget(save_btn)
        layout.addLayout(save_layout)
        
        # Encryption key
        layout.addWidget(QLabel("Encryption Key"))
        self.recv_key_input = QLineEdit()
        self.recv_key_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.recv_key_input)
        
        # Receive button
        recv_btn = QPushButton("Start Receiving")
        recv_btn.clicked.connect(self.receive_data)
        layout.addWidget(recv_btn)
        
        # Log area
        layout.addWidget(self.log)
        
        receiver_tab.setLayout(layout)
        return receiver_tab
    
    def create_config_tab(self):
        config_tab = QWidget()
        layout = QVBoxLayout()
        
        # Network protocol (example setting)
        layout.addWidget(QLabel("Network Protocol"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["UDP", "TCP"])
        layout.addWidget(self.protocol_combo)
        
        # Save settings button
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        # Log area
        layout.addWidget(self.log)
        
        config_tab.setLayout(layout)
        return config_tab
    
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Data File")
        if file_path:
            self.file_input.setText(file_path)
    
    def select_save_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Received Data")
        if file_path:
            self.save_input.setText(file_path)
    
    def send_data(self):
        target = self.target_input.text().split(":")
        if len(target) != 2:
            self.log.append("Error: Invalid IP:Port format")
            return
        ip, port = target
        file_path = self.file_input.text()
        key = self.key_input.text()
        
        if not file_path or not key:
            self.log.append("Error: File path and key are required")
            return
        
        result = self.stego_core.send_data(ip, port, file_path, key)
        self.log.append(result)
    
    def receive_data(self):
        port = self.listen_port.text()
        save_path = self.save_input.text()
        key = self.recv_key_input.text()
        
        if not port or not save_path or not key:
            self.log.append("Error: Port, save path, and key are required")
            return
        
        result = self.stego_core.receive_data(port, save_path, key)
        self.log.append(result)
    
    def save_settings(self):
        protocol = self.protocol_combo.currentText()
        self.log.append(f"Settings saved: Protocol = {protocol}")
        # Add logic to save settings to a config file if needed

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StegoGUI()
    window.show()
    sys.exit(app.exec())