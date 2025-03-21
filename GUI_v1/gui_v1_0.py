import sys
import os
import subprocess
import shutil
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                              QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                              QPushButton, QFileDialog, QTextEdit, QComboBox,
                              QSpinBox)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette, QColor

def read_key_file(key_file):
    try:
        with open(key_file, 'r') as f:
            return f.read().strip()
    except Exception as e:
        return f"Error reading key file: {str(e)}"

def encrypt_file(input_file, encrypted_file, key):
    try:
        aes_binary = "./../AES_withInput/aes_encrypt"
        if not os.path.exists(aes_binary):
            return f"Error: AES binary not found at {aes_binary}"
        
        result = subprocess.run(
            [aes_binary, "-e", input_file, encrypted_file, key],
            capture_output=True, text=True
        )
        return result.stderr if result.returncode != 0 else f"Encrypted to {encrypted_file}"
    except Exception as e:
        return f"Encryption error: {str(e)}"

def chunk_file(input_file, output_file, chunk_size=8):
    try:
        with open(input_file, 'rb') as infile:
            with open(output_file, 'w') as outfile:
                while True:
                    chunk = infile.read(chunk_size)
                    if not chunk:
                        break
                    hex_string = ' '.join(f'{byte:02x}' for byte in chunk)
                    outfile.write(f"{hex_string}\n")
        return f"Chunked to {output_file}"
    except Exception as e:
        return f"Chunking error: {str(e)}"

class StegoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Steganography Tool")
        self.setGeometry(100, 100, 900, 650)
        
        # Dark theme stylesheet
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
            }
            QLabel {
                font-size: 14px;
                color: #e0e0e0;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #3c3c3c;
                color: #e0e0e0;
            }
            QPushButton {
                padding: 8px 15px;
                background-color: #1e88e5;
                color: white;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #1976d2;
            }
            QTextEdit {
                background-color: #333;
                border: 1px solid #444;
                border-radius: 4px;
                padding: 5px;
                color: #e0e0e0;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                background-color: #333;
            }
            QTabBar::tab {
                background-color: #444;
                color: #e0e0e0;
                padding: 8px 20px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #333;
                border-top: 2px solid #1e88e5;
                color: #ffffff;
            }
            QSpinBox {
                padding: 5px;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #3c3c3c;
                color: #e0e0e0;
            }
            QComboBox {
                padding: 5px;
                border: 1px solid #555;
                border-radius: 4px;
                background-color: #3c3c3c;
                color: #e0e0e0;
            }
            QComboBox::drop-down {
                border: none;
            }
        """)
        
        # Initialize UI components
        self.tabs = QTabWidget()
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        
        self.setCentralWidget(self.tabs)
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
        file_widget = QWidget()
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("Input File:"))
        self.file_input = QLineEdit()
        file_btn = QPushButton("Browse")
        file_btn.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(file_btn)
        file_widget.setLayout(file_layout)
        layout.addWidget(file_widget)
        
        # Encryption key file
        key_widget = QWidget()
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("Key File:"))
        self.key_file_input = QLineEdit("key.txt")
        key_btn = QPushButton("Browse")
        key_btn.clicked.connect(self.select_key_file)
        key_layout.addWidget(self.key_file_input)
        key_layout.addWidget(key_btn)
        key_widget.setLayout(key_layout)
        layout.addWidget(key_widget)
        
        # Chunk size
        chunk_widget = QWidget()
        chunk_layout = QHBoxLayout()
        chunk_layout.addWidget(QLabel("Chunk Size (bytes):"))
        self.chunk_size = QSpinBox()
        self.chunk_size.setRange(1, 16)
        self.chunk_size.setValue(8)
        chunk_layout.addWidget(self.chunk_size)
        chunk_widget.setLayout(chunk_layout)
        layout.addWidget(chunk_widget)
        
        # Send button
        send_btn = QPushButton("Encrypt, Chunk & Send")
        send_btn.clicked.connect(self.process_and_send)
        layout.addWidget(send_btn)
        
        layout.addWidget(self.log)
        layout.addStretch()
        sender_tab.setLayout(layout)
        return sender_tab
    
    def create_receiver_tab(self):
        receiver_tab = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Listen Port"))
        self.listen_port = QLineEdit("5555")
        layout.addWidget(self.listen_port)
        
        save_widget = QWidget()
        save_layout = QHBoxLayout()
        save_layout.addWidget(QLabel("Save To:"))
        self.save_input = QLineEdit()
        save_btn = QPushButton("Browse")
        save_btn.clicked.connect(self.select_save_file)
        save_layout.addWidget(self.save_input)
        save_layout.addWidget(save_btn)
        save_widget.setLayout(save_layout)
        layout.addWidget(save_widget)
        
        layout.addWidget(QLabel("Decryption Key File"))
        self.recv_key_input = QLineEdit("key.txt")
        layout.addWidget(self.recv_key_input)
        
        recv_btn = QPushButton("Receive & Decrypt")
        recv_btn.clicked.connect(self.receive_data)
        layout.addWidget(recv_btn)
        
        layout.addWidget(self.log)
        layout.addStretch()
        receiver_tab.setLayout(layout)
        return receiver_tab
    
    def create_config_tab(self):
        config_tab = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Network Protocol"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["UDP", "TCP"])
        layout.addWidget(self.protocol_combo)
        
        save_btn = QPushButton("Save Settings")
        save_btn.clicked.connect(self.save_settings)
        layout.addWidget(save_btn)
        
        layout.addWidget(self.log)
        layout.addStretch()
        config_tab.setLayout(layout)
        return config_tab
    
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Data File")
        if file_path:
            self.file_input.setText(file_path)
    
    def select_key_file(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Key File")
        if key_path:
            self.key_file_input.setText(key_path)
    
    def select_save_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Received Data")
        if file_path:
            self.save_input.setText(file_path)
    
    def process_and_send(self):
        target = self.target_input.text().split(":")
        if len(target) != 2:
            self.log.append("Error: Invalid IP:Port format")
            return
            
        ip, port = target
        file_path = self.file_input.text()
        key_file = self.key_file_input.text()
        chunk_size = self.chunk_size.value()
        
        if not all([file_path, key_file]):
            self.log.append("Error: File path and key file are required")
            return
        
        # Read key
        key = read_key_file(key_file)
        if "Error" in key:
            self.log.append(key)
            return
        
        # Create temp directory
        temp_dir = "temp"
        os.makedirs(temp_dir, exist_ok=True)
        encrypted_file = os.path.join(temp_dir, "encrypted.bin")
        chunked_file = os.path.join(temp_dir, "chunked.txt")
        
        # Encrypt
        encrypt_result = encrypt_file(file_path, encrypted_file, key)
        self.log.append(encrypt_result)
        if "error" in encrypt_result.lower():
            return
            
        # Chunk
        chunk_result = chunk_file(encrypted_file, chunked_file, chunk_size)
        self.log.append(chunk_result)
        if "error" in chunk_result.lower():
            return
            
        # Here you would add actual network sending logic
        self.log.append(f"Sending chunked data to {ip}:{port}")
    
    def receive_data(self):
        port = self.listen_port.text()
        save_path = self.save_input.text()
        key_file = self.recv_key_input.text()
        
        if not all([port, save_path, key_file]):
            self.log.append("Error: Port, save path, and key file required")
            return
            
        # Here you would add actual receiving logic
        self.log.append(f"Receiving data on port {port}, saving to {save_path}")
        # After receiving, you'd need to reverse_chunk and decrypt (not implemented here)
    
    def save_settings(self):
        protocol = self.protocol_combo.currentText()
        self.log.append(f"Settings saved: Protocol = {protocol}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Set dark palette for native elements
    palette = app.palette()
    palette.setColor(QPalette.Window, QColor(43, 43, 43))
    palette.setColor(QPalette.WindowText, QColor(224, 224, 224))
    palette.setColor(QPalette.Base, QColor(51, 51, 51))
    palette.setColor(QPalette.AlternateBase, QColor(60, 60, 60))
    palette.setColor(QPalette.Text, QColor(224, 224, 224))
    palette.setColor(QPalette.Button, QColor(30, 136, 229))
    palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
    app.setPalette(palette)
    
    window = StegoGUI()
    window.show()
    sys.exit(app.exec())