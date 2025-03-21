# CrypticRoute GUI

A graphical user interface for the CrypticRoute network steganography tool.

## Overview

CrypticRoute GUI provides a user-friendly interface for the sender and receiver components of the CrypticRoute network steganography system. This tool allows you to:

- Send files covertly over the network using TCP packet steganography
- Optionally encrypt the data before transmission
- Monitor transmission progress in real-time
- Receive and assemble steganographic data from network packets
- Decrypt received data with the appropriate key

## Features

- **Clean, modern Qt-based interface**
- **Sender functionality:**
  - Select target IP address
  - Choose input file to transmit
  - Optional encryption key
  - Customizable packet delay and chunk size
  - Real-time progress monitoring
  - Detailed logging
  
- **Receiver functionality:**
  - Select network interface to monitor
  - Choose output file location
  - Optional decryption key
  - Customizable inactivity timeout
  - Real-time progress monitoring
  - Detailed logging

## Requirements

- Python 3.6+
- PyQt5
- Scapy
- Cryptography
- Netifaces
- Psutil

## Installation

1. Clone this repository:
   ```
   git clone [repository-url]
   cd crypticroute-gui
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   python cryptic_route_gui.py
   ```

2. **To Send a File:**
   - Switch to the "Send File" tab
   - Enter the target IP address
   - Select the input file to transmit
   - Optionally select an encryption key file
   - Adjust packet delay and chunk size if needed
   - Click "Start Transmission"

3. **To Receive a File:**
   - Switch to the "Receive File" tab
   - Select the output file location
   - Optionally select a decryption key file
   - Choose the network interface to monitor
   - Click "Start Listening"

## Notes

- Running the application may require administrative privileges for packet capture
- For proper operation, ensure the original `sender.py` and `receiver.py` files are in the same directory as the GUI application
- Encryption/decryption requires the same key file on both ends

## Security Considerations

- This tool is designed for educational and legitimate purposes only
- Always obtain proper authorization before using steganography on networks you don't own
- Data is not completely invisible and can be detected by specialized network monitoring tools
