# CrypticRoute v3 (GUI v2.1) - Network Steganography Tool

[![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) <!-- Assuming MIT, adjust if different -->
<!-- Add other badges if applicable, e.g., build status -->

**CrypticRoute is a network steganography tool designed to transmit data covertly by embedding it within crafted TCP packets. This version introduces a key-based broadcast discovery mechanism for automatic peer finding on a LAN and a comprehensive Graphical User Interface (GUI) for ease of use and visualization.**

The core idea is to hide data within inconspicuous fields of TCP packets (like sequence/acknowledgment numbers, window size, and IP ID) and utilize custom handshake and acknowledgment protocols for reliable, hidden data transfer between two machines on the same local network without prior IP configuration.

## Key Features

*   **Network Steganography:** Hides data within standard TCP packet fields (Seq, Ack, Window, IP ID).
*   **Key-Based LAN Discovery:** Sender and Receiver automatically find each other using broadcast probes secured by a shared secret key hash, eliminating the need for manual IP entry.
*   **Graphical User Interface (GUI):** (`crypticroute_gui.py`)
    *   User-friendly tabbed interface for Sending and Receiving.
    *   File selection, key management, interface selection, parameter configuration.
    *   **Real-time Visualizations:**
        *   Handshake progress indicator (SYN -> SYN-ACK -> ACK).
        *   IP Exchange panel showing local/remote IPs and connection status.
        *   Overall transmission/reception progress bar.
        *   **Dedicated ACK Status Window:** Detailed grid view showing the acknowledgment status of each individual data chunk.
    *   Detailed logging and preview panes.
    *   Settings persistence.
*   **Command Line Interface (CLI):** (`crypticroute_cli.py`)
    *   Combined script supporting `sender` and `receiver` modes.
    *   Full functionality accessible via command-line arguments.
    *   Suitable for scripting and headless environments.
*   **Reliable Transmission:**
    *   Custom 3-way handshake to establish a connection.
    *   Custom ACK system confirms receipt of each data chunk.
    *   Automatic retransmission of unacknowledged chunks with configurable timeouts and retries.
*   **Data Security & Integrity:**
    *   AES-256 CFB encryption using a shared key file.
    *   MD5 checksum appended to the payload ensures data integrity upon reception.
*   **Organized Output:** Creates timestamped session directories (`stealth_output/`) for both sender and receiver, containing logs, configuration, and intermediate data files for debugging and analysis.

## How it Works (Core Concepts)

1.  **Key Preparation:** A shared secret key (from a file) is used. It's processed (padded/truncated to AES-256 size) and used to derive two 4-byte identifiers via SHA-256 hashing.
2.  **Discovery:**
    *   The Sender broadcasts TCP packets (`PSH|URG`, `Window=0xFACE`) to the discovery port (`54321`) on the LAN. The packet's sequence number contains the first key-derived identifier (probe hash).
    *   The Receiver listens on the discovery port. Upon receiving a probe, it checks if the sequence number matches its expected probe hash.
    *   If matched, the Receiver responds to the Sender's source IP/Port with a TCP packet (`PSH|FIN`, `Window=0xCAFE`). The sequence number of this response contains the second key-derived identifier (response hash).
    *   The Sender listens for this response. If the sequence number matches its expected response hash, discovery is complete, and the Sender knows the Receiver's IP and the port it responded from.
3.  **Handshake:**
    *   Sender sends a TCP SYN packet (`Window=0xDEAD`) to the Receiver's discovered IP/Port.
    *   Receiver responds with a TCP SYN-ACK packet (`Window=0xBEEF`) from a random port.
    *   Sender sends a final TCP ACK packet (`Window=0xF00D`) to the Receiver's *new* response port, confirming the connection.
4.  **Data Transfer:**
    *   The payload (File Data + IV + MD5 Checksum) is chunked (default 8 bytes).
    *   Each chunk is embedded into a TCP packet:
        *   First 4 bytes -> Sequence Number
        *   Next 4 bytes -> Acknowledgment Number
        *   Chunk sequence number (1, 2, 3...) -> Window field
        *   Total number of chunks -> MSS Option field
        *   CRC32 checksum of the 8-byte chunk -> IP ID field
        *   These packets use the SYN flag and random destination ports.
    *   The Sender sends data packets sequentially.
5.  **Acknowledgment & Retransmission:**
    *   For each *data* packet received correctly (checksum OK), the Receiver sends a custom ACK packet back to the Sender (TCP ACK flag, `Window=0xCAFE`, `Ack Number = Chunk Sequence Number`).
    *   The Sender waits for an ACK for each chunk. If an ACK isn't received within a timeout, it retransmits the chunk (up to `max_retries`).
6.  **Completion:**
    *   Sender sends multiple TCP FIN packets (`Window=0xFFFF`) to signal the end of transmission.
    *   Receiver stops listening upon receiving the FIN signal or after an inactivity timeout.
7.  **Reassembly & Verification:**
    *   Receiver reassembles the received chunks in order.
    *   It verifies the MD5 checksum of the reassembled (IV + encrypted data) payload.
    *   It decrypts the data using the shared key and the prepended IV.
    *   The final decrypted data is saved to the specified output file.
<!-- 
## Screenshots (GUI)

*(Placeholder: Insert screenshots of the GUI here if possible)*

*   *Screenshot of the Sender Panel during transmission.*
*   *Screenshot of the Receiver Panel during reception.*
*   *Screenshot of the ACK Status Window.* -->

## Installation

### Prerequisites

*   **Python 3:** (Tested with Python 3.8+)
*   **Root Privileges:** Required for raw socket operations (packet crafting/sniffing). See Permissions section.

### Using `requirements.txt` (Recommended)

1.  Clone the repository:
    ```bash
    git clone <repository_url>
    cd crypticroute
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Manual Dependency Installation

```bash
pip install PyQt6 psutil netifaces cryptography scapy
```

### Distribution-Specific Notes

*   **Arch Linux / Manjaro:** If encountering `externally-managed-environment` errors with `pip` when using `sudo`, install dependencies system-wide via pacman:
    ```bash
    sudo pacman -S --noconfirm python-pyqt6 python-psutil python-netifaces python-cryptography python-scapy
    ```

## Permissions

CrypticRoute needs elevated privileges to interact directly with network interfaces for sending custom packets and sniffing traffic.

**Option 1: Run with `sudo` (Easiest)**

```bash
sudo python3 crypticroute_gui.py
# or
sudo python3 crypticroute_cli.py [mode] [options]
```

**Option 2: Grant Network Capabilities (More Secure)**

Grant the necessary capabilities (`cap_net_raw` for raw sockets, `cap_net_admin` for interface manipulation) directly to your Python interpreter. *Note: The exact path to `python3` may vary.*

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(realpath $(which python3))
```

After setting capabilities, you might be able to run the scripts without `sudo`. *Use this method with caution and understand the security implications.*

## Usage

### Generating Keys and Test Files

The `TestConfigs/` directory contains sample input files and keys. You can generate your own using the provided script:

```bash
cd TestConfigs
bash createTest.sh
cd ..
```
This will create `key_*.txt` (hex-encoded AES-256 keys) and `input_*.txt` files.

### GUI Usage (`crypticroute_gui.py`)

1.  Launch the GUI with root privileges:
    ```bash
    sudo python3 crypticroute_gui.py
    ```
2.  **Receiver Setup:**
    *   Navigate to the "Receive File" tab.
    *   **Output File:** Browse and select the path where the received file should be saved.
    *   **Key File:** Browse and select the **same secret key file** that the sender will use. This is *required* for discovery and decryption.
    *   **Interface:** Choose the network interface to listen on (e.g., `eth0`, `wlan0`). `default` attempts automatic detection. Use "Refresh Interfaces" if needed.
    *   *(Optional)* **Session Dir:** Specify a custom parent directory for logs and session data.
    *   **Timeout:** Configure the inactivity timeout (seconds).
    *   Click **"Start Listening"**. The status will indicate "Listening for sender probe...". IP Exchange panel will show local IP.
3.  **Sender Setup:**
    *   Navigate to the "Send File" tab.
    *   **Input File:** Browse and select the file you want to transmit.
    *   **Key File:** Browse and select the **same secret key file** used by the receiver. *Required*.
    *   **Network Interface:** Choose the network interface to send from (must be on the same LAN as the receiver). `default` attempts automatic detection.
    *   *(Optional)* **Output Dir:** Specify a custom parent directory for logs and session data.
    *   **Packet Delay / Chunk Size:** Configure timing and data chunking parameters if needed.
    *   Click **"Start Transmission"**.
4.  **Operation:**
    *   The Sender broadcasts discovery probes.
    *   The Receiver should detect a valid probe (matching key hash) and respond.
    *   The GUI visualizes the IP exchange and handshake progress.
    *   Data transmission begins. The Sender's progress bar updates, and the "Ack Status" button becomes active. Click it to open a window showing which chunks have been acknowledged.
    *   Once complete, the Receiver automatically reassembles, verifies integrity, decrypts, and saves the file. The status is updated, and a preview may appear in the "Received Data" panel.

### CLI Usage (`crypticroute_cli.py`)

The command-line interface uses subparsers for `sender` and `receiver` modes.

1.  **Receiver:** Start the receiver first on Machine A:
    ```bash
    # Example:
    sudo python3 crypticroute_cli.py receiver \
        --output received_file.dat \
        --key TestConfigs/key_1.txt \
        --interface eth0 \
        --output-dir stealth_sessions/receiver
    ```
    *   Replace arguments with your desired paths and interface.
    *   `--key` is required.
    *   It will print `[DISCOVERY] Listening for sender probe...`.

2.  **Sender:** Start the sender on Machine B (same LAN):
    ```bash
    # Example:
    sudo python3 crypticroute_cli.py sender \
        --input my_document.pdf \
        --key TestConfigs/key_1.txt \
        --interface eth0 \
        --output-dir stealth_sessions/sender \
        --delay 0.05
    ```
    *   Replace arguments with your file and interface.
    *   Use the **same** `--key` file as the receiver.
    *   The sender will broadcast, discover the receiver, perform the handshake, and transfer the file. Progress is printed to the console.

3.  **Help:** Use `--help` for detailed options:
    ```bash
    python3 crypticroute_cli.py --help
    python3 crypticroute_cli.py sender --help
    python3 crypticroute_cli.py receiver --help
    ```

## Output Structure

Both the GUI and CLI create timestamped session directories for logging and debugging, typically within `stealth_output/` (or the custom directory specified). Symlinks `sender_latest` and `receiver_latest` point to the most recent session.

Example structure (`stealth_output/sender_session_YYYYMMDD_HHMMSS/`):

*   `logs/`:
    *   `sender_session_debug.log`: Detailed operational log.
    *   `sent_chunks.json`: Record of chunks sent (seq num, hex data).
    *   `received_acks.json`: Record of ACKs received (seq num).
    *   `chunks_info.json`: Details on how the payload was chunked.
    *   `session_summary.json`: Session parameters.
    *   `completion_info.json`: Final status and statistics.
*   `data/`:
    *   `original_data.bin`: Raw input file data.
    *   `key.bin`: Processed encryption key used.
    *   `iv.bin`: IV used for encryption.
    *   `encrypted_data.bin`: Data after encryption (before IV/checksum).
    *   `encrypted_package.bin`: IV + Encrypted Data.
    *   `md5_checksum.bin`: MD5 checksum generated.
    *   `final_data_package.bin`: The complete payload sent (IV + Encrypted Data + Checksum).
    *   *(Receiver)* `reassembled_data.bin`: Data after reassembly.
    *   *(Receiver)* `data_without_checksum.bin`: Data after checksum verification.
    *   *(Receiver)* `decrypted_data.bin`: Final decrypted data.
    *   `output_content.txt`: Text representation of final data (if applicable).
*   `chunks/`:
    *   `chunk_NNN.bin`: Raw binary data for each chunk sent/received.
    *   *(Receiver)* `raw/`: Raw chunks as received.
    *   *(Receiver)* `cleaned/`: Chunks after potential padding removal.

## Dependencies

*   **Python 3.x**
*   **PyQt6:** For the Graphical User Interface.
*   **psutil:** Used by the GUI for process management (stopping threads).
*   **netifaces:** For network interface discovery (IPs, broadcast addresses).
*   **cryptography:** For AES encryption/decryption.
*   **scapy:** For packet crafting, sending, and sniffing.

(See `requirements.txt` for exact versions if needed).

## Troubleshooting

*   **Permission Denied:** Ensure you are running the script with `sudo` or have granted the necessary network capabilities (see Permissions section).
*   **Discovery Fails:**
    *   Ensure Sender and Receiver are on the same **local network segment** (broadcast domain).
    *   Verify both are using the **exact same key file**.
    *   Check that no **firewall** (on either machine or the network) is blocking UDP broadcast traffic or TCP traffic on the discovery port (`54321`) or the ephemeral ports used for response/connection.
    *   Ensure the correct **network interfaces** are selected in the GUI or specified in the CLI.
*   **Slow Transfer / Many Retransmissions:** Network congestion or packet loss on the LAN can affect performance. Experiment with the `--delay` option (sender CLI) or Packet Delay (GUI).
*   **GUI Freezes:** If the GUI becomes unresponsive during long operations, check the console output for errors. Very large file transfers might strain resources.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs, feature requests, or improvements.

*(Optional: Add more specific contribution guidelines if desired)*

## License

This project is licensed under the MIT License - see the LICENSE file for details.

*(Create a LICENSE file with the MIT License text if you haven't already)*
