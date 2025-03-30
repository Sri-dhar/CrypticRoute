# CrypticRoute v3 - Network Steganography Tool

## Overview

CrypticRoute is a network steganography tool designed to transmit data covertly by embedding it within seemingly normal network traffic (specifically crafted TCP packets). This version (v3) introduces a key-based broadcast discovery mechanism, allowing the sender and receiver to find each other on the local network without pre-configured IP addresses, along with a graphical user interface (GUI) for easier operation and visualization.

The core idea is to hide data within fields of TCP packets (like sequence/acknowledgment numbers, window size, and IP ID checksum) and use custom handshake and acknowledgment protocols to ensure reliable delivery.

## Key Concepts

*   **Network Steganography:** Hiding data within network protocols. CrypticRoute uses TCP packet fields.
*   **Key-Based Discovery:** The sender broadcasts probes containing a hash derived from a shared secret key. The receiver listens for these probes, verifies the hash, and responds with another key-derived hash, allowing them to find each other securely on the LAN.
*   **Custom Handshake:** A three-way handshake (SYN -> SYN-ACK -> ACK) using packets with specific flags and window values establishes a connection before data transfer.
*   **Data Chunking & Encoding:** The payload (file data + IV + checksum) is split into small chunks (default 8 bytes). These chunks are encoded into TCP packet fields (sequence, acknowledgment, checksum).
*   **Acknowledgment (ACK) System:** The receiver sends custom ACK packets back to the sender to confirm the successful reception of each data chunk.
*   **Retransmission:** If the sender doesn't receive an ACK for a chunk within a timeout period, it retransmits the chunk.
*   **Integrity Check:** An MD5 checksum of the encrypted payload (including the IV) is appended before chunking to verify data integrity upon reassembly.
*   **Organized Output:** Both sender and receiver create timestamped session directories containing logs, raw/processed data, and configuration details for debugging and analysis.

## Features

### Graphical User Interface (GUI - `gui.py`)

The GUI provides a user-friendly way to interact with the sender and receiver functionalities.

*   **Tabbed Interface:** Separate tabs for "Send File" and "Receive File".
*   **Sender Panel:**
    *   Select Input File.
    *   Select Encryption Key File (Required).
    *   Select Network Interface (for discovery/sending).
    *   Configure Packet Delay and Chunk Size.
    *   Optional custom output directory for session logs.
    *   Start/Stop Transmission controls.
    *   **Visualizations:**
        *   **Handshake Indicator:** Shows the progress of the SYN -> SYN-ACK -> ACK connection setup.
        *   **IP Exchange Panel:** Displays local IP/Port and discovered Remote IP/Port status.
        *   **Progress Bar:** Shows overall transmission progress.
        *   **ACK Status Window (Separate):** Provides a detailed grid view of which chunks have been acknowledged by the receiver.
    *   Detailed Transmission Log.
*   **Receiver Panel:**
    *   Specify Output File path.
    *   Select Decryption Key File (Required).
    *   Select Network Interface (for discovery/listening).
    *   Configure Inactivity Timeout.
    *   Optional custom output directory for session logs.
    *   Start/Stop Listening controls.
    *   Refresh Network Interfaces button.
    *   **Visualizations:**
        *   **Handshake Indicator:** Shows the progress of the connection setup from the receiver's perspective.
        *   **IP Exchange Panel:** Displays local IP/Port and discovered Remote IP/Port status.
        *   **Progress Bar:** Shows overall reception progress.
    *   Split view for Transmission Log and Received Data Preview.
    *   Option to save displayed text data.
*   **Modern Look & Feel:** Uses PyQt6 with custom styling and animations.
*   **Settings Persistence:** Remembers last used paths and settings between sessions.
*   **Status Bar:** Provides real-time status updates.

### Command Line Interface (CLI - `sender.py` & `receiver.py`)

The CLI scripts provide the core functionality and can be used for automation or in environments without a graphical display.

*   **`sender.py`:**
    *   Requires input file (`-i`) and key file (`-k`).
    *   Broadcasts discovery probes using the shared key (`--interface` optional).
    *   Waits for a valid receiver response (`--discovery-timeout`).
    *   Establishes connection via handshake.
    *   Encrypts data using AES (key file provides the key).
    *   Chunks data and embeds into TCP packets.
    *   Sends packets to the discovered receiver.
    *   Handles ACKs and retransmissions (`--ack-timeout`, `--max-retries`).
    *   Sends completion signal.
    *   Configurable delay (`-d`), chunk size (`-c`).
    *   Creates detailed session output directory (`--output-dir`).
*   **`receiver.py`:**
    *   Requires output file path (`-o`) and key file (`-k`).
    *   Listens for discovery probes matching the key hash (`--interface` optional, `--discovery-timeout`).
    *   Responds to valid probes to enable discovery.
    *   Listens for connection requests (SYN) from the discovered sender.
    *   Completes handshake (sends SYN-ACK).
    *   Receives data packets, extracts chunks.
    *   Sends ACK packets for received chunks.
    *   Stops listening on completion signal or inactivity timeout (`-t`).
    *   Reassembles data chunks in order.
    *   Verifies data integrity using MD5 checksum.
    *   Decrypts data using AES.
    *   Saves the final data to the specified output file.
    *   Creates detailed session output directory (`--output-dir`).

## Dependencies

*   **Python 3:** Core language.
*   **Scapy:** For packet crafting, sending, and sniffing (`pip install scapy`).
*   **Cryptography:** For AES encryption/decryption (`pip install cryptography`).
*   **netifaces:** For network interface discovery (broadcast address, IP listing) (`pip install netifaces`).
*   **psutil:** Used by the GUI for process management (`pip install psutil`).
*   **PyQt6:** For the Graphical User Interface (`pip install PyQt6`).

## Running the Application

### Permissions

Both the GUI and CLI scripts require **root privileges** (or appropriate network capabilities like `cap_net_raw`, `cap_net_admin`) to perform raw socket operations (sending custom packets and sniffing network traffic).

Run using `sudo`:

```bash
sudo python3 v3_Broadcast/gui.py
# or
sudo python3 v3_Broadcast/sender.py [options]
sudo python3 v3_Broadcast/receiver.py [options]
```

### GUI Usage

1.  Launch the GUI: `sudo python3 v3_Broadcast/gui.py`
2.  **Receiver:**
    *   Go to the "Receive File" tab.
    *   Select the output file path where the received data should be saved.
    *   Select the **same secret key file** used by the sender.
    *   Choose the network interface to listen on (or leave as default).
    *   Click "Start Listening". The status will indicate it's waiting for discovery.
3.  **Sender:**
    *   Go to the "Send File" tab.
    *   Select the input file to send.
    *   Select the **same secret key file** used by the receiver.
    *   Choose the network interface to send from (must be on the same LAN as the receiver).
    *   Click "Start Transmission".
4.  The sender will broadcast discovery probes. The receiver should detect a probe, respond, and the connection handshake will proceed (visualized in the GUI).
5.  Data transmission will begin, with progress and ACKs shown in the sender's GUI.
6.  Once complete, the receiver will reassemble, verify, decrypt, and save the file.

### CLI Usage

1.  **Receiver:** Start the receiver first on one machine:
    ```bash
    sudo python3 v3_Broadcast/receiver.py -o received_file.txt -k shared_secret.key -i eth0
    ```
    *   Replace `received_file.txt` with your desired output path.
    *   Replace `shared_secret.key` with the path to your shared key file.
    *   Replace `eth0` with the appropriate network interface if needed.
    *   It will print "[DISCOVERY] Listening for sender probe...".

2.  **Sender:** Start the sender on another machine on the same network:
    ```bash
    sudo python3 v3_Broadcast/sender.py -i file_to_send.txt -k shared_secret.key -I eth0
    ```
    *   Replace `file_to_send.txt` with the file you want to send.
    *   Use the **same** `shared_secret.key` file.
    *   Replace `eth0` with the appropriate network interface.
    *   The sender will broadcast probes. If the receiver detects it, they will exchange discovery info, perform the handshake, and transfer the file. Progress will be printed to the console.

## Output Structure

Both sender and receiver create session directories inside `stealth_output/` (or the directory specified by `--output-dir` / `-d`).

Example (`stealth_output/sender_session_YYYYMMDD_HHMMSS/`):

*   `logs/`:
    *   `sender_debug.log`: Detailed debug messages.
    *   `sent_chunks.json`: Record of sequence numbers and hex data sent.
    *   `received_acks.json`: Record of sequence numbers acknowledged.
    *   `chunks_info.json`: Details about how the payload was chunked.
    *   `session_summary.json`: Parameters used for the session.
    *   `completion_info.json`: Final status and statistics.
*   `data/`:
    *   `original_data.bin`: The raw input file data.
    *   `key.bin`: The encryption key used (padded/truncated).
    *   `iv.bin`: The IV used for encryption.
    *   `encrypted_data.bin`: Data after encryption but before IV prepending.
    *   `encrypted_package.bin`: IV + Encrypted Data.
    *   `md5_checksum.bin`: MD5 checksum of the package.
    *   `final_data_package.bin`: IV + Encrypted Data + Checksum (the actual payload sent).
    *   `original_content.txt`: Input file content decoded as text (if possible).
*   `chunks/`:
    *   `chunk_NNN.bin`: Raw binary data for each chunk sent.

A similar structure is created by the receiver, logging received chunks, sent ACKs, reassembly info, checksum verification, and various stages of data processing.

A symlink `stealth_output/sender_latest` (and `receiver_latest`) points to the most recent session directory.


## Installation

### Arch Linux / Manjaro

If running on Arch Linux or a derivative and encountering issues when running with `sudo` due to missing libraries in the root environment (e.g., `externally-managed-environment` error with pip), install the dependencies system-wide using pacman:

```bash
sudo pacman -S --noconfirm python-pyqt6 python-psutil python-netifaces python-cryptography python-scapy
```
