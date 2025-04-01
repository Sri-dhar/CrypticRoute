# CrypticRoute Tests

This directory contains the automated tests for the CrypticRoute project, ensuring the reliability and correctness of the file transfer mechanism.

## Test Structure

The tests are organized into unit and integration tests:

*   **`conftest.py`**: This file defines shared `pytest` fixtures used across multiple test files.
    *   `temp_dirs`: Creates a set of temporary directories (for logs, raw chunks, cleaned chunks, and final data) for each test function. This ensures tests run in isolation without interfering with each other or leaving artifacts. It also pre-creates dummy log files (`received_chunks.json`, `sent_acks.json`) expected by the receiver during initialization.
    *   `dummy_key_file` (in `test_receiver_flow.py`'s scope, but conceptually similar): Creates a temporary file containing sample key data for tests that require key processing.

*   **`unit/`**: Houses unit tests that verify individual functions and class methods in isolation, heavily relying on mocking external dependencies (like network calls, file I/O).
    *   `test_core.py`: Contains comprehensive tests for `crypticroute/receiver/core.py`.
        *   **`reassemble_data` tests**: Verify the logic for combining received data chunks, handling ordered/unordered chunks, missing chunks, and removing padding.
        *   **`SteganographyReceiver` tests**: Test the receiver class methods individually:
            *   Initialization (`__init__`).
            *   Discovery packet creation (`_create_discovery_response_packet`) and sending (`_send_discovery_response`).
            *   Processing valid and invalid discovery probes (`process_discovery_probe`).
            *   Data ACK packet creation (`_create_data_ack_packet`) and sending (`send_data_ack`), including logging.
            *   SYN-ACK packet creation (`_create_syn_ack_packet`) and sending (`_send_syn_ack`).
            *   `process_packet`: Tests the main packet handling logic for different packet types (SYN, final ACK, data chunks, duplicates, completion signal) and states (before/after connection established).
        *   **`receive_file_logic` tests**: Mock the entire environment (receiver class, sniff, helper functions, threading) to test the high-level control flow for various scenarios: successful reception, discovery timeout, decryption failure, and handling of missing chunks.
    *   `test_utils.py`: (Currently empty) Intended to contain unit tests for utility functions in `crypticroute/common/utils.py`.

*   **`integration/`**: Contains integration tests that verify the interaction between different components with minimal mocking, focusing on the overall flow.
    *   `test_receiver_flow.py`: Simulates a complete sender-receiver interaction by:
        1.  Preparing a key using the real `prepare_key` function.
        2.  Creating a real `SteganographyReceiver` instance.
        3.  Manually creating Scapy packets representing each stage (Discovery Probe, SYN, Final ACK, Data Chunks, Completion FIN).
        4.  Calling the receiver's `process_discovery_probe` and `process_packet` methods with these simulated packets.
        5.  Asserting the receiver's internal state changes (e.g., `discovery_probe_processed`, `sender_ip`, `connection_established`, `received_chunks`).
        6.  Verifying that the correct responses (Discovery Response, SYN-ACK, Data ACKs) would have been sent by checking calls to the mocked `send` function.
        7.  Checking that expected log files and raw chunk files are created in the temporary directories.

## Running Tests

Tests are run using the `pytest` framework.

1.  **Install Dependencies**: Ensure you have `pytest` and all project dependencies (from `requirements.txt`) installed in your environment.
    ```bash
    pip install -r requirements.txt
    pip install pytest # If not already included
    ```
2.  **Run from Root**: Navigate to the project's root directory (`/home/solomons/CrypticRoute`) in your terminal.
3.  **Execute Pytest**:
    ```bash
    pytest
    ```
    Pytest will automatically discover and run all tests within the `Tests` directory.
