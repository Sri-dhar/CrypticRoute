# CrypticRoute Tests

This directory contains the automated tests for the CrypticRoute project.

## Test Structure

*   **`conftest.py`**: Contains shared fixtures and configuration used across different test files.
*   **`unit/`**: Houses unit tests that verify individual components in isolation.
    *   `test_core.py`: Tests the core logic of the sender and receiver modules.
    *   `test_utils.py`: Tests the utility functions found in `crypticroute/common/utils.py`.
*   **`integration/`**: Contains integration tests that verify the interaction between different components.
    *   `test_receiver_flow.py`: Tests the end-to-end flow of the receiver component.

## Running Tests

Tests are typically run using a test runner like `pytest`. Ensure you have the necessary dependencies installed (refer to the main `requirements.txt`) and run `pytest` from the project root directory:

```bash
pytest Tests/
