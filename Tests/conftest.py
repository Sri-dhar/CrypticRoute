import pytest
import os

# Define constants used by the fixture if they are not globally accessible otherwise
# (In this case, they are imported within the test files, so this is fine)
RAW_CHUNKS_SUBDIR = "raw"
CLEANED_CHUNKS_SUBDIR = "cleaned"
DATA_SUBDIR = "data" # Assuming this constant exists

@pytest.fixture(scope="function") # function scope is usually appropriate
def temp_dirs(tmp_path):
    """Creates temporary directories for logs, chunks, and data for a test session."""
    session_dir = tmp_path / "session_test"
    logs_dir = session_dir / "logs"
    chunks_dir = session_dir / "chunks"
    data_dir = session_dir / "data"
    raw_chunks_dir = chunks_dir / RAW_CHUNKS_SUBDIR
    cleaned_chunks_dir = chunks_dir / CLEANED_CHUNKS_SUBDIR

    logs_dir.mkdir(parents=True)
    raw_chunks_dir.mkdir(parents=True)
    cleaned_chunks_dir.mkdir(parents=True)
    data_dir.mkdir(parents=True)

    # Create dummy log files expected by SteganographyReceiver init
    try:
        with open(os.path.join(logs_dir, "received_chunks.json"), "w") as f: f.write("{}")
        with open(os.path.join(logs_dir, "sent_acks.json"), "w") as f: f.write("{}")
    except IOError:
        pytest.fail("Failed to create initial dummy log files in temp_dirs fixture")


    paths = {
        "session_dir": str(session_dir), # Add session_dir itself
        "logs_dir": str(logs_dir),
        "chunks_dir": str(chunks_dir),
        "data_dir": str(data_dir),
        "raw_chunks_dir": str(raw_chunks_dir),
        "cleaned_chunks_dir": str(cleaned_chunks_dir)
    }
    print(f"Created temp dirs for test: {paths}") # Optional: for debugging test setup
    return paths
