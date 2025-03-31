#!/usr/bin/env python3
"""
Worker Thread for handling background tasks in CrypticRoute GUI
"""

import os
import re
import time
import subprocess
from PyQt6.QtCore import QThread, pyqtSignal

class WorkerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)
    handshake_signal = pyqtSignal(str)      # Signal for handshake status
    ack_signal = pyqtSignal(int)            # Signal for acknowledged packets
    total_chunks_signal = pyqtSignal(int)   # Signal for total chunks count

    def __init__(self, operation, args):
        super().__init__()
        self.operation = operation
        self.args = args
        self.process = None
        self.stopped = False

    def run(self):
        try:
            if self.operation == "send":
                self.run_sender()
            elif self.operation == "receive":
                self.run_receiver()
        except Exception as e:
            self.update_signal.emit(f"Error: {str(e)}")
            self.finished_signal.emit(False)

    def run_sender(self):
        # Update the command construction for sender.py
        input_file = self.args.get("input_file")
        key_file = self.args.get("key_file")
        delay = self.args.get("delay", 0.1)
        chunk_size = self.args.get("chunk_size", 8)
        interface = self.args.get("interface")
        output_dir = self.args.get("output_dir")

        # Build command for the new crypticroute_cli.py sender mode
        cmd = ["python3", "crypticroute_cli.py", "sender", "--input", input_file, "--key", key_file]
        if interface:
            cmd.extend(["--interface", interface])
        if output_dir:
            # Note: cli.py sender uses -o for output-dir, but the GUI uses -o for the file in receiver.
            # We stick to --output-dir for sender command consistency here.
            cmd.extend(["--output-dir", output_dir])
        cmd.extend(["--delay", str(delay), "--chunk-size", str(chunk_size)])
        # Add other sender-specific args if they were added to the GUI panel later
        # e.g., cmd.extend(["--ack-timeout", str(ack_timeout_value)])
        # e.g., cmd.extend(["--max-retries", str(max_retries_value)])
        # e.g., cmd.extend(["--discovery-timeout", str(discovery_timeout_value)])

        self.status_signal.emit(f"Starting sender with command: {' '.join(cmd)}")
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=0, # Changed bufsize from 1 to 0 for true unbuffering
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"))
        total_chunks = 0
        current_chunk = 0

        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break

            line_stripped = line.strip() # Use stripped line for checks
            if not line_stripped: # Skip empty lines
                continue

            self.update_signal.emit(line_stripped)

            # Track handshake stage
            if "[HANDSHAKE] Initiating connection" in line_stripped:
                self.handshake_signal.emit("syn_sent")
            elif "[HANDSHAKE] Received SYN-ACK response" in line_stripped:
                self.handshake_signal.emit("syn_ack_received")
            elif "[HANDSHAKE] Sending final ACK" in line_stripped:
                self.handshake_signal.emit("ack_sent")
            elif "[HANDSHAKE] Connection established" in line_stripped:
                self.handshake_signal.emit("established")
                self.status_signal.emit("Connection established")

            # Detect ACK received - improved pattern matching
            ack_match = re.search(r"\[ACK\] Received acknowledgment for chunk (\d+)", line_stripped)
            if ack_match:
                try:
                    chunk_num = int(ack_match.group(1))
                    print(f"Detected ACK for chunk {chunk_num}")
                    self.ack_signal.emit(chunk_num)
                except (ValueError, IndexError) as e:
                    print(f"Error parsing ACK number: {e}")

            # Also detect successful delivery confirmations as another way to track ACKs
            confirmed_match = re.search(r"\[CONFIRMED\] Chunk (\d+) successfully delivered", line_stripped)
            if confirmed_match:
                try:
                    chunk_num = int(confirmed_match.group(1))
                    print(f"Detected confirmation for chunk {chunk_num}")
                    self.ack_signal.emit(chunk_num)
                except (ValueError, IndexError) as e:
                    print(f"Error parsing confirmation number: {e}")

            # Parse total chunks information early to set up visualization properly
            if "[PREP] Data split into" in line_stripped and total_chunks == 0: # Only parse first time
                try:
                    # More robust parsing
                    match = re.search(r"into (\d+) chunks", line_stripped)
                    if match:
                        total_chunks = int(match.group(1))
                        if total_chunks > 0:
                            self.status_signal.emit(f"Total chunks: {total_chunks}")
                            # Emit special signal to set up visualization with correct total
                            self.total_chunks_signal.emit(total_chunks)
                    else:
                        print(f"Could not parse total chunks from: {line_stripped}")
                except Exception as e:
                    print(f"Error parsing chunk count: {e}")
                    
            # Parse progress updates from the standardized progress messages
            if "[PROGRESS]" in line_stripped:
                try:
                    # Try to extract current/total and percentage
                    progress_match = re.search(r"chunk (\d+)/(\d+) \| Progress: ([\d\.]+)%", line_stripped)
                    if progress_match:
                        current_chunk = int(progress_match.group(1))
                        new_total = int(progress_match.group(2))
                        if new_total > 0 and total_chunks == 0:
                            total_chunks = new_total
                            self.total_chunks_signal.emit(total_chunks)
                        
                        self.progress_signal.emit(current_chunk, total_chunks)
                except Exception as e:
                    print(f"Error parsing progress: {e}")

            # Parse chunk counts for progress bar
            if "[STATUS] Completed chunk" in line_stripped or "[PROGRESS] " in line_stripped:
                try:
                    # Prefer explicit progress messages if available
                    progress_match = re.search(r"Progress:\s*(\d+)/(\d+)", line_stripped)
                    if progress_match:
                        current_chunk = int(progress_match.group(1))
                        new_total = int(progress_match.group(2))
                        if new_total > 0 and total_chunks == 0: # Update total if not set yet
                            total_chunks = new_total
                            self.total_chunks_signal.emit(total_chunks)
                        if total_chunks > 0:
                            self.progress_signal.emit(current_chunk, total_chunks)

                    elif "[STATUS] Completed chunk" in line_stripped:
                        parts = line_stripped.split()
                        chunk_info_match = re.search(r"(\d+)/(\d+)", parts[3])
                        if chunk_info_match:
                            current_chunk = int(chunk_info_match.group(1))
                            new_total = int(chunk_info_match.group(2))
                            if new_total > 0 and total_chunks == 0:
                                total_chunks = new_total
                                self.total_chunks_signal.emit(total_chunks)
                            if total_chunks > 0:
                                self.progress_signal.emit(current_chunk, total_chunks)
                    elif "[PROGRESS] " in line_stripped and "New highest sequence:" in line_stripped:
                        seq_match = re.search(r"sequence:\s*(\d+)", line_stripped)
                        if seq_match:
                            current_chunk = int(seq_match.group(1))
                            # Only update progress if total is known
                            if total_chunks > 0:
                                self.progress_signal.emit(current_chunk, total_chunks)

                except Exception as e:
                    print(f"Error parsing progress: {e} from line: {line_stripped}")

            elif "[COMPLETE] Transmission successfully completed" in line_stripped:
                self.status_signal.emit("Transmission complete")
                if total_chunks > 0: # Ensure progress hits 100% on success
                    self.progress_signal.emit(total_chunks, total_chunks)


        stderr_output = []
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped:
                break
            line_stripped = line.strip()
            if line_stripped:
                stderr_output.append(line_stripped)
                self.update_signal.emit(f"ERROR: {line_stripped}")

        exit_code = self.process.wait()
        success = (exit_code == 0)

        # If process finished but wasn't explicitly stopped by user, check stderr for critical errors
        if not self.stopped and exit_code != 0 and stderr_output:
            self.update_signal.emit(f"Sender process exited with code {exit_code}. Errors:")
            for err_line in stderr_output:
                self.update_signal.emit(f"--> {err_line}")
            success = False

        self.finished_signal.emit(success)

    def run_receiver(self):
        output_file = self.args.get("output_file")
        key_file = self.args.get("key_file")
        interface = self.args.get("interface")
        timeout = self.args.get("timeout", 120)
        output_dir = self.args.get("output_dir") # This is the session output dir

        # Build command for the new crypticroute_cli.py receiver mode
        cmd = ["python3", "crypticroute_cli.py", "receiver", "--output", output_file]
        if key_file:
            cmd.extend(["--key", key_file])
        if interface and interface != "default":
            cmd.extend(["--interface", interface])
        if output_dir:
            # Note: cli.py receiver uses -d or --output-dir for session dir
            cmd.extend(["--output-dir", output_dir])
        cmd.extend(["--timeout", str(timeout)]) # Inactivity timeout
        # Add other receiver-specific args if they were added to the GUI panel later
        # e.g., cmd.extend(["--discovery-timeout", str(discovery_timeout_value)])

        self.status_signal.emit(f"Starting receiver with command: {' '.join(cmd)}")
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=1, # bufsize=1 for line buffering
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"))
        
        from ..utils.progress_tracker import ProgressTracker
        progress_tracker = ProgressTracker(self.progress_signal)
        total_chunks = 0
        current_chunk = 0

        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break

            line_stripped = line.strip()
            if not line_stripped: # Skip empty lines
                continue

            self.update_signal.emit(line_stripped)

            # Track handshake stage
            if "[HANDSHAKE] Received connection request (SYN)" in line_stripped:
                self.handshake_signal.emit("syn_received")
            elif "[HANDSHAKE] Sending SYN-ACK response" in line_stripped:
                self.handshake_signal.emit("syn_ack_sent")
            elif "[HANDSHAKE] Connection established with sender" in line_stripped:
                self.handshake_signal.emit("established")
                self.status_signal.emit("Connection established")

            # Detect chunk reception and update progress
            chunk_match = re.search(r"\[CHUNK\] Received chunk (\d+)/(\d+)", line_stripped)
            if chunk_match:
                try:
                    current = int(chunk_match.group(1))
                    total = int(chunk_match.group(2))
                    
                    # Update total chunks if not set yet
                    if total_chunks == 0 and total > 0:
                        total_chunks = total
                        self.total_chunks_signal.emit(total_chunks)
                    
                    # Update progress
                    if total_chunks > 0:
                        self.progress_signal.emit(current, total_chunks)
                except Exception as e:
                    print(f"Error parsing chunk info: {e}")

            # Get total chunks information from various message patterns
            # Check for "Total chunks expected: X" first
            total_expected_match = re.search(r"Total chunks expected: (\d+)", line_stripped)
            if total_expected_match and total_chunks == 0:
                try:
                    new_total = int(total_expected_match.group(1))
                    if new_total > 0:
                        total_chunks = new_total
                        self.total_chunks_signal.emit(total_chunks) # Send total (though Receiver panel doesn't use it currently)
                        print(f"Set total chunks from EXPECTED message to {total_chunks}")
                        if current_chunk > 0: # Update progress immediately if we have current
                            progress_tracker.update_from_counts(current_chunk, total_chunks)
                except Exception as e:
                    print(f"Error parsing total expected chunks: {e}")

            # Then check for "X/Y" patterns
            chunk_total_match = re.search(r"Total: \d+/(\d+)", line_stripped)
            if chunk_total_match and total_chunks == 0:
                try:
                    new_total = int(chunk_total_match.group(1))
                    if new_total > 0:
                        total_chunks = new_total
                        self.total_chunks_signal.emit(total_chunks)
                        print(f"Set total chunks from CHUNK message to {total_chunks}")
                        if current_chunk > 0:
                            progress_tracker.update_from_counts(current_chunk, total_chunks)
                except Exception as e:
                    print(f"Error parsing chunk total: {e}")


            # Extract data content if present
            data_extracted = False
            try:
                # Prioritize specific data markers
                data_markers = {
                    "[DATA] ": 7,
                    "Decoded data: ": len("Decoded data: "),
                    "Chunk content: ": len("Chunk content: "),
                    "Received chunk data: ": len("Received chunk data: "),
                }
                for marker, offset in data_markers.items():
                    if line_stripped.startswith(marker):
                        data_part = line_stripped[offset:].strip()
                        if data_part:
                            self.update_signal.emit(f"[DATA] {data_part}") # Re-emit with standard prefix for parsing
                            print(f"Data extracted: {data_part[:20]}{'...' if len(data_part) > 20 else ''}")
                            data_extracted = True
                            break
                # Fallback for less specific patterns
                if not data_extracted:
                    fallback_patterns = ["Data chunk:", "CHUNK_DATA:"]
                    for pattern in fallback_patterns:
                        if pattern in line_stripped:
                            data_part = line_stripped.split(pattern, 1)[1].strip()
                            if data_part:
                                self.update_signal.emit(f"[DATA] {data_part}") # Re-emit
                                print(f"Fallback Data extracted: {data_part[:20]}{'...' if len(data_part) > 20 else ''}")
                                data_extracted = True
                                break
            except Exception as e:
                print(f"Error extracting data: {e}")


            # Track progress - improved logic for reliable updates
            try:
                # Explicit progress percentage - high priority
                if "Progress:" in line_stripped:
                    progress_part = line_stripped.split("Progress:")[1].strip()
                    percentage_match = re.search(r"(\d+(\.\d+)?)%", progress_part)
                    if percentage_match:
                        percentage = float(percentage_match.group(1))
                        progress_tracker.update_from_percentage(percentage)
                        print(f"Direct progress update: {percentage:.1f}%")

                # Chunk received info - medium priority (most reliable source)
                # Look for "Received chunk X" or similar patterns indicating successful reception of a chunk
                # e.g., "[CHUNK] Received chunk 5 / 10" or "[RECV] Processed chunk 12"
                processed_chunk_match = re.search(r"(?:Received|Processed) chunk (\d+)", line_stripped, re.IGNORECASE)
                if processed_chunk_match:
                    chunk_num = int(processed_chunk_match.group(1))
                    if chunk_num > current_chunk:
                        current_chunk = chunk_num

                    # Try to find total in the same line "X / Y"
                    total_in_line_match = re.search(r"(\d+)\s*/\s*(\d+)", line_stripped)
                    if total_in_line_match:
                        curr_in_line = int(total_in_line_match.group(1))
                        tot_in_line = int(total_in_line_match.group(2))
                        if tot_in_line > 0 and total_chunks == 0: # Update total if not known
                            total_chunks = tot_in_line
                            self.total_chunks_signal.emit(total_chunks)
                        current_chunk = max(current_chunk, curr_in_line) # Ensure current chunk is highest seen

                    if total_chunks > 0:
                        progress_tracker.update_from_counts(current_chunk, total_chunks)
                        print(f"Chunk progress update: {current_chunk}/{total_chunks}")
                    else:
                        # If we don't have total yet, use current+10 as an estimate for the bar
                        progress_tracker.update_from_counts(current_chunk, max(100, current_chunk + 10))
                        print(f"Chunk progress update (no total): {current_chunk}")


                # Highest sequence number - lower priority, use if other methods fail
                elif "New highest sequence:" in line_stripped:
                    seq_match = re.search(r"sequence:\s*(\d+)", line_stripped)
                    if seq_match:
                        seq_num = int(seq_match.group(1))
                        if seq_num > current_chunk:
                            current_chunk = seq_num
                            if total_chunks > 0:
                                progress_tracker.update_from_counts(current_chunk, total_chunks)
                            else:
                                progress_tracker.update_from_counts(current_chunk, max(100, current_chunk + 10))
                            print(f"Sequence progress update: {current_chunk}")


            except Exception as e:
                print(f"Error in progress parsing: {e} from line: {line_stripped}")

            # Update status messages
            if "[COMPLETE] Reception complete" in line_stripped:
                self.status_signal.emit("Reception complete")
                if total_chunks > 0: # Ensure 100% on completion
                    self.progress_signal.emit(total_chunks, total_chunks)
                else:
                    self.progress_signal.emit(100, 100) # Fallback to 100%
            elif "[INFO]" in line_stripped and "All session data saved to:" in line_stripped:
                self.status_signal.emit("Data saved successfully")
            elif "[SAVE]" in line_stripped and "File saved successfully" in line_stripped:
                self.status_signal.emit("File saved successfully")


        stderr_output = []
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped:
                break
            line_stripped = line.strip()
            if line_stripped:
                stderr_output.append(line_stripped)
                self.update_signal.emit(f"ERROR: {line_stripped}")

        exit_code = self.process.wait()
        success = (exit_code == 0)

        # If process finished but wasn't explicitly stopped by user, check stderr for critical errors
        if not self.stopped and exit_code != 0 and stderr_output:
            self.update_signal.emit(f"Receiver process exited with code {exit_code}. Errors:")
            for err_line in stderr_output:
                self.update_signal.emit(f"--> {err_line}")
            success = False

        if success and current_chunk > 0:
            # Ensure progress bar shows complete on success
            if total_chunks > 0:
                self.progress_signal.emit(total_chunks, total_chunks)
            else:
                self.progress_signal.emit(100,100)


        self.finished_signal.emit(success)

    def stop(self):
        self.stopped = True
        if self.process:
            try:
                # Try terminating gracefully first
                print(f"Terminating process {self.process.pid}...")
                self.process.terminate()
                try:
                    # Wait for a short period
                    self.process.wait(timeout=1.0)
                    print(f"Process {self.process.pid} terminated.")
                except subprocess.TimeoutExpired:
                    # Force kill if terminate didn't work
                    print(f"Process {self.process.pid} did not terminate, killing...")
                    self.process.kill()
                    self.process.wait() # Wait for kill to complete
                    print(f"Process {self.process.pid} killed.")
            except ProcessLookupError:
                print(f"Process {self.process.pid} already finished.")
            except Exception as e:
                print(f"Error stopping process {self.process.pid}: {e}")
                # Attempt kill as a fallback
                try:
                    self.process.kill()
                    self.process.wait()
                except: pass # Ignore errors during fallback kill

            self.process = None # Clear process reference

        self.update_signal.emit("Process stopped by user.")
        self.finished_signal.emit(False) # Treat manual stop as not successful
