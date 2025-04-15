#!/usr/bin/env python3
"""
Worker Thread for handling background tasks in CrypticRoute GUI
"""

import os
import re
import time
import subprocess
import io             # For redirection
import contextlib     # For redirection
import traceback    # Ensure traceback is imported
import threading    # Import threading for Event
import sys          # To get the current Python executable
import shutil       # To check if command exists in PATH

from PyQt6.QtCore import QThread, pyqtSignal

# Import LogRedirector and log_debug
from ..utils.redirector import LogRedirector
from crypticroute.common.utils import log_debug # Import log_debug

class WorkerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)
    handshake_signal = pyqtSignal(str)      # Signal for handshake status
    ack_signal = pyqtSignal(int)            # Signal for acknowledged packets
    total_chunks_signal = pyqtSignal(int)   # Signal for total chunks count
    file_received_signal = pyqtSignal(str)  # Signal emitted when a file segment is saved

    def __init__(self, operation, args):
        super().__init__()
        self.operation = operation
        self.args = args
        self.process = None
        self.stopped = False # Keep for sender logic compatibility? Or remove if receiver is main focus? Let's keep for now.
        self._stop_event = threading.Event() # Event to signal receiver logic to stop
        self._receiver_total_chunks = 0 # Internal state for receiver progress

    def run(self):
        try:
            if self.operation == "send":
                self.run_sender()
            elif self.operation == "receive":
                self.run_receiver()
        except Exception as e:
            # Ensure traceback is imported if error happens early
            import traceback
            error_msg = f"Error in worker thread run: {e}\n{traceback.format_exc()}"
            print(error_msg) # Print to console for debugging
            try:
                # Try emitting signal if possible
                self.update_signal.emit(error_msg)
                self.finished_signal.emit(False)
            except Exception as sig_e:
                print(f"Error emitting signal from worker thread exception handler: {sig_e}")


    def run_sender(self):
        # (Sender logic remains unchanged - uses subprocess)
        input_file = self.args.get("input_file")
        key_file = self.args.get("key_file")
        delay = self.args.get("delay", 0.1)
        chunk_size = self.args.get("chunk_size", 8)
        interface = self.args.get("interface")
        output_dir = self.args.get("output_dir")

        # Determine how to call the CLI script based on execution context
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.abspath(os.path.join(script_dir, '..', '..'))
        source_cli_script_path = os.path.join(project_root, 'crypticroute_cli.py')

        if os.path.exists(source_cli_script_path):
            # Running from source: crypticroute_cli.py exists relative to this script
            self.update_signal.emit("[INFO] Running from source directory.")
            # Use sys.executable to ensure the correct Python interpreter is used
            cmd_base = [sys.executable, source_cli_script_path]
        else:
            # Running installed version: crypticroute_cli.py is NOT relative to this script
            # Look for the installed command in PATH
            self.update_signal.emit("[INFO] Running installed version, looking for 'crypticroute-cli' in PATH.")
            cli_executable = shutil.which("crypticroute-cli")
            if cli_executable:
                cmd_base = [cli_executable]
            else:
                # This indicates a problem with the installation or PATH
                self.update_signal.emit("[ERROR] Cannot find 'crypticroute-cli' command in PATH. Installation may be broken.")
                self.finished_signal.emit(False)
                return # Cannot proceed

        # Construct the full command
        cmd = cmd_base + ["sender", "--input", input_file, "--key", key_file]
        if interface:
            cmd.extend(["--interface", interface])
        if output_dir:
            cmd.extend(["--output-dir", output_dir])
        cmd.extend(["--delay", str(delay), "--chunk-size", str(chunk_size)])

        self.status_signal.emit(f"Starting sender with command: {' '.join(cmd)}")
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=0,
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"))
        total_chunks = 0
        current_chunk = 0

        for line in iter(self.process.stdout.readline, ''):
            if self.stopped: break
            line_stripped = line.strip()
            if not line_stripped: continue
            self.update_signal.emit(line_stripped) # Emit raw line to log

            # --- Signal Parsing Logic (unchanged) ---
            if "[HANDSHAKE] Initiating connection" in line_stripped: self.handshake_signal.emit("syn_sent")
            elif "[HANDSHAKE] Received SYN-ACK response" in line_stripped: self.handshake_signal.emit("syn_ack_received")
            elif "[HANDSHAKE] Sending final ACK" in line_stripped: self.handshake_signal.emit("ack_sent")
            elif "[HANDSHAKE] Connection established" in line_stripped:
                self.handshake_signal.emit("established")
                self.status_signal.emit("Connection established")

            ack_match = re.search(r"\[ACK\] Received acknowledgment for chunk (\d+)", line_stripped)
            if ack_match:
                try: self.ack_signal.emit(int(ack_match.group(1)))
                except: pass
            confirmed_match = re.search(r"\[CONFIRMED\] Chunk (\d+) successfully delivered", line_stripped)
            if confirmed_match:
                try: self.ack_signal.emit(int(confirmed_match.group(1)))
                except: pass

            if "[PREP] Data split into" in line_stripped and total_chunks == 0:
                match = re.search(r"into (\d+) chunks", line_stripped)
                if match:
                    try:
                        total_chunks = int(match.group(1))
                        if total_chunks > 0:
                            self.status_signal.emit(f"Total chunks: {total_chunks}")
                            self.total_chunks_signal.emit(total_chunks)
                    except: pass

            if "[PROGRESS]" in line_stripped:
                progress_match = re.search(r"chunk (\d+)/(\d+) \| Progress: ([\d\.]+)%", line_stripped)
                if progress_match:
                    try:
                        current_chunk = int(progress_match.group(1))
                        new_total = int(progress_match.group(2))
                        if new_total > 0 and total_chunks == 0:
                            total_chunks = new_total
                            self.total_chunks_signal.emit(total_chunks)
                        self.progress_signal.emit(current_chunk, total_chunks)
                    except: pass

            elif "[COMPLETE] Transmission successfully completed" in line_stripped:
                self.status_signal.emit("Transmission complete")
                if total_chunks > 0: self.progress_signal.emit(total_chunks, total_chunks)
            # --- End Signal Parsing ---

        stderr_output = []
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped: break
            line_stripped = line.strip()
            if line_stripped:
                stderr_output.append(line_stripped)
                self.update_signal.emit(f"ERROR: {line_stripped}")

        exit_code = self.process.wait()
        success = (exit_code == 0)

        if not self.stopped and exit_code != 0 and stderr_output:
            self.update_signal.emit(f"Sender process exited with code {exit_code}. Errors:")
            for err_line in stderr_output: self.update_signal.emit(f"--> {err_line}")
            success = False

        self.finished_signal.emit(success)

    def _process_receiver_log_line(self, line_stripped):
        """Parses receiver log lines for progress and status updates."""
        # Track handshake stage
        if "[HANDSHAKE] Received connection request (SYN)" in line_stripped:
            self.handshake_signal.emit("syn_received")
        elif "[HANDSHAKE] Sending SYN-ACK response" in line_stripped:
            self.handshake_signal.emit("syn_ack_sent")
        elif "[HANDSHAKE] Connection established with sender" in line_stripped:
            self.handshake_signal.emit("established")
            self.status_signal.emit("Connection established")

        # Detect chunk reception and update progress
        # Example: [CHUNK] Received chunk 0015/0015 | Total: 0015/0015 | Progress: 100.0%
        chunk_match = re.search(r"\[CHUNK\] Received chunk (\d+)/(\d+)", line_stripped)
        if chunk_match:
            try:
                current = int(chunk_match.group(1))
                total = int(chunk_match.group(2))

                # Update total chunks if not set yet or if it changed (unlikely but possible)
                if total > 0 and self._receiver_total_chunks != total:
                    self._receiver_total_chunks = total
                    self.total_chunks_signal.emit(total) # Emit for potential use

                # Update progress
                if self._receiver_total_chunks > 0:
                    self.progress_signal.emit(current, self._receiver_total_chunks)
            except Exception as e:
                print(f"Error parsing chunk info from log: {e}")

        # Reset progress and total on discovery restart or completion
        elif "[INFO] Segment processed. Restarting discovery" in line_stripped or \
             "[TIMEOUT] No activity detected" in line_stripped:
            self._receiver_total_chunks = 0
            self.progress_signal.emit(0, 0) # Reset progress bar
            # self.handshake_indicator.reset() # Reset handshake indicator too - Handled in ReceiverPanel

        # Update status messages based on other keywords
        elif "[COMPLETE] Reception complete" in line_stripped:
            self.status_signal.emit("Reception complete")
            if self._receiver_total_chunks > 0: # Ensure 100% on completion
                self.progress_signal.emit(self._receiver_total_chunks, self._receiver_total_chunks)
            else:
                self.progress_signal.emit(100, 100) # Fallback
        elif "[SAVE] File segment saved successfully" in line_stripped:
            self.status_signal.emit("Data saved successfully")
        elif "[DISCOVERY] Listening indefinitely" in line_stripped:
             self.status_signal.emit("Listening for sender...")
             # self.handshake_indicator.reset() # Reset for new discovery attempt - Handled in ReceiverPanel
             self._receiver_total_chunks = 0 # Reset total chunks for new session
             self.progress_signal.emit(0, 0) # Reset progress bar


    def run_receiver(self):
        output_file = self.args.get("output_file")
        key_file = self.args.get("key_file")
        interface = self.args.get("interface")
        timeout = self.args.get("timeout", 120)
        output_dir = self.args.get("output_dir") # This is the session output dir
        self._receiver_total_chunks = 0 # Reset internal total count

        # --- Direct call to core logic ---
        from crypticroute.receiver.core import receive_file_logic
        from crypticroute.common.utils import setup_directories # Need this for session paths
        from crypticroute.common.constants import RECEIVER_SESSION_PREFIX, LATEST_RECEIVER_LINK

        self.status_signal.emit("Starting receiver core logic...")
        # Instantiate redirector passing BOTH the signal emitter AND the line processor
        log_redirector = LogRedirector(self.update_signal.emit, self._process_receiver_log_line)
        success = False # Default to failure
        try:
            # Setup directories needed by core logic
            session_paths = setup_directories(output_dir or ".", RECEIVER_SESSION_PREFIX, LATEST_RECEIVER_LINK)

            # Redirect stdout/stderr for the duration of the call
            with contextlib.redirect_stdout(log_redirector), contextlib.redirect_stderr(log_redirector):
                # Call the core function directly, passing the signal
                success = receive_file_logic(
                    output_path=output_file, # Still needed for potential fallback/logging? Check core logic.
                    key_path=key_file,
                    interface=interface if interface != "default" else None, # Pass None if default
                    timeout=timeout,
                    discovery_timeout=self.args.get("discovery_timeout", 60), # Get discovery timeout if set
                    session_paths=session_paths,
                    update_signal=self.file_received_signal, # Pass the file received signal emitter
                    stop_event=self._stop_event # Pass the stop event
                )
            # Check if stopped before emitting finished signal
            if not self._stop_event.is_set():
                self.finished_signal.emit(success)
            else:
                # If stopped, emit failure, but maybe a specific status?
                self.status_signal.emit("Reception stopped by user")
                self.finished_signal.emit(False) # Indicate it didn't complete successfully

        except Exception as e:
             # Handle exceptions during direct call setup or execution
             error_msg = f"Error running receiver logic: {e}\n{traceback.format_exc()}"
             # Use the redirector to emit the error message to the log GUI as well
             # Check if log_redirector was successfully created before using
             if 'log_redirector' in locals():
                 log_redirector.write(error_msg)
             else:
                 # Fallback if redirector failed (shouldn't happen)
                 self.update_signal.emit(error_msg)
             log_debug(error_msg) # Log the error to file too
             self.finished_signal.emit(False)

        # No return needed here as signals handle completion/failure

    def stop(self):
        # Set the event first to signal the receiver logic
        self._stop_event.set()
        self.stopped = True # Keep this flag for sender logic if needed

        # --- Sender Subprocess Termination (remains the same) ---
        if self.process:
            try:
                print(f"Terminating process {self.process.pid}...")
                self.process.terminate()
                try:
                    self.process.wait(timeout=1.0)
                    print(f"Process {self.process.pid} terminated.")
                except subprocess.TimeoutExpired:
                    print(f"Process {self.process.pid} did not terminate, killing...")
                    self.process.kill()
                    self.process.wait()
                    print(f"Process {self.process.pid} killed.")
            except ProcessLookupError:
                print(f"Process {self.process.pid} already finished.")
            except Exception as e:
                print(f"Error stopping process {self.process.pid}: {e}")
                try: self.process.kill(); self.process.wait()
                except: pass
            self.process = None
        # --- End Sender Subprocess Termination ---

        # No need to manually interrupt receiver thread now, the event handles it.
        # The status update is now handled within run_receiver when stop_event is checked.
        # self.update_signal.emit("Process stop requested by user.") # Redundant now
