#!/usr/bin/env python3
"""
CrypticRoute GUI - Network Steganography Tool
A graphical interface for the sender and receiver components of CrypticRoute
"""

import sys
import os
import time
import datetime
import threading
import json
import queue
import signal
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                            QHBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
                            QSpinBox, QDoubleSpinBox, QTextEdit, QFileDialog, QComboBox,
                            QProgressBar, QGroupBox, QCheckBox, QSplitter, QFrame,
                            QMessageBox, QStyle, QStatusBar)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QSettings
from PyQt5.QtGui import QIcon, QTextCursor, QFont, QPixmap
import subprocess
import psutil
import netifaces
import signal

# Constants
DEFAULT_CHUNK_SIZE = 8
DEFAULT_TIMEOUT = 120
DEFAULT_DELAY = 0.1

class LogRedirector:
    """Redirects log output to a queue for display in the GUI."""
    
    def __init__(self, log_queue):
        self.log_queue = log_queue
        
    def write(self, text):
        if text.strip():  # Only queue non-empty strings
            self.log_queue.put(text)
            
    def flush(self):
        pass

class ProgressTracker:
    """A thread-safe class to track and update progress consistently."""
    
    def __init__(self, progress_signal):
        self.progress_signal = progress_signal
        self.current = 0
        self.total = 100
        self.percentage = 0
        self.has_direct_percentage = False
        self.lock = threading.Lock()
        self.last_update_time = 0
        self.update_interval = 0.03  # 30ms update interval
        self.last_emitted_value = -1  # Track last emitted value to avoid duplicates
        
    def update_from_percentage(self, percentage):
        """Update progress from a direct percentage value."""
        with self.lock:
            # Sanity check - don't allow progress to go backward significantly
            if percentage < self.percentage - 5 and self.percentage > 20:
                print(f"Warning: Progress went backward from {self.percentage:.1f}% to {percentage:.1f}%")
                return
            
            self.percentage = min(100, percentage)
            self.has_direct_percentage = True
            self._emit_update()
    
    def update_from_counts(self, current, total):
        """Update progress from current/total counts."""
        with self.lock:
            if total <= 0:
                return
                
            new_percentage = min(100, (current / total * 100))
            
            # Only update if we don't have a direct percentage or this gives a higher value
            if not self.has_direct_percentage or new_percentage > self.percentage:
                self.current = current
                self.total = total
                self.percentage = new_percentage
                self._emit_update()
    
    def _emit_update(self):
        """Emit the progress update if enough time has passed or value changed significantly."""
        current_time = time.time()
        int_percentage = int(self.percentage)
        
        # Emit update if enough time has passed or value changed by at least 1%
        if (current_time - self.last_update_time >= self.update_interval or 
                abs(int_percentage - self.last_emitted_value) >= 1):
            
            if self.has_direct_percentage:
                # If we have a direct percentage, use it
                self.progress_signal.emit(int_percentage, 100)
            else:
                # Otherwise use current/total
                self.progress_signal.emit(self.current, self.total)
                
            # print(f"Setting progress to {self.percentage:.1f}%")
            self.last_update_time = current_time
            self.last_emitted_value = int_percentage

class WorkerThread(QThread):
    """Background worker thread for running operations without blocking the GUI."""
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)  # current, total
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)  # success/failure
    
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
        """Run the sender process."""
        target_ip = self.args.get("target_ip")
        input_file = self.args.get("input_file")
        key_file = self.args.get("key_file")
        delay = self.args.get("delay", DEFAULT_DELAY)
        chunk_size = self.args.get("chunk_size", DEFAULT_CHUNK_SIZE)
        output_dir = self.args.get("output_dir")

        cmd = ["python3", "sender.py", "--target", target_ip, "--input", input_file]
        
        if key_file:
            cmd.extend(["--key", key_file])
        
        if output_dir:
            cmd.extend(["--output-dir", output_dir])
            
        cmd.extend(["--delay", str(delay), "--chunk-size", str(chunk_size)])
        
        self.status_signal.emit(f"Starting sender with command: {' '.join(cmd)}")
        
        # Start the process with pipe for stdout and stderr (unbuffered)
        self.process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=0,  # Unbuffered output
            env=dict(os.environ, PYTHONUNBUFFERED="1")  # Force Python to be unbuffered
        )
        
        # Track progress
        total_chunks = 0
        current_chunk = 0
        
        # Process output
        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break
                
            self.update_signal.emit(line.strip())
            
            # Extract progress information - improved parsing
            if "[PREP] Data split into" in line:
                try:
                    total_chunks = int(line.split("into")[1].strip().split()[0])
                    self.status_signal.emit(f"Total chunks: {total_chunks}")
                except Exception as e:
                    print(f"Error parsing chunk count: {e}")
            
            elif "[STATUS] Completed chunk" in line or "[PROGRESS] " in line:
                try:
                    # Try to extract data from different log line formats
                    if "[STATUS] Completed chunk" in line:
                        parts = line.split()
                        chunk_info = parts[3].split('/')
                        current_chunk = int(chunk_info[0])
                        # If we can also extract total from this line, update it
                        if len(chunk_info) > 1 and chunk_info[1].isdigit():
                            total_chunks = int(chunk_info[1])
                    elif "[PROGRESS] " in line:
                        # Handle progress lines
                        if "New highest sequence:" in line:
                            current_chunk = int(line.split("sequence:")[1].strip())
                    
                    # Only emit progress updates when we have both values
                    if current_chunk > 0 and total_chunks > 0:
                        self.progress_signal.emit(current_chunk, total_chunks)
                except Exception as e:
                    print(f"Error parsing progress: {e}")
            
            elif "[COMPLETE] Transmission successfully completed" in line:
                self.status_signal.emit("Transmission complete")
        
        # Process any errors
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped:
                break
            self.update_signal.emit(f"ERROR: {line.strip()}")
        
        # Wait for process to complete
        exit_code = self.process.wait()
        
        # Signal completion
        success = (exit_code == 0)
        self.finished_signal.emit(success)
    
    def run_receiver(self):
        """Run the receiver process."""
        output_file = self.args.get("output_file")
        key_file = self.args.get("key_file")
        interface = self.args.get("interface")
        timeout = self.args.get("timeout", DEFAULT_TIMEOUT)
        output_dir = self.args.get("output_dir")

        cmd = ["python3", "receiver.py", "--output", output_file]
        
        if key_file:
            cmd.extend(["--key", key_file])
        
        if interface and interface != "default":
            cmd.extend(["--interface", interface])
            
        if output_dir:
            cmd.extend(["--output-dir", output_dir])
            
        cmd.extend(["--timeout", str(timeout)])
        
        self.status_signal.emit(f"Starting receiver with command: {' '.join(cmd)}")
        
        # Start the process with pipe for stdout and stderr
        self.process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        # Initialize progress tracker
        progress_tracker = ProgressTracker(self.progress_signal)
        
        # Process output
        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break
                
            line_stripped = line.strip()
            
            # Enhanced data detection - check for data patterns first
            data_extracted = False
            try:
                # Improved data detection with more patterns
                data_patterns = [
                    "Received chunk data:", 
                    "Data chunk:", 
                    "CHUNK_DATA:",
                    "Decoded data:", 
                    "Data:", 
                    "[CHUNK] Data:", 
                    "Chunk content:"
                ]
                
                for pattern in data_patterns:
                    if pattern in line_stripped:
                        # Extract data and emit a special data signal
                        data_part = line_stripped.split(pattern, 1)[1].strip()
                        if data_part:
                            # Emit a specific marker for data that will be caught by the receiver
                            self.update_signal.emit(f"[DATA] {data_part}")
                            print(f"Data extracted: {data_part[:20]}{'...' if len(data_part) > 20 else ''}")
                            data_extracted = True
                            break
            except Exception as e:
                print(f"Error extracting data: {e}")
            
            # Send the original line if we didn't extract data
            if not data_extracted:
                self.update_signal.emit(line_stripped)
            
            # Extract progress information with improved parsing
            try:
                # Direct percentage has highest priority - look for it everywhere
                if "Progress:" in line_stripped:
                    try:
                        progress_part = line_stripped.split("Progress:")[1].strip()
                        percentage = float(progress_part.split("%")[0])
                        progress_tracker.update_from_percentage(percentage)
                    except Exception as e:
                        print(f"Error parsing direct percentage: {e}")
                
                # Look for chunk counts in various formats
                if "[CHUNK]" in line_stripped:
                    try:
                        # Try to find current/total in various formats
                        for part in line_stripped.split('|'):
                            if "Received:" in part:
                                parts = part.strip().split(':')[1].strip().split('/')
                                if len(parts) >= 2:
                                    try:
                                        curr = int(parts[0].strip())
                                        tot = int(parts[1].strip())
                                        progress_tracker.update_from_counts(curr, tot)
                                        break
                                    except ValueError:
                                        pass
                            elif "Total:" in part:
                                parts = part.strip().split(':')[1].strip().split('/')
                                if len(parts) >= 2:
                                    try:
                                        curr = int(parts[0].strip())
                                        tot = int(parts[1].strip())
                                        progress_tracker.update_from_counts(curr, tot)
                                        break
                                    except ValueError:
                                        pass
                    except Exception as e:
                        print(f"Error parsing chunk info: {e}")
                
                # Handle packet counter format
                elif "[PACKET]" in line_stripped:
                    try:
                        chunks_part = None
                        for part in line_stripped.split('|'):
                            if "Chunks:" in part:
                                chunks_part = part.strip()
                                break
                                
                        if chunks_part:
                            current_chunk = int(chunks_part.split(':')[1].strip())
                            # We don't know total, so assume it's at least current + 10
                            if current_chunk > 0:
                                progress_tracker.update_from_counts(current_chunk, max(100, current_chunk + 10))
                    except Exception as e:
                        print(f"Error parsing packet info: {e}")
                
                # Handle progress format
                elif "[PROGRESS]" in line_stripped:
                    try:
                        if "New highest sequence:" in line_stripped:
                            seq_part = line_stripped.split("sequence:")[1].strip()
                            current_chunk = int(seq_part)
                            # If we don't know total yet, at least update with what we know
                            if current_chunk > 0:
                                progress_tracker.update_from_counts(current_chunk, max(100, current_chunk + 10))
                    except Exception as e:
                        print(f"Error parsing progress info: {e}")
                
            except Exception as e:
                print(f"Error in progress parsing: {e}")
                
            # Update status based on log messages
            if "[COMPLETE]" in line or "Reception complete" in line:
                self.status_signal.emit("Reception complete")
            elif "[INFO]" in line and "All session data saved to:" in line:
                self.status_signal.emit("Data saved successfully")
            elif "[SAVE]" in line and "File saved successfully" in line:
                self.status_signal.emit("File saved successfully")
        
        # Process any errors
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped:
                break
            self.update_signal.emit(f"ERROR: {line.strip()}")
        
        # Wait for process to complete
        exit_code = self.process.wait()
        
        # Signal completion
        success = (exit_code == 0)
        self.finished_signal.emit(success)
    
    def stop(self):
        """Stop the running process."""
        self.stopped = True
        if self.process:
            # Try to terminate gracefully first
            self.process.terminate()
            
            # Give it a moment to terminate
            time.sleep(0.5)
            
            # If still running, kill it
            if self.process.poll() is None:
                self.process.kill()
                
            self.update_signal.emit("Process stopped by user.")
            self.finished_signal.emit(False)

class SenderPanel(QWidget):
    """Panel for the sender functionality."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.setup_ui()
        
        # Setup timer for log updates
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(50)  # Update logs every 50ms for smoother updates
        
        # Load saved settings
        self.load_settings()
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout()
        
        # Create form for input fields
        form_group = QGroupBox("Transmission Settings")
        form_layout = QFormLayout()
        
        # Target IP
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("Enter target IP address (e.g., 192.168.1.100)")
        form_layout.addRow("Target IP:", self.target_ip_edit)
        
        # Input file
        input_layout = QHBoxLayout()
        self.input_file_edit = QLineEdit()
        self.input_file_edit.setPlaceholderText("Path to input file")
        self.input_file_button = QPushButton("Browse...")
        self.input_file_button.clicked.connect(self.browse_input_file)
        input_layout.addWidget(self.input_file_edit)
        input_layout.addWidget(self.input_file_button)
        form_layout.addRow("Input File:", input_layout)
        
        # Key file
        key_layout = QHBoxLayout()
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("Path to encryption key file (optional)")
        self.key_file_button = QPushButton("Browse...")
        self.key_file_button.clicked.connect(self.browse_key_file)
        key_layout.addWidget(self.key_file_edit)
        key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)
        
        # Output directory
        output_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Custom output directory (optional)")
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.browse_output_dir)
        output_layout.addWidget(self.output_dir_edit)
        output_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_layout)
        
        # Delay
        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0.01, 5.0)
        self.delay_spin.setSingleStep(0.1)
        self.delay_spin.setValue(DEFAULT_DELAY)
        self.delay_spin.setSuffix(" sec")
        form_layout.addRow("Packet Delay:", self.delay_spin)
        
        # Chunk size
        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(1, 8)
        self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)
        self.chunk_size_spin.setSuffix(" bytes")
        form_layout.addRow("Chunk Size:", self.chunk_size_spin)
        
        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)
        
        # Add control buttons
        control_layout = QHBoxLayout()
        
        self.send_button = QPushButton("Start Transmission")
        self.send_button.clicked.connect(self.start_transmission)
        self.send_button.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold;")
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_transmission)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.clear_log)
        
        control_layout.addWidget(self.send_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        
        main_layout.addLayout(control_layout)
        
        # Add progress bar
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        self.status_label = QLabel("Ready")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        # Add log area
        log_group = QGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        
        log_layout.addWidget(self.log_edit)
        
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group, 1)  # Give log area more vertical space
        
        self.setLayout(main_layout)
    
    def browse_input_file(self):
        """Open file dialog to select input file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Input File", "", "All Files (*)"
        )
        if file_path:
            self.input_file_edit.setText(file_path)
    
    def browse_key_file(self):
        """Open file dialog to select key file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Key File", "", "All Files (*)"
        )
        if file_path:
            self.key_file_edit.setText(file_path)
    
    def browse_output_dir(self):
        """Open directory dialog to select output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", ""
        )
        if dir_path:
            self.output_dir_edit.setText(dir_path)
    
    def add_log_message(self, message):
        """Add a message to the log."""
        # Filter out some very high-frequency messages to avoid log flooding
        if "[PACKET] #" in message and not (message.endswith("0") or message.endswith("5")):
            return  # Only show every 5th packet message to reduce log spam
            
        self.log_edit.append(message)
        # Use a more efficient cursor movement
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.log_edit.setTextCursor(cursor)
    
    def update_log(self):
        """Update the log with messages from the queue."""
        try:
            # Process multiple log messages in one batch for efficiency
            messages = []
            for _ in range(20):  # Process up to 20 messages at once
                if not self.log_queue.empty():
                    messages.append(self.log_queue.get_nowait())
                else:
                    break
                    
            if messages:
                # Append all messages at once to avoid multiple redraws
                self.log_edit.append('\n'.join(messages))
                self.log_edit.moveCursor(QTextCursor.End)
        except Exception as e:
            print(f"Error updating log: {e}")
    
    def clear_log(self):
        """Clear the log area."""
        self.log_edit.clear()
    
    def start_transmission(self):
        """Start the transmission process."""
        # Validate input
        target_ip = self.target_ip_edit.text().strip()
        if not target_ip:
            QMessageBox.warning(self, "Input Error", "Target IP address is required.")
            return
        
        input_file = self.input_file_edit.text().strip()
        if not input_file:
            QMessageBox.warning(self, "Input Error", "Input file is required.")
            return
        
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "Input Error", f"Input file does not exist: {input_file}")
            return
        
        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file):
            QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}")
            return
        
        output_dir = self.output_dir_edit.text().strip()
        if output_dir and not os.path.exists(output_dir):
            response = QMessageBox.question(
                self, "Create Directory?", 
                f"Output directory does not exist: {output_dir}\nCreate it?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if response == QMessageBox.Yes:
                try:
                    os.makedirs(output_dir)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}")
                    return
            else:
                return
        
        # Prepare arguments
        args = {
            "target_ip": target_ip,
            "input_file": input_file,
            "delay": self.delay_spin.value(),
            "chunk_size": self.chunk_size_spin.value()
        }
        
        if key_file:
            args["key_file"] = key_file
            
        if output_dir:
            args["output_dir"] = output_dir
        
        # Save settings
        self.save_settings()
        
        # Clear log and reset progress
        self.clear_log()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting transmission...")
        
        # Disable controls during transmission
        self.send_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Create and start worker thread
        self.worker_thread = WorkerThread("send", args)
        self.worker_thread.update_signal.connect(self.add_log_message)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.transmission_finished)
        self.worker_thread.start()
    
    def stop_transmission(self):
        """Stop the current transmission."""
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping transmission...")
            self.worker_thread.stop()
    
    def update_progress(self, current, total):
        """Update the progress bar."""
        if total > 0:
            percentage = (current / total) * 100
            self.progress_bar.setValue(int(percentage))
            
            # Update parent's status bar
            if self.parent:
                self.parent.statusBar().showMessage(f"Sending: {current}/{total} chunks ({percentage:.1f}%)")
    
    def update_status(self, status):
        """Update the status label."""
        self.status_label.setText(status)
    
    def transmission_finished(self, success):
        """Handle the completion of transmission."""
        # Enable controls
        self.send_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Update status
        if success:
            self.status_label.setText("Transmission completed successfully")
            self.progress_bar.setValue(100)
            if self.parent:
                self.parent.statusBar().showMessage("Transmission completed successfully")
        else:
            self.status_label.setText("Transmission failed or was stopped")
            if self.parent:
                self.parent.statusBar().showMessage("Transmission failed or was stopped")
    
    def save_settings(self):
        """Save current settings."""
        settings = QSettings("CrypticRoute", "SenderPanel")
        settings.setValue("target_ip", self.target_ip_edit.text())
        settings.setValue("input_file", self.input_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("delay", self.delay_spin.value())
        settings.setValue("chunk_size", self.chunk_size_spin.value())
    
    def load_settings(self):
        """Load saved settings."""
        settings = QSettings("CrypticRoute", "SenderPanel")
        self.target_ip_edit.setText(settings.value("target_ip", ""))
        self.input_file_edit.setText(settings.value("input_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        self.output_dir_edit.setText(settings.value("output_dir", ""))
        
        delay = settings.value("delay", DEFAULT_DELAY)
        try:
            self.delay_spin.setValue(float(delay))
        except:
            self.delay_spin.setValue(DEFAULT_DELAY)
            
        chunk_size = settings.value("chunk_size", DEFAULT_CHUNK_SIZE)
        try:
            self.chunk_size_spin.setValue(int(chunk_size))
        except:
            self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)

class ReceiverPanel(QWidget):
    """Panel for the receiver functionality."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.data_queue = queue.Queue()  # New queue for received data
        self.setup_ui()
        
        # Setup timer for log updates
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(25)  # Update logs every 25ms for smoother updates
        
        # Setup timer for data display updates
        self.data_timer = QTimer(self)
        self.data_timer.timeout.connect(self.update_data_display)
        self.data_timer.start(50)  # Update data display every 50ms
        
        # Load saved settings
        self.load_settings()
        
    def display_received_file(self, file_path):
        """Read and display the content of the received file."""
        try:
            if not os.path.exists(file_path):
                print(f"Warning: Cannot display file - {file_path} doesn't exist")
                return
                
            # Read the file content
            with open(file_path, 'r') as f:
                content = f.read()
                
            # Clear the current display and show the file content
            self.clear_data_display()
            self.data_display.setText(content)
            print(f"Displayed content from file: {file_path}")
            
            # Add a note at the beginning indicating this is the file content
            cursor = self.data_display.textCursor()
            cursor.setPosition(0)
            self.data_display.setTextCursor(cursor)
            self.data_display.insertPlainText(f"--- Content from {os.path.basename(file_path)} ---\n\n")
            
        except Exception as e:
            print(f"Error reading received file: {e}")
            error_msg = f"Error reading file: {str(e)}"
            self.data_display.setText(error_msg)
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout()
        
        # Create form for input fields
        form_group = QGroupBox("Reception Settings")
        form_layout = QFormLayout()
        
        # Output file
        output_layout = QHBoxLayout()
        self.output_file_edit = QLineEdit()
        self.output_file_edit.setPlaceholderText("Path to save received data")
        self.output_file_button = QPushButton("Browse...")
        self.output_file_button.clicked.connect(self.browse_output_file)
        output_layout.addWidget(self.output_file_edit)
        output_layout.addWidget(self.output_file_button)
        form_layout.addRow("Output File:", output_layout)
        
        # Key file
        key_layout = QHBoxLayout()
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("Path to decryption key file (optional)")
        self.key_file_button = QPushButton("Browse...")
        self.key_file_button.clicked.connect(self.browse_key_file)
        key_layout.addWidget(self.key_file_edit)
        key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)
        
        # Network interface
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("default")
        self.populate_interfaces()
        form_layout.addRow("Interface:", self.interface_combo)
        
        # Output directory
        output_dir_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Custom output directory (optional)")
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.browse_output_dir)
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_dir_layout)
        
        # Timeout
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 600)
        self.timeout_spin.setValue(DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" sec")
        form_layout.addRow("Timeout:", self.timeout_spin)
        
        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)
        
        # Add control buttons
        control_layout = QHBoxLayout()
        
        self.receive_button = QPushButton("Start Listening")
        self.receive_button.clicked.connect(self.start_reception)
        self.receive_button.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_reception)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.clear_log)
        
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self.populate_interfaces)
        
        control_layout.addWidget(self.receive_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.refresh_button)
        
        main_layout.addLayout(control_layout)
        
        # Add progress bar
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        self.status_label = QLabel("Ready")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        # Create a splitter for log and data display
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        
        # Log area
        log_group = QGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        splitter.addWidget(log_group)
        
        # Data display area (new)
        data_group = QGroupBox("Received Data")
        data_layout = QVBoxLayout()
        
        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.data_display.setFont(QFont("Courier", 9))
        
        # Add a save button for the received data
        self.save_data_button = QPushButton("Save Displayed Data")
        self.save_data_button.clicked.connect(self.save_displayed_data)
        
        # Add a clear button for the data display
        self.clear_data_button = QPushButton("Clear Display")
        self.clear_data_button.clicked.connect(self.clear_data_display)
        
        data_buttons_layout = QHBoxLayout()
        data_buttons_layout.addWidget(self.save_data_button)
        data_buttons_layout.addWidget(self.clear_data_button)
        
        data_layout.addWidget(self.data_display)
        data_layout.addLayout(data_buttons_layout)
        data_group.setLayout(data_layout)
        splitter.addWidget(data_group)
        
        # Set initial sizes for the splitter (50% each)
        splitter.setSizes([500, 500])
        
        main_layout.addWidget(splitter, 1)  # Give splitter more vertical space
        
        self.setLayout(main_layout)
    
    def populate_interfaces(self):
        """Populate the interface dropdown with available network interfaces."""
        current_selection = self.interface_combo.currentText()
        self.interface_combo.clear()
        
        # Always add the default option
        self.interface_combo.addItem("default")
        
        try:
            # Get all network interfaces
            interfaces = netifaces.interfaces()
            
            for iface in interfaces:
                # Skip loopback interface
                if iface.startswith("lo"):
                    continue
                    
                # Add interface to the dropdown
                self.interface_combo.addItem(iface)
                
                # Try to get IP address for this interface
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        self.interface_combo.setItemText(
                            self.interface_combo.count() - 1,
                            f"{iface} ({ip})"
                        )
                except:
                    pass
        except Exception as e:
            self.add_log_message(f"Error populating interfaces: {str(e)}")
        
        # Try to restore previous selection
        index = self.interface_combo.findText(current_selection)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
    
    def browse_output_file(self):
        """Open file dialog to select output file."""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Select Output File", "", "All Files (*)"
        )
        if file_path:
            self.output_file_edit.setText(file_path)
    
    def browse_key_file(self):
        """Open file dialog to select key file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Key File", "", "All Files (*)"
        )
        if file_path:
            self.key_file_edit.setText(file_path)
    
    def browse_output_dir(self):
        """Open directory dialog to select output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory", ""
        )
        if dir_path:
            self.output_dir_edit.setText(dir_path)
    
    def add_log_message(self, message):
        """Add a message to the log."""
        self.log_edit.append(message)
        self.log_edit.moveCursor(QTextCursor.End)
        
        # Enhanced data detection
        try:
            # Check specifically for our [DATA] tag first (from WorkerThread)
            if message.startswith("[DATA] "):
                data = message[7:].strip()  # Remove the [DATA] prefix
                print(f"Adding to data display: {data[:20]}{'...' if len(data) > 20 else ''}")
                self.data_queue.put(data)
                return  # We've handled this message, return early
            
            # Also check for other known data patterns in case we missed some
            data_markers = [
                "[CHUNK] Data:", 
                "Decoded data:", 
                "Received chunk data:", 
                "Data chunk", 
                "CHUNK_DATA"
            ]
            
            for marker in data_markers:
                if marker in message:
                    data = message.split(marker, 1)[1].strip()
                    print(f"Alternative data match: {data[:20]}{'...' if len(data) > 20 else ''}")
                    self.data_queue.put(data)
                    break
        except Exception as e:
            print(f"Error processing data for display: {e}")
    
    def update_log(self):
        """Update the log with messages from the queue."""
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.add_log_message(message)
    
    def update_data_display(self):
        """Update the data display with received data."""
        try:
            # Process multiple data updates in one batch for efficiency
            data_batch = []
            max_items = 20  # Process up to 20 items at once
            
            for _ in range(max_items):
                if not self.data_queue.empty():
                    data_batch.append(self.data_queue.get_nowait())
                else:
                    break
                    
            if data_batch:
                # Combine all new data
                new_data = '\n'.join(data_batch)
                
                # Add to display with improved cursor handling
                cursor = self.data_display.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.insertText(new_data + '\n')
                self.data_display.setTextCursor(cursor)
                self.data_display.ensureCursorVisible()
                
                print(f"Updated data display with {len(data_batch)} new items")
        except Exception as e:
            print(f"Error updating data display: {e}")
    
    def clear_log(self):
        """Clear the log area."""
        self.log_edit.clear()
    
    def clear_data_display(self):
        """Clear the data display area."""
        self.data_display.clear()
    
    def save_displayed_data(self):
        """Save the currently displayed data to a file."""
        # Get a filename to save to
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Displayed Data", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.data_display.toPlainText())
                QMessageBox.information(self, "Success", f"Data saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save data: {str(e)}")
    
    def start_reception(self):
        """Start the reception process."""
        # Validate input
        output_file = self.output_file_edit.text().strip()
        if not output_file:
            QMessageBox.warning(self, "Input Error", "Output file is required.")
            return
        
        # Check if output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            response = QMessageBox.question(
                self, "Create Directory?", 
                f"Output directory does not exist: {output_dir}\nCreate it?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if response == QMessageBox.Yes:
                try:
                    os.makedirs(output_dir)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}")
                    return
            else:
                return
        
        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file):
            QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}")
            return
        
        custom_output_dir = self.output_dir_edit.text().strip()
        if custom_output_dir and not os.path.exists(custom_output_dir):
            response = QMessageBox.question(
                self, "Create Directory?", 
                f"Custom output directory does not exist: {custom_output_dir}\nCreate it?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if response == QMessageBox.Yes:
                try:
                    os.makedirs(custom_output_dir)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}")
                    return
            else:
                return
        
        # Prepare arguments
        args = {
            "output_file": output_file,
            "timeout": self.timeout_spin.value()
        }
        
        # Get interface
        interface_text = self.interface_combo.currentText()
        if interface_text and interface_text != "default":
            # Extract interface name if it includes IP
            interface = interface_text.split()[0] if "(" in interface_text else interface_text
            args["interface"] = interface
        
        if key_file:
            args["key_file"] = key_file
            
        if custom_output_dir:
            args["output_dir"] = custom_output_dir
        
        # Save settings
        self.save_settings()
        
        # Clear log and reset progress
        self.clear_log()
        self.clear_data_display()  # Also clear the data display
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting reception...")
        
        # Disable controls during reception
        self.receive_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Create and start worker thread
        self.worker_thread = WorkerThread("receive", args)
        self.worker_thread.update_signal.connect(self.add_log_message)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.reception_finished)
        self.worker_thread.start()
    
    def stop_reception(self):
        """Stop the current reception."""
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping reception...")
            self.worker_thread.stop()
    
    def update_progress(self, current, total):
        """Update the progress bar directly without any throttling or smoothing."""
        try:
            if total <= 0:
                return
                
            # Calculate percentage - ensure we don't exceed 100%
            percentage = min(100, (current / total) * 100)
            
            # Set the progress bar value directly
            self.progress_bar.setValue(int(percentage))
            print(f"Setting progress to {percentage:.1f}%")
            
            # Update parent's status bar without any throttling
            if self.parent:
                if isinstance(current, int) and isinstance(total, int):
                    self.parent.statusBar().showMessage(f"Receiving: {current}/{total} chunks ({percentage:.1f}%)")
                else:
                    self.parent.statusBar().showMessage(f"Receiving: {percentage:.1f}%")
        except Exception as e:
            print(f"Error updating progress: {e}")
    
    def update_status(self, status):
        """Update the status label."""
        self.status_label.setText(status)
    
    def reception_finished(self, success):
        """Handle the completion of reception."""
        # Enable controls
        self.receive_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
        # Update status
        if success:
            self.status_label.setText("Reception completed successfully")
            if self.parent:
                self.parent.statusBar().showMessage("Reception completed successfully")
                
            # Display the content of the received file
            output_file = self.output_file_edit.text().strip()
            if output_file:
                self.display_received_file(output_file)
        else:
            self.status_label.setText("Reception failed or was stopped")
            if self.parent:
                self.parent.statusBar().showMessage("Reception failed or was stopped")
    
    def save_settings(self):
        """Save current settings."""
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        settings.setValue("output_file", self.output_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("interface", self.interface_combo.currentText())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("timeout", self.timeout_spin.value())
    
    def load_settings(self):
        """Load saved settings."""
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        self.output_file_edit.setText(settings.value("output_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        
        interface = settings.value("interface", "default")
        index = self.interface_combo.findText(interface)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
            
        self.output_dir_edit.setText(settings.value("output_dir", ""))
        
        timeout = settings.value("timeout", DEFAULT_TIMEOUT)
        try:
            self.timeout_spin.setValue(int(timeout))
        except:
            self.timeout_spin.setValue(DEFAULT_TIMEOUT)

class MainWindow(QMainWindow):
    """Main application window."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CrypticRoute - Network Steganography Tool")
        self.setMinimumSize(800, 600)
        
        # Create and set central widget
        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)
        
        # Add sender panel
        self.sender_panel = SenderPanel(self)
        self.central_widget.addTab(self.sender_panel, "Send File")
        
        # Add receiver panel
        self.receiver_panel = ReceiverPanel(self)
        self.central_widget.addTab(self.receiver_panel, "Receive File")
        
        # Add status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
        # Connect tab change to status bar update
        self.central_widget.currentChanged.connect(self.update_status_on_tab_change)
        
        # Set up the UI
        self.setup_ui()
        
        # Load window settings
        self.load_settings()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Set application icon
        # icon = QIcon("icon.png")  # Replace with your icon if you have one
        # self.setWindowIcon(icon)
        
        # Create menu bar
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)
    
    def update_status_on_tab_change(self, index):
        """Update status bar when tabs are changed."""
        if index == 0:  # Sender tab
            self.status_bar.showMessage("Sender: Ready")
        else:  # Receiver tab
            self.status_bar.showMessage("Receiver: Ready")
    
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About CrypticRoute",
            "<h1>CrypticRoute</h1>"
            "<p>Network Steganography Tool</p>"
            "<p>Version 1.0</p>"
            "<p>A graphical interface for sending and receiving hidden data through network packets.</p>"
        )
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop any running threads
        if self.sender_panel.worker_thread and self.sender_panel.worker_thread.isRunning():
            self.sender_panel.stop_transmission()
            
        if self.receiver_panel.worker_thread and self.receiver_panel.worker_thread.isRunning():
            self.receiver_panel.stop_reception()
        
        # Save window settings
        self.save_settings()
        
        event.accept()
    
    def save_settings(self):
        """Save window settings."""
        settings = QSettings("CrypticRoute", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("state", self.saveState())
        settings.setValue("current_tab", self.central_widget.currentIndex())
    
    def load_settings(self):
        """Load window settings."""
        settings = QSettings("CrypticRoute", "MainWindow")
        geometry = settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
            
        state = settings.value("state")
        if state:
            self.restoreState(state)
            
        tab = settings.value("current_tab", 0)
        try:
            self.central_widget.setCurrentIndex(int(tab))
        except:
            self.central_widget.setCurrentIndex(0)

def check_environment():
    """Check if XDG_RUNTIME_DIR is set and fix it if needed."""
    if "XDG_RUNTIME_DIR" not in os.environ:
        # Create a temporary runtime directory and set the environment variable
        runtime_dir = f"/tmp/runtime-{os.getuid()}"
        if not os.path.exists(runtime_dir):
            try:
                os.makedirs(runtime_dir, mode=0o700)
            except:
                pass
        os.environ["XDG_RUNTIME_DIR"] = runtime_dir
        print(f"Set XDG_RUNTIME_DIR to {runtime_dir}")

def main():
    """Main application entry point."""
    # Fix XDG_RUNTIME_DIR issue
    check_environment()
    
    # Set up signal handling in main thread
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    # Handle high DPI screens
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setApplicationName("CrypticRoute")
    app.setApplicationVersion("1.0")
    
    # Set style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    # Display a helpful message about root permissions if running as root
    if os.geteuid() == 0:
        print("Running CrypticRoute GUI as root. For a better approach, consider using capabilities instead:")
        print("sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
        print("This will allow running without sudo while still having necessary permissions.")
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()