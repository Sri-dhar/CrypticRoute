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
        
        # Start the process with pipe for stdout and stderr
        self.process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        
        # Track progress
        total_chunks = 0
        current_chunk = 0
        
        # Process output
        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break
                
            self.update_signal.emit(line.strip())
            
            # Extract progress information
            if "[PREP] Data split into" in line:
                try:
                    total_chunks = int(line.split("into")[1].strip().split()[0])
                    self.status_signal.emit(f"Total chunks: {total_chunks}")
                except:
                    pass
            
            elif "[STATUS] Completed chunk" in line:
                try:
                    parts = line.split()
                    chunk_info = parts[3].split('/')
                    current_chunk = int(chunk_info[0])
                    self.progress_signal.emit(current_chunk, total_chunks)
                except:
                    pass
            
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
        
        # Track progress
        total_chunks = 0
        current_chunk = 0
        
        # Process output
        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break
                
            self.update_signal.emit(line.strip())
            
            # Extract progress information
            if "[CHUNK] Received" in line and "Total" in line:
                try:
                    parts = line.split('|')
                    chunk_info = parts[1].strip().split('/')
                    current_chunk = int(chunk_info[0])
                    total_chunk = int(chunk_info[1])
                    self.progress_signal.emit(current_chunk, total_chunk)
                except:
                    pass
            
            elif "[COMPLETE] Received transmission complete signal" in line:
                self.status_signal.emit("Reception complete")
        
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
        self.log_timer.start(100)  # Update logs every 100ms
        
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
        self.log_edit.append(message)
        self.log_edit.moveCursor(QTextCursor.End)
    
    def update_log(self):
        """Update the log with messages from the queue."""
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.add_log_message(message)
    
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
        self.setup_ui()
        
        # Setup timer for log updates
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(100)  # Update logs every 100ms
        
        # Load saved settings
        self.load_settings()
    
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
        
        # Add log area
        log_group = QGroupBox("Reception Log")
        log_layout = QVBoxLayout()
        
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        
        log_layout.addWidget(self.log_edit)
        
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group, 1)  # Give log area more vertical space
        
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
    
    def update_log(self):
        """Update the log with messages from the queue."""
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.add_log_message(message)
    
    def clear_log(self):
        """Clear the log area."""
        self.log_edit.clear()
    
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
        """Update the progress bar."""
        if total > 0:
            percentage = (current / total) * 100
            self.progress_bar.setValue(int(percentage))
            
            # Update parent's status bar
            if self.parent:
                self.parent.statusBar().showMessage(f"Receiving: {current}/{total} chunks ({percentage:.1f}%)")
    
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

def main():
    """Main application entry point."""
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
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
