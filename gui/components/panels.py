#!/usr/bin/env python3
"""
Main panels for CrypticRoute GUI: Sender and Receiver
"""

import os
import sys # Import sys
import time
import queue
import random
import threading
import netifaces
import re
import traceback # Import traceback

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLabel,
                             QLineEdit, QPushButton, QSpinBox, QDoubleSpinBox, QComboBox,
                             QTextEdit, QFileDialog, QGroupBox, QMessageBox, QScrollArea,
                             QFrame, QSplitter)
from PyQt6.QtCore import Qt, QTimer, QSettings, QEvent
from PyQt6.QtGui import QFont, QTextCursor

from ..utils.constants import COLORS, DEFAULT_CHUNK_SIZE, DEFAULT_TIMEOUT, DEFAULT_DELAY
# LogRedirector is used in WorkerThread now
# from ..utils.redirector import LogRedirector
from .indicators import HandshakeIndicator, IPExchangePanel, AnimatedStatusLabel
from .buttons import AnimatedButton
from .progress_bars import AnimatedProgressBar
from .worker_thread import WorkerThread
from .status_window import AckStatusWindow


class ModernGroupBox(QGroupBox):
    def __init__(self, title, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                border: 1px solid {COLORS['secondary']};
                border-radius: 8px;
                margin-top: 1.5ex;
                padding: 10px;
                background-color: {COLORS['light']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                color: {COLORS['primary']};
                background-color: {COLORS['light']};
            }}
        """)


class SenderPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker_thread = None
        self.log_queue = queue.Queue() # Sender still uses queue via subprocess stdout
        self.ack_status_window = None # Reference to the separate ACK window
        self.total_chunks_for_ack = 0 # Store total chunks locally
        self.acknowledged_chunks_set = set() # Store received ACKs locally
        self.setup_ui()
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(50) # Check log queue every 50ms
        self.load_settings()
        self.resizing = False # Flag for log resizing

        # Setup source_port for sender
        self.source_port = random.randint(10000, 60000)

        # Try to get the local IP address for IP exchange panel
        try:
            # Get the default interface and its IP
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if interface.startswith('lo'): # Skip loopback
                    continue
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    local_ip = addrs[netifaces.AF_INET][0]['addr']
                    if not local_ip.startswith('127.'):
                        self.ip_exchange_panel.set_local_ip(f"{local_ip}:{self.source_port}")
                        break
        except Exception as e:
            print(f"Error getting local IP for sender panel: {e}")
            # If we can't get IP info, just skip it
            pass

    def eventFilter(self, obj, event):
        # Handle resize events for the log edit
        if obj.objectName() == "logContainer" or \
        (hasattr(obj, 'text') and obj.text() == "⣿") or \
        obj == self.log_edit:

            if event.type() == QEvent.Type.MouseButtonPress and event.button() == Qt.MouseButton.LeftButton:
                # Start resize operation
                self.resizing = True
                self.resize_start_y = event.globalPosition().y()
                self.resize_start_height = self.log_edit.height()
                return True

            elif event.type() == QEvent.Type.MouseMove and self.resizing:
                # Calculate new height based on mouse movement
                delta_y = event.globalPosition().y() - self.resize_start_y
                new_height = max(100, self.resize_start_height + delta_y)  # Enforce minimum height

                # Apply the new height
                self.log_edit.setMinimumHeight(int(new_height))
                self.log_edit.setMaximumHeight(int(new_height))
                return True

            elif event.type() == QEvent.Type.MouseButtonRelease:
                # End resize operation
                self.resizing = False
                return True

        # Pass event to parent class if not handled
        return super().eventFilter(obj, event)

    def setup_ui(self):
        # Create a scroll area to make the UI scrollable
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        # Create a container widget for the scroll area
        container_widget = QWidget()

        # Main layout for the container
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        self.setStyleSheet(f"""
            QWidget {{
                font-size: 10pt;
                color: {COLORS['text']};
            }}
            QLabel {{
                font-size: 10pt;
            }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
                padding: 8px;
                border: 1px solid {COLORS['secondary']};
                border-radius: 4px;
                background-color: white;
            }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
                border: 2px solid {COLORS['primary']};
            }}
        """)

        # Create a widget to hold all upper elements
        upper_widget = QWidget()
        upper_layout = QVBoxLayout(upper_widget)
        upper_layout.setContentsMargins(0, 0, 0, 0)
        upper_layout.setSpacing(10)

        # Transmission Settings Group
        form_group = ModernGroupBox("Transmission Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)

        # Change target_ip to interface selection (similar to ReceiverPanel)
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("default")
        self.populate_interfaces() # Add this method to SenderPanel (copy from ReceiverPanel)
        form_layout.addRow("Network Interface:", self.interface_combo)

        input_layout = QHBoxLayout()
        input_layout.setSpacing(8)
        self.input_file_edit = QLineEdit()
        self.input_file_edit.setPlaceholderText("Path to input file")
        self.input_file_button = QPushButton("Browse...")
        self.input_file_button.clicked.connect(self.browse_input_file)
        self.input_file_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['secondary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #7e8a9a;
            }}
        """)
        input_layout.addWidget(self.input_file_edit)
        input_layout.addWidget(self.input_file_button)
        form_layout.addRow("Input File:", input_layout)

        key_layout = QHBoxLayout()
        key_layout.setSpacing(8)
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("Path to encryption key file (optional)")
        self.key_file_button = QPushButton("Browse...")
        self.key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['secondary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #7e8a9a;
            }}
        """)
        key_layout.addWidget(self.key_file_edit)
        key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)

        output_layout = QHBoxLayout()
        output_layout.setSpacing(8)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Custom output directory (optional)")
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.browse_output_dir)
        self.output_dir_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['secondary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #7e8a9a;
            }}
        """)
        output_layout.addWidget(self.output_dir_edit)
        output_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_layout)

        self.delay_spin = QDoubleSpinBox()
        self.delay_spin.setRange(0.01, 5.0)
        self.delay_spin.setSingleStep(0.1)
        self.delay_spin.setValue(DEFAULT_DELAY)
        self.delay_spin.setSuffix(" sec")
        form_layout.addRow("Packet Delay:", self.delay_spin)

        self.chunk_size_spin = QSpinBox()
        self.chunk_size_spin.setRange(1, 8) # Keep range limited as per original design?
        self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)
        self.chunk_size_spin.setSuffix(" bytes")
        form_layout.addRow("Chunk Size:", self.chunk_size_spin)

        form_group.setLayout(form_layout)
        upper_layout.addWidget(form_group)

        # Control buttons
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        self.send_button = AnimatedButton("Start Transmission", color=COLORS['success'])
        self.send_button.clicked.connect(self.start_transmission)
        self.stop_button = AnimatedButton("Stop", color=COLORS['danger'])
        self.stop_button.clicked.connect(self.stop_transmission)
        self.stop_button.setEnabled(False)
        self.clear_button = AnimatedButton("Clear Log", color=COLORS['secondary'])
        self.clear_button.clicked.connect(self.clear_log)
        # --- Add Ack Status Button ---
        self.ack_status_button = AnimatedButton("Ack Status", color=COLORS['info'])
        self.ack_status_button.clicked.connect(self.show_ack_status_window)
        self.ack_status_button.setEnabled(False) # Initially disabled

        control_layout.addWidget(self.send_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.ack_status_button) # Add the new button
        control_layout.addStretch()
        upper_layout.addLayout(control_layout)

        # Simplified Connection Status
        self.handshake_indicator = HandshakeIndicator()
        upper_layout.addWidget(self.handshake_indicator)

        # Add IP Exchange Panel (new)
        self.ip_exchange_panel = IPExchangePanel()
        upper_layout.addWidget(self.ip_exchange_panel)

        # Progress bar
        progress_group = ModernGroupBox("Progress")
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(10)
        self.progress_bar = AnimatedProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = AnimatedStatusLabel("Ready")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)
        upper_layout.addWidget(progress_group)

        # Log area
        log_group = ModernGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        self.log_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border-radius: 4px;
                padding: 5px;
            }}
        """)
        # Set minimum height for log edit to look good when splitter is moved
        self.log_edit.setMinimumHeight(300)
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)

        # Create a vertical splitter to allow resizing between top elements and log
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(upper_widget)
        splitter.addWidget(log_group)
        # Set initial sizes - adjust these values to your preference
        splitter.setSizes([300, 1700])
        # Make splitter handle more visible
        splitter.setHandleWidth(8)
        splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS['secondary']};
                border-radius: 2px;
            }}
            QSplitter::handle:hover {{
                background-color: {COLORS['primary']};
            }}
        """)

        # Add the splitter to the main layout
        main_layout.addWidget(splitter)

        # Set the container as the scroll area's widget
        scroll_area.setWidget(container_widget)

        # Main layout for this panel
        panel_layout = QVBoxLayout(self)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.addWidget(scroll_area)
        self.setLayout(panel_layout)

    def populate_interfaces(self):
        self.interface_combo.clear()
        self.interface_combo.addItem("default")
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                # Skip loopback and potentially virtual interfaces unless explicitly needed
                if iface.startswith("lo") or "veth" in iface or "docker" in iface:
                    continue
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        self.interface_combo.addItem(f"{iface} ({ip})")
                    else:
                        # Add interface even if no IPv4 found, might be IPv6 only
                        self.interface_combo.addItem(iface)
                except Exception as iface_err:
                    print(f"Could not get address for {iface}: {iface_err}")
                    self.interface_combo.addItem(iface) # Add by name only
        except ImportError:
            self.add_log_message("ERROR: 'netifaces' library not found. Cannot list interfaces. Please install it (`pip install netifaces`).")
        except Exception as e:
            self.add_log_message(f"Error populating interfaces: {str(e)}")


    def browse_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", "All Files (*)")
        if file_path:
            self.input_file_edit.setText(file_path)

    def browse_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "All Files (*)")
        if file_path:
            self.key_file_edit.setText(file_path)

    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory", "")
        if dir_path:
            self.output_dir_edit.setText(dir_path)

    def add_log_message(self, message):
        # Reduce log spam for packet numbers (optional)
        # if "[PACKET] #" in message and not (message.endswith("0") or message.endswith("5")):
        #     return

        styled_message = message

        # Apply styling based on message content
        if message.startswith("ERROR:") or "Traceback" in message:
            styled_message = f'<span style="color:{COLORS["danger"]};">{message}</span>'
        elif "[COMPLETE]" in message or "Success" in message:
            styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'
        elif "[INFO]" in message:
            styled_message = f'<span style="color:{COLORS["info"]};">{message}</span>'
        elif "[WARNING]" in message or "Warning" in message:
            styled_message = f'<span style="color:{COLORS["warning"]};">{message}</span>'
        elif "[HANDSHAKE]" in message:
            styled_message = f'<span style="color:{COLORS["handshake"]};">{message}</span>'
        elif "[ACK]" in message:
            styled_message = f'<span style="color:{COLORS["ack"]};">{message}</span>'
        elif "[CONFIRMED]" in message:
            styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'

        self.log_edit.append(styled_message)
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_edit.setTextCursor(cursor)

    def update_log(self):
        try:
            messages = []
            # Process multiple messages per timer tick for responsiveness
            for _ in range(20):
                if not self.log_queue.empty():
                    messages.append(self.log_queue.get_nowait())
                else:
                    break
            if messages:
                for message in messages:
                    self.add_log_message(message)
                # Scroll only after adding all messages in the batch
                self.log_edit.ensureCursorVisible()
        except queue.Empty:
            pass # Expected if queue becomes empty during batch read
        except Exception as e:
            print(f"Error updating log: {e}")

    def clear_log(self):
        self.log_edit.clear()

    def process_ip_exchange(self, message):
        """Process IP exchange messages from the log."""
        if "[IP_EXCHANGE]" in message:
            # Extract IP and port information
            if "Receiver IP discovered:" in message:
                # Format: [IP_EXCHANGE] Receiver IP discovered: 192.168.1.x
                parts = message.split("Receiver IP discovered:")
                if len(parts) > 1:
                    ip = parts[1].strip()
                    self.ip_exchange_panel.set_remote_discovered(ip)
            elif "Connecting to receiver at" in message:
                # Format: [IP_EXCHANGE] Connecting to receiver at 192.168.1.x:port
                parts = message.split("Connecting to receiver at")
                if len(parts) > 1:
                    ip_port = parts[1].strip()
                    self.ip_exchange_panel.set_connection_requested()
            elif "Confirmed connection with" in message:
                # Format: [IP_EXCHANGE] Confirmed connection with 192.168.1.x:port
                parts = message.split("Confirmed connection with")
                if len(parts) > 1:
                    ip_port = parts[1].strip()
                    self.ip_exchange_panel.set_connection_established()

    def show_ack_status_window(self):
        """Creates (if needed) and shows the separate ACK status window."""
        if not self.ack_status_window or not self.ack_status_window.isVisible():
            # Create a new window instance, passing main window as parent
            # This helps with automatic cleanup if the main window closes
            self.ack_status_window = AckStatusWindow(self.parent)

            # IMPORTANT: Populate the new window with the current ACK state
            self.ack_status_window.update_state(self.total_chunks_for_ack, self.acknowledged_chunks_set)

            self.ack_status_window.show()
        else:
            # If window exists and is visible, just bring it to the front
            self.ack_status_window.raise_()
            self.ack_status_window.activateWindow()

    def start_transmission(self):
        # Input file validation
        input_file = self.input_file_edit.text().strip()
        if not input_file:
            QMessageBox.warning(self, "Input Error", "Input file is required.")
            return
        if not os.path.exists(input_file):
            QMessageBox.warning(self, "Input Error", f"Input file does not exist: {input_file}")
            return

        # Key file validation
        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file):
            QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}")
            return

        # Output directory validation
        output_dir = self.output_dir_edit.text().strip()
        if output_dir and not os.path.exists(output_dir):
            response = QMessageBox.question(self, "Create Directory?",
                                            f"Output directory does not exist: {output_dir}\nCreate it?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                            QMessageBox.StandardButton.Yes)
            if response == QMessageBox.StandardButton.Yes:
                try:
                    os.makedirs(output_dir)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}")
                    return
            else:
                return

        args = {
            "input_file": input_file,
            "delay": self.delay_spin.value(),
            "chunk_size": self.chunk_size_spin.value(),
        }

        # Get the interface if it's not default
        interface_text = self.interface_combo.currentText()
        if interface_text and interface_text != "default":
            # Extract only the interface name (before parenthesis if present)
            interface = interface_text.split('(')[0].strip()
            args["interface"] = interface
            print(f"Using interface: {interface}")

        if key_file:
            args["key_file"] = key_file
        if output_dir:
            args["output_dir"] = output_dir

        self.save_settings()
        self.clear_log()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting transmission...")

        # Reset visualization components and internal state
        self.handshake_indicator.reset()
        self.ip_exchange_panel.reset()  # Reset IP exchange panel
        self.total_chunks_for_ack = 0
        self.acknowledged_chunks_set = set()
        # Close existing ACK window if open
        if self.ack_status_window:
            self.ack_status_window.close()
            self.ack_status_window = None # Clear reference
        self.ack_status_button.setEnabled(False) # Disable button until total chunks known

        self.send_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.worker_thread = WorkerThread("send", args)
        self.worker_thread.update_signal.connect(self.log_queue.put) # Put raw messages in queue
        self.worker_thread.update_signal.connect(self.process_ip_exchange) # Process IP exchange messages
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.transmission_finished)

        # Connect signals for handshake and ACK visualization
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        self.worker_thread.ack_signal.connect(self.update_ack)
        self.worker_thread.total_chunks_signal.connect(self.handle_total_chunks) # Connect to handler

        self.worker_thread.start()

    def stop_transmission(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping transmission...")
            self.worker_thread.stop()
            # Buttons will be re-enabled in transmission_finished

    def update_progress(self, current, total):
        if total > 0:
            percentage = min(100, (current / total) * 100) # Ensure not over 100%
            self.progress_bar.setValue(int(percentage))
            if self.parent:
                self.parent.statusBar().showMessage(f"Sending: {current}/{total} chunks ({percentage:.1f}%)")
        elif current > 0: # Handle case where total might be 0 temporarily
            self.progress_bar.setValue(0) # Avoid division by zero, maybe show indeterminate later
            if self.parent:
                self.parent.statusBar().showMessage(f"Sending: Chunk {current}...")


    def update_status(self, status):
        self.status_label.setText(status)

    def update_handshake(self, stage):
        """Update the handshake indicator based on the current stage."""
        if stage == "syn_sent":
            self.handshake_indicator.set_syn_sent()
        elif stage == "syn_ack_received":
            # Usually sender gets SYN-ACK, receiver sends it
            self.handshake_indicator.set_syn_ack_sent() # Visually mark SYN-ACK step done
        elif stage == "ack_sent":
            self.handshake_indicator.set_ack_sent()
        elif stage == "established":
            self.handshake_indicator.set_connection_established()

    def handle_total_chunks(self, total):
        """Handles receiving the total number of chunks."""
        if total > 0:
            print(f"Sender Panel Received total chunks: {total}")
            self.total_chunks_for_ack = total
            self.ack_status_button.setEnabled(True) # Enable the button now
            # If the window is already open, update its total
            if self.ack_status_window and self.ack_status_window.isVisible():
                self.ack_status_window.set_total_chunks(total)

    def update_ack(self, chunk_num):
        """Update the acknowledgment status when a chunk is acknowledged."""
        if chunk_num > 0:
            print(f"SenderPanel updating ACK for chunk {chunk_num}")
            # Store ACK locally
            self.acknowledged_chunks_set.add(chunk_num)
            # Update the separate window if it's open
            if self.ack_status_window and self.ack_status_window.isVisible():
                self.ack_status_window.acknowledge_chunk(chunk_num)

    def transmission_finished(self, success):
        self.send_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        final_message = ""
        if success:
            self.status_label.setText("Transmission completed successfully")
            self.progress_bar.setValue(100)
            final_message = "Transmission completed successfully"
            # Optionally update ACK window one last time
            if self.ack_status_window and self.ack_status_window.isVisible():
                self.ack_status_window.update_state(self.total_chunks_for_ack, self.acknowledged_chunks_set)
        else:
            # Check if stopped manually or failed
            current_status = self.status_label.text().lower()
            if "stopping" in current_status or "stopped by user" in current_status:
                self.status_label.setText("Transmission stopped by user")
                final_message = "Transmission stopped by user"
            else:
                self.status_label.setText("Transmission failed")
                final_message = "Transmission failed"

        if self.parent:
            self.parent.statusBar().showMessage(final_message, 5000) # Show for 5 seconds

        # Keep ACK button enabled if transmission finished (failed or success)
        # self.ack_status_button.setEnabled(False) # Maybe keep enabled? User decision. Let's keep it enabled.

        self.worker_thread = None # Clear thread reference

    def save_settings(self):
        settings = QSettings("CrypticRoute", "SenderPanel")
        settings.setValue("interface", self.interface_combo.currentText())
        settings.setValue("input_file", self.input_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("delay", self.delay_spin.value())
        settings.setValue("chunk_size", self.chunk_size_spin.value())

    def load_settings(self):
        settings = QSettings("CrypticRoute", "SenderPanel")
        interface = settings.value("interface", "default")
        # FindText might be slow if many interfaces, but fine here
        index = self.interface_combo.findText(interface, Qt.MatchFlag.MatchContains)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
        else:
            self.interface_combo.setCurrentIndex(0) # Fallback to default
        self.input_file_edit.setText(settings.value("input_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        self.output_dir_edit.setText(settings.value("output_dir", ""))

        delay = settings.value("delay", DEFAULT_DELAY)
        try:
            self.delay_spin.setValue(float(delay))
        except ValueError:
            self.delay_spin.setValue(DEFAULT_DELAY)

        chunk_size = settings.value("chunk_size", DEFAULT_CHUNK_SIZE)
        try:
            self.chunk_size_spin.setValue(int(chunk_size))
        except ValueError:
            self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)


class ReceiverPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker_thread = None
        # self.log_queue = queue.Queue() # Receiver now uses direct call, queue not used for logs
        self.data_queue = queue.Queue() # Still used for data display updates
        self.setup_ui()
        # self.log_timer = QTimer(self) # Log updates handled by direct signal emit
        # self.log_timer.timeout.connect(self.update_log)
        # self.log_timer.start(25)
        self.data_timer = QTimer(self)
        self.data_timer.timeout.connect(self.update_data_display)
        self.data_timer.start(50) # Data display updates
        self.load_settings()

        # Setup source_port for receiver
        self.source_port = random.randint(10000, 60000)

        # Try to get the local IP address for IP exchange panel
        try:
            # Get the default interface and its IP from the interface combo
            interface_text = self.interface_combo.currentText()
            if "(" in interface_text:
                local_ip = interface_text.split("(")[1].split(")")[0]
                self.ip_exchange_panel.set_local_ip(f"{local_ip}:{self.source_port}")
        except Exception as e:
            print(f"Error getting local IP for receiver panel: {e}")
            # If we can't get IP info, just skip it
            pass

    def setup_ui(self):
        # Create a scroll area to make the UI scrollable
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)

        # Create a container widget for the scroll area
        container_widget = QWidget()

        # Main layout for the container
        main_layout = QVBoxLayout(container_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)

        self.setStyleSheet(f"""
            QWidget {{
                font-size: 10pt;
                color: {COLORS['text']};
            }}
            QLabel {{
                font-size: 10pt;
            }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
                padding: 8px;
                border: 1px solid {COLORS['secondary']};
                border-radius: 4px;
                background-color: white;
            }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
                border: 2px solid {COLORS['primary']};
            }}
            QComboBox::drop-down {{
                border: 0px;
                width: 30px;
            }}
            /* QComboBox::down-arrow - Consider using default or theme arrow */
        """)

        # Reception Settings Form
        form_group = ModernGroupBox("Reception Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)

        output_layout = QHBoxLayout()
        output_layout.setSpacing(8)
        self.output_file_edit = QLineEdit()
        self.output_file_edit.setPlaceholderText("Path to save received data")
        self.output_file_button = QPushButton("Browse...")
        self.output_file_button.clicked.connect(self.browse_output_file)
        self.output_file_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['secondary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #7e8a9a;
            }}
        """)
        output_layout.addWidget(self.output_file_edit)
        output_layout.addWidget(self.output_file_button)
        form_layout.addRow("Output File:", output_layout)

        key_layout = QHBoxLayout()
        key_layout.setSpacing(8)
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("Path to decryption key file (optional)")
        self.key_file_button = QPushButton("Browse...")
        self.key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['secondary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #7e8a9a;
            }}
        """)
        key_layout.addWidget(self.key_file_edit)
        key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)

        self.interface_combo = QComboBox()
        self.interface_combo.addItem("default")
        self.populate_interfaces()
        form_layout.addRow("Interface:", self.interface_combo)

        output_dir_layout = QHBoxLayout()
        output_dir_layout.setSpacing(8)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Custom session output directory (optional)")
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.browse_output_dir)
        self.output_dir_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['secondary']};
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: #7e8a9a;
            }}
        """)
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Session Dir:", output_dir_layout) # Renamed label for clarity

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 600)
        self.timeout_spin.setValue(DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" sec")
        form_layout.addRow("Timeout:", self.timeout_spin)

        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)

        # Control buttons
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        self.receive_button = AnimatedButton("Start Listening", color=COLORS['primary'])
        self.receive_button.clicked.connect(self.start_reception)
        self.stop_button = AnimatedButton("Stop", color=COLORS['danger'])
        self.stop_button.clicked.connect(self.stop_reception)
        self.stop_button.setEnabled(False)
        self.clear_button = AnimatedButton("Clear Log", color=COLORS['secondary'])
        self.clear_button.clicked.connect(self.clear_log)
        self.refresh_button = AnimatedButton("Refresh Interfaces", color=COLORS['info'])
        self.refresh_button.clicked.connect(self.populate_interfaces)
        control_layout.addWidget(self.receive_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.refresh_button)
        control_layout.addStretch()
        main_layout.addLayout(control_layout)

        # Connection status indicator
        self.handshake_indicator = HandshakeIndicator()
        main_layout.addWidget(self.handshake_indicator)

        # Add IP Exchange Panel (new)
        self.ip_exchange_panel = IPExchangePanel()
        main_layout.addWidget(self.ip_exchange_panel)

        # Progress bar
        progress_group = ModernGroupBox("Progress")
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(10)
        self.progress_bar = AnimatedProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = AnimatedStatusLabel("Ready")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)

        # Log and data display area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)

        log_group = ModernGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        self.log_edit.setMinimumHeight(400)
        self.log_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border-radius: 4px;
                padding: 5px;
            }}
        """)
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        splitter.addWidget(log_group)

        data_group = ModernGroupBox("Received Data / File Preview") # Updated title
        data_layout = QVBoxLayout()
        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.data_display.setFont(QFont("Courier", 9))
        self.data_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap) # Prevent wrapping for better readability
        self.data_display.setMinimumHeight(400)
        self.data_display.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border-radius: 4px;
                padding: 5px;
            }}
        """)
        data_buttons_layout = QHBoxLayout()
        data_buttons_layout.setSpacing(10)
        self.save_data_button = AnimatedButton("Save Displayed Text", color=COLORS['info'])
        self.save_data_button.clicked.connect(self.save_displayed_data)
        self.clear_data_button = AnimatedButton("Clear Display", color=COLORS['secondary'])
        self.clear_data_button.clicked.connect(self.clear_data_display)
        data_buttons_layout.addWidget(self.save_data_button)
        data_buttons_layout.addWidget(self.clear_data_button)
        data_buttons_layout.addStretch()
        data_layout.addWidget(self.data_display, 1) # Give data display stretch factor
        data_layout.addLayout(data_buttons_layout)
        data_group.setLayout(data_layout)
        splitter.addWidget(data_group)

        splitter.setSizes([500, 500]) # Initial equal split
        main_layout.addWidget(splitter, 1) # Give splitter stretch factor

        # Set the container as the scroll area's widget
        scroll_area.setWidget(container_widget)

        # Main layout for this panel
        panel_layout = QVBoxLayout(self)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.addWidget(scroll_area)
        self.setLayout(panel_layout)


    def populate_interfaces(self):
        self.interface_combo.clear()
        self.interface_combo.addItem("default")
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                # Skip loopback and potentially virtual interfaces unless explicitly needed
                if iface.startswith("lo") or "veth" in iface or "docker" in iface:
                    continue
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        self.interface_combo.addItem(f"{iface} ({ip})")
                    else:
                        # Add interface even if no IPv4 found, might be IPv6 only
                        self.interface_combo.addItem(iface)
                except Exception as iface_err:
                    print(f"Could not get address for {iface}: {iface_err}")
                    self.interface_combo.addItem(iface) # Add by name only
        except ImportError:
            self.add_log_message("ERROR: 'netifaces' library not found. Cannot list interfaces. Please install it (`pip install netifaces`).")
        except Exception as e:
            self.add_log_message(f"Error populating interfaces: {str(e)}")


    def browse_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Select Output File", "", "All Files (*)")
        if file_path:
            self.output_file_edit.setText(file_path)

    def browse_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "All Files (*)")
        if file_path:
            self.key_file_edit.setText(file_path)

    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Session Output Directory", "")
        if dir_path:
            self.output_dir_edit.setText(dir_path)

    def add_log_message(self, message):
        styled_message = message

        # Apply styling based on message content
        if message.startswith("ERROR:") or "Traceback" in message:
            styled_message = f'<span style="color:{COLORS["danger"]};">{message}</span>'
        elif "[COMPLETE]" in message or "Success" in message:
            styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'
        elif "[INFO]" in message:
            styled_message = f'<span style="color:{COLORS["info"]};">{message}</span>'
        elif "[WARNING]" in message or "Warning" in message:
            styled_message = f'<span style="color:{COLORS["warning"]};">{message}</span>'
        elif "[HANDSHAKE]" in message:
            styled_message = f'<span style="color:{COLORS["handshake"]};">{message}</span>'
        elif "[ACK]" in message: # ACKs sent by receiver
            styled_message = f'<span style="color:{COLORS["ack"]};">{message}</span>'
        elif message.startswith("[DATA] "): # Check for the standardized data prefix
            # Display data prefix in a distinct color, actual data in default
            styled_message = f'<span style="color:#8888FF;">[DATA] </span>{message[7:]}'
            # Put the actual data part into the data queue
            try:
                data = message[7:].strip()
                if data:
                    print(f"Adding to data display: {data[:20]}{'...' if len(data) > 20 else ''}")
                    self.data_queue.put(data)
            except Exception as e:
                print(f"Error queuing data for display: {e}")

        self.log_edit.append(styled_message)
        # Don't auto-scroll here, let update_log handle it after batch processing

    def update_log(self):
        # This method now primarily handles messages emitted by update_signal
        # which includes redirected stdout/stderr from receiver core logic
        # No queue needed for receiver logs anymore
        pass # Keep method for potential future use or sender compatibility

    def update_data_display(self):
        try:
            data_batch = []
            max_items = 20
            for _ in range(max_items):
                if not self.data_queue.empty():
                    data_batch.append(self.data_queue.get_nowait())
                else:
                    break
            if data_batch:
                # Append data efficiently
                current_text = self.data_display.toPlainText()
                # Add newline only if display isn't empty and doesn't end with newline
                separator = '\n' if current_text and not current_text.endswith('\n') else ''
                new_data = separator + '\n'.join(data_batch)

                self.data_display.moveCursor(QTextCursor.MoveOperation.End)
                self.data_display.insertPlainText(new_data)
                self.data_display.ensureCursorVisible() # Scroll to bottom
                print(f"Updated data display with {len(data_batch)} new items")
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Error updating data display: {e}")

    def clear_log(self):
        self.log_edit.clear()

    def clear_data_display(self):
        self.data_display.clear()

    def process_ip_exchange(self, message):
        """Process IP exchange messages from the log."""
        if "[IP_EXCHANGE]" in message:
            # Extract IP and port information
            if "Sender IP identified:" in message:
                # Format: [IP_EXCHANGE] Sender IP identified: 192.168.1.x:port
                parts = message.split("Sender IP identified:")
                if len(parts) > 1:
                    ip_port = parts[1].strip()
                    self.ip_exchange_panel.set_remote_discovered(ip_port)
            elif "Sending confirmation to" in message:
                # Format: [IP_EXCHANGE] Sending confirmation to 192.168.1.x:port
                parts = message.split("Sending confirmation to")
                if len(parts) > 1:
                    ip_port = parts[1].strip()
                    # Show our listening port
                    interface_text = self.interface_combo.currentText()
                    if "(" in interface_text:
                        local_ip = interface_text.split("(")[1].split(")")[0]
                        self.ip_exchange_panel.set_local_ip(local_ip)
            elif "Connection request from" in message:
                # Format: [IP_EXCHANGE] Connection request from 192.168.1.x:port
                parts = message.split("Connection request from")
                if len(parts) > 1:
                    ip_port = parts[1].strip()
                    self.ip_exchange_panel.set_connection_requested()
            elif "Connection confirmed with" in message:
                # Format: [IP_EXCHANGE] Connection confirmed with 192.168.1.x:port
                parts = message.split("Connection confirmed with")
                if len(parts) > 1:
                    ip_port = parts[1].strip()
                    self.ip_exchange_panel.set_connection_established()

    def save_displayed_data(self):
        displayed_text = self.data_display.toPlainText()
        if not displayed_text.strip():
            QMessageBox.information(self, "Info", "Nothing to save from the display.")
            return

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Displayed Text", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    # Skip potential info line if present
                    lines = displayed_text.splitlines()
                    if lines and lines[0].startswith("--- Content from"):
                        f.write('\n'.join(lines[2:])) # Skip first two lines (info + blank)
                    else:
                        f.write(displayed_text)
                QMessageBox.information(self, "Success", f"Displayed text saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save data: {str(e)}")

    def start_reception(self):
        output_file = self.output_file_edit.text().strip()
        if not output_file:
            QMessageBox.warning(self, "Input Error", "Output file path is required.")
            return

        # Check if output directory needs creation
        output_dir_path = os.path.dirname(output_file)
        if output_dir_path and not os.path.exists(output_dir_path):
            response = QMessageBox.question(self, "Create Directory?",
                                            f"Output directory does not exist: {output_dir_path}\nCreate it?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                            QMessageBox.StandardButton.Yes)
            if response == QMessageBox.StandardButton.Yes:
                try:
                    os.makedirs(output_dir_path)
                    print(f"Created directory: {output_dir_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create output directory: {str(e)}")
                    return
            else:
                QMessageBox.warning(self, "Cancelled", "Output directory not created. Cannot start reception.")
                return

        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file):
            QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}")
            return

        custom_output_dir = self.output_dir_edit.text().strip() # Session dir
        if custom_output_dir and not os.path.exists(custom_output_dir):
            response = QMessageBox.question(self, "Create Directory?",
                                            f"Session output directory does not exist: {custom_output_dir}\nCreate it?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                            QMessageBox.StandardButton.Yes)
            if response == QMessageBox.StandardButton.Yes:
                try:
                    os.makedirs(custom_output_dir)
                    print(f"Created session directory: {custom_output_dir}")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create session directory: {str(e)}")
                    return
            else:
                QMessageBox.warning(self, "Cancelled", "Session directory not created. Proceeding without it.")
                custom_output_dir = None # Clear if user cancelled creation


        args = {"output_file": output_file, "timeout": self.timeout_spin.value()}
        interface_text = self.interface_combo.currentText()
        if interface_text and interface_text != "default":
            # Extract only the interface name (before parenthesis if present)
            interface = interface_text.split('(')[0].strip()
            args["interface"] = interface
            print(f"Using interface: {interface}")
        if key_file:
            args["key_file"] = key_file
        if custom_output_dir:
            args["output_dir"] = custom_output_dir # Pass session dir

        self.save_settings()
        self.clear_log()
        self.clear_data_display()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting reception...")

        # Reset handshake indicator and IP exchange panel
        self.handshake_indicator.reset()
        self.ip_exchange_panel.reset()

        self.receive_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.refresh_button.setEnabled(False) # Disable refresh while running

        self.worker_thread = WorkerThread("receive", args)
        # Connect update_signal directly to add_log_message for receiver
        self.worker_thread.update_signal.connect(self.add_log_message)
        # self.worker_thread.update_signal.connect(self.log_queue.put) # No longer needed for receiver
        self.worker_thread.update_signal.connect(self.process_ip_exchange) # Process IP exchange messages
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.reception_finished)

        # Connect signals for handshake visualization
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        # Connect the new signal for file reception updates
        self.worker_thread.file_received_signal.connect(self.display_received_file)

        self.worker_thread.start()

    def stop_reception(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping reception...")
            self.worker_thread.stop()
            # Immediately update button states for better UX,
            # even if the thread takes time to actually stop.
            # reception_finished will handle the final state if the thread exits cleanly.
            self.stop_button.setEnabled(False)
            self.receive_button.setEnabled(True)
            self.refresh_button.setEnabled(True)

    def update_progress(self, current, total):
        try:
            if total <= 0:
                # If total is unknown, maybe use current value for indeterminate display?
                # Or just show 0 until total is known. Let's show 0.
                percentage = 0
                self.progress_bar.setValue(0)
                status_msg = f"Receiving: Chunk {current}..."
            else:
                # Cap percentage at 100% to avoid overflow
                percentage = min(100, (current / total) * 100)
                self.progress_bar.setValue(int(percentage))
                status_msg = f"Receiving: {current}/{total} chunks ({percentage:.1f}%)"

            print(f"Setting progress to {percentage:.1f}% ({current}/{total})")
            if self.parent:
                self.parent.statusBar().showMessage(status_msg)
        except Exception as e:
            print(f"Error updating progress: {e}")
            # Fallback display
            if self.parent:
                self.parent.statusBar().showMessage(f"Receiving: Progress update error")


    def update_status(self, status):
        self.status_label.setText(status)

    def update_handshake(self, stage):
        """Update the handshake indicator based on the current stage."""
        if stage == "syn_received":
            self.handshake_indicator.set_syn_sent() # Show SYN part as done
        elif stage == "syn_ack_sent":
            self.handshake_indicator.set_syn_ack_sent() # Show SYN-ACK part as done
        elif stage == "ack_received":
            # Receiver establishes connection *after* receiving final ACK from sender
            self.handshake_indicator.set_ack_sent() # Show ACK part as done
        elif stage == "established":
            self.handshake_indicator.set_connection_established()

    def reception_finished(self, success):
        self.receive_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.refresh_button.setEnabled(True) # Re-enable refresh button
        final_message = ""

        if success:
            self.status_label.setText("Reception completed successfully")
            final_message = "Reception completed successfully"
            # Ensure progress is 100%
            self.progress_bar.setValue(100)
            # File display is now handled by the file_received_signal connection
        else:
            current_status = self.status_label.text().lower()
            if "stopping" in current_status or "stopped by user" in current_status:
                self.status_label.setText("Reception stopped by user")
                final_message = "Reception stopped by user"
            else:
                self.status_label.setText("Reception failed or timed out")
                final_message = "Reception failed or timed out"

        if self.parent:
            self.parent.statusBar().showMessage(final_message, 5000)

        self.worker_thread = None # Clear thread reference

    def display_received_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                print(f"Warning: Cannot display file - {file_path} doesn't exist")
                self.add_log_message(f"Warning: Output file {file_path} not found after reception.")
                return
            # Limit reading large files to avoid freezing GUI
            file_size = os.path.getsize(file_path)
            max_display_size = 10 * 1024 * 1024 # 10 MB limit for display
            if file_size > max_display_size:
                content = f"--- File too large to display ({file_size / (1024*1024):.2f} MB) ---\n"
                content += f"--- Full content saved to: {file_path} ---"
            else:
                # Try detecting encoding, default to utf-8 with error handling
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                except UnicodeDecodeError:
                    try:
                        with open(file_path, 'r', encoding='latin-1') as f:
                            content = f.read()
                        content = f"--- File read using latin-1 (potential encoding issue) ---\n\n" + content
                    except Exception as read_err:
                        content = f"--- Error reading file content: {read_err} ---"
                except Exception as read_err:
                        content = f"--- Error reading file content: {read_err} ---"

            self.clear_data_display()
            # Prepend info line
            info_line = f"--- Content from {os.path.basename(file_path)} ---\n\n"
            self.data_display.setPlainText(info_line + content) # Use setPlainText for efficiency
            print(f"Displayed content (or info) from file: {file_path}")
            cursor = self.data_display.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start) # Go to start
            self.data_display.setTextCursor(cursor)

        except Exception as e:
            error_msg = f"Error reading received file: {e}"
            print(error_msg)
            self.data_display.setPlainText(f"--- {error_msg} ---")

    def save_settings(self):
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        settings.setValue("output_file", self.output_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("interface", self.interface_combo.currentText())
        settings.setValue("output_dir", self.output_dir_edit.text()) # Save session dir
        settings.setValue("timeout", self.timeout_spin.value())

    def load_settings(self):
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        self.output_file_edit.setText(settings.value("output_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        interface = settings.value("interface", "default")
        # FindText might be slow if many interfaces, but fine here
        index = self.interface_combo.findText(interface, Qt.MatchFlag.MatchContains)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
        else:
            self.interface_combo.setCurrentIndex(0) # Fallback to default
        self.output_dir_edit.setText(settings.value("output_dir", "")) # Load session dir
        timeout = settings.value("timeout", DEFAULT_TIMEOUT)
        try:
            self.timeout_spin.setValue(int(timeout))
        except ValueError:
            self.timeout_spin.setValue(DEFAULT_TIMEOUT)
