#!/usr/bin/env python3
"""
CrypticRoute GUI - Network Steganography Tool
A graphical interface for the sender and receiver components of CrypticRoute
Enhanced with PyQt6 and visualization for handshake and ACK system
"""

import sys
import os
import time
import datetime
import threading
import json
import queue
import signal
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                            QHBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
                            QSpinBox, QDoubleSpinBox, QTextEdit, QFileDialog, QComboBox,
                            QProgressBar, QGroupBox, QCheckBox, QSplitter, QFrame,
                            QMessageBox, QStyle, QStatusBar, QGridLayout, QScrollArea)
from PyQt6.QtCore import (QThread, pyqtSignal, Qt, QTimer, QSettings, QPropertyAnimation,
                          QEasingCurve, QSize)
from PyQt6.QtGui import QIcon, QTextCursor, QFont, QPixmap, QColor, QPalette
import subprocess
import psutil
import netifaces
import signal
import re

# Constants
DEFAULT_CHUNK_SIZE = 8
DEFAULT_TIMEOUT = 120
DEFAULT_DELAY = 0.1
DEFAULT_ACK_TIMEOUT = 10
DEFAULT_MAX_RETRIES = 10

# Modern color scheme
COLORS = {
    'primary': '#2563EB',
    'secondary': '#64748B',
    'success': '#10B981',
    'danger': '#EF4444',
    'warning': '#F59E0B',
    'info': '#3B82F6',
    'dark': '#1E293B',
    'light': '#F1F5F9',
    'text': '#334155',
    'text_light': '#F8FAFC',
    'background': '#FFFFFF',
    'handshake': '#8B5CF6',  # Purple for handshake
    'ack': '#06B6D4',        # Cyan for ACKs
}

class AnimatedProgressBar(QProgressBar):
    """A progress bar with value animation effects"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation = QPropertyAnimation(self, b"value")
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.setDuration(300)
        self.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 5px;
                text-align: center;
                background-color: {COLORS['light']};
                height: 25px;
            }}
            QProgressBar::chunk {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 {COLORS['primary']}, 
                                                stop:1 {COLORS['info']});
                border-radius: 4px;
            }}
        """)
    
    def setValue(self, value):
        if self.animation.state() == QPropertyAnimation.State.Running:
            self.animation.stop()
        self.animation.setStartValue(self.value())
        self.animation.setEndValue(value)
        self.animation.start()

class AckProgressBar(AnimatedProgressBar):
    """Progress bar specifically for ACK visualization"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 5px;
                text-align: center;
                background-color: {COLORS['light']};
                height: 25px;
            }}
            QProgressBar::chunk {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 {COLORS['ack']}, 
                                                stop:1 {COLORS['success']});
                border-radius: 4px;
            }}
        """)

class HandshakeIndicator(QWidget):
    """Widget to visualize the TCP-like handshake process"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.reset()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        title_label = QLabel("Connection Status")
        title_label.setStyleSheet(f"font-weight: bold; color: {COLORS['text']};")
        layout.addWidget(title_label)
        
        stages_layout = QHBoxLayout()
        
        # SYN Stage
        self.syn_indicator = QLabel("SYN")
        self.syn_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
        """)
        stages_layout.addWidget(self.syn_indicator)
        
        # Arrow 1
        arrow1 = QLabel("→")
        arrow1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stages_layout.addWidget(arrow1)
        
        # SYN-ACK Stage
        self.syn_ack_indicator = QLabel("SYN-ACK")
        self.syn_ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 5px;
            min-width: 80px;
        """)
        stages_layout.addWidget(self.syn_ack_indicator)
        
        # Arrow 2
        arrow2 = QLabel("→")
        arrow2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        stages_layout.addWidget(arrow2)
        
        # ACK Stage
        self.ack_indicator = QLabel("ACK")
        self.ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
        """)
        stages_layout.addWidget(self.ack_indicator)
        
        # Final status
        stages_layout.addStretch()
        self.status_label = QLabel("Not Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['danger']};
            font-weight: bold;
            padding: 5px;
        """)
        stages_layout.addWidget(self.status_label)
        
        layout.addLayout(stages_layout)
        
    def reset(self):
        """Reset all indicators to their initial state."""
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
        """)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 5px;
            min-width: 80px;
        """)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
        """)
        self.status_label.setText("Not Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['danger']};
            font-weight: bold;
            padding: 5px;
        """)
    
    def set_syn_sent(self):
        """Mark the SYN stage as completed."""
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
            font-weight: bold;
        """)
        self.status_label.setText("SYN Sent")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['handshake']};
            font-weight: bold;
            padding: 5px;
        """)
    
    def set_syn_ack_sent(self):
        """Mark the SYN-ACK stage as completed."""
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 5px;
            min-width: 80px;
            font-weight: bold;
        """)
        self.status_label.setText("SYN-ACK Sent")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['handshake']};
            font-weight: bold;
            padding: 5px;
        """)
    
    def set_ack_sent(self):
        """Mark the ACK stage as completed."""
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
            font-weight: bold;
        """)
    
    def set_connection_established(self):
        """Mark the connection as fully established."""
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
            font-weight: bold;
        """)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 5px;
            min-width: 80px;
            font-weight: bold;
        """)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 5px;
            min-width: 60px;
            font-weight: bold;
        """)
        self.status_label.setText("Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['success']};
            font-weight: bold;
            padding: 5px;
        """)

class AcknowledgmentPanel(QWidget):
    """Panel to visualize packet acknowledgments"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.acked_chunks = set()
        self.total_chunks = 0
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        title_layout = QHBoxLayout()
        title_label = QLabel("Packet Acknowledgments")
        title_label.setStyleSheet(f"font-weight: bold; color: {COLORS['text']};")
        title_layout.addWidget(title_label)
        
        self.ack_count_label = QLabel("0/0 packets acknowledged")
        self.ack_count_label.setStyleSheet(f"color: {COLORS['text']};")
        title_layout.addWidget(self.ack_count_label, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addLayout(title_layout)
        
        # Progress bar for ACKs
        self.ack_progress = AckProgressBar()
        self.ack_progress.setValue(0)
        layout.addWidget(self.ack_progress)
        
        # Grid of indicators - will be created dynamically as needed
        self.grid_container = QWidget()
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(2)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)
        
        # Add scroll area for the grid
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.grid_container)
        scroll_area.setMaximumHeight(120)
        scroll_area.setStyleSheet(f"""
            QScrollArea {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 4px;
                background-color: {COLORS['light']};
            }}
        """)
        
        layout.addWidget(scroll_area)
    
    def reset(self):
        """Reset the acknowledgment panel."""
        self.acked_chunks = set()
        self.total_chunks = 0
        self.ack_progress.setValue(0)
        self.ack_count_label.setText("0/0 packets acknowledged")
        
        # Clear the grid
        for i in reversed(range(self.grid_layout.count())):
            self.grid_layout.itemAt(i).widget().setParent(None)
    
    def set_total_chunks(self, total):
        """Set the total number of chunks and initialize the grid."""
        if total <= 0:
            return
            
        self.total_chunks = total
        self.ack_count_label.setText(f"0/{total} packets acknowledged")
        
        # Clear the grid first
        for i in reversed(range(self.grid_layout.count())):
            self.grid_layout.itemAt(i).widget().setParent(None)
        
        # Calculate grid dimensions
        cols = min(20, total)  # Maximum 20 columns
        rows = (total + cols - 1) // cols  # Ceiling division
        
        # Create the grid of packet indicators
        for i in range(total):
            row = i // cols
            col = i % cols
            
            indicator = QLabel(f"{i+1}")
            indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
            indicator.setFixedSize(QSize(30, 20))
            indicator.setStyleSheet(f"""
                background-color: {COLORS['light']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['secondary']};
                border-radius: 2px;
                font-size: 8pt;
            """)
            self.grid_layout.addWidget(indicator, row, col)
    
    def acknowledge_chunk(self, chunk_num):
        """Mark a specific chunk as acknowledged."""
        if chunk_num <= 0 or chunk_num > self.total_chunks:
            return
            
        # Add to the set of acknowledged chunks
        self.acked_chunks.add(chunk_num)
        
        # Update the counter and progress
        ack_count = len(self.acked_chunks)
        self.ack_count_label.setText(f"{ack_count}/{self.total_chunks} packets acknowledged")
        
        if self.total_chunks > 0:
            progress = (ack_count / self.total_chunks) * 100
            self.ack_progress.setValue(int(progress))
        
        # Find and update the indicator in the grid
        cols = min(20, self.total_chunks)
        row = (chunk_num - 1) // cols
        col = (chunk_num - 1) % cols
        
        item = self.grid_layout.itemAtPosition(row, col)
        if item and item.widget():
            indicator = item.widget()
            indicator.setStyleSheet(f"""
                background-color: {COLORS['ack']};
                color: {COLORS['text_light']};
                border: 1px solid {COLORS['ack']};
                border-radius: 2px;
                font-size: 8pt;
                font-weight: bold;
            """)

class AnimatedStatusLabel(QLabel):
    """A status label without fade animations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            font-weight: bold;
            padding: 5px;
            border-radius: 4px;
        """)
    
    def setText(self, text):
        super(AnimatedStatusLabel, self).setText(text)
        if any(word in text.lower() for word in ["completed", "success", "complete"]):
            self.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["error", "failed", "stopped"]):
            self.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["warning", "caution"]):
            self.setStyleSheet(f"color: {COLORS['warning']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["starting", "listening", "waiting"]):
            self.setStyleSheet(f"color: {COLORS['info']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["connected", "established", "connection"]):
            self.setStyleSheet(f"color: {COLORS['handshake']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        else:
            self.setStyleSheet(f"color: {COLORS['text']}; font-weight: bold; padding: 5px; border-radius: 4px;")

class AnimatedButton(QPushButton):
    """A button with hover and click effects (no opacity animations)"""
    
    def __init__(self, text, parent=None, color=COLORS['primary']):
        super().__init__(text, parent)
        self.base_color = color
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                font-weight: bold;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {self._lighten_color(color, 0.1)};
            }}
            QPushButton:pressed {{
                background-color: {self._darken_color(color, 0.1)};
            }}
            QPushButton:disabled {{
                background-color: #cccccc;
                color: #666666;
            }}
        """)
    
    def _lighten_color(self, color, amount=0.2):
        c = QColor(color)
        h, s, l, a = c.getHsl()
        l = min(255, int(l * (1 + amount)))
        c.setHsl(h, s, l, a)
        return c.name()
    
    def _darken_color(self, color, amount=0.2):
        c = QColor(color)
        h, s, l, a = c.getHsl()
        l = max(0, int(l * (1 - amount)))
        c.setHsl(h, s, l, a)
        return c.name()

class LogRedirector:
    def __init__(self, log_queue):
        self.log_queue = log_queue
    
    def write(self, text):
        if text.strip():
            self.log_queue.put(text)
    
    def flush(self):
        pass

class ProgressTracker:
    def __init__(self, progress_signal):
        self.progress_signal = progress_signal
        self.current = 0
        self.total = 100
        self.percentage = 0
        self.has_direct_percentage = False
        self.lock = threading.Lock()
        self.last_update_time = 0
        self.update_interval = 0.03
        self.last_emitted_value = -1
    
    def update_from_percentage(self, percentage):
        with self.lock:
            if percentage < self.percentage - 5 and self.percentage > 20:
                print(f"Warning: Progress went backward from {self.percentage:.1f}% to {percentage:.1f}%")
                return
            self.percentage = min(100, percentage)
            self.has_direct_percentage = True
            self._emit_update()
    
    def update_from_counts(self, current, total):
        with self.lock:
            if total <= 0:
                return
            new_percentage = min(100, (current / total * 100))
            if not self.has_direct_percentage or new_percentage > self.percentage:
                self.current = current
                self.total = total
                self.percentage = new_percentage
                self._emit_update()
    
    def _emit_update(self):
        current_time = time.time()
        int_percentage = int(self.percentage)
        if (current_time - self.last_update_time >= self.update_interval or 
                abs(int_percentage - self.last_emitted_value) >= 1):
            if self.has_direct_percentage:
                self.progress_signal.emit(int_percentage, 100)
            else:
                self.progress_signal.emit(self.current, self.total)
            self.last_update_time = current_time
            self.last_emitted_value = int_percentage

class WorkerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int)
    status_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(bool)
    handshake_signal = pyqtSignal(str)  # Signal for handshake status
    ack_signal = pyqtSignal(int)         # Signal for acknowledged packets
    
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
        target_ip = self.args.get("target_ip")
        input_file = self.args.get("input_file")
        key_file = self.args.get("key_file")
        delay = self.args.get("delay", DEFAULT_DELAY)
        chunk_size = self.args.get("chunk_size", DEFAULT_CHUNK_SIZE)
        output_dir = self.args.get("output_dir")
        ack_timeout = self.args.get("ack_timeout", DEFAULT_ACK_TIMEOUT)
        max_retries = self.args.get("max_retries", DEFAULT_MAX_RETRIES)
        
        cmd = ["python3", "sender.py", "--target", target_ip, "--input", input_file]
        if key_file:
            cmd.extend(["--key", key_file])
        if output_dir:
            cmd.extend(["--output-dir", output_dir])
        cmd.extend(["--delay", str(delay), "--chunk-size", str(chunk_size)])
        cmd.extend(["--ack-timeout", str(ack_timeout), "--max-retries", str(max_retries)])
        
        self.status_signal.emit(f"Starting sender with command: {' '.join(cmd)}")
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=0,
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"))
        total_chunks = 0
        current_chunk = 0
        
        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break
                
            self.update_signal.emit(line.strip())
            
            # Track handshake stage
            if "[HANDSHAKE] Initiating connection" in line:
                self.handshake_signal.emit("syn_sent")
            elif "[HANDSHAKE] Received SYN-ACK response" in line:
                self.handshake_signal.emit("syn_ack_received")
            elif "[HANDSHAKE] Sending final ACK" in line:
                self.handshake_signal.emit("ack_sent")
            elif "[HANDSHAKE] Connection established" in line:
                self.handshake_signal.emit("established")
                self.status_signal.emit("Connection established")

            # Track ACK received
            ack_match = re.search(r"\[ACK\] Received acknowledgment for chunk (\d+)", line)
            if ack_match:
                chunk_num = int(ack_match.group(1))
                self.ack_signal.emit(chunk_num)
                
            # Parse chunk counts for progress bar
            if "[PREP] Data split into" in line:
                try:
                    total_chunks = int(line.split("into")[1].strip().split()[0])
                    self.status_signal.emit(f"Total chunks: {total_chunks}")
                except Exception as e:
                    print(f"Error parsing chunk count: {e}")
            elif "[STATUS] Completed chunk" in line or "[PROGRESS] " in line:
                try:
                    if "[STATUS] Completed chunk" in line:
                        parts = line.split()
                        chunk_info = parts[3].split('/')
                        current_chunk = int(chunk_info[0])
                        if len(chunk_info) > 1 and chunk_info[1].isdigit():
                            total_chunks = int(chunk_info[1])
                    elif "[PROGRESS] " in line and "New highest sequence:" in line:
                        current_chunk = int(line.split("sequence:")[1].strip())
                    if current_chunk > 0 and total_chunks > 0:
                        self.progress_signal.emit(current_chunk, total_chunks)
                except Exception as e:
                    print(f"Error parsing progress: {e}")
            elif "[COMPLETE] Transmission successfully completed" in line:
                self.status_signal.emit("Transmission complete")
                
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped:
                break
            self.update_signal.emit(f"ERROR: {line.strip()}")
            
        exit_code = self.process.wait()
        success = (exit_code == 0)
        self.finished_signal.emit(success)
    
    def run_receiver(self):
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
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=1)
        progress_tracker = ProgressTracker(self.progress_signal)
        
        for line in iter(self.process.stdout.readline, ''):
            if self.stopped:
                break
                
            line_stripped = line.strip()
            self.update_signal.emit(line_stripped)
            
            # Track handshake stage
            if "[HANDSHAKE] Received connection request (SYN)" in line_stripped:
                self.handshake_signal.emit("syn_received")
            elif "[HANDSHAKE] Sending SYN-ACK response" in line_stripped:
                self.handshake_signal.emit("syn_ack_sent")
            elif "[HANDSHAKE] Connection established with sender" in line_stripped:
                self.handshake_signal.emit("established")
                self.status_signal.emit("Connection established")
            
            # Track ACK sent
            ack_match = re.search(r"\[ACK\] Sending acknowledgment for chunk (\d+)", line_stripped)
            if ack_match:
                chunk_num = int(ack_match.group(1))
                self.ack_signal.emit(chunk_num)
            
            # Extract data content if present
            data_extracted = False
            try:
                data_patterns = ["Received chunk data:", "Data chunk:", "CHUNK_DATA:",
                                "Decoded data:", "Data:", "[CHUNK] Data:", "Chunk content:"]
                for pattern in data_patterns:
                    if pattern in line_stripped:
                        data_part = line_stripped.split(pattern, 1)[1].strip()
                        if data_part:
                            self.update_signal.emit(f"[DATA] {data_part}")
                            print(f"Data extracted: {data_part[:20]}{'...' if len(data_part) > 20 else ''}")
                            data_extracted = True
                            break
            except Exception as e:
                print(f"Error extracting data: {e}")
            
            # Track progress
            try:
                if "Progress:" in line_stripped:
                    progress_part = line_stripped.split("Progress:")[1].strip()
                    percentage = float(progress_part.split("%")[0])
                    progress_tracker.update_from_percentage(percentage)
                elif "[CHUNK]" in line_stripped:
                    for part in line_stripped.split('|'):
                        if "Received:" in part or "Total:" in part:
                            parts = part.strip().split(':')[1].strip().split('/')
                            if len(parts) >= 2:
                                try:
                                    curr = int(parts[0].strip())
                                    tot = int(parts[1].strip())
                                    progress_tracker.update_from_counts(curr, tot)
                                    break
                                except ValueError:
                                    pass
                elif "[PACKET]" in line_stripped:
                    for part in line_stripped.split('|'):
                        if "Chunks:" in part:
                            current_chunk = int(part.strip().split(':')[1].strip())
                            if current_chunk > 0:
                                progress_tracker.update_from_counts(current_chunk, max(100, current_chunk + 10))
                            break
                elif "[PROGRESS]" in line_stripped and "New highest sequence:" in line_stripped:
                    current_chunk = int(line_stripped.split("sequence:")[1].strip())
                    if current_chunk > 0:
                        progress_tracker.update_from_counts(current_chunk, max(100, current_chunk + 10))
            except Exception as e:
                print(f"Error in progress parsing: {e}")
                
            # Update status messages
            if "[COMPLETE]" in line or "Reception complete" in line:
                self.status_signal.emit("Reception complete")
            elif "[INFO]" in line and "All session data saved to:" in line:
                self.status_signal.emit("Data saved successfully")
            elif "[SAVE]" in line and "File saved successfully" in line:
                self.status_signal.emit("File saved successfully")
                
        for line in iter(self.process.stderr.readline, ''):
            if self.stopped:
                break
            self.update_signal.emit(f"ERROR: {line.strip()}")
            
        exit_code = self.process.wait()
        success = (exit_code == 0)
        self.finished_signal.emit(success)
    
    def stop(self):
        self.stopped = True
        if self.process:
            self.process.terminate()
            time.sleep(0.5)
            if self.process.poll() is None:
                self.process.kill()
            self.update_signal.emit("Process stopped by user.")
            self.finished_signal.emit(False)

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
        self.log_queue = queue.Queue()
        self.setup_ui()
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(50)
        self.load_settings()
    
    def setup_ui(self):
        main_layout = QVBoxLayout()
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
        
        # Transmission Settings Group
        form_group = ModernGroupBox("Transmission Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)
        
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("Enter target IP address (e.g., 192.168.1.100)")
        form_layout.addRow("Target IP:", self.target_ip_edit)
        
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
        self.chunk_size_spin.setRange(1, 8)
        self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)
        self.chunk_size_spin.setSuffix(" bytes")
        form_layout.addRow("Chunk Size:", self.chunk_size_spin)
        
        # Add new parameters for ACK system
        self.ack_timeout_spin = QDoubleSpinBox()
        self.ack_timeout_spin.setRange(0.5, 30.0)
        self.ack_timeout_spin.setSingleStep(0.5)
        self.ack_timeout_spin.setValue(DEFAULT_ACK_TIMEOUT)
        self.ack_timeout_spin.setSuffix(" sec")
        form_layout.addRow("ACK Timeout:", self.ack_timeout_spin)
        
        self.max_retries_spin = QSpinBox()
        self.max_retries_spin.setRange(1, 50)
        self.max_retries_spin.setValue(DEFAULT_MAX_RETRIES)
        self.max_retries_spin.setSuffix(" tries")
        form_layout.addRow("Max Retries:", self.max_retries_spin)
        
        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)
        
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
        control_layout.addWidget(self.send_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addStretch()
        main_layout.addLayout(control_layout)
        
        # Connection status indicator
        connection_group = ModernGroupBox("Connection Status")
        connection_layout = QVBoxLayout()
        self.handshake_indicator = HandshakeIndicator()
        connection_layout.addWidget(self.handshake_indicator)
        connection_group.setLayout(connection_layout)
        main_layout.addWidget(connection_group)
        
        # ACK visualization
        ack_group = ModernGroupBox("Acknowledgment Status")
        ack_layout = QVBoxLayout()
        self.ack_panel = AcknowledgmentPanel()
        ack_layout.addWidget(self.ack_panel)
        ack_group.setLayout(ack_layout)
        main_layout.addWidget(ack_group)
        
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
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group, 1)
        
        self.setLayout(main_layout)
    
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
        if "[PACKET] #" in message and not (message.endswith("0") or message.endswith("5")):
            return
            
        styled_message = message
        
        # Apply styling based on message content
        if message.startswith("ERROR:"):
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
            
        self.log_edit.append(styled_message)
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_edit.setTextCursor(cursor)
    
    def update_log(self):
        try:
            messages = []
            for _ in range(20):
                if not self.log_queue.empty():
                    messages.append(self.log_queue.get_nowait())
                else:
                    break
            if messages:
                for message in messages:
                    self.add_log_message(message)
        except Exception as e:
            print(f"Error updating log: {e}")
    
    def clear_log(self):
        self.log_edit.clear()
    
    def start_transmission(self):
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
            "target_ip": target_ip,
            "input_file": input_file,
            "delay": self.delay_spin.value(),
            "chunk_size": self.chunk_size_spin.value(),
            "ack_timeout": self.ack_timeout_spin.value(),
            "max_retries": self.max_retries_spin.value()
        }
        
        if key_file:
            args["key_file"] = key_file
        if output_dir:
            args["output_dir"] = output_dir
            
        self.save_settings()
        self.clear_log()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting transmission...")
        
        # Reset visualization components
        self.handshake_indicator.reset()
        self.ack_panel.reset()
        
        self.send_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        self.worker_thread = WorkerThread("send", args)
        self.worker_thread.update_signal.connect(self.add_log_message)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.transmission_finished)
        
        # Connect new signals for handshake and ACK visualization
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        self.worker_thread.ack_signal.connect(self.update_ack)
        
        self.worker_thread.start()
    
    def stop_transmission(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping transmission...")
            self.worker_thread.stop()
    
    def update_progress(self, current, total):
        if total > 0:
            percentage = (current / total) * 100
            self.progress_bar.setValue(int(percentage))
            if self.parent:
                self.parent.statusBar().showMessage(f"Sending: {current}/{total} chunks ({percentage:.1f}%)")
                
            # Update total chunks in ACK panel if needed
            if total != self.ack_panel.total_chunks:
                self.ack_panel.set_total_chunks(total)
    
    def update_status(self, status):
        self.status_label.setText(status)
    
    def update_handshake(self, stage):
        """Update the handshake indicator based on the current stage."""
        if stage == "syn_sent":
            self.handshake_indicator.set_syn_sent()
        elif stage == "syn_ack_received":
            self.handshake_indicator.set_syn_ack_sent()
        elif stage == "ack_sent":
            self.handshake_indicator.set_ack_sent()
        elif stage == "established":
            self.handshake_indicator.set_connection_established()
    
    def update_ack(self, chunk_num):
        """Update the acknowledgment panel when a chunk is acknowledged."""
        self.ack_panel.acknowledge_chunk(chunk_num)
    
    def transmission_finished(self, success):
        self.send_button.setEnabled(True)
        self.stop_button.setEnabled(False)
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
        settings = QSettings("CrypticRoute", "SenderPanel")
        settings.setValue("target_ip", self.target_ip_edit.text())
        settings.setValue("input_file", self.input_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("delay", self.delay_spin.value())
        settings.setValue("chunk_size", self.chunk_size_spin.value())
        settings.setValue("ack_timeout", self.ack_timeout_spin.value())
        settings.setValue("max_retries", self.max_retries_spin.value())
    
    def load_settings(self):
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
            
        ack_timeout = settings.value("ack_timeout", DEFAULT_ACK_TIMEOUT)
        try:
            self.ack_timeout_spin.setValue(float(ack_timeout))
        except:
            self.ack_timeout_spin.setValue(DEFAULT_ACK_TIMEOUT)
            
        max_retries = settings.value("max_retries", DEFAULT_MAX_RETRIES)
        try:
            self.max_retries_spin.setValue(int(max_retries))
        except:
            self.max_retries_spin.setValue(DEFAULT_MAX_RETRIES)

class ReceiverPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.data_queue = queue.Queue()
        self.setup_ui()
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(25)
        self.data_timer = QTimer(self)
        self.data_timer.timeout.connect(self.update_data_display)
        self.data_timer.start(50)
        self.load_settings()
    
    def display_received_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                print(f"Warning: Cannot display file - {file_path} doesn't exist")
                return
            with open(file_path, 'r') as f:
                content = f.read()
            self.clear_data_display()
            self.data_display.setText(content)
            print(f"Displayed content from file: {file_path}")
            cursor = self.data_display.textCursor()
            cursor.setPosition(0)
            self.data_display.setTextCursor(cursor)
            self.data_display.insertPlainText(f"--- Content from {os.path.basename(file_path)} ---\n\n")
        except Exception as e:
            print(f"Error reading received file: {e}")
            error_msg = f"Error reading file: {str(e)}"
            self.data_display.setText(error_msg)
    
    def setup_ui(self):
        main_layout = QVBoxLayout()
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
            QComboBox::down-arrow {{
                image: url(down-arrow.png);
                width: 12px;
                height: 12px;
            }}
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
        output_dir_layout.addWidget(self.output_dir_edit)
        output_dir_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_dir_layout)
        
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
        connection_group = ModernGroupBox("Connection Status")
        connection_layout = QVBoxLayout()
        self.handshake_indicator = HandshakeIndicator()
        connection_layout.addWidget(self.handshake_indicator)
        connection_group.setLayout(connection_layout)
        main_layout.addWidget(connection_group)
        
        # ACK visualization
        ack_group = ModernGroupBox("Acknowledgment Status")
        ack_layout = QVBoxLayout()
        self.ack_panel = AcknowledgmentPanel()
        ack_layout.addWidget(self.ack_panel)
        ack_group.setLayout(ack_layout)
        main_layout.addWidget(ack_group)
        
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
        
        data_group = ModernGroupBox("Received Data")
        data_layout = QVBoxLayout()
        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.data_display.setFont(QFont("Courier", 9))
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
        self.save_data_button = AnimatedButton("Save Displayed Data", color=COLORS['info'])
        self.save_data_button.clicked.connect(self.save_displayed_data)
        self.clear_data_button = AnimatedButton("Clear Display", color=COLORS['secondary'])
        self.clear_data_button.clicked.connect(self.clear_data_display)
        data_buttons_layout.addWidget(self.save_data_button)
        data_buttons_layout.addWidget(self.clear_data_button)
        data_buttons_layout.addStretch()
        data_layout.addWidget(self.data_display)
        data_layout.addLayout(data_buttons_layout)
        data_group.setLayout(data_layout)
        splitter.addWidget(data_group)
        
        splitter.setSizes([500, 500])
        main_layout.addWidget(splitter, 1)
        
        self.setLayout(main_layout)
    
    def populate_interfaces(self):
        current_selection = self.interface_combo.currentText()
        self.interface_combo.clear()
        self.interface_combo.addItem("default")
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface.startswith("lo"):
                    continue
                self.interface_combo.addItem(iface)
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        self.interface_combo.setItemText(self.interface_combo.count() - 1, f"{iface} ({ip})")
                except:
                    pass
        except Exception as e:
            self.add_log_message(f"Error populating interfaces: {str(e)}")
        index = self.interface_combo.findText(current_selection)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
    
    def browse_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Select Output File", "", "All Files (*)")
        if file_path:
            self.output_file_edit.setText(file_path)
    
    def browse_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", "", "All Files (*)")
        if file_path:
            self.key_file_edit.setText(file_path)
    
    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory", "")
        if dir_path:
            self.output_dir_edit.setText(dir_path)
    
    def add_log_message(self, message):
        styled_message = message
        
        # Apply styling based on message content
        if message.startswith("ERROR:"):
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
        elif message.startswith("[DATA]"):
            styled_message = f'<span style="color:#00FFFF;">{message}</span>'
            
        self.log_edit.append(styled_message)
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_edit.setTextCursor(cursor)
        
        # Extract data for display
        try:
            if message.startswith("[DATA] "):
                data = message[7:].strip()
                print(f"Adding to data display: {data[:20]}{'...' if len(data) > 20 else ''}")
                self.data_queue.put(data)
                return
            data_markers = ["[CHUNK] Data:", "Decoded data:", "Received chunk data:", "Data chunk", "CHUNK_DATA"]
            for marker in data_patterns:
                if marker in message:
                    data = message.split(marker, 1)[1].strip()
                    print(f"Alternative data match: {data[:20]}{'...' if len(data) > 20 else ''}")
                    self.data_queue.put(data)
                    break
        except Exception as e:
            print(f"Error processing data for display: {e}")
    
    def update_log(self):
        while not self.log_queue.empty():
            message = self.log_queue.get()
            self.add_log_message(message)
    
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
                new_data = '\n'.join(data_batch)
                cursor = self.data_display.textCursor()
                cursor.movePosition(QTextCursor.MoveOperation.End)
                cursor.insertText(new_data + '\n')
                self.data_display.setTextCursor(cursor)
                self.data_display.ensureCursorVisible()
                print(f"Updated data display with {len(data_batch)} new items")
        except Exception as e:
            print(f"Error updating data display: {e}")
    
    def clear_log(self):
        self.log_edit.clear()
    
    def clear_data_display(self):
        self.data_display.clear()
    
    def save_displayed_data(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Displayed Data", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(self.data_display.toPlainText())
                QMessageBox.information(self, "Success", f"Data saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save data: {str(e)}")
    
    def start_reception(self):
        output_file = self.output_file_edit.text().strip()
        if not output_file:
            QMessageBox.warning(self, "Input Error", "Output file is required.")
            return
        output_dir = os.path.dirname(output_file)
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
        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file):
            QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}")
            return
        custom_output_dir = self.output_dir_edit.text().strip()
        if custom_output_dir and not os.path.exists(custom_output_dir):
            response = QMessageBox.question(self, "Create Directory?", 
                                            f"Custom output directory does not exist: {custom_output_dir}\nCreate it?",
                                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                                            QMessageBox.StandardButton.Yes)
            if response == QMessageBox.StandardButton.Yes:
                try:
                    os.makedirs(custom_output_dir)
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}")
                    return
            else:
                return
                
        args = {"output_file": output_file, "timeout": self.timeout_spin.value()}
        interface_text = self.interface_combo.currentText()
        if interface_text and interface_text != "default":
            interface = interface_text.split()[0] if "(" in interface_text else interface_text
            args["interface"] = interface
        if key_file:
            args["key_file"] = key_file
        if custom_output_dir:
            args["output_dir"] = custom_output_dir
            
        self.save_settings()
        self.clear_log()
        self.clear_data_display()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting reception...")
        
        # Reset visualization components
        self.handshake_indicator.reset()
        self.ack_panel.reset()
        
        self.receive_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        self.worker_thread = WorkerThread("receive", args)
        self.worker_thread.update_signal.connect(self.add_log_message)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.reception_finished)
        
        # Connect new signals for handshake and ACK visualization
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        self.worker_thread.ack_signal.connect(self.update_ack)
        
        self.worker_thread.start()
    
    def stop_reception(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping reception...")
            self.worker_thread.stop()
    
    def update_progress(self, current, total):
        try:
            if total <= 0:
                return
            percentage = min(100, (current / total) * 100)
            self.progress_bar.setValue(int(percentage))
            print(f"Setting progress to {percentage:.1f}%")
            if self.parent:
                if isinstance(current, int) and isinstance(total, int):
                    self.parent.statusBar().showMessage(f"Receiving: {current}/{total} chunks ({percentage:.1f}%)")
                else:
                    self.parent.statusBar().showMessage(f"Receiving: {percentage:.1f}%")
                    
            # Update total chunks in ACK panel if needed
            if total != self.ack_panel.total_chunks:
                self.ack_panel.set_total_chunks(total)
        except Exception as e:
            print(f"Error updating progress: {e}")
    
    def update_status(self, status):
        self.status_label.setText(status)
    
    def update_handshake(self, stage):
        """Update the handshake indicator based on the current stage."""
        if stage == "syn_received":
            self.handshake_indicator.set_syn_sent()
        elif stage == "syn_ack_sent":
            self.handshake_indicator.set_syn_ack_sent()
        elif stage == "ack_received":
            self.handshake_indicator.set_ack_sent()
        elif stage == "established":
            self.handshake_indicator.set_connection_established()
    
    def update_ack(self, chunk_num):
        """Update the acknowledgment panel when a chunk is acknowledged."""
        self.ack_panel.acknowledge_chunk(chunk_num)
    
    def reception_finished(self, success):
        self.receive_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        if success:
            self.status_label.setText("Reception completed successfully")
            if self.parent:
                self.parent.statusBar().showMessage("Reception completed successfully")
            output_file = self.output_file_edit.text().strip()
            if output_file:
                self.display_received_file(output_file)
        else:
            self.status_label.setText("Reception failed or was stopped")
            if self.parent:
                self.parent.statusBar().showMessage("Reception failed or was stopped")
    
    def save_settings(self):
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        settings.setValue("output_file", self.output_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("interface", self.interface_combo.currentText())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("timeout", self.timeout_spin.value())
    
    def load_settings(self):
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
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CrypticRoute - Network Steganography Tool")
        self.setMinimumSize(900, 650)
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {COLORS['background']};
            }}
            QTabWidget::pane {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 8px;
                background-color: {COLORS['background']};
                padding: 5px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['light']};
                border: 1px solid {COLORS['secondary']};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 10px 20px;
                margin-right: 2px;
                color: {COLORS['secondary']};
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['primary']};
                color: white;
                font-weight: bold;
            }}
            QTabBar::tab:hover:!selected {{
                background-color: #dbe4ff;
            }}
            QStatusBar {{
                background-color: {COLORS['light']};
                color: {COLORS['text']};
                padding: 5px;
                font-size: 10pt;
            }}
        """)
        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)
        self.sender_panel = SenderPanel(self)
        self.central_widget.addTab(self.sender_panel, "Send File")
        self.receiver_panel = ReceiverPanel(self)
        self.central_widget.addTab(self.receiver_panel, "Receive File")
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        self.central_widget.currentChanged.connect(self.update_status_on_tab_change)
        self.setup_ui()
        self.load_settings()
    
    def setup_ui(self):
        menubar = self.menuBar()
        menubar.setStyleSheet(f"""
            QMenuBar {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                padding: 5px;
                font-size: 10pt;
            }}
            QMenuBar::item {{
                background-color: transparent;
                padding: 8px 15px;
                border-radius: 4px;
            }}
            QMenuBar::item:selected {{
                background-color: {COLORS['primary']};
            }}
            QMenu {{
                background-color: {COLORS['light']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['secondary']};
                border-radius: 4px;
            }}
            QMenu::item {{
                padding: 8px 15px;
            }}
            QMenu::item:selected {{
                background-color: {COLORS['primary']};
                color: white;
                border-radius: 2px;
            }}
            QMenu::separator {{
                height: 1px;
                background-color: {COLORS['secondary']};
                margin: 5px 15px;
            }}
        """)
        file_menu = menubar.addMenu("File")
        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)
        help_menu = menubar.addMenu("Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)
    
    def update_status_on_tab_change(self, index):
        if index == 0:
            self.status_bar.showMessage("Sender: Ready")
        else:
            self.status_bar.showMessage("Receiver: Ready")
    
    def show_about(self):
        QMessageBox.about(self, "About CrypticRoute",
                          "<h1 style='color: #2563EB;'>CrypticRoute</h1>"
                          "<p style='font-size: 12pt;'>Network Steganography Tool</p>"
                          "<p style='font-size: 11pt;'>Version 2.0</p>"
                          "<p style='font-size: 10pt;'>A graphical interface for sending and receiving hidden data through network packets.</p>"
                          "<p style='font-size: 10pt;'>Enhanced with connection handshake and packet acknowledgment visualization.</p>")
    
    def closeEvent(self, event):
        if self.sender_panel.worker_thread and self.sender_panel.worker_thread.isRunning():
            self.sender_panel.stop_transmission()
        if self.receiver_panel.worker_thread and self.receiver_panel.worker_thread.isRunning():
            self.receiver_panel.stop_reception()
        self.save_settings()
        event.accept()
    
    def save_settings(self):
        settings = QSettings("CrypticRoute", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("state", self.saveState())
        settings.setValue("current_tab", self.central_widget.currentIndex())
    
    def load_settings(self):
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
    if "XDG_RUNTIME_DIR" not in os.environ:
        runtime_dir = f"/tmp/runtime-{os.getuid()}"
        if not os.path.exists(runtime_dir):
            try:
                os.makedirs(runtime_dir, mode=0o700)
            except:
                pass
        os.environ["XDG_RUNTIME_DIR"] = runtime_dir
        print(f"Set XDG_RUNTIME_DIR to {runtime_dir}")

def main():
    check_environment()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = QApplication(sys.argv)
    app.setApplicationName("CrypticRoute")
    app.setApplicationVersion("2.0")
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    if os.geteuid() == 0:
        print("Running CrypticRoute GUI as root. For a better approach, consider using capabilities instead:")
        print("sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
        print("This will allow running without sudo while still having necessary permissions.")
    sys.exit(app.exec())

if __name__ == "__main__":
    main()