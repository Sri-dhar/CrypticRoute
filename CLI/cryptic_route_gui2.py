#!/usr/bin/env python3
"""
CrypticRoute GUI - Network Steganography Tool
A graphical interface for the sender and receiver components of CrypticRoute
Enhanced with PyQt6 and modern animations
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
                            QMessageBox, QStyle, QStatusBar, QGraphicsOpacityEffect)
from PyQt6.QtCore import (QThread, pyqtSignal, Qt, QTimer, QSettings, QPropertyAnimation,
                          QEasingCurve, QSize, QPoint, QRect, QParallelAnimationGroup, 
                          QSequentialAnimationGroup)
from PyQt6.QtGui import QIcon, QTextCursor, QFont, QPixmap, QColor, QPalette
import subprocess
import psutil
import netifaces
import signal

# Constants
DEFAULT_CHUNK_SIZE = 8
DEFAULT_TIMEOUT = 120
DEFAULT_DELAY = 0.1

# Modern color scheme
COLORS = {
    'primary': '#2563EB',      # Main blue color
    'secondary': '#64748B',    # Secondary gray color
    'success': '#10B981',      # Green for success
    'danger': '#EF4444',       # Red for errors/warning
    'warning': '#F59E0B',      # Yellow for warnings
    'info': '#3B82F6',         # Light blue for info
    'dark': '#1E293B',         # Dark color for backgrounds
    'light': '#F1F5F9',        # Light color for backgrounds
    'text': '#334155',         # Text color
    'text_light': '#F8FAFC',   # Light text color
    'background': '#FFFFFF',   # Background color
}

class AnimatedProgressBar(QProgressBar):
    """A progress bar with animation effects"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation = QPropertyAnimation(self, b"value")
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.setDuration(300)  # 300ms animation
        
        # Apply styling
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

class AnimatedStatusLabel(QLabel):
    """A status label with fade in/out animation"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(1.0)
        
        self.animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.animation.setDuration(500)  # 500ms for fade
        
        # Apply styling
        self.setStyleSheet(f"""
            font-weight: bold;
            padding: 5px;
            border-radius: 4px;
        """)
    
    def setText(self, text):
        if self.animation.state() == QPropertyAnimation.State.Running:
            self.animation.stop()
        
        # Fade out then in
        animation_group = QSequentialAnimationGroup()
        
        fade_out = QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.3)
        fade_out.setDuration(150)
        
        fade_in = QPropertyAnimation(self.opacity_effect, b"opacity")
        fade_in.setStartValue(0.3)
        fade_in.setEndValue(1.0)
        fade_in.setDuration(350)
        
        animation_group.addAnimation(fade_out)
        animation_group.addAnimation(fade_in)
        
        # Set text when opacity is lowest
        def update_text():
            super(AnimatedStatusLabel, self).setText(text)
            
            # Update color based on text content
            if any(word in text.lower() for word in ["completed", "success", "complete"]):
                self.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px; border-radius: 4px;")
            elif any(word in text.lower() for word in ["error", "failed", "stopped"]):
                self.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; padding: 5px; border-radius: 4px;")
            elif any(word in text.lower() for word in ["warning", "caution"]):
                self.setStyleSheet(f"color: {COLORS['warning']}; font-weight: bold; padding: 5px; border-radius: 4px;")
            elif any(word in text.lower() for word in ["starting", "listening", "waiting"]):
                self.setStyleSheet(f"color: {COLORS['info']}; font-weight: bold; padding: 5px; border-radius: 4px;")
            else:
                self.setStyleSheet(f"color: {COLORS['text']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        
        fade_out.finished.connect(update_text)
        animation_group.start()

class AnimatedButton(QPushButton):
    """A button with hover and click animations"""
    
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
        
        # Add a shadow effect for depth
        self.setGraphicsEffect(self._create_shadow_effect())
    
    def _create_shadow_effect(self):
        shadow = QGraphicsOpacityEffect(self)
        shadow.setOpacity(0.95)  # Slight transparency for a shadow-like effect
        return shadow
    
    def _lighten_color(self, color, amount=0.2):
        """Lighten a hex color by the given amount"""
        c = QColor(color)
        h, s, l, a = c.getHsl()
        l = min(255, int(l * (1 + amount)))  # Lighten
        c.setHsl(h, s, l, a)
        return c.name()
    
    def _darken_color(self, color, amount=0.2):
        """Darken a hex color by the given amount"""
        c = QColor(color)
        h, s, l, a = c.getHsl()
        l = max(0, int(l * (1 - amount)))  # Darken
        c.setHsl(h, s, l, a)
        return c.name()

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

class ModernGroupBox(QGroupBox):
    """A styled group box with animations"""
    
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
        
        # Set initial panel animation
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0)
        
        # Fade in animation
        self.fade_in = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_in.setDuration(500)
        self.fade_in.setStartValue(0)
        self.fade_in.setEndValue(1)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        QTimer.singleShot(100, self.fade_in.start)
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Apply base styling to the panel
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
        
        # Create form for input fields
        form_group = ModernGroupBox("Transmission Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)
        
        # Target IP
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("Enter target IP address (e.g., 192.168.1.100)")
        form_layout.addRow("Target IP:", self.target_ip_edit)
        
        # Input file
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
        
        # Key file
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
        
        # Output directory
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
        
        # Add progress bar
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
        
        # Add log area
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
            
        # Add color styling based on message type
        styled_message = message
        if message.startswith("ERROR:"):
            styled_message = f'<span style="color:{COLORS["danger"]};">{message}</span>'
        elif "[COMPLETE]" in message or "Success" in message:
            styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'
        elif "[INFO]" in message:
            styled_message = f'<span style="color:{COLORS["info"]};">{message}</span>'
        elif "[WARNING]" in message or "Warning" in message:
            styled_message = f'<span style="color:{COLORS["warning"]};">{message}</span>'
            
        self.log_edit.append(styled_message)
        # Use a more efficient cursor movement
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
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
                for message in messages:
                    self.add_log_message(message)
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
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                QMessageBox.StandardButton.Yes
            )
            if response == QMessageBox.StandardButton.Yes:
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
        # Enable controls with animation
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
        
        # Set initial panel animation
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)
        self.opacity_effect.setOpacity(0)
        
        # Fade in animation
        self.fade_in = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_in.setDuration(500)
        self.fade_in.setStartValue(0)
        self.fade_in.setEndValue(1)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        QTimer.singleShot(100, self.fade_in.start)
        
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
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Apply base styling to the panel
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
                image: url(down-arrow.png);  /* You would need to provide this image */
                width: 12px;
                height: 12px;
            }}
        """)
        
        # Create form for input fields
        form_group = ModernGroupBox("Reception Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)
        
        # Output file
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
        
        # Key file
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
        
        # Network interface
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("default")
        self.populate_interfaces()
        form_layout.addRow("Interface:", self.interface_combo)
        
        # Output directory
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
        
        # Add progress bar
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
        
        # Create a splitter for log and data display
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        
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
        splitter.addWidget(log_group)
        
        # Data display area (new)
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
        
        # Add buttons for data display actions
        data_buttons_layout = QHBoxLayout()
        data_buttons_layout.setSpacing(10)
        
        # Add a save button for the received data
        self.save_data_button = AnimatedButton("Save Displayed Data", color=COLORS['info'])
        self.save_data_button.clicked.connect(self.save_displayed_data)
        
        # Add a clear button for the data display
        self.clear_data_button = AnimatedButton("Clear Display", color=COLORS['secondary'])
        self.clear_data_button.clicked.connect(self.clear_data_display)
        
        data_buttons_layout.addWidget(self.save_data_button)
        data_buttons_layout.addWidget(self.clear_data_button)
        data_buttons_layout.addStretch()
        
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
        # Apply color styling based on message type
        styled_message = message
        if message.startswith("ERROR:"):
            styled_message = f'<span style="color:{COLORS["danger"]};">{message}</span>'
        elif "[COMPLETE]" in message or "Success" in message:
            styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'
        elif "[INFO]" in message:
            styled_message = f'<span style="color:{COLORS["info"]};">{message}</span>'
        elif "[WARNING]" in message or "Warning" in message:
            styled_message = f'<span style="color:{COLORS["warning"]};">{message}</span>'
        elif message.startswith("[DATA]"):
            styled_message = f'<span style="color:#00FFFF;">{message}</span>'
            
        self.log_edit.append(styled_message)
        # Use Qt6 cursor movement
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.log_edit.setTextCursor(cursor)
        
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
                cursor.movePosition(QTextCursor.MoveOperation.End)
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
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                QMessageBox.StandardButton.Yes
            )
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
            response = QMessageBox.question(
                self, "Create Directory?", 
                f"Custom output directory does not exist: {custom_output_dir}\nCreate it?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, 
                QMessageBox.StandardButton.Yes
            )
            if response == QMessageBox.StandardButton.Yes:
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
        self.setMinimumSize(900, 650)
        
        # Apply main window styling
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
        
        # Connect tab animation
        self.central_widget.currentChanged.connect(self.animate_tab_change)
        
        # Set up the UI
        self.setup_ui()
        
        # Load window settings
        self.load_settings()
    
    def animate_tab_change(self, index):
        """Animate tab change with a fade effect."""
        if index == 0:
            widget = self.sender_panel
        else:
            widget = self.receiver_panel
            
        # Apply fade animation
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        
        animation = QPropertyAnimation(effect, b"opacity")
        animation.setDuration(300)
        animation.setStartValue(0.4)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.start()
    
    def setup_ui(self):
        """Set up the user interface."""
        # Set application icon
        # icon = QIcon("icon.png")  # Replace with your icon if you have one
        # self.setWindowIcon(icon)
        
        # Create menu bar with modern styling
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
            "<h1 style='color: #2563EB;'>CrypticRoute</h1>"
            "<p style='font-size: 12pt;'>Network Steganography Tool</p>"
            "<p style='font-size: 11pt;'>Version 1.0</p>"
            "<p style='font-size: 10pt;'>A graphical interface for sending and receiving hidden data through network packets.</p>"
            "<p style='font-size: 10pt; margin-top: 20px;'>Enhanced with PyQt6 and modern animations.</p>"
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
    # QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)
    # QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    
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
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()