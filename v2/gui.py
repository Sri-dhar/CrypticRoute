# --- START OF FILE gui.py ---

# --- START OF ENHANCED gui.py ---

#!/usr/bin/env python3
"""
CrypticRoute GUI - Network Steganography Tool
A graphical interface for the sender and receiver components of CrypticRoute
Enhanced with PyQt6 and visualization for handshake and ACK system
(Modified: ACK progress bar moved to separate window, main panel shows count)
(Enhanced: Handshake indicators integrated in progress bar, resizable transmission log)
"""

import sys
import os
import time
import datetime
import threading
import json
import queue
import signal
# Corrected QtWidgets import (Added QSplitter, QFrame)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                            QHBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
                            QSpinBox, QDoubleSpinBox, QTextEdit, QFileDialog, QComboBox,
                            QProgressBar, QGroupBox, QCheckBox, QSplitter, QFrame, # Added QSplitter, QFrame
                            QMessageBox, QStyle, QStatusBar, QGridLayout, QScrollArea)
from PyQt6.QtCore import (QThread, pyqtSignal, Qt, QTimer, QSettings, QPropertyAnimation,
                          QEasingCurve, QSize)
# Corrected QtGui import (Added QAction)
from PyQt6.QtGui import QIcon, QTextCursor, QFont, QPixmap, QColor, QPalette, QAction
import subprocess
import psutil
import netifaces
# Removed signal import below as it's already imported above
# import signal
import re

# Constants
DEFAULT_CHUNK_SIZE = 8
DEFAULT_TIMEOUT = 120
DEFAULT_DELAY = 0.1

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

# --- Classes (AnimatedProgressBar, AckProgressBar unchanged) ---

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
        # Ensure value is within range
        value = max(0, min(100, value))
        if self.value() == value:
             return # No change needed
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

# --- HandshakeIndicator REMOVED as it's integrated into HandshakeProgressBar ---
# class HandshakeIndicator(QWidget): ...

# --- AcknowledgmentPanel: Modified for Details Window ---
class AcknowledgmentPanel(QWidget):
    """Panel to visualize packet acknowledgments (CONTENT FOR AckDetailsWindow)"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.acked_chunks = set()
        self.total_chunks = 0
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10) # Add some margins
        layout.setSpacing(5)

        # Counter label at the top
        self.ack_count_label = QLabel("0/0 packets acknowledged")
        self.ack_count_label.setStyleSheet(f"color: {COLORS['text']}; font-weight: bold;")
        layout.addWidget(self.ack_count_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Progress bar for ACKs
        self.ack_progress = AckProgressBar()
        self.ack_progress.setValue(0)
        layout.addWidget(self.ack_progress)

        # Grid of indicators
        self.grid_container = QWidget()
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(2)
        self.grid_layout.setContentsMargins(0, 0, 0, 0)

        # Scroll area for the grid
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.grid_container)
        # Allow more height in separate window
        self.scroll_area.setMinimumHeight(120)
        self.scroll_area.setStyleSheet(f"""
            QScrollArea {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 4px;
                background-color: {COLORS['light']};
            }}
             QWidget {{ /* Style the container widget inside scroll area */
                background-color: {COLORS['light']};
            }}
        """)
        layout.addWidget(self.scroll_area, 1) # Allow scroll area to stretch

    def clear_grid(self):
        """Helper to clear grid widgets"""
        while self.grid_layout.count():
            item = self.grid_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def reset(self):
        """Reset the acknowledgment panel."""
        self.acked_chunks.clear()
        self.total_chunks = 0
        self.ack_progress.setValue(0)
        self.ack_count_label.setText("0/0 packets acknowledged")
        self.clear_grid()

    def set_total_chunks(self, total):
        """Set the total number of chunks and initialize the grid."""
        print(f"[AckPanel] Setting total chunks to {total}") # Debug
        if total <= 0:
            self.reset()
            return

        # Update total and count label, but keep existing ACKs
        ack_count = len(self.acked_chunks)
        self.total_chunks = total
        self.ack_count_label.setText(f"{ack_count}/{total} packets acknowledged")
        self.ack_progress.setRange(0, 100) # Standard percentage range
        if total > 0:
            progress = int((ack_count / total) * 100) if total > 0 else 0
            self.ack_progress.setValue(progress)
        else:
             self.ack_progress.setValue(0)


        # Rebuild the grid
        self.clear_grid()

        cols = min(25, total) # Allow more columns
        rows = (total + cols - 1) // cols

        for i in range(total):
            chunk_num = i + 1
            row = i // cols
            col = i % cols

            indicator = QLabel(f"{chunk_num}")
            indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
            indicator.setFixedSize(QSize(25, 18))
            # Set style based on whether it's already ACKed
            if chunk_num in self.acked_chunks:
                 indicator.setStyleSheet(f"""
                    background-color: {COLORS['ack']};
                    color: {COLORS['text_light']};
                    border: 1px solid {COLORS['ack']};
                    border-radius: 2px; font-size: 7pt; font-weight: bold;
                 """)
            else:
                indicator.setStyleSheet(f"""
                    background-color: {COLORS['light']};
                    color: {COLORS['text']};
                    border: 1px solid {COLORS['secondary']};
                    border-radius: 2px; font-size: 7pt;
                """)
            self.grid_layout.addWidget(indicator, row, col)
        print(f"[AckPanel] Rebuilt grid for {total} chunks") # Debug

    def acknowledge_chunk(self, chunk_num):
        """Mark a specific chunk as acknowledged."""
        if chunk_num <= 0 or chunk_num > self.total_chunks:
            # print(f"[AckPanel] Warning: Chunk number {chunk_num} out of bounds (total: {self.total_chunks})") # Debug
            return

        is_new = chunk_num not in self.acked_chunks
        if is_new:
            self.acked_chunks.add(chunk_num)

            # Update counter and progress bar
            ack_count = len(self.acked_chunks)
            self.ack_count_label.setText(f"{ack_count}/{self.total_chunks} packets acknowledged")
            if self.total_chunks > 0:
                progress = int((ack_count / self.total_chunks) * 100)
                self.ack_progress.setValue(progress)

        # Update the indicator in the grid regardless (in case grid was rebuilt)
        cols = min(25, self.total_chunks) if self.total_chunks > 0 else 1
        row = (chunk_num - 1) // cols
        col = (chunk_num - 1) % cols

        item = self.grid_layout.itemAtPosition(row, col)
        if item and item.widget():
            indicator = item.widget()
            # Apply highlighting style
            indicator.setStyleSheet(f"""
                background-color: {COLORS['ack']};
                color: {COLORS['text_light']};
                border: 1px solid {COLORS['ack']};
                border-radius: 2px; font-size: 7pt; font-weight: bold;
            """)
            # if is_new: print(f"[AckPanel] Highlighted chunk {chunk_num}") # Debug
        else:
            # This might happen briefly if total_chunks arrives slightly after first ACK
            # print(f"[AckPanel] Warning: No indicator for chunk {chunk_num} at ({row}, {col})") # Debug
            pass

# --- AckDetailsWindow (New Class) ---
class AckDetailsWindow(QWidget):
    """A separate window to display detailed acknowledgment status."""
    def __init__(self, sender_panel, parent=None):
        super().__init__(parent)
        self.sender_panel = sender_panel # Reference to call back on close
        self.setWindowTitle("Acknowledgment Details")
        self.setMinimumSize(450, 300)

        # Main content is the AcknowledgmentPanel
        self.ack_panel = AcknowledgmentPanel()

        layout = QVBoxLayout(self)
        layout.addWidget(self.ack_panel)
        self.setLayout(layout)

        # Load initial state from sender panel
        self.reset() # Ensure clean state
        if self.sender_panel: # Check if sender_panel exists
            self.set_total_chunks(self.sender_panel.total_chunks)
            for chunk in sorted(list(self.sender_panel.acked_chunks)):
                 self.acknowledge_chunk(chunk)


    def set_total_chunks(self, total):
        self.ack_panel.set_total_chunks(total)

    def acknowledge_chunk(self, chunk_num):
        self.ack_panel.acknowledge_chunk(chunk_num)

    def reset(self):
        self.ack_panel.reset()

    def closeEvent(self, event):
        """Notify the sender panel when this window is closed."""
        print("AckDetailsWindow closing.")
        if self.sender_panel:
            self.sender_panel.ack_details_window = None # Clear the reference
        super().closeEvent(event)


# --- AnimatedStatusLabel, AnimatedButton, LogRedirector, ProgressTracker unchanged ---

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
        if any(word in text.lower() for word in ["completed", "success", "complete", "saved"]):
            self.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["error", "failed", "stopped"]):
            self.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["warning", "caution"]):
            self.setStyleSheet(f"color: {COLORS['warning']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["starting", "listening", "waiting", "initializing"]):
            self.setStyleSheet(f"color: {COLORS['info']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["established", "connection established"]): # Focus on established state
            self.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        else: # Default/Ready state
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
                 # Handle case where current > 0 but total is unknown/0
                 if current > 0:
                     # Estimate progress - maybe assume total is slightly larger than current?
                     # This is tricky, maybe just show 0% or a different indicator
                     effective_total = max(current + 10, 100) # Simple estimation
                     new_percentage = min(100, (current / effective_total * 100))
                 else:
                     return # No progress to show if both are 0 or less
            else:
                new_percentage = min(100, (current / total * 100))

            # Allow updates if percentage is same or higher, OR if using counts after percentage
            if not self.has_direct_percentage or new_percentage >= self.percentage:
                self.current = current
                self.total = total
                self.percentage = new_percentage
                self._emit_update()

    def _emit_update(self):
        current_time = time.time()
        int_percentage = int(self.percentage)
        if (current_time - self.last_update_time >= self.update_interval or
                abs(int_percentage - self.last_emitted_value) >= 1):
            # Always emit current/total if available, otherwise percentage
            # Note: The GUI update_progress method will calculate percentage from counts
            if self.total > 0:
                 self.progress_signal.emit(self.current, self.total)
            elif self.has_direct_percentage:
                 self.progress_signal.emit(int_percentage, 100) # Emit as percentage/100
            else:
                 # Fallback: emit current count with an estimated total if total is unknown
                 self.progress_signal.emit(self.current, max(self.current + 10, 100))

            self.last_update_time = current_time
            self.last_emitted_value = int_percentage


# --- WorkerThread unchanged ---
class WorkerThread(QThread):
    update_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int, int) # (current, total)
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
            self.update_signal.emit(f"Error starting process: {str(e)}")
            self.status_signal.emit(f"Error: {str(e)}")
            self.finished_signal.emit(False)

    def run_sender(self):
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

        self.status_signal.emit(f"Starting sender...") # Concise status
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            universal_newlines=True, bufsize=1, # Line buffered
                                            env=dict(os.environ, PYTHONUNBUFFERED="1"),
                                            errors='replace') # Handle potential encoding errors
        except FileNotFoundError:
            self.update_signal.emit("ERROR: sender.py not found. Make sure it's in the same directory or PATH.")
            self.status_signal.emit("Error: sender.py not found")
            self.finished_signal.emit(False)
            return
        except Exception as e:
            self.update_signal.emit(f"ERROR launching sender: {e}")
            self.status_signal.emit(f"Error launching sender")
            self.finished_signal.emit(False)
            return

        total_chunks = 0
        current_chunk = 0

        stdout_iterator = iter(self.process.stdout.readline, '')
        stderr_iterator = iter(self.process.stderr.readline, '')

        while not self.stopped:
            line = None
            err_line = None
            try:
                # Non-blocking read-like approach
                line = next(stdout_iterator, None)
                err_line = next(stderr_iterator, None)

                if line is None and err_line is None and self.process.poll() is not None:
                    break # Process finished

                if line is None and err_line is None:
                    time.sleep(0.01) # Prevent busy-waiting
                    continue

            except StopIteration:
                 # Should not happen with universal_newlines=True, bufsize=1, but handle defensively
                 if self.process.poll() is not None: break
                 else: time.sleep(0.01); continue
            except Exception as e:
                 self.update_signal.emit(f"ERROR reading sender output: {e}")
                 time.sleep(0.1)
                 continue

            if err_line:
                 self.update_signal.emit(f"ERROR: {err_line.strip()}")

            if line:
                line = line.strip()
                if not line: continue # Skip empty lines
                self.update_signal.emit(line)

                # Track handshake stage
                if "[HANDSHAKE] Initiating connection" in line:
                    self.handshake_signal.emit("syn_sent")
                elif "[HANDSHAKE] Received SYN-ACK response" in line:
                    self.handshake_signal.emit("syn_ack_received") # Corrected stage name
                elif "[HANDSHAKE] Sending final ACK" in line:
                    self.handshake_signal.emit("ack_sent")
                elif "[HANDSHAKE] Connection established" in line:
                    self.handshake_signal.emit("established")
                    self.status_signal.emit("Connection established")

                # Detect ACK received
                ack_match = re.search(r"\[(?:ACK|CONFIRMED)\].*(?:chunk|sequence) (\d+)", line, re.IGNORECASE)
                if ack_match:
                    try:
                        chunk_num = int(ack_match.group(1))
                        # print(f"Sender detected ACK/Confirm for chunk {chunk_num}") # Debug
                        self.ack_signal.emit(chunk_num)
                    except (ValueError, IndexError) as e:
                        print(f"Sender: Error parsing ACK/Confirm number from '{line}': {e}")


                # Parse total chunks information
                total_chunks_match = re.search(r"Data split into (\d+) chunks", line)
                if total_chunks_match:
                    try:
                        new_total_chunks = int(total_chunks_match.group(1))
                        if new_total_chunks != total_chunks:
                            total_chunks = new_total_chunks
                            self.status_signal.emit(f"Total chunks: {total_chunks}")
                            self.total_chunks_signal.emit(total_chunks)
                            # print(f"Sender emitted total chunks: {total_chunks}") # Debug
                            # Update progress immediately if we have the total now
                            if current_chunk > 0:
                                self.progress_signal.emit(current_chunk, total_chunks)
                    except Exception as e:
                        print(f"Sender: Error parsing total chunk count from '{line}': {e}")

                # Parse chunk counts for progress bar
                # Look for "Completed chunk X/Y", "[PROGRESS] ... sequence: X/Y", or just "Completed chunk X"
                progress_match = re.search(r"(?:Completed chunk|\[PROGRESS\].*sequence:)\s*(\d+)(?:/(\d+))?", line)
                if progress_match:
                    try:
                        current_chunk = int(progress_match.group(1))
                        if progress_match.group(2): # Total present in this line
                            new_total_chunks = int(progress_match.group(2))
                            if new_total_chunks != total_chunks and new_total_chunks > 0:
                                total_chunks = new_total_chunks
                                self.total_chunks_signal.emit(total_chunks)
                                # print(f"Sender updated total chunks from progress: {total_chunks}") # Debug
                        # Emit progress signal: Use known total if available, otherwise 0
                        self.progress_signal.emit(current_chunk, total_chunks if total_chunks > 0 else 0)

                    except Exception as e:
                        print(f"Sender: Error parsing progress from '{line}': {e}")

                elif "[COMPLETE] Transmission successfully completed" in line:
                    self.status_signal.emit("Transmission complete")
                    # Ensure progress hits 100%
                    if total_chunks > 0: self.progress_signal.emit(total_chunks, total_chunks)
                    else: self.progress_signal.emit(100, 100) # Assume 100% if total unknown


        # Read any remaining stderr after loop finishes
        if self.process:
            for err_line in self.process.stderr:
                 if self.stopped: break
                 self.update_signal.emit(f"ERROR: {err_line.strip()}")

        exit_code = self.process.wait() if self.process else -1
        success = (exit_code == 0 and not self.stopped)

        # Final status update
        if self.stopped:
             self.status_signal.emit("Transmission stopped by user")
        elif success:
             self.status_signal.emit("Transmission successfully completed")
             # Ensure 100% progress on success
             if total_chunks > 0: self.progress_signal.emit(total_chunks, total_chunks)
             else: self.progress_signal.emit(100, 100)
        else:
             self.status_signal.emit(f"Transmission failed (Exit code: {exit_code})")

        self.finished_signal.emit(success)

    # --- run_receiver is unchanged from previous version ---
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

        self.status_signal.emit(f"Starting receiver...") # Concise
        try:
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            universal_newlines=True, bufsize=1,
                                            env=dict(os.environ, PYTHONUNBUFFERED="1"),
                                            errors='replace')
        except FileNotFoundError:
            self.update_signal.emit("ERROR: receiver.py not found. Make sure it's in the same directory or PATH.")
            self.status_signal.emit("Error: receiver.py not found")
            self.finished_signal.emit(False)
            return
        except Exception as e:
            self.update_signal.emit(f"ERROR launching receiver: {e}")
            self.status_signal.emit(f"Error launching receiver")
            self.finished_signal.emit(False)
            return

        progress_tracker = ProgressTracker(self.progress_signal)
        current_total_chunks = 0 # Track total known so far

        stdout_iterator = iter(self.process.stdout.readline, '')
        stderr_iterator = iter(self.process.stderr.readline, '')

        while not self.stopped:
            line = None
            err_line = None
            try:
                # Non-blocking read-like approach
                line = next(stdout_iterator, None)
                err_line = next(stderr_iterator, None)

                if line is None and err_line is None and self.process.poll() is not None:
                    break # Process finished

                if line is None and err_line is None:
                    time.sleep(0.01) # Prevent busy-waiting
                    continue

            except StopIteration:
                 if self.process.poll() is not None: break
                 else: time.sleep(0.01); continue
            except Exception as e:
                 self.update_signal.emit(f"ERROR reading receiver output: {e}")
                 time.sleep(0.1)
                 continue

            if err_line:
                 self.update_signal.emit(f"ERROR: {err_line.strip()}")

            if line:
                line = line.strip()
                if not line: continue # Skip empty lines
                self.update_signal.emit(line)

                # Track handshake stage
                if "[HANDSHAKE] Received connection request (SYN)" in line:
                    self.handshake_signal.emit("syn_received")
                elif "[HANDSHAKE] Sending SYN-ACK response" in line:
                    self.handshake_signal.emit("syn_ack_sent")
                elif "[HANDSHAKE] Received final ACK" in line:
                    self.handshake_signal.emit("ack_received")
                elif "[HANDSHAKE] Connection established with sender" in line:
                    self.handshake_signal.emit("established")
                    self.status_signal.emit("Connection established")

                # Detect Receiver sending an ACK (for logging/debug maybe)
                ack_match = re.search(r"\[ACK\] Sending acknowledgment for chunk (\d+)", line)
                if ack_match:
                    try:
                        chunk_num = int(ack_match.group(1))
                        # print(f"Receiver sent ACK for chunk {chunk_num}") # Debug
                        # self.ack_signal.emit(chunk_num) # Receiver panel doesn't use this currently
                    except (ValueError, IndexError) as e:
                        print(f"Receiver: Error parsing sent ACK number from '{line}': {e}")

                # Update total chunks if found
                # Look for "Total: X/Y", "total_chunks=Y", "highest sequence ...: Y" etc.
                total_match = re.search(r"(?:Total:\s*\d+/(\d+)|total_chunks=(\d+)|highest sequence.*:\s*(\d+))", line, re.IGNORECASE)
                if total_match:
                    try:
                        total_str = next((g for g in total_match.groups() if g is not None), None)
                        if total_str:
                            new_total = int(total_str)
                            if new_total > current_total_chunks:
                                current_total_chunks = new_total
                                self.total_chunks_signal.emit(current_total_chunks)
                                # print(f"Receiver emitted total chunks: {current_total_chunks}") # Debug
                                # Immediately update progress tracker with new total
                                progress_tracker.update_from_counts(progress_tracker.current, current_total_chunks)
                    except Exception as e:
                        print(f"Receiver: Error parsing total chunks from '{line}': {e}")

                # Extract data content for display (if pattern matches)
                data_extracted = False
                # Simplified patterns for common data markers
                data_patterns = [
                    r"\[DATA\]\s*(.+)",
                    r"(?:Decoded|Received|Assembled) data:\s*(.+)",
                    r"CHUNK_DATA:\s*(.+)"
                    ]
                for pattern in data_patterns:
                    data_match = re.search(pattern, line, re.IGNORECASE)
                    if data_match:
                        data_part = data_match.group(1).strip()
                        if data_part and len(data_part) < 500: # Avoid flooding with huge chunks
                            self.update_signal.emit(f"[DATA] {data_part}") # Prefix for clarity
                            data_extracted = True
                            break # Only match one data pattern per line

                # Track progress (using ProgressTracker)
                try:
                    percent_match = re.search(r"Progress:\s*([\d\.]+)\s*%", line)
                    if percent_match:
                        percentage = float(percent_match.group(1))
                        progress_tracker.update_from_percentage(percentage)
                    else:
                        # Look for counts like "Received X/Y", "Chunk X", "Sequence X"
                        count_match = re.search(r"(?:Received|Chunk|Sequence|Processing chunk)\s*:?\s*(\d+)(?:/(\d+))?", line, re.IGNORECASE)
                        if count_match:
                            curr = int(count_match.group(1))
                            tot = current_total_chunks # Use the latest known total
                            if count_match.group(2): # Total found in this line
                                line_total = int(count_match.group(2))
                                if line_total > current_total_chunks:
                                    # Update total if this line has a higher one
                                    current_total_chunks = line_total
                                    self.total_chunks_signal.emit(current_total_chunks)
                                tot = current_total_chunks # Use the updated total

                            progress_tracker.update_from_counts(curr, tot)

                except Exception as e:
                    print(f"Receiver: Error in progress parsing from '{line}': {e}")

                # Update status messages based on keywords
                if "[COMPLETE]" in line or "Reception complete" in line or "Successfully reassembled" in line:
                    self.status_signal.emit("Reception complete")
                    # Ensure 100% on completion
                    progress_tracker.update_from_counts(max(progress_tracker.current, current_total_chunks), max(1, current_total_chunks)) # Use max(1,...) to avoid 0/0
                elif "[SAVE]" in line and ("File saved successfully" in line or "Data saved to" in line):
                    # Extract filename if possible for better status
                    save_match = re.search(r"(?:saved to|File saved successfully):\s*(.+)", line)
                    if save_match:
                         self.status_signal.emit(f"File saved: {os.path.basename(save_match.group(1).strip())}")
                    else:
                         self.status_signal.emit("File saved successfully")
                elif "Timeout reached" in line:
                     self.status_signal.emit("Timeout reached waiting for data")


        # Read any remaining stderr
        if self.process:
            for err_line in self.process.stderr:
                if self.stopped: break
                self.update_signal.emit(f"ERROR: {err_line.strip()}")

        exit_code = self.process.wait() if self.process else -1
        success = (exit_code == 0 and not self.stopped)

        # Final status update
        if self.stopped:
             self.status_signal.emit("Reception stopped by user")
        elif success:
             # Ensure status reflects completion, might already be set by [COMPLETE] etc.
             if "complete" not in self.status_label.text().lower() and "saved" not in self.status_label.text().lower():
                  self.status_signal.emit("Reception finished successfully")
             # Ensure 100% progress
             progress_tracker.update_from_counts(max(progress_tracker.current, current_total_chunks), max(1, current_total_chunks))
        elif "Timeout" in self.status_label.text():
             pass # Keep timeout message
        else:
             self.status_signal.emit(f"Reception failed (Exit code: {exit_code})")

        self.finished_signal.emit(success)


    def stop(self):
        self.stopped = True
        if self.process and self.process.poll() is None:
            self.status_signal.emit("Stopping process...")
            self.update_signal.emit("Sending termination signal...")
            try:
                # Try terminate first (more graceful)
                self.process.terminate()
                try:
                    # Wait briefly for termination
                    self.process.wait(timeout=1.5)
                    self.update_signal.emit("Process terminated.")
                except subprocess.TimeoutExpired:
                    # Force kill if terminate didn't work
                    self.update_signal.emit("Process did not terminate gracefully, killing.")
                    self.process.kill()
                    self.process.wait() # Wait for kill to complete
                    self.update_signal.emit("Process killed.")
                self.status_signal.emit("Process stopped by user.")
            except Exception as e:
                self.update_signal.emit(f"Error stopping process: {e}")
                self.status_signal.emit(f"Error stopping process")
                # Ensure it's killed if possible
                try:
                    if self.process.poll() is None:
                        self.process.kill()
                        self.process.wait()
                except Exception as ke:
                     self.update_signal.emit(f"Error during final kill attempt: {ke}")
        else:
            self.status_signal.emit("Process already stopped or not running.")

        # Ensure finished signal is emitted if thread is still running somehow
        if self.isRunning():
             self.finished_signal.emit(False) # Signal failure if stopped manually


# --- ModernGroupBox unchanged ---
class ModernGroupBox(QGroupBox):
    def __init__(self, title, parent=None):
        super().__init__(title, parent)
        self.setStyleSheet(f"""
            QGroupBox {{
                font-weight: bold;
                border: 1px solid {COLORS['secondary']};
                border-radius: 8px;
                margin-top: 1.5ex; /* Space for the title */
                padding: 15px 10px 10px 10px; /* Top padding adjusted for title */
                background-color: {COLORS['light']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                left: 10px; /* Position title slightly indented */
                padding: 0 5px;
                color: {COLORS['primary']};
                background-color: {COLORS['light']}; /* Match background */
                font-size: 10pt; /* Ensure title font size matches */
            }}
        """)

# NEW: Integrated progress bar with handshake indicators
class HandshakeProgressBar(QWidget):
    """A progress bar that includes handshake stage indicators"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.reset()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5) # Space between progress bar and indicators

        # Progress bar
        self.progress_bar = AnimatedProgressBar()
        layout.addWidget(self.progress_bar)

        # Handshake indicators inside a layout
        handshake_layout = QHBoxLayout()
        handshake_layout.setSpacing(5)

        # SYN Indicator
        self.syn_indicator = QLabel("SYN")
        self.syn_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        # Define common style parts
        self.base_style = f"""
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            font-size: 9pt;
        """
        self.default_style = f"background-color: {COLORS['light']}; color: {COLORS['text']};" + self.base_style
        self.handshake_style = f"background-color: {COLORS['handshake']}; color: {COLORS['text_light']}; font-weight: bold;" + self.base_style.replace(f"border: 1px solid {COLORS['secondary']}", f"border: 1px solid {COLORS['handshake']}")
        self.success_style = f"background-color: {COLORS['success']}; color: {COLORS['text_light']}; font-weight: bold;" + self.base_style.replace(f"border: 1px solid {COLORS['secondary']}", f"border: 1px solid {COLORS['success']}")

        self.syn_indicator.setStyleSheet(self.default_style + "min-width: 40px;")
        self.syn_indicator.setToolTip("Synchronization packet (Initiate Connection)")

        # SYN-ACK Indicator
        self.syn_ack_indicator = QLabel("SYN-ACK")
        self.syn_ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.syn_ack_indicator.setStyleSheet(self.default_style + "min-width: 60px;")
        self.syn_ack_indicator.setToolTip("Synchronization Acknowledgment (Confirm Initiation)")

        # ACK Indicator
        self.ack_indicator = QLabel("ACK")
        self.ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ack_indicator.setStyleSheet(self.default_style + "min-width: 40px;")
        self.ack_indicator.setToolTip("Acknowledgment (Confirm SYN-ACK / Establish Connection)")

        # Status Label (integrated within this widget)
        self.status_label = QLabel("Not Connected")
        self.status_label.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; padding: 2px; font-size: 9pt;")
        self.status_label.setToolTip("Current connection status")


        # Add all indicators to layout
        handshake_layout.addWidget(self.syn_indicator)
        handshake_layout.addWidget(QLabel("→"), 0, alignment=Qt.AlignmentFlag.AlignCenter)
        handshake_layout.addWidget(self.syn_ack_indicator)
        handshake_layout.addWidget(QLabel("→"), 0, alignment=Qt.AlignmentFlag.AlignCenter)
        handshake_layout.addWidget(self.ack_indicator)
        handshake_layout.addStretch(1) # Push status label to the right
        handshake_layout.addWidget(self.status_label)

        layout.addLayout(handshake_layout)

    def setValue(self, value):
        """Set the progress bar value"""
        self.progress_bar.setValue(value)

    def reset(self):
        """Reset all indicators to their initial state"""
        self.progress_bar.setValue(0)
        # Reset styles
        self.syn_indicator.setStyleSheet(self.default_style + "min-width: 40px;")
        self.syn_ack_indicator.setStyleSheet(self.default_style + "min-width: 60px;")
        self.ack_indicator.setStyleSheet(self.default_style + "min-width: 40px;")
        # Reset Status Label
        self.status_label.setText("Not Connected")
        self.status_label.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; padding: 2px; font-size: 9pt;")

    def set_syn_sent(self): # Also used for SYN Received on receiver side
        """Mark the SYN stage as active"""
        self.syn_indicator.setStyleSheet(self.handshake_style + "min-width: 40px;")
        self.status_label.setText("SYN")
        self.status_label.setStyleSheet(f"color: {COLORS['handshake']}; font-weight: bold; padding: 2px; font-size: 9pt;")

    def set_syn_ack_sent(self): # Or received, depending on perspective
        """Mark the SYN-ACK stage as active"""
        # Ensure previous stage is also marked (visually makes sense)
        self.set_syn_sent()
        self.syn_ack_indicator.setStyleSheet(self.handshake_style + "min-width: 60px;")
        self.status_label.setText("SYN-ACK") # Keep status concise
        self.status_label.setStyleSheet(f"color: {COLORS['handshake']}; font-weight: bold; padding: 2px; font-size: 9pt;")

    def set_ack_sent(self): # Or received
        """Mark the ACK stage as active"""
        # Ensure previous stages are also marked
        self.set_syn_ack_sent()
        self.ack_indicator.setStyleSheet(self.handshake_style + "min-width: 40px;")
        self.status_label.setText("ACK Handshake") # Status before final "Connected"
        self.status_label.setStyleSheet(f"color: {COLORS['handshake']}; font-weight: bold; padding: 2px; font-size: 9pt;")

    def set_connection_established(self):
        """Mark the connection as fully established"""
        # Color all indicators green
        self.syn_indicator.setStyleSheet(self.success_style + "min-width: 40px;")
        self.syn_ack_indicator.setStyleSheet(self.success_style + "min-width: 60px;")
        self.ack_indicator.setStyleSheet(self.success_style + "min-width: 40px;")

        self.status_label.setText("Connected")
        self.status_label.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 2px; font-size: 9pt;")

# --- Base Panel class (Optional, but can reduce redundancy if needed) ---
# class BasePanel(QWidget): ... # Could contain common methods like browse_*, load/save_settings etc.

# --- SenderPanel class definition (placeholder for original structure) ---
class SenderPanel(QWidget):
     # Define signals expected by AckDetailsWindow if needed, or handle directly
     # This placeholder is needed because EnhancedSenderPanel inherits from it.
     # In a real refactor, common elements could go into a BasePanel.
     def __init__(self, parent=None):
         super().__init__(parent)
         # Minimal required attributes/methods assumed by inheriting classes or details window
         self.total_chunks = 0
         self.acked_chunks = set()
         self.ack_details_window = None
         self.parent = parent # Store parent reference

     # Placeholder methods that will be overridden but are called by super()
     def start_transmission(self): pass
     def stop_transmission(self): pass
     def transmission_finished(self, success): pass
     def load_settings(self): pass
     def save_settings(self): pass
     def clear_log(self): pass
     def browse_input_file(self): pass
     def browse_key_file(self): pass
     def browse_output_dir(self): pass
     def update_log(self): pass
     def show_ack_details(self): pass
     def update_ack_count(self): pass


# --- ReceiverPanel class definition (placeholder for original structure) ---
class ReceiverPanel(QWidget):
     # Placeholder needed for inheritance
     def __init__(self, parent=None):
         super().__init__(parent)
         self.parent = parent # Store parent reference
         self.splitter = None # Ensure splitter attribute exists

     # Placeholder methods
     def start_reception(self): pass
     def stop_reception(self): pass
     def reception_finished(self, success): pass
     def load_settings(self): pass
     def save_settings(self): pass
     def clear_log(self): pass
     def clear_data_display(self): pass
     def save_displayed_data(self): pass
     def browse_output_file(self): pass
     def browse_key_file(self): pass
     def browse_output_dir(self): pass
     def populate_interfaces(self): pass
     def update_log(self): pass
     def update_data_display(self): pass

# --- EnhancedSenderPanel: Uses HandshakeProgressBar and resizable log ---
class EnhancedSenderPanel(SenderPanel): # Inherit from the placeholder
    # Signals are defined in WorkerThread, connected here
    def __init__(self, parent=None):
        super().__init__(parent) # Call placeholder __init__
        # Initialize attributes defined in placeholder that are used here
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.ack_details_window = None # Initialized in placeholder
        self.acked_chunks = set() # Initialized in placeholder
        self.total_chunks = 0 # Initialized in placeholder

        # Setup our custom UI
        self.setup_enhanced_ui()

        # Set up timer and load settings (using methods that should exist in base/placeholder)
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(50) # Update log every 50ms
        self.load_settings() # Call the (potentially overridden) load_settings

    def setup_enhanced_ui(self):
        # Scroll area for the main settings/controls
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame) # Make scroll area background transparent
        scroll_area.setStyleSheet("background-color: transparent;")

        scroll_content_widget = QWidget() # Widget to hold the contents of the scroll area
        scroll_content_widget.setStyleSheet("background-color: transparent;")
        content_layout = QVBoxLayout(scroll_content_widget) # Layout for the scroll content
        content_layout.setContentsMargins(0, 0, 0, 0) # No margins within scroll content itself
        content_layout.setSpacing(10)

        # Common Stylesheet for controls inside the panel
        self.setStyleSheet(f"""
            QWidget {{ font-size: 10pt; color: {COLORS['text']}; }}
            QLabel {{ font-size: 10pt; }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
                padding: 8px; border: 1px solid {COLORS['secondary']};
                border-radius: 4px; background-color: white;
            }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
                border: 2px solid {COLORS['primary']};
            }}
            QPushButton {{ padding: 8px 12px; border-radius: 4px; }} /* Basic button style */
        """)

        # --- Transmission Settings Group ---
        form_group = ModernGroupBox("Transmission Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)

        # Target IP
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("Enter target IP address (e.g., 192.168.1.100)")
        self.target_ip_edit.setToolTip("The IP address of the receiving machine.")
        form_layout.addRow("Target IP:", self.target_ip_edit)

        # Input File
        input_layout = QHBoxLayout(); input_layout.setSpacing(8); input_layout.setContentsMargins(0,0,0,0)
        self.input_file_edit = QLineEdit(); self.input_file_edit.setPlaceholderText("Path to input file")
        self.input_file_edit.setToolTip("Select the file you want to transmit.")
        self.input_file_button = QPushButton("Browse...")
        self.input_file_button.setStyleSheet(f"background-color: {COLORS['secondary']}; color: white; border: none;")
        self.input_file_button.setToolTip("Browse for the input file.")
        self.input_file_button.clicked.connect(self.browse_input_file) # Connect to method
        input_layout.addWidget(self.input_file_edit, 1); input_layout.addWidget(self.input_file_button)
        form_layout.addRow("Input File:", input_layout)

        # Key File
        key_layout = QHBoxLayout(); key_layout.setSpacing(8); key_layout.setContentsMargins(0,0,0,0)
        self.key_file_edit = QLineEdit(); self.key_file_edit.setPlaceholderText("Path to encryption key file (optional)")
        self.key_file_edit.setToolTip("Optional: Select a key file for AES encryption.")
        self.key_file_button = QPushButton("Browse...");
        self.key_file_button.setStyleSheet(f"background-color: {COLORS['secondary']}; color: white; border: none;")
        self.key_file_button.setToolTip("Browse for the key file.")
        self.key_file_button.clicked.connect(self.browse_key_file) # Connect to method
        key_layout.addWidget(self.key_file_edit, 1); key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)

        # Output Directory (for logs/metadata)
        output_layout = QHBoxLayout(); output_layout.setSpacing(8); output_layout.setContentsMargins(0,0,0,0)
        self.output_dir_edit = QLineEdit(); self.output_dir_edit.setPlaceholderText("Session output directory (optional)")
        self.output_dir_edit.setToolTip("Optional: Specify a directory to save transmission logs and metadata.")
        self.output_dir_button = QPushButton("Browse...");
        self.output_dir_button.setStyleSheet(f"background-color: {COLORS['secondary']}; color: white; border: none;")
        self.output_dir_button.setToolTip("Browse for the output directory.")
        self.output_dir_button.clicked.connect(self.browse_output_dir) # Connect to method
        output_layout.addWidget(self.output_dir_edit, 1); output_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_layout)

        # Delay
        self.delay_spin = QDoubleSpinBox(); self.delay_spin.setRange(0.01, 5.0); self.delay_spin.setSingleStep(0.05); self.delay_spin.setValue(DEFAULT_DELAY); self.delay_spin.setSuffix(" sec")
        self.delay_spin.setToolTip("Delay between sending packets. Increase if packets are dropped.")
        self.delay_spin.setDecimals(2)
        form_layout.addRow("Packet Delay:", self.delay_spin)

        # Chunk Size
        self.chunk_size_spin = QSpinBox(); self.chunk_size_spin.setRange(1, 8); self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE); self.chunk_size_spin.setSuffix(" bytes")
        self.chunk_size_spin.setToolTip("Amount of data (bytes) hidden in the ID field of each packet (1-8).")
        form_layout.addRow("Chunk Size:", self.chunk_size_spin)

        form_group.setLayout(form_layout)
        content_layout.addWidget(form_group) # Add form group to scroll area content

        # --- Control Buttons ---
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        self.send_button = AnimatedButton("Start Transmission", color=COLORS['success'])
        self.send_button.clicked.connect(self.start_transmission) # Connect to method
        self.stop_button = AnimatedButton("Stop", color=COLORS['danger'])
        self.stop_button.clicked.connect(self.stop_transmission) # Connect to method
        self.stop_button.setEnabled(False) # Disabled initially
        self.clear_button = AnimatedButton("Clear Log", color=COLORS['secondary'])
        self.clear_button.clicked.connect(self.clear_log) # Connect to method
        self.ack_details_button = AnimatedButton("ACK Details", color=COLORS['info'])
        self.ack_details_button.clicked.connect(self.show_ack_details) # Connect to method
        self.ack_details_button.setToolTip("Show detailed acknowledgment status window.")


        control_layout.addWidget(self.send_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.ack_details_button)
        control_layout.addStretch()
        content_layout.addLayout(control_layout) # Add controls to scroll area content

        # --- Progress Group - using the NEW combined widget ---
        progress_group = ModernGroupBox("Progress & Status")
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(8)

        # Use the combined HandshakeProgressBar
        self.combined_progress_bar = HandshakeProgressBar()
        progress_layout.addWidget(self.combined_progress_bar)

        # General Status Label and ACK Count (below the combined bar)
        status_ack_layout = QHBoxLayout()
        self.status_label = AnimatedStatusLabel("Ready") # Main status indicator
        self.ack_count_label = QLabel("ACKs: 0/0") # ACK counter remains separate
        self.ack_count_label.setStyleSheet(f"color: {COLORS['ack']}; font-size: 9pt; font-weight: bold;")
        self.ack_count_label.setToolTip("Number of acknowledged packets out of total expected.")

        status_ack_layout.addWidget(self.status_label, 1) # Give status label more space
        status_ack_layout.addWidget(self.ack_count_label, 0, alignment=Qt.AlignmentFlag.AlignRight)
        progress_layout.addLayout(status_ack_layout)

        progress_group.setLayout(progress_layout)
        content_layout.addWidget(progress_group) # Add progress group to scroll area content

        # Finish Scroll Area Setup
        scroll_area.setWidget(scroll_content_widget) # Set the content widget for the scroll area

        # --- SPLITTER IMPLEMENTATION ---
        # Create a vertical splitter for settings/controls vs log
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setChildrenCollapsible(False) # Prevent sections from collapsing completely
        main_splitter.setHandleWidth(8) # Make handle visible
        main_splitter.setStyleSheet(f"""
            QSplitter::handle:vertical {{
                background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                               stop:0 {COLORS['light']},
                                               stop:0.5 {COLORS['secondary']},
                                               stop:1 {COLORS['light']});
                border: 1px solid {COLORS['secondary']};
                height: 5px; /* Make handle slightly thicker vertically */
                margin: 2px 0px;
                border-radius: 2px;
            }}
            QSplitter::handle:vertical:hover {{
                background-color: {COLORS['primary']};
            }}
        """)

        # Add the scroll area (containing settings/controls/progress) to the TOP of the splitter
        main_splitter.addWidget(scroll_area)

        # Log Area Group
        log_group = ModernGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier New", 9)) # Monospaced font
        self.log_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap) # Prevent wrapping
        self.log_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border: 1px solid {COLORS['secondary']};
                border-radius: 4px;
                padding: 5px;
            }}
        """)
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)

        # Add the log group to the BOTTOM of the splitter
        main_splitter.addWidget(log_group)

        # Set initial sizes for the splitter sections (adjust ratio as needed)
        # Give slightly more space to the settings/controls initially
        initial_height = self.parent.height() if self.parent else 600
        main_splitter.setSizes([int(initial_height * 0.55), int(initial_height * 0.45)])


        # Main Layout of the panel now contains ONLY the splitter
        main_panel_layout = QVBoxLayout(self)
        main_panel_layout.setContentsMargins(10, 10, 10, 10) # Use panel margins
        main_panel_layout.addWidget(main_splitter)
        self.setLayout(main_panel_layout)

        # Store the splitter for settings persistence
        self.main_splitter = main_splitter

    # --- Method Overrides and New Methods ---

    # Override update methods to target the combined widget
    def update_handshake(self, stage):
        """Update the handshake indicators within the combined progress bar."""
        print(f"[GUI] Sender Handshake Update: {stage}") # Debug
        if stage == "syn_sent":
            self.combined_progress_bar.set_syn_sent()
        elif stage == "syn_ack_received": # Sender receives SYN-ACK
            self.combined_progress_bar.set_syn_ack_sent()
        elif stage == "ack_sent": # Sender sends final ACK
            self.combined_progress_bar.set_ack_sent()
        elif stage == "established":
            self.combined_progress_bar.set_connection_established()
            self.status_label.setText("Connection Established") # Update main status too

    def update_progress(self, current, total):
        """Update the progress bar value within the combined widget."""
        # print(f"[GUI] Sender Progress Update: {current}/{total}") # Debug
        if total > 0:
            percentage = min(100, int((current / total) * 100))
            self.combined_progress_bar.setValue(percentage)
            # Update status bar (optional, but good practice)
            if self.parent: # Check if parent exists (MainWindow)
                self.parent.statusBar().showMessage(f"Sending: {current}/{total} chunks ({percentage}%)")
        elif current > 0: # Progress known, but total isn't yet
             self.combined_progress_bar.setValue(0) # Keep at 0 until total known? Or estimate?
             # self.combined_progress_bar.setValue(int((current / max(current+10, 100)) * 100)) # Basic estimation
             if self.parent:
                self.parent.statusBar().showMessage(f"Sending: Chunk {current}...")
        else: # No progress yet
             self.combined_progress_bar.setValue(0)
             if self.parent:
                 self.parent.statusBar().showMessage(f"Initializing Send...")

    # Override: Start Transmission
    def start_transmission(self):
        self.log_edit.clear()
        self.status_label.setText("Initializing...")
        self.combined_progress_bar.reset()
        self.acked_chunks.clear()
        self.total_chunks = 0
        self.update_ack_count() # Reset count display
        if self.ack_details_window:
            self.ack_details_window.reset()

        target_ip = self.target_ip_edit.text().strip()
        input_file = self.input_file_edit.text().strip()

        if not target_ip or not input_file:
            QMessageBox.warning(self, "Input Required", "Please specify Target IP and Input File.")
            self.status_label.setText("Ready")
            return

        if not os.path.isfile(input_file):
             QMessageBox.warning(self, "File Not Found", f"Input file not found:\n{input_file}")
             self.status_label.setText("Ready")
             return

        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.isfile(key_file):
             QMessageBox.warning(self, "File Not Found", f"Key file not found:\n{key_file}")
             self.status_label.setText("Ready")
             return

        output_dir = self.output_dir_edit.text().strip()
        if output_dir and not os.path.isdir(output_dir):
             reply = QMessageBox.question(self, "Create Directory?",
                                          f"Output directory does not exist:\n{output_dir}\n\nCreate it?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                          QMessageBox.StandardButton.No)
             if reply == QMessageBox.StandardButton.Yes:
                 try:
                     os.makedirs(output_dir, exist_ok=True)
                 except OSError as e:
                     QMessageBox.critical(self, "Error", f"Could not create directory:\n{e}")
                     self.status_label.setText("Ready")
                     return
             else:
                 self.status_label.setText("Ready")
                 return


        args = {
            "target_ip": target_ip,
            "input_file": input_file,
            "key_file": key_file or None,
            "delay": self.delay_spin.value(),
            "chunk_size": self.chunk_size_spin.value(),
            "output_dir": output_dir or None,
        }

        self.save_settings() # Save current settings

        self.worker_thread = WorkerThread("send", args)
        self.worker_thread.update_signal.connect(self.append_log)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.transmission_finished)
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        self.worker_thread.ack_signal.connect(self.handle_ack)
        self.worker_thread.total_chunks_signal.connect(self.handle_total_chunks)

        self.send_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.set_controls_enabled(False) # Disable form fields
        self.status_label.setText("Starting transmission...")
        self.worker_thread.start()

    # Override: Stop Transmission
    def stop_transmission(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping...")
            self.worker_thread.stop()
            # finished_signal will handle re-enabling buttons

    # Override: Transmission Finished
    def transmission_finished(self, success):
        self.send_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.set_controls_enabled(True) # Re-enable form fields
        if self.worker_thread: # Check if thread exists
            # Update status label based on final signal if not already set
            final_status = self.status_label.text() # Get current status
            if "Stopping" in final_status: # If stop was initiated
                self.status_label.setText("Transmission stopped by user")
            elif success and "complete" not in final_status.lower():
                self.status_label.setText("Transmission successfully completed")
            elif not success and "failed" not in final_status.lower() and "error" not in final_status.lower():
                 self.status_label.setText("Transmission failed or stopped")

            if success:
                self.combined_progress_bar.setValue(100) # Ensure 100%
                self.combined_progress_bar.set_connection_established() # Show green state
            else:
                 # Optionally reset handshake on failure/stop, or leave as is
                 # self.combined_progress_bar.reset()
                 pass # Keep last state for review?

        self.worker_thread = None # Clear thread reference

    # --- Helper Methods (Potentially moved to BasePanel in a refactor) ---

    def set_controls_enabled(self, enabled):
        """Enable/disable input controls during transmission."""
        self.target_ip_edit.setEnabled(enabled)
        self.input_file_edit.setEnabled(enabled)
        self.input_file_button.setEnabled(enabled)
        self.key_file_edit.setEnabled(enabled)
        self.key_file_button.setEnabled(enabled)
        self.output_dir_edit.setEnabled(enabled)
        self.output_dir_button.setEnabled(enabled)
        self.delay_spin.setEnabled(enabled)
        self.chunk_size_spin.setEnabled(enabled)
        # self.ack_details_button.setEnabled(enabled) # Keep ACK details accessible?

    def append_log(self, text):
        """Append text to the log view, handling colors."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Basic color coding based on keywords
        if text.startswith("ERROR:") or "Failed" in text:
            color = COLORS['danger']
        elif text.startswith("WARN:") or "Warning" in text:
            color = COLORS['warning']
        elif "[HANDSHAKE]" in text:
             color = COLORS['handshake']
        elif "[ACK]" in text or "[CONFIRMED]" in text:
             color = COLORS['ack']
        elif "[PROGRESS]" in text or "Completed chunk" in text:
             color = COLORS['info']
        elif "[COMPLETE]" in text:
            color = COLORS['success']
        else:
            color = COLORS['light'] # Default log text color

        # Insert timestamp (greyed out)
        cursor.insertHtml(f'<span style="color:{COLORS["secondary"]};">[{timestamp}] </span>')
        # Insert message with color
        cursor.insertHtml(f'<span style="color:{color};">{text}</span><br>')

        self.log_edit.setTextCursor(cursor)
        self.log_edit.ensureCursorVisible() # Auto-scroll

    def update_status(self, text):
        """Update the main status label."""
        self.status_label.setText(text)

    def clear_log(self):
        self.log_edit.clear()

    def update_log(self):
        """Process messages from the log queue."""
        while not self.log_queue.empty():
            try:
                message = self.log_queue.get_nowait()
                self.append_log(message)
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing log queue: {e}") # Debug

    def browse_input_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Input File")
        if filename:
            self.input_file_edit.setText(filename)

    def browse_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Key File")
        if filename:
            self.key_file_edit.setText(filename)

    def browse_output_dir(self):
        dirname = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dirname:
            self.output_dir_edit.setText(dirname)

    def handle_ack(self, chunk_num):
        """Handle received ACK signal."""
        if chunk_num > 0:
            # print(f"[GUI] Received ACK for chunk: {chunk_num}") # Debug
            self.acked_chunks.add(chunk_num)
            self.update_ack_count()
            if self.ack_details_window:
                self.ack_details_window.acknowledge_chunk(chunk_num)

    def handle_total_chunks(self, total):
        """Handle total chunks signal."""
        if total > 0 and total != self.total_chunks:
             print(f"[GUI] Received Total Chunks: {total}") # Debug
             self.total_chunks = total
             self.update_ack_count()
             if self.ack_details_window:
                 self.ack_details_window.set_total_chunks(total)
             # Update progress bar range if needed (though it's usually 0-100)
             self.update_progress(len(self.acked_chunks), self.total_chunks) # Update progress based on current ACKs

    def update_ack_count(self):
        """Update the ACK counter label."""
        count = len(self.acked_chunks)
        total = self.total_chunks if self.total_chunks > 0 else "?"
        self.ack_count_label.setText(f"ACKs: {count}/{total}")

    def show_ack_details(self):
        """Show or focus the ACK details window."""
        if self.ack_details_window is None:
            print("Creating AckDetailsWindow...")
            self.ack_details_window = AckDetailsWindow(self) # Pass self
            # Ensure it gets the current state
            self.ack_details_window.set_total_chunks(self.total_chunks)
            for chunk in sorted(list(self.acked_chunks)):
                self.ack_details_window.acknowledge_chunk(chunk)
            self.ack_details_window.show()
        else:
            print("Activating existing AckDetailsWindow...")
            self.ack_details_window.activateWindow()
            self.ack_details_window.raise_()

    def load_settings(self):
        """Load settings specific to the sender panel."""
        settings = QSettings("CrypticRoute", "SenderPanel")
        self.target_ip_edit.setText(settings.value("target_ip", ""))
        self.input_file_edit.setText(settings.value("input_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        self.output_dir_edit.setText(settings.value("output_dir", ""))
        self.delay_spin.setValue(float(settings.value("delay", DEFAULT_DELAY)))
        self.chunk_size_spin.setValue(int(settings.value("chunk_size", DEFAULT_CHUNK_SIZE)))

    def save_settings(self):
        """Save settings specific to the sender panel."""
        settings = QSettings("CrypticRoute", "SenderPanel")
        settings.setValue("target_ip", self.target_ip_edit.text())
        settings.setValue("input_file", self.input_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("delay", self.delay_spin.value())
        settings.setValue("chunk_size", self.chunk_size_spin.value())

    # Ensure placeholder methods are implemented if not inheriting useful ones
    def __getattr__(self, name):
        # Basic fallback for methods expected by AckDetailsWindow or setup if not implemented
        if name in ["browse_input_file", "browse_key_file", "browse_output_dir", "clear_log", "show_ack_details", "update_log"]:
            def _missing_method(*args, **kwargs):
                print(f"Warning: Method {name} called but not fully implemented in EnhancedSenderPanel.")
            return _missing_method
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


# --- EnhancedReceiverPanel: Uses HandshakeProgressBar and resizable log/data areas ---
class EnhancedReceiverPanel(ReceiverPanel): # Inherit from placeholder
    # Signals are defined in WorkerThread, connected here
    def __init__(self, parent=None):
        super().__init__(parent) # Call placeholder __init__
        # Initialize attributes used here
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.data_queue = queue.Queue() # Queue for received data snippets
        self.last_displayed_file = None # Track displayed file content
        self.main_splitter = None # Initialize splitter attribute

        # Setup our custom UI
        self.setup_enhanced_ui()

        # Set up timers and load settings
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(50) # Update log view periodically

        self.data_timer = QTimer(self) # Timer for updating data display view
        self.data_timer.timeout.connect(self.update_data_display)
        self.data_timer.start(100) # Update data display less frequently

        self.load_settings()

    def setup_enhanced_ui(self):
        # Scroll area for settings/controls
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("background-color: transparent;")

        container_widget = QWidget() # Widget holding content for scroll area
        container_widget.setStyleSheet("background-color: transparent;")
        scroll_content_layout = QVBoxLayout(container_widget) # Layout for scroll content
        scroll_content_layout.setContentsMargins(0, 0, 0, 0)
        scroll_content_layout.setSpacing(10)

        # Common stylesheet for controls
        self.setStyleSheet(f"""
            QWidget {{ font-size: 10pt; color: {COLORS['text']}; }}
            QLabel {{ font-size: 10pt; }}
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{
                padding: 8px; border: 1px solid {COLORS['secondary']};
                border-radius: 4px; background-color: white;
            }}
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{
                border: 2px solid {COLORS['primary']};
            }}
            QComboBox::drop-down {{ border: 0px; width: 20px; }} /* Style dropdown arrow */
             QPushButton {{ padding: 8px 12px; border-radius: 4px; }} /* Basic button style */
        """)

        # --- Reception Settings Form ---
        form_group = ModernGroupBox("Reception Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)

        # Output File
        output_layout = QHBoxLayout(); output_layout.setSpacing(8); output_layout.setContentsMargins(0,0,0,0)
        self.output_file_edit = QLineEdit()
        self.output_file_edit.setPlaceholderText("Path to save received data")
        self.output_file_edit.setToolTip("Specify the file name to save the reassembled data.")
        self.output_file_button = QPushButton("Browse...")
        self.output_file_button.setStyleSheet(f"background-color: {COLORS['secondary']}; color: white; border: none;")
        self.output_file_button.setToolTip("Browse for the output file location.")
        self.output_file_button.clicked.connect(self.browse_output_file) # Connect
        output_layout.addWidget(self.output_file_edit, 1)
        output_layout.addWidget(self.output_file_button)
        form_layout.addRow("Output File:", output_layout)

        # Key File
        key_layout = QHBoxLayout(); key_layout.setSpacing(8); key_layout.setContentsMargins(0,0,0,0)
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("Path to decryption key file (optional)")
        self.key_file_edit.setToolTip("Optional: Select the key file used for encryption by the sender.")
        self.key_file_button = QPushButton("Browse...")
        self.key_file_button.setStyleSheet(f"background-color: {COLORS['secondary']}; color: white; border: none;")
        self.key_file_button.setToolTip("Browse for the key file.")
        self.key_file_button.clicked.connect(self.browse_key_file) # Connect
        key_layout.addWidget(self.key_file_edit, 1)
        key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)

        # Interface Selection
        self.interface_combo = QComboBox()
        self.interface_combo.addItem("default", None) # Add default option
        self.interface_combo.setToolTip("Select the network interface to listen on. 'default' tries to auto-detect.")
        self.populate_interfaces() # Populate with system interfaces
        form_layout.addRow("Interface:", self.interface_combo)

        # Output Directory (for logs/metadata)
        output_dir_layout = QHBoxLayout(); output_dir_layout.setSpacing(8); output_dir_layout.setContentsMargins(0,0,0,0)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Session output directory (optional)")
        self.output_dir_edit.setToolTip("Optional: Specify a directory to save reception logs and metadata.")
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.setStyleSheet(f"background-color: {COLORS['secondary']}; color: white; border: none;")
        self.output_dir_button.setToolTip("Browse for the output directory.")
        self.output_dir_button.clicked.connect(self.browse_output_dir) # Connect
        output_dir_layout.addWidget(self.output_dir_edit, 1)
        output_dir_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_dir_layout)

        # Timeout
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 600) # 10 seconds to 10 minutes
        self.timeout_spin.setValue(DEFAULT_TIMEOUT)
        self.timeout_spin.setSuffix(" sec")
        self.timeout_spin.setToolTip("Timeout in seconds to wait for packets before stopping.")
        form_layout.addRow("Timeout:", self.timeout_spin)

        form_group.setLayout(form_layout)
        scroll_content_layout.addWidget(form_group) # Add form group to scroll content

        # --- Control Buttons ---
        control_layout = QHBoxLayout()
        control_layout.setSpacing(10)
        self.receive_button = AnimatedButton("Start Listening", color=COLORS['primary'])
        self.receive_button.clicked.connect(self.start_reception) # Connect
        self.stop_button = AnimatedButton("Stop", color=COLORS['danger'])
        self.stop_button.clicked.connect(self.stop_reception) # Connect
        self.stop_button.setEnabled(False)
        self.clear_log_button = AnimatedButton("Clear Log", color=COLORS['secondary'])
        self.clear_log_button.clicked.connect(self.clear_log) # Connect
        self.refresh_button = AnimatedButton("Refresh Interfaces", color=COLORS['info'])
        self.refresh_button.clicked.connect(self.populate_interfaces) # Connect
        self.refresh_button.setToolTip("Rescan network interfaces.")

        control_layout.addWidget(self.receive_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_log_button)
        control_layout.addWidget(self.refresh_button)
        control_layout.addStretch()
        scroll_content_layout.addLayout(control_layout) # Add controls to scroll content

        # --- Progress bar group - using the NEW combined widget ---
        progress_group = ModernGroupBox("Progress & Status")
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(10) # Slightly more space

        # Use combined progress bar with handshake
        self.combined_progress_bar = HandshakeProgressBar()
        self.status_label = AnimatedStatusLabel("Ready") # Keep general status separate

        progress_layout.addWidget(self.combined_progress_bar) # Add combined widget
        progress_layout.addWidget(self.status_label) # Add general status below it
        progress_group.setLayout(progress_layout)
        scroll_content_layout.addWidget(progress_group) # Add group to scroll content

        # Complete the scroll area setup
        scroll_area.setWidget(container_widget) # Assign the container widget to the scroll area

        # --- SPLITTER IMPLEMENTATION ---
        # Create main *vertical* splitter for settings vs log/data area
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        main_splitter.setChildrenCollapsible(False)
        main_splitter.setHandleWidth(8)
        main_splitter.setStyleSheet(f"""
            QSplitter::handle:vertical {{
                 background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                               stop:0 {COLORS['light']},
                                               stop:0.5 {COLORS['secondary']},
                                               stop:1 {COLORS['light']});
                border: 1px solid {COLORS['secondary']};
                height: 5px;
                margin: 2px 0px;
                border-radius: 2px;
            }}
            QSplitter::handle:vertical:hover {{
                background-color: {COLORS['primary']};
            }}
        """)

        # Add settings/control area (in the scroll_area) to the TOP of the main splitter
        main_splitter.addWidget(scroll_area)

        # --- Log and data display area (Horizontal Splitter) ---
        log_data_splitter = QSplitter(Qt.Orientation.Horizontal)
        log_data_splitter.setChildrenCollapsible(False)
        log_data_splitter.setHandleWidth(10) # Slightly thicker handle for horizontal
        log_data_splitter.setStyleSheet(f"""
            QSplitter::handle:horizontal {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                               stop:0 {COLORS['light']},
                                               stop:0.5 {COLORS['secondary']},
                                               stop:1 {COLORS['light']});
                border: 1px solid {COLORS['secondary']};
                width: 5px; /* Handle width */
                margin: 0px 2px; /* Vertical margin */
                border-radius: 2px;
            }}
            QSplitter::handle:horizontal:hover {{
                background-color: {COLORS['primary']};
            }}
        """)

        # Log area group
        log_group = ModernGroupBox("Reception Log")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier New", 9))
        self.log_edit.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap) # No wrap
        self.log_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['dark']}; color: {COLORS['light']};
                border: 1px solid {COLORS['secondary']}; border-radius: 4px; padding: 5px;
            }}""")
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        log_data_splitter.addWidget(log_group) # Add log to left of horizontal splitter

        # Data display area group
        data_group = ModernGroupBox("Received Data / File Preview")
        data_layout = QVBoxLayout()
        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.data_display.setFont(QFont("Courier New", 9))
        self.data_display.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth) # Wrap lines in data view
        self.data_display.setPlaceholderText("Decoded data snippets or saved file content will appear here...")
        self.data_display.setStyleSheet(f"""
             QTextEdit {{
                background-color: {COLORS['dark']}; color: {COLORS['light']};
                border: 1px solid {COLORS['secondary']}; border-radius: 4px; padding: 5px;
            }}""")

        data_buttons_layout = QHBoxLayout()
        data_buttons_layout.setSpacing(10)
        self.save_data_button = AnimatedButton("Save Displayed Text", color=COLORS['info'])
        self.save_data_button.setToolTip("Save the currently displayed text content to a new file.")
        self.save_data_button.clicked.connect(self.save_displayed_data) # Connect
        self.clear_data_button = AnimatedButton("Clear Display", color=COLORS['secondary'])
        self.clear_data_button.setToolTip("Clear the data display area.")
        self.clear_data_button.clicked.connect(self.clear_data_display) # Connect
        data_buttons_layout.addWidget(self.save_data_button)
        data_buttons_layout.addWidget(self.clear_data_button)
        data_buttons_layout.addStretch()

        data_layout.addWidget(self.data_display, 1) # Data display takes vertical space
        data_layout.addLayout(data_buttons_layout) # Buttons below data display
        data_group.setLayout(data_layout)
        log_data_splitter.addWidget(data_group) # Add data group to right of horizontal splitter

        # Add the horizontal log/data splitter to the BOTTOM of the main vertical splitter
        main_splitter.addWidget(log_data_splitter)

        # Set initial sizes for splitters
        initial_width = self.parent.width() if self.parent else 800
        initial_height = self.parent.height() if self.parent else 600
        log_data_splitter.setSizes([int(initial_width * 0.5), int(initial_width * 0.5)]) # 50/50 horizontal split
        main_splitter.setSizes([int(initial_height * 0.5), int(initial_height * 0.5)]) # 50/50 vertical split

        # Main panel layout now contains ONLY the main vertical splitter
        panel_layout = QVBoxLayout(self)
        panel_layout.setContentsMargins(10, 10, 10, 10) # Use panel margins
        panel_layout.addWidget(main_splitter)
        self.setLayout(panel_layout)

        # Store splitters for settings persistence
        self.main_splitter = main_splitter
        self.splitter = log_data_splitter # Keep reference to horizontal splitter

    # --- Method Overrides and New Methods ---

    # Override update methods to target the combined widget
    def update_handshake(self, stage):
        """Update the handshake indicators within the combined progress bar."""
        print(f"[GUI] Receiver Handshake Update: {stage}") # Debug
        # Note: Receiver stages are slightly different in meaning but map visually
        if stage == "syn_received": # Receiver gets SYN
            self.combined_progress_bar.set_syn_sent() # Visually represents first step active
        elif stage == "syn_ack_sent": # Receiver sends SYN-ACK
            self.combined_progress_bar.set_syn_ack_sent()
        elif stage == "ack_received": # Receiver gets final ACK
            self.combined_progress_bar.set_ack_sent() # Visually represents third step active
        elif stage == "established":
            self.combined_progress_bar.set_connection_established()
            self.status_label.setText("Connection Established") # Update main status

    def update_progress(self, current, total):
        """Update the progress bar value within the combined widget."""
        # print(f"[GUI] Receiver Progress Update: {current}/{total}") # Debug
        try:
            if total <= 0 and current <= 0:
                # Reset progress if no valid numbers
                self.combined_progress_bar.setValue(0)
                if self.parent:
                    self.parent.statusBar().showMessage("Listening...")
                return

            # Handle case where total might be 0 initially but current increases
            effective_total = max(total, current, 1) # Avoid division by zero, ensure minimum total of 1
            percentage = min(100, int((current / effective_total) * 100))
            self.combined_progress_bar.setValue(percentage)

            if self.parent:
                status_msg = f"Receiving: {current}/{total} chunks ({percentage}%)" if total > 0 else f"Receiving: Chunk {current}..."
                self.parent.statusBar().showMessage(status_msg)
        except Exception as e:
            print(f"Error updating receiver progress: {e}") # Log potential errors

    # Override: Start Reception
    def start_reception(self):
        self.log_edit.clear()
        self.data_display.clear()
        self.status_label.setText("Initializing...")
        self.combined_progress_bar.reset()
        self.last_displayed_file = None

        output_file = self.output_file_edit.text().strip()
        if not output_file:
            QMessageBox.warning(self, "Output File Required", "Please specify an Output File path.")
            self.status_label.setText("Ready")
            return

        # Check if output directory exists, create if necessary
        output_dir_path = os.path.dirname(output_file)
        if output_dir_path and not os.path.exists(output_dir_path):
             reply = QMessageBox.question(self, "Create Directory?",
                                          f"Output directory does not exist:\n{output_dir_path}\n\nCreate it?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                          QMessageBox.StandardButton.No)
             if reply == QMessageBox.StandardButton.Yes:
                 try:
                     os.makedirs(output_dir_path, exist_ok=True)
                 except OSError as e:
                     QMessageBox.critical(self, "Error", f"Could not create directory:\n{e}")
                     self.status_label.setText("Ready")
                     return
             else:
                 self.status_label.setText("Ready")
                 return


        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.isfile(key_file):
             QMessageBox.warning(self, "File Not Found", f"Key file not found:\n{key_file}")
             self.status_label.setText("Ready")
             return

        interface_name = self.interface_combo.currentText()
        interface_addr = self.interface_combo.currentData() # Get stored address if available

        output_dir_log = self.output_dir_edit.text().strip() # Log dir is separate
        if output_dir_log and not os.path.isdir(output_dir_log):
             reply = QMessageBox.question(self, "Create Directory?",
                                          f"Log output directory does not exist:\n{output_dir_log}\n\nCreate it?",
                                          QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                          QMessageBox.StandardButton.No)
             if reply == QMessageBox.StandardButton.Yes:
                 try:
                     os.makedirs(output_dir_log, exist_ok=True)
                 except OSError as e:
                     QMessageBox.critical(self, "Error", f"Could not create directory:\n{e}")
                     self.status_label.setText("Ready")
                     return
             else:
                 self.status_label.setText("Ready")
                 return


        args = {
            "output_file": output_file,
            "key_file": key_file or None,
            "interface": interface_name if interface_name != "default" else None, # Pass name if not default
            "timeout": self.timeout_spin.value(),
            "output_dir": output_dir_log or None, # Pass separate log dir
        }

        self.save_settings() # Save current settings

        self.worker_thread = WorkerThread("receive", args)
        self.worker_thread.update_signal.connect(self.handle_worker_output) # Route output
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.reception_finished)
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        # Connect total chunks if receiver needs it directly (e.g., for progress calculation)
        self.worker_thread.total_chunks_signal.connect(self.handle_total_chunks)

        self.receive_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.set_controls_enabled(False) # Disable form fields
        self.status_label.setText(f"Listening on {interface_name}...")
        self.worker_thread.start()

    # Override: Stop Reception
    def stop_reception(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping...")
            self.worker_thread.stop()
            # finished_signal handles button states

    # Override: Reception Finished
    def reception_finished(self, success):
        self.receive_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.set_controls_enabled(True) # Re-enable form

        final_status = self.status_label.text()
        if "Stopping" in final_status:
             self.status_label.setText("Reception stopped by user")
        elif success:
            # Update status if not already showing completion/save
            if "complete" not in final_status.lower() and "saved" not in final_status.lower():
                 self.status_label.setText("Reception finished successfully")
            self.combined_progress_bar.setValue(100)
            self.combined_progress_bar.set_connection_established() # Show green state
            # Attempt to display the saved file content
            output_file = self.output_file_edit.text().strip()
            if output_file and os.path.exists(output_file) and output_file != self.last_displayed_file:
                 self.display_file_content(output_file)

        elif "Timeout" not in final_status: # Keep timeout message if that was the cause
             if "failed" not in final_status.lower() and "error" not in final_status.lower():
                  self.status_label.setText("Reception failed or stopped")
             # Reset progress bar on failure?
             # self.combined_progress_bar.reset()

        self.worker_thread = None # Clear thread reference

    # --- Helper Methods ---

    def set_controls_enabled(self, enabled):
        """Enable/disable input controls during reception."""
        self.output_file_edit.setEnabled(enabled)
        self.output_file_button.setEnabled(enabled)
        self.key_file_edit.setEnabled(enabled)
        self.key_file_button.setEnabled(enabled)
        self.interface_combo.setEnabled(enabled)
        self.refresh_button.setEnabled(enabled)
        self.output_dir_edit.setEnabled(enabled)
        self.output_dir_button.setEnabled(enabled)
        self.timeout_spin.setEnabled(enabled)

    def handle_worker_output(self, text):
        """Route worker output to log or data queue."""
        # Check for data prefix (or other data indicators)
        if text.startswith("[DATA]"):
             data_content = text[len("[DATA]"):].strip()
             if data_content:
                 self.data_queue.put(data_content)
        # Check for file saved message to trigger display
        elif ("[SAVE]" in text and ("File saved successfully" in text or "Data saved to" in text)) or \
             ("[COMPLETE]" in text and "file saved" in text.lower()):
            self.append_log(text) # Log the save message
            # Try to extract filename and display it
            save_match = re.search(r"(?:saved to|File saved successfully|file saved):\s*([\/\w\.\-\_\s]+)", text)
            if save_match:
                saved_file = save_match.group(1).strip()
                if os.path.exists(saved_file) and saved_file != self.last_displayed_file:
                    self.display_file_content(saved_file)
        else:
            # Default to appending to the log
            self.append_log(text)


    def append_log(self, text):
        """Append text to the log view, handling colors."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        cursor = self.log_edit.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        # Basic color coding
        if text.startswith("ERROR:") or "Failed" in text or "Timeout" in text:
            color = COLORS['danger']
        elif text.startswith("WARN:") or "Warning" in text:
            color = COLORS['warning']
        elif "[HANDSHAKE]" in text:
             color = COLORS['handshake']
        elif "[ACK]" in text: # Receiver sending ACK
             color = COLORS['ack']
        elif "[PROGRESS]" in text or "Received chunk" in text or "Processing chunk" in text:
             color = COLORS['info']
        elif "[COMPLETE]" in text or "[SAVE]" in text:
            color = COLORS['success']
        else:
            color = COLORS['light'] # Default log text color

        # Insert timestamp and message
        cursor.insertHtml(f'<span style="color:{COLORS["secondary"]};">[{timestamp}] </span>')
        cursor.insertHtml(f'<span style="color:{color};">{text}</span><br>')

        self.log_edit.setTextCursor(cursor)
        self.log_edit.ensureCursorVisible() # Auto-scroll

    def update_status(self, text):
        """Update the main status label."""
        self.status_label.setText(text)

    def handle_total_chunks(self, total):
        """Handle total chunks signal (if needed by receiver GUI)."""
        print(f"[GUI] Receiver Total Chunks: {total}") # Debug
        # Currently receiver progress is handled by ProgressTracker based on counts/percentage
        # This signal might be useful if GUI needs to display total explicitly somewhere else.
        # self.some_total_label.setText(f"Total Chunks Expected: {total}")

    def clear_log(self):
        self.log_edit.clear()

    def update_log(self):
        """Process messages from the log queue."""
        while not self.log_queue.empty():
            try:
                message = self.log_queue.get_nowait()
                # Decide if message goes to log or data display based on content?
                # For now, assume worker thread directs via update_signal -> handle_worker_output
                self.append_log(message) # Default to log
            except queue.Empty:
                break
            except Exception as e:
                print(f"Error processing log queue: {e}")

    def update_data_display(self):
         """Append received data snippets from the queue to the data display."""
         if not self.data_queue.empty():
             cursor = self.data_display.textCursor()
             cursor.movePosition(QTextCursor.MoveOperation.End)
             while not self.data_queue.empty():
                 try:
                     data_snippet = self.data_queue.get_nowait()
                     # Simple formatting - maybe add timestamp or context later?
                     cursor.insertText(data_snippet + "\n")
                 except queue.Empty:
                     break
                 except Exception as e:
                     print(f"Error processing data queue: {e}")
                     cursor.insertText(f"\n<Error displaying data: {e}>\n")
             self.data_display.setTextCursor(cursor)
             self.data_display.ensureCursorVisible()

    def display_file_content(self, filepath):
        """Display content of the saved file in the data area."""
        try:
            # Limit file size to prevent GUI freeze
            if os.path.getsize(filepath) > 5 * 1024 * 1024: # 5 MB limit
                self.data_display.setPlainText(f"<File content too large to display ({os.path.getsize(filepath)/1024/1024:.1f} MB)>")
                self.last_displayed_file = None # Don't mark as displayed
                return

            with open(filepath, 'r', errors='ignore') as f: # Ignore decoding errors for preview
                content = f.read(100 * 1024) # Read up to 100KB for preview
                self.data_display.setPlainText(content)
                if len(content) == 100 * 1024:
                     self.data_display.append("\n\n<File content truncated for display>")
                self.last_displayed_file = filepath # Mark as displayed
                self.status_label.setText(f"Saved and previewing: {os.path.basename(filepath)}")

        except Exception as e:
            self.data_display.setPlainText(f"<Error displaying file content: {e}>")
            self.last_displayed_file = None

    def clear_data_display(self):
        self.data_display.clear()
        self.last_displayed_file = None # Clear tracking

    def save_displayed_data(self):
        """Save the text currently in the data display area to a new file."""
        content = self.data_display.toPlainText()
        if not content:
            QMessageBox.information(self, "Nothing to Save", "The data display area is empty.")
            return

        filename, _ = QFileDialog.saveFileName(self, "Save Displayed Text As...", filter="Text Files (*.txt);;All Files (*)")
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                self.status_label.setText(f"Displayed text saved to: {os.path.basename(filename)}")
            except Exception as e:
                QMessageBox.critical(self, "Error Saving File", f"Could not save file:\n{e}")

    def browse_output_file(self):
        filename, _ = QFileDialog.saveFileName(self, "Select Output File")
        if filename:
            self.output_file_edit.setText(filename)

    def browse_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Select Key File")
        if filename:
            self.key_file_edit.setText(filename)

    def browse_output_dir(self):
        dirname = QFileDialog.getExistingDirectory(self, "Select Log Output Directory")
        if dirname:
            self.output_dir_edit.setText(dirname)

    def populate_interfaces(self):
        """Populate the interface dropdown."""
        self.interface_combo.clear()
        self.interface_combo.addItem("default", None) # Add default first
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                try:
                    # Try to get an IPv4 address for display/filtering
                    addrs = netifaces.ifaddresses(iface)
                    ipv4_addr = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', None)
                    # Display name and IPv4 if available
                    display_text = f"{iface}" + (f" ({ipv4_addr})" if ipv4_addr else "")
                    self.interface_combo.addItem(display_text, iface) # Store real name as data
                except ValueError:
                     self.interface_combo.addItem(f"{iface} (No Addr)", iface) # Handle interfaces without addresses
        except Exception as e:
            self.append_log(f"ERROR: Could not list network interfaces: {e}")
            QMessageBox.warning(self, "Interface Error", "Could not retrieve network interface list.")

        # Restore previous selection if possible
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        saved_iface = settings.value("interface_name", "default")
        index = self.interface_combo.findText(saved_iface, Qt.MatchFlag.MatchStartsWith) # Try matching start
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
        else:
            index = self.interface_combo.findData(saved_iface) # Try matching stored data
            if index >= 0:
                 self.interface_combo.setCurrentIndex(index)
            else:
                 self.interface_combo.setCurrentIndex(0) # Default to "default"


    def load_settings(self):
        """Load settings specific to the receiver panel."""
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        self.output_file_edit.setText(settings.value("output_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        self.output_dir_edit.setText(settings.value("output_dir_log", ""))
        self.timeout_spin.setValue(int(settings.value("timeout", DEFAULT_TIMEOUT)))
        # Interface loaded in populate_interfaces using saved setting

    def save_settings(self):
        """Save settings specific to the receiver panel."""
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        settings.setValue("output_file", self.output_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("output_dir_log", self.output_dir_edit.text()) # Save log dir separately
        settings.setValue("timeout", self.timeout_spin.value())
        settings.setValue("interface_name", self.interface_combo.currentText()) # Save displayed text for restoration hint
        settings.setValue("interface_data", self.interface_combo.currentData()) # Save actual interface name

    # Ensure placeholder methods are implemented
    def __getattr__(self, name):
        if name in ["browse_output_file", "browse_key_file", "browse_output_dir", "clear_log", "clear_data_display", "save_displayed_data", "populate_interfaces", "update_log", "update_data_display"]:
            def _missing_method(*args, **kwargs):
                print(f"Warning: Method {name} called but not fully implemented in EnhancedReceiverPanel.")
            return _missing_method
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")


# --- MainWindow class definition (Placeholder for original structure) ---
class MainWindow(QMainWindow):
    # Placeholder needed for inheritance
     def __init__(self):
        super().__init__()
        self.status_bar = QStatusBar() # Ensure status_bar exists
        self.setStatusBar(self.status_bar)

     # Placeholder methods
     def closeEvent(self, event): super().closeEvent(event)
     def save_settings(self): pass
     def load_settings(self): pass
     def setup_menu(self): pass
     def show_about(self): pass
     def check_environment(self): pass
     def update_status_on_tab_change(self, index): pass


# --- EnhancedMainWindow: Integrates Enhanced Panels ---
class EnhancedMainWindow(MainWindow): # Inherit from placeholder
    def __init__(self):
        super().__init__() # Call placeholder __init__
        self.setWindowTitle("CrypticRoute - Network Steganography Tool v2.3") # Updated title
        self.setMinimumSize(850, 650) # Slightly larger default size

        # --- Apply Styles ---
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: {COLORS['background']}; }}
            QTabWidget::pane {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 8px;
                background-color: {COLORS['background']};
                padding: 0px; /* Let panel handle internal padding */
                margin: 0px;
            }}
            QTabBar::tab {{
                background-color: {COLORS['light']};
                border: 1px solid {COLORS['secondary']};
                border-bottom: none; /* Join with pane */
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                padding: 10px 25px; /* More horizontal padding */
                margin-right: 2px;
                color: {COLORS['secondary']};
                font-weight: bold;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS['primary']};
                color: white;
                border-bottom: 1px solid {COLORS['primary']}; /* Blend selected tab with pane */
            }}
            QTabBar::tab:hover:!selected {{
                background-color: #e2e8f0; /* Slightly darker hover */
                color: {COLORS['primary']};
            }}
            QStatusBar {{
                background-color: {COLORS['light']};
                color: {COLORS['text']};
                padding: 5px;
                font-size: 10pt;
                border-top: 1px solid {COLORS['secondary']};
            }}
            QToolTip {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                border: 1px solid {COLORS['secondary']};
                padding: 4px;
                border-radius: 3px;
            }}
        """)

        # --- Create Tabs ---
        self.central_widget = QTabWidget()
        self.central_widget.setDocumentMode(True) # More modern tab look
        self.setCentralWidget(self.central_widget)

        # --- Create Enhanced Panels ---
        # Pass `self` as the parent so panels can access the main window (e.g., status bar)
        self.sender_panel = EnhancedSenderPanel(self)
        self.central_widget.addTab(self.sender_panel, "Send File")
        send_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp)
        self.central_widget.setTabIcon(0, send_icon)

        self.receiver_panel = EnhancedReceiverPanel(self)
        self.central_widget.addTab(self.receiver_panel, "Receive File")
        receive_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown)
        self.central_widget.setTabIcon(1, receive_icon)


        # Status bar already created in placeholder __init__
        self.status_bar.showMessage("Ready")

        # Connect tab change signal
        self.central_widget.currentChanged.connect(self.update_status_on_tab_change)

        # Setup menu (using placeholder method)
        self.setup_menu()
        self.load_settings() # Load main window and panel settings

    # Override: Save Settings (include splitter states)
    def save_settings(self):
        settings = QSettings("CrypticRoute", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        settings.setValue("windowState", self.saveState()) # Save maximize state etc.
        settings.setValue("current_tab", self.central_widget.currentIndex())

        # Save panel settings (calls panel's save method)
        if hasattr(self.sender_panel, 'save_settings'):
            self.sender_panel.save_settings()
        if hasattr(self.receiver_panel, 'save_settings'):
            self.receiver_panel.save_settings()

        # Save splitter states if they exist
        if hasattr(self.sender_panel, 'main_splitter') and self.sender_panel.main_splitter:
            settings.setValue("sender_splitter_state", self.sender_panel.main_splitter.saveState())

        if hasattr(self.receiver_panel, 'main_splitter') and self.receiver_panel.main_splitter:
            settings.setValue("receiver_main_splitter_state", self.receiver_panel.main_splitter.saveState())

        # Save horizontal splitter state for the receiver
        if hasattr(self.receiver_panel, 'splitter') and self.receiver_panel.splitter:
            settings.setValue("receiver_log_data_splitter_state", self.receiver_panel.splitter.saveState())

        print("Settings saved.")

    # Override: Load Settings (include splitter states)
    def load_settings(self):
        settings = QSettings("CrypticRoute", "MainWindow")

        # Restore window geometry and state
        geometry = settings.value("geometry")
        if geometry: self.restoreGeometry(geometry)
        windowState = settings.value("windowState")
        if windowState: self.restoreState(windowState)

        # Load panel settings (calls panel's load method)
        if hasattr(self.sender_panel, 'load_settings'):
            self.sender_panel.load_settings()
        if hasattr(self.receiver_panel, 'load_settings'):
            self.receiver_panel.load_settings()

        # Restore splitter states if they exist
        if hasattr(self.sender_panel, 'main_splitter') and self.sender_panel.main_splitter:
            sender_splitter_state = settings.value("sender_splitter_state")
            if sender_splitter_state:
                self.sender_panel.main_splitter.restoreState(sender_splitter_state)

        if hasattr(self.receiver_panel, 'main_splitter') and self.receiver_panel.main_splitter:
            receiver_main_splitter_state = settings.value("receiver_main_splitter_state")
            if receiver_main_splitter_state:
                self.receiver_panel.main_splitter.restoreState(receiver_main_splitter_state)

        if hasattr(self.receiver_panel, 'splitter') and self.receiver_panel.splitter:
            receiver_log_data_splitter_state = settings.value("receiver_log_data_splitter_state")
            if receiver_log_data_splitter_state:
                self.receiver_panel.splitter.restoreState(receiver_log_data_splitter_state)

        # Restore current tab
        try:
            tab_index = int(settings.value("current_tab", 0))
            if 0 <= tab_index < self.central_widget.count():
                self.central_widget.setCurrentIndex(tab_index)
            else:
                self.central_widget.setCurrentIndex(0)
        except ValueError:
            self.central_widget.setCurrentIndex(0) # Default to first tab on error

        print("Settings loaded.")

    # Override: Setup Menu
    def setup_menu(self):
        menu_bar = self.menuBar()

        # File Menu
        file_menu = menu_bar.addMenu("&File")
        exit_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton), "&Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.setStatusTip("Exit CrypticRoute")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Tools Menu (Placeholder)
        # tools_menu = menu_bar.addMenu("&Tools")
        # Add tools later if needed (e.g., key generator, packet analyzer)

        # Help Menu
        help_menu = menu_bar.addMenu("&Help")
        about_action = QAction(self.style().standardIcon(QStyle.StandardPixmap.SP_DialogHelpButton), "&About", self)
        about_action.setStatusTip("Show information about CrypticRoute")
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    # Override: Show About Dialog
    def show_about(self):
        QMessageBox.about(self, "About CrypticRoute",
                          """<b>CrypticRoute v2.3</b><br><br>
                          A network steganography tool for covert data transmission
                          using modified IP packet headers.<br><br>
                          Features TCP-like handshake, acknowledgments, optional AES encryption,
                          and GUI controls.<br><br>
                          <i>Note: Requires appropriate permissions (root/capabilities) for raw socket operations, especially on the receiver side. Use responsibly and ethically.</i>
                          """)

    # Override: Check Environment (placeholder implementation)
    def check_environment(self):
         """Basic environment checks (e.g., python version, dependencies)."""
         print(f"Python version: {sys.version}")
         try:
            import netifaces
            import psutil
            print("Required libraries (PyQt6, netifaces, psutil) seem present.")
         except ImportError as e:
            print(f"WARNING: Missing library: {e}. GUI functionality might be limited.")
            QMessageBox.warning(self, "Dependency Error", f"Missing required library: {e}. Please install it.")

         is_root = (hasattr(os, 'geteuid') and os.geteuid() == 0) or \
                   (hasattr(psutil, 'Process') and psutil.Process(os.getpid()).username() == 'root')

         if not is_root and sys.platform != 'win32':
              print("INFO: Running as non-root. Receiver might require root/sudo or network capabilities (e.g., CAP_NET_RAW).")
              self.status_bar.showMessage("Ready (Note: Receiver may require root/sudo)")
         elif is_root:
              print("INFO: Running with root privileges.")
              self.status_bar.showMessage("Ready (Running as root)")
         else: # Windows
              print("INFO: Running on Windows.")
              self.status_bar.showMessage("Ready")


    # Override: Update status bar when tab changes
    def update_status_on_tab_change(self, index):
        widget = self.central_widget.widget(index)
        if hasattr(widget, 'status_label') and widget.status_label:
             status = widget.status_label.text()
             self.status_bar.showMessage(status)
        else:
             self.status_bar.showMessage("Ready")


    # Override: Close Event (save settings)
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop any running threads gracefully
        if self.sender_panel.worker_thread and self.sender_panel.worker_thread.isRunning():
             self.sender_panel.stop_transmission()
             # Potentially wait here or show message? For now, just trigger stop.
        if self.receiver_panel.worker_thread and self.receiver_panel.worker_thread.isRunning():
             self.receiver_panel.stop_reception()

        # Close ACK details window if open
        if self.sender_panel.ack_details_window:
             self.sender_panel.ack_details_window.close()

        self.save_settings() # Save geometry, splitters, panel settings
        print("Exiting CrypticRoute GUI.")
        super().closeEvent(event)


# --- Entry point modification ---
def main():
    # Handle Ctrl+C in the terminal more gracefully
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # Force a consistent style if needed
    # os.environ['QT_STYLE_OVERRIDE'] = 'Fusion'
    app = QApplication(sys.argv)
    app.setApplicationName("CrypticRoute")
    app.setApplicationVersion("2.3") # Match version

    # Use the enhanced main window
    window = EnhancedMainWindow()
    window.check_environment() # Perform checks after window creation
    window.show()

    # Redirect stdout/stderr if needed for debugging within GUI log
    # log_queue = window.sender_panel.log_queue # Or a shared queue
    # sys.stdout = LogRedirector(log_queue)
    # sys.stderr = LogRedirector(log_queue)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
# --- END OF ENHANCED gui.py ---
