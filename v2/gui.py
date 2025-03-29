# --- START OF MODIFIED gui.py ---

#!/usr/bin/env python3
"""
CrypticRoute GUI - Network Steganography Tool
A graphical interface for the sender and receiver components of CrypticRoute
Enhanced with PyQt6 and visualization for handshake and ACK system
(Modified: ACK progress bar moved to separate window, main panel shows count)
"""

import sys
import os
import time
import datetime
import threading
import json
import queue
import signal
# Corrected QtWidgets import (Removed QAction)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                            QHBoxLayout, QFormLayout, QLabel, QLineEdit, QPushButton,
                            QSpinBox, QDoubleSpinBox, QTextEdit, QFileDialog, QComboBox,
                            QProgressBar, QGroupBox, QCheckBox, QSplitter, QFrame,
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

# --- Classes (AnimatedProgressBar, AckProgressBar, HandshakeIndicator unchanged) ---

# --- (Place this class definition somewhere before EnhancedSenderPanel, e.g., after ModernGroupBox) ---

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
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)

        # SYN-ACK Indicator
        self.syn_ack_indicator = QLabel("SYN-ACK")
        self.syn_ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-size: 9pt;
        """)

        # ACK Indicator
        self.ack_indicator = QLabel("ACK")
        self.ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)

        # Status Label
        self.status_label = QLabel("Not Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['danger']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

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
        # Reset SYN
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)
        # Reset SYN-ACK
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-size: 9pt;
        """)
        # Reset ACK
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)
        # Reset Status Label
        self.status_label.setText("Not Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['danger']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

    def set_syn_sent(self):
        """Mark the SYN stage as completed"""
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.status_label.setText("SYN Sent")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['handshake']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

    def set_syn_ack_sent(self): # Or received, depending on perspective
        """Mark the SYN-ACK stage as completed"""
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.status_label.setText("SYN-ACK") # Keep status concise
        self.status_label.setStyleSheet(f"""
            color: {COLORS['handshake']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

    def set_ack_sent(self): # Or received
        """Mark the ACK stage as completed"""
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-weight: bold;
            font-size: 9pt;
        """)
        # Status usually becomes "Connected" shortly after this

    def set_connection_established(self):
        """Mark the connection as fully established"""
        # Color all indicators green
        style_established = f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 2px;
            font-weight: bold;
            font-size: 9pt;
        """
        self.syn_indicator.setStyleSheet(style_established + "min-width: 40px;")
        self.syn_ack_indicator.setStyleSheet(style_established + "min-width: 60px;")
        self.ack_indicator.setStyleSheet(style_established + "min-width: 40px;")

        self.status_label.setText("Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['success']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

# --- END OF HandshakeProgressBar class ---

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

class HandshakeIndicator(QWidget):
    """Widget to visualize the TCP-like handshake process"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.reset()
        # Initially hidden until connection starts
        self.setVisible(False)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)

        # More compact layout
        stages_layout = QHBoxLayout()
        stages_layout.setSpacing(3)

        # SYN Stage
        self.syn_indicator = QLabel("SYN")
        self.syn_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)
        stages_layout.addWidget(self.syn_indicator)

        # Arrow 1
        arrow1 = QLabel("→")
        arrow1.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow1.setFixedWidth(15)
        stages_layout.addWidget(arrow1)

        # SYN-ACK Stage
        self.syn_ack_indicator = QLabel("SYN-ACK")
        self.syn_ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-size: 9pt;
        """)
        stages_layout.addWidget(self.syn_ack_indicator)

        # Arrow 2
        arrow2 = QLabel("→")
        arrow2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        arrow2.setFixedWidth(15)
        stages_layout.addWidget(arrow2)

        # ACK Stage
        self.ack_indicator = QLabel("ACK")
        self.ack_indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)
        stages_layout.addWidget(self.ack_indicator)

        # Status with less space
        self.status_label = QLabel("Not Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['danger']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)
        stages_layout.addWidget(self.status_label, 1, alignment=Qt.AlignmentFlag.AlignRight)

        layout.addLayout(stages_layout)

    def reset(self):
        """Reset all indicators to their initial state."""
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-size: 9pt;
        """)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['light']};
            color: {COLORS['text']};
            border: 1px solid {COLORS['secondary']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-size: 9pt;
        """)
        self.status_label.setText("Not Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['danger']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)
        # Hide the indicator again
        self.setVisible(False)

    def set_syn_sent(self):
        """Mark the SYN stage as completed."""
        # Make the indicator visible when connection starts
        self.setVisible(True)
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.status_label.setText("SYN Sent")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['handshake']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

    def set_syn_ack_sent(self):
        """Mark the SYN-ACK stage as completed."""
        self.setVisible(True)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.status_label.setText("SYN-ACK") # Simplified status
        self.status_label.setStyleSheet(f"""
            color: {COLORS['handshake']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

    def set_ack_sent(self):
        """Mark the ACK stage as completed."""
        self.setVisible(True)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['handshake']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['handshake']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-weight: bold;
            font-size: 9pt;
        """)

    def set_connection_established(self):
        """Mark the connection as fully established."""
        self.setVisible(True)
        self.syn_indicator.setStyleSheet(f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.syn_ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 2px;
            min-width: 60px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.ack_indicator.setStyleSheet(f"""
            background-color: {COLORS['success']};
            color: {COLORS['text_light']};
            border: 1px solid {COLORS['success']};
            border-radius: 4px;
            padding: 2px;
            min-width: 40px;
            font-weight: bold;
            font-size: 9pt;
        """)
        self.status_label.setText("Connected")
        self.status_label.setStyleSheet(f"""
            color: {COLORS['success']};
            font-weight: bold;
            padding: 2px;
            font-size: 9pt;
        """)

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
        if any(word in text.lower() for word in ["completed", "success", "complete"]):
            self.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["error", "failed", "stopped"]):
            self.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["warning", "caution"]):
            self.setStyleSheet(f"color: {COLORS['warning']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["starting", "listening", "waiting"]):
            self.setStyleSheet(f"color: {COLORS['info']}; font-weight: bold; padding: 5px; border-radius: 4px;")
        elif any(word in text.lower() for word in ["connected", "established", "connection", "syn-ack"]): # Added syn-ack
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
            if not self.has_direct_percentage or new_percentage >= self.percentage: # Allow updates if percentage is same or higher
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


# --- WorkerThread unchanged ---
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
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=1, # Line buffered
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"),
                                        errors='replace') # Handle potential encoding errors
        total_chunks = 0
        current_chunk = 0

        stdout_iterator = iter(self.process.stdout.readline, '')
        stderr_iterator = iter(self.process.stderr.readline, '')

        while not self.stopped:
            line = None
            try:
                line = next(stdout_iterator, None)
                if line is None:
                    err_line = next(stderr_iterator, None)
                    if err_line:
                         self.update_signal.emit(f"ERROR: {err_line.strip()}")
                    elif self.process.poll() is not None:
                        break
                    else:
                        time.sleep(0.01)
                        continue
                else:
                    line = line.strip()
                    if not line: continue
            except StopIteration:
                 if self.process.poll() is not None: break
                 else: time.sleep(0.01); continue

            if line:
                self.update_signal.emit(line)

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
                    except Exception as e:
                        print(f"Sender: Error parsing total chunk count from '{line}': {e}")

                # Parse chunk counts for progress bar
                progress_match = re.search(r"(?:Completed chunk|\[PROGRESS\].*sequence:)\s*(\d+)(?:/(\d+))?", line)
                if progress_match:
                    try:
                        current_chunk = int(progress_match.group(1))
                        if progress_match.group(2): # Total present
                            new_total_chunks = int(progress_match.group(2))
                            if new_total_chunks != total_chunks and new_total_chunks > 0:
                                total_chunks = new_total_chunks
                                self.total_chunks_signal.emit(total_chunks)
                                # print(f"Sender updated total chunks from progress: {total_chunks}") # Debug
                        if current_chunk > 0 and total_chunks > 0:
                             self.progress_signal.emit(current_chunk, total_chunks)
                        elif current_chunk > 0: # Estimate total
                             self.progress_signal.emit(current_chunk, max(current_chunk, 100))
                    except Exception as e:
                        print(f"Sender: Error parsing progress from '{line}': {e}")

                elif "[COMPLETE] Transmission successfully completed" in line:
                    self.status_signal.emit("Transmission complete")
                    if total_chunks > 0: self.progress_signal.emit(total_chunks, total_chunks)


        # Read remaining stderr
        for err_line in stderr_iterator:
             if self.stopped: break
             self.update_signal.emit(f"ERROR: {err_line.strip()}")

        exit_code = self.process.wait()
        success = (exit_code == 0 and not self.stopped)
        if success and total_chunks > 0:
            self.progress_signal.emit(total_chunks, total_chunks) # Ensure 100% on success
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
        self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, bufsize=1,
                                        env=dict(os.environ, PYTHONUNBUFFERED="1"),
                                        errors='replace')
        progress_tracker = ProgressTracker(self.progress_signal)
        current_total_chunks = 0

        stdout_iterator = iter(self.process.stdout.readline, '')
        stderr_iterator = iter(self.process.stderr.readline, '')

        while not self.stopped:
            line = None
            try:
                line = next(stdout_iterator, None)
                if line is None:
                    err_line = next(stderr_iterator, None)
                    if err_line:
                         self.update_signal.emit(f"ERROR: {err_line.strip()}")
                    elif self.process.poll() is not None: break
                    else: time.sleep(0.01); continue
                else:
                    line = line.strip()
                    if not line: continue
            except StopIteration:
                 if self.process.poll() is not None: break
                 else: time.sleep(0.01); continue

            if line:
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
                        # self.ack_signal.emit(chunk_num) # Receiver panel doesn't use this
                    except (ValueError, IndexError) as e:
                        print(f"Receiver: Error parsing sent ACK number from '{line}': {e}")

                # Update total chunks
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
                    except Exception as e:
                        print(f"Receiver: Error parsing total chunks from '{line}': {e}")

                # Extract data content
                data_extracted = False
                data_patterns = [r"\[DATA\]\s*(.*)", r"(?:Received chunk data|Decoded data|Data chunk|CHUNK_DATA):\s*(.*)"]
                for pattern in data_patterns:
                    data_match = re.search(pattern, line, re.IGNORECASE)
                    if data_match:
                        data_part = data_match.group(1).strip()
                        if data_part:
                            self.update_signal.emit(f"[DATA] {data_part}")
                            data_extracted = True
                            break

                # Track progress
                try:
                    percent_match = re.search(r"Progress:\s*([\d\.]+)\s*%", line)
                    if percent_match:
                        percentage = float(percent_match.group(1))
                        progress_tracker.update_from_percentage(percentage)
                    elif "[CHUNK]" in line or "[PACKET]" in line:
                        count_match = re.search(r"(?:Received|Chunks|sequence):\s*(\d+)(?:/(\d+))?", line, re.IGNORECASE)
                        if count_match:
                            curr = int(count_match.group(1))
                            tot = current_total_chunks
                            if count_match.group(2):
                                line_total = int(count_match.group(2))
                                if line_total > current_total_chunks:
                                    current_total_chunks = line_total
                                    self.total_chunks_signal.emit(current_total_chunks)
                                tot = current_total_chunks
                            if tot > 0: progress_tracker.update_from_counts(curr, tot)
                            elif curr > 0: progress_tracker.update_from_counts(curr, max(curr + 10, 100))
                except Exception as e:
                    print(f"Receiver: Error in progress parsing from '{line}': {e}")

                # Update status messages
                if "[COMPLETE]" in line or "Reception complete" in line:
                    self.status_signal.emit("Reception complete")
                    if current_total_chunks > 0: progress_tracker.update_from_counts(current_total_chunks, current_total_chunks)
                    else: progress_tracker.update_from_percentage(100.0)
                elif "[INFO]" in line and "All session data saved to:" in line:
                    self.status_signal.emit("Data saved successfully")
                elif "[SAVE]" in line and "File saved successfully" in line:
                    self.status_signal.emit("File saved successfully")


        for err_line in stderr_iterator:
            if self.stopped: break
            self.update_signal.emit(f"ERROR: {err_line.strip()}")

        exit_code = self.process.wait()
        success = (exit_code == 0 and not self.stopped)
        if success:
            if current_total_chunks > 0: progress_tracker.update_from_counts(current_total_chunks, current_total_chunks)
            else: progress_tracker.update_from_percentage(100.0)
        self.finished_signal.emit(success)


    def stop(self):
        self.stopped = True
        if self.process and self.process.poll() is None:
            self.update_signal.emit("Stopping process...")
            try:
                self.process.terminate()
                try:
                    self.process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    self.update_signal.emit("Process did not terminate gracefully, killing.")
                    self.process.kill()
                    self.process.wait()
                self.update_signal.emit("Process stopped by user.")
            except Exception as e:
                self.update_signal.emit(f"Error stopping process: {e}")
                try:
                    if self.process.poll() is None:
                        self.process.kill(); self.process.wait()
                except Exception as ke:
                     self.update_signal.emit(f"Error killing process: {ke}")
        if self.isRunning():
             self.finished_signal.emit(False)


# --- ModernGroupBox unchanged ---
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

# --- SenderPanel Modified ---
class SenderPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.worker_thread = None
        self.log_queue = queue.Queue()
        self.ack_details_window = None # Reference to the details window
        self.acked_chunks = set()     # Keep track of ACKs internally
        self.total_chunks = 0         # Keep track of total chunks
        self.setup_ui()
        self.log_timer = QTimer(self)
        self.log_timer.timeout.connect(self.update_log)
        self.log_timer.start(50)
        self.load_settings()

    def setup_ui(self):
        # Scroll area for the main settings/controls
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        scroll_area.setStyleSheet("background-color: transparent;")

        scroll_content_widget = QWidget()
        scroll_content_widget.setStyleSheet("background-color: transparent;")
        content_layout = QVBoxLayout(scroll_content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        # Common Stylesheet
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
        """)

        # Transmission Settings Group (Inside Scroll Area)
        form_group = ModernGroupBox("Transmission Settings")
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.setSpacing(10)
        # ... (Target IP, Input File, Key File, Output Dir, Delay, Chunk Size - unchanged) ...
        self.target_ip_edit = QLineEdit()
        self.target_ip_edit.setPlaceholderText("Enter target IP address (e.g., 192.168.1.100)")
        form_layout.addRow("Target IP:", self.target_ip_edit)

        input_layout = QHBoxLayout(); input_layout.setSpacing(8)
        self.input_file_edit = QLineEdit(); self.input_file_edit.setPlaceholderText("Path to input file")
        self.input_file_button = QPushButton("Browse..."); self.input_file_button.clicked.connect(self.browse_input_file)
        self.input_file_button.setStyleSheet(f"QPushButton {{ background-color: {COLORS['secondary']}; color: white; border: none; padding: 8px 12px; border-radius: 4px; }} QPushButton:hover {{ background-color: #7e8a9a; }}")
        input_layout.addWidget(self.input_file_edit); input_layout.addWidget(self.input_file_button)
        form_layout.addRow("Input File:", input_layout)

        key_layout = QHBoxLayout(); key_layout.setSpacing(8)
        self.key_file_edit = QLineEdit(); self.key_file_edit.setPlaceholderText("Path to encryption key file (optional)")
        self.key_file_button = QPushButton("Browse..."); self.key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_button.setStyleSheet(f"QPushButton {{ background-color: {COLORS['secondary']}; color: white; border: none; padding: 8px 12px; border-radius: 4px; }} QPushButton:hover {{ background-color: #7e8a9a; }}")
        key_layout.addWidget(self.key_file_edit); key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)

        output_layout = QHBoxLayout(); output_layout.setSpacing(8)
        self.output_dir_edit = QLineEdit(); self.output_dir_edit.setPlaceholderText("Custom output directory (optional)")
        self.output_dir_button = QPushButton("Browse..."); self.output_dir_button.clicked.connect(self.browse_output_dir)
        self.output_dir_button.setStyleSheet(f"QPushButton {{ background-color: {COLORS['secondary']}; color: white; border: none; padding: 8px 12px; border-radius: 4px; }} QPushButton:hover {{ background-color: #7e8a9a; }}")
        output_layout.addWidget(self.output_dir_edit); output_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_layout)

        self.delay_spin = QDoubleSpinBox(); self.delay_spin.setRange(0.01, 5.0); self.delay_spin.setSingleStep(0.1); self.delay_spin.setValue(DEFAULT_DELAY); self.delay_spin.setSuffix(" sec")
        form_layout.addRow("Packet Delay:", self.delay_spin)

        self.chunk_size_spin = QSpinBox(); self.chunk_size_spin.setRange(1, 8); self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE); self.chunk_size_spin.setSuffix(" bytes")
        form_layout.addRow("Chunk Size:", self.chunk_size_spin)

        form_group.setLayout(form_layout)
        content_layout.addWidget(form_group) # Add to scrollable content

        # Control buttons (Inside Scroll Area)
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
        content_layout.addLayout(control_layout) # Add to scrollable content

        # Handshake Indicator (Inside Scroll Area)
        self.handshake_indicator = HandshakeIndicator()
        content_layout.addWidget(self.handshake_indicator) # Add to scrollable content

        # Progress Group (Inside Scroll Area)
        progress_group = ModernGroupBox("Progress")
        progress_layout = QVBoxLayout()
        progress_layout.setSpacing(8) # Reduced spacing
        self.progress_bar = AnimatedProgressBar()
        self.progress_bar.setValue(0)
        self.status_label = AnimatedStatusLabel("Ready")
        # Add ACK counter label here
        self.ack_count_label = QLabel("ACKs: 0/0")
        self.ack_count_label.setStyleSheet(f"color: {COLORS['ack']}; font-size: 9pt;")

        status_ack_layout = QHBoxLayout() # Layout for status and ACK count
        status_ack_layout.addWidget(self.status_label)
        status_ack_layout.addStretch()
        status_ack_layout.addWidget(self.ack_count_label)

        progress_layout.addWidget(self.progress_bar)
        progress_layout.addLayout(status_ack_layout) # Add combined status/ACK layout

        progress_group.setLayout(progress_layout)
        content_layout.addWidget(progress_group) # Add to scrollable content

        # --- REMOVED ACK Group Box ---

        # Finish Scroll Area Setup
        scroll_area.setWidget(scroll_content_widget)

        # Log Area (Outside Scroll Area)
        log_group = ModernGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        self.log_edit.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS['dark']}; color: {COLORS['light']};
                border-radius: 4px; padding: 5px;
            }}""")
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)

        # Main Panel Layout (Scroll Area + Log Area)
        panel_layout = QVBoxLayout(self)
        panel_layout.setContentsMargins(0, 0, 0, 0) # Use container margins
        panel_layout.addWidget(scroll_area)   # Scroll area takes its preferred height
        panel_layout.addWidget(log_group, 1) # Log area stretches
        self.setLayout(panel_layout)

    # --- browse_input_file, browse_key_file, browse_output_dir unchanged ---
    def browse_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Input File", self.input_file_edit.text() or QSettings("CrypticRoute", "SenderPanel").value("last_dir", ""), "All Files (*)")
        if file_path:
            self.input_file_edit.setText(file_path)
            QSettings("CrypticRoute", "SenderPanel").setValue("last_dir", os.path.dirname(file_path))

    def browse_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", self.key_file_edit.text() or QSettings("CrypticRoute", "SenderPanel").value("last_dir", ""), "All Files (*)")
        if file_path:
            self.key_file_edit.setText(file_path)
            QSettings("CrypticRoute", "SenderPanel").setValue("last_dir", os.path.dirname(file_path))

    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.output_dir_edit.text() or QSettings("CrypticRoute", "SenderPanel").value("last_dir", ""))
        if dir_path:
            self.output_dir_edit.setText(dir_path)
            QSettings("CrypticRoute", "SenderPanel").setValue("last_dir", dir_path)

    # --- add_log_message, update_log, clear_log unchanged ---
    def add_log_message(self, message):
        # Filtering example (optional)
        # if "[PACKET] #" in message and not (message.endswith("0") or message.endswith("5")):
        #     return

        styled_message = message
        # Apply styling
        if message.startswith("ERROR:"): styled_message = f'<span style="color:{COLORS["danger"]};">{message}</span>'
        elif "[COMPLETE]" in message or "Success" in message: styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'
        elif "[INFO]" in message: styled_message = f'<span style="color:{COLORS["info"]};">{message}</span>'
        elif "[WARNING]" in message or "Warning" in message: styled_message = f'<span style="color:{COLORS["warning"]};">{message}</span>'
        elif "[HANDSHAKE]" in message: styled_message = f'<span style="color:{COLORS["handshake"]};">{message}</span>'
        elif "[ACK]" in message or "[CONFIRMED]" in message: styled_message = f'<span style="color:{COLORS["ack"]};">{message}</span>'

        self.log_edit.append(styled_message)
        # Auto-scroll if near bottom
        scrollbar = self.log_edit.verticalScrollBar()
        if scrollbar.value() >= scrollbar.maximum() - 15:
             self.log_edit.moveCursor(QTextCursor.MoveOperation.End)
             self.log_edit.ensureCursorVisible()

    def update_log(self):
        try:
            messages_processed = 0
            max_messages_per_update = 50
            while not self.log_queue.empty() and messages_processed < max_messages_per_update:
                message = self.log_queue.get_nowait()
                self.add_log_message(message)
                messages_processed += 1
        except queue.Empty: pass
        except Exception as e: print(f"Error updating log: {e}")

    def clear_log(self):
        self.log_edit.clear()

    def start_transmission(self):
        # --- Input validation unchanged ---
        target_ip = self.target_ip_edit.text().strip()
        if not target_ip: QMessageBox.warning(self, "Input Error", "Target IP address is required."); return
        input_file = self.input_file_edit.text().strip()
        if not input_file: QMessageBox.warning(self, "Input Error", "Input file is required."); return
        if not os.path.exists(input_file): QMessageBox.warning(self, "Input Error", f"Input file does not exist: {input_file}"); return
        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file): QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}"); return
        output_dir = self.output_dir_edit.text().strip()
        if output_dir and not os.path.exists(output_dir):
            response = QMessageBox.question(self, "Create Directory?", f"Output directory does not exist: {output_dir}\nCreate it?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)
            if response == QMessageBox.StandardButton.Yes:
                try: os.makedirs(output_dir, exist_ok=True)
                except Exception as e: QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}"); return
            else: return

        args = {
            "target_ip": target_ip, "input_file": input_file,
            "delay": self.delay_spin.value(), "chunk_size": self.chunk_size_spin.value(),
        }
        if key_file: args["key_file"] = key_file
        if output_dir: args["output_dir"] = output_dir

        self.save_settings()
        self.clear_log()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting transmission...")
        self.acked_chunks.clear() # Clear internal ACK set
        self.total_chunks = 0     # Reset internal total
        self.update_ack_count_label() # Update label

        # Reset visualization components
        self.handshake_indicator.reset()
        if self.ack_details_window: # Reset details window if open
            self.ack_details_window.reset()

        self.send_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.worker_thread = WorkerThread("send", args)
        self.worker_thread.update_signal.connect(self.add_log_message)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.transmission_finished)

        # Connect signals for handshake and ACK logic
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        self.worker_thread.ack_signal.connect(self.handle_ack_received) # Renamed slot
        self.worker_thread.total_chunks_signal.connect(self.handle_total_chunks) # Renamed slot

        self.worker_thread.start()

    def stop_transmission(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping transmission...")
            self.worker_thread.stop()
            self.stop_button.setEnabled(False) # Disable immediately

    def update_progress(self, current, total):
        if total > 0:
            percentage = min(100, (current / total) * 100)
            self.progress_bar.setValue(int(percentage))
            if self.parent:
                self.parent.statusBar().showMessage(f"Sending: {current}/{total} chunks ({percentage:.1f}%)")
        elif current > 0:
             self.progress_bar.setValue(0)
             if self.parent: self.parent.statusBar().showMessage(f"Sending: Chunk {current}...")

    def update_status(self, status):
        self.status_label.setText(status)

    def update_handshake(self, stage):
        """Update the handshake indicator based on the current stage."""
        if stage == "syn_sent": self.handshake_indicator.set_syn_sent()
        elif stage == "syn_ack_received": self.handshake_indicator.set_syn_ack_sent()
        elif stage == "ack_sent": self.handshake_indicator.set_ack_sent()
        elif stage == "established": self.handshake_indicator.set_connection_established()

    def update_ack_count_label(self):
        """Updates the simple ACK counter label."""
        self.ack_count_label.setText(f"ACKs: {len(self.acked_chunks)}/{self.total_chunks}")

    def handle_total_chunks(self, total):
        """Handles receiving the total chunk count."""
        if total > 0 and total != self.total_chunks:
             print(f"[SenderPanel] Total chunks received: {total}")
             self.total_chunks = total
             self.update_ack_count_label()
             # Update details window if open
             if self.ack_details_window:
                 self.ack_details_window.set_total_chunks(total)

    def handle_ack_received(self, chunk_num):
        """Handles receiving an acknowledgment for a chunk."""
        if chunk_num > 0 and chunk_num not in self.acked_chunks:
            # print(f"[SenderPanel] Received ACK for chunk {chunk_num}") # Debug
            self.acked_chunks.add(chunk_num)
            self.update_ack_count_label()
            # Update details window if open
            if self.ack_details_window:
                self.ack_details_window.acknowledge_chunk(chunk_num)

    def transmission_finished(self, success):
        self.send_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        final_status = "Transmission completed successfully" if success else "Transmission failed or was stopped"
        self.status_label.setText(final_status)
        if success:
            self.progress_bar.setValue(100)
            # Ensure final ACK count matches total if successful
            if self.total_chunks > 0:
                 self.ack_count_label.setText(f"ACKs: {self.total_chunks}/{self.total_chunks}")
                 if self.ack_details_window:
                      self.ack_details_window.ack_panel.ack_count_label.setText(f"{self.total_chunks}/{self.total_chunks}")
                      self.ack_details_window.ack_panel.ack_progress.setValue(100)


        if self.parent: self.parent.statusBar().showMessage(final_status)
        self.worker_thread = None

    def save_settings(self):
        settings = QSettings("CrypticRoute", "SenderPanel")
        settings.setValue("target_ip", self.target_ip_edit.text())
        settings.setValue("input_file", self.input_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("delay", self.delay_spin.value())
        settings.setValue("chunk_size", self.chunk_size_spin.value())
        # Save last dir
        if self.input_file_edit.text(): settings.setValue("last_dir", os.path.dirname(self.input_file_edit.text()))
        elif self.output_dir_edit.text(): settings.setValue("last_dir", self.output_dir_edit.text())


    def load_settings(self):
        settings = QSettings("CrypticRoute", "SenderPanel")
        self.target_ip_edit.setText(settings.value("target_ip", ""))
        self.input_file_edit.setText(settings.value("input_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        self.output_dir_edit.setText(settings.value("output_dir", ""))
        try: self.delay_spin.setValue(float(settings.value("delay", DEFAULT_DELAY)))
        except: self.delay_spin.setValue(DEFAULT_DELAY)
        try: self.chunk_size_spin.setValue(int(settings.value("chunk_size", DEFAULT_CHUNK_SIZE)))
        except: self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)

    def open_ack_details_window(self):
        """Creates or shows the Acknowledgment Details window."""
        if self.ack_details_window is None:
            print("Creating AckDetailsWindow")
            self.ack_details_window = AckDetailsWindow(self) # Pass self reference
            # Immediately update with current state
            self.ack_details_window.set_total_chunks(self.total_chunks)
            for chunk in sorted(list(self.acked_chunks)):
                 self.ack_details_window.acknowledge_chunk(chunk)
            self.ack_details_window.show()
        else:
            print("Showing existing AckDetailsWindow")
            self.ack_details_window.raise_()
            self.ack_details_window.activateWindow()
            # Re-sync state just in case
            self.ack_details_window.set_total_chunks(self.total_chunks)
            for chunk in sorted(list(self.acked_chunks)):
                 self.ack_details_window.acknowledge_chunk(chunk)

# --- ReceiverPanel unchanged from previous version ---
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
        self.last_displayed_file = None
        self.load_settings()

    def display_received_file(self, file_path):
        try:
            if not os.path.exists(file_path):
                print(f"Warning: Cannot display file - {file_path} doesn't exist")
                self.clear_data_display(); self.data_display.setText(f"--- File not found: {os.path.basename(file_path)} ---")
                self.last_displayed_file = None; return
            if file_path == self.last_displayed_file: return # Already shown

            content = ""
            try:
                with open(file_path, 'r', errors='replace') as f:
                    content = f.read(5 * 1024 * 1024) # Limit display size
                    if len(content) == 5 * 1024 * 1024: content += "\n\n--- File content truncated for display ---"
            except UnicodeDecodeError: content = f"--- Cannot display binary file content: {os.path.basename(file_path)} ---"
            except Exception as e: content = f"--- Error reading file: {os.path.basename(file_path)} ({e}) ---"

            self.clear_data_display()
            header = f"--- Content from {os.path.basename(file_path)} ---\n\n"
            self.data_display.setText(header + content)
            print(f"Displayed content from file: {file_path}")
            cursor = self.data_display.textCursor(); cursor.setPosition(0); self.data_display.setTextCursor(cursor)
            self.last_displayed_file = file_path
        except Exception as e:
            print(f"Error displaying received file: {e}")
            self.clear_data_display(); self.data_display.setText(f"Error displaying file: {str(e)}")
            self.last_displayed_file = None

    def setup_ui(self):
        # Scroll area setup
        scroll_area = QScrollArea(); scroll_area.setWidgetResizable(True); scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        container_widget = QWidget()
        main_layout = QVBoxLayout(container_widget); main_layout.setContentsMargins(10, 10, 10, 10); main_layout.setSpacing(10)
        self.setStyleSheet(f"""QWidget {{ font-size: 10pt; color: {COLORS['text']}; }} QLabel {{ font-size: 10pt; }} QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {{ padding: 8px; border: 1px solid {COLORS['secondary']}; border-radius: 4px; background-color: white; }} QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {{ border: 2px solid {COLORS['primary']}; }} QComboBox::drop-down {{ border: 0px; width: 20px; }}""")

        # Reception Settings Form
        form_group = ModernGroupBox("Reception Settings")
        form_layout = QFormLayout(); form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight); form_layout.setSpacing(10)
        # ... (Output File, Key File, Interface, Output Dir, Timeout - unchanged) ...
        output_layout = QHBoxLayout(); output_layout.setSpacing(8)
        self.output_file_edit = QLineEdit(); self.output_file_edit.setPlaceholderText("Path to save received data")
        self.output_file_button = QPushButton("Browse..."); self.output_file_button.clicked.connect(self.browse_output_file)
        self.output_file_button.setStyleSheet(f"QPushButton {{ background-color: {COLORS['secondary']}; color: white; border: none; padding: 8px 12px; border-radius: 4px; }} QPushButton:hover {{ background-color: #7e8a9a; }}")
        output_layout.addWidget(self.output_file_edit); output_layout.addWidget(self.output_file_button)
        form_layout.addRow("Output File:", output_layout)

        key_layout = QHBoxLayout(); key_layout.setSpacing(8)
        self.key_file_edit = QLineEdit(); self.key_file_edit.setPlaceholderText("Path to decryption key file (optional)")
        self.key_file_button = QPushButton("Browse..."); self.key_file_button.clicked.connect(self.browse_key_file)
        self.key_file_button.setStyleSheet(f"QPushButton {{ background-color: {COLORS['secondary']}; color: white; border: none; padding: 8px 12px; border-radius: 4px; }} QPushButton:hover {{ background-color: #7e8a9a; }}")
        key_layout.addWidget(self.key_file_edit); key_layout.addWidget(self.key_file_button)
        form_layout.addRow("Key File:", key_layout)

        self.interface_combo = QComboBox(); self.interface_combo.addItem("default"); self.populate_interfaces()
        form_layout.addRow("Interface:", self.interface_combo)

        output_dir_layout = QHBoxLayout(); output_dir_layout.setSpacing(8)
        self.output_dir_edit = QLineEdit(); self.output_dir_edit.setPlaceholderText("Custom output directory (optional)")
        self.output_dir_button = QPushButton("Browse..."); self.output_dir_button.clicked.connect(self.browse_output_dir)
        self.output_dir_button.setStyleSheet(f"QPushButton {{ background-color: {COLORS['secondary']}; color: white; border: none; padding: 8px 12px; border-radius: 4px; }} QPushButton:hover {{ background-color: #7e8a9a; }}")
        output_dir_layout.addWidget(self.output_dir_edit); output_dir_layout.addWidget(self.output_dir_button)
        form_layout.addRow("Output Dir:", output_dir_layout)

        self.timeout_spin = QSpinBox(); self.timeout_spin.setRange(10, 600); self.timeout_spin.setValue(DEFAULT_TIMEOUT); self.timeout_spin.setSuffix(" sec")
        form_layout.addRow("Timeout:", self.timeout_spin)

        form_group.setLayout(form_layout)
        main_layout.addWidget(form_group)

        # Control buttons
        control_layout = QHBoxLayout(); control_layout.setSpacing(10)
        self.receive_button = AnimatedButton("Start Listening", color=COLORS['primary']); self.receive_button.clicked.connect(self.start_reception)
        self.stop_button = AnimatedButton("Stop", color=COLORS['danger']); self.stop_button.clicked.connect(self.stop_reception); self.stop_button.setEnabled(False)
        self.clear_button = AnimatedButton("Clear Log", color=COLORS['secondary']); self.clear_button.clicked.connect(self.clear_log)
        self.refresh_button = AnimatedButton("Refresh Interfaces", color=COLORS['info']); self.refresh_button.clicked.connect(self.populate_interfaces)
        control_layout.addWidget(self.receive_button); control_layout.addWidget(self.stop_button); control_layout.addWidget(self.clear_button); control_layout.addWidget(self.refresh_button); control_layout.addStretch()
        main_layout.addLayout(control_layout)

        # Connection status indicator
        self.handshake_indicator = HandshakeIndicator()
        main_layout.addWidget(self.handshake_indicator)

        # Progress bar
        progress_group = ModernGroupBox("Progress")
        progress_layout = QVBoxLayout(); progress_layout.setSpacing(10)
        self.progress_bar = AnimatedProgressBar(); self.progress_bar.setValue(0)
        self.status_label = AnimatedStatusLabel("Ready")
        progress_layout.addWidget(self.progress_bar); progress_layout.addWidget(self.status_label)
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)

        # Log and data display area (Splitter)
        splitter = QSplitter(Qt.Orientation.Horizontal); splitter.setChildrenCollapsible(False); splitter.setHandleWidth(10)
        splitter.setStyleSheet(f"QSplitter::handle:horizontal {{ background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {COLORS['light']}, stop:0.5 {COLORS['secondary']}, stop:1 {COLORS['light']}); border: 1px solid {COLORS['secondary']}; width: 5px; margin: 4px 0px; border-radius: 2px; }} QSplitter::handle:horizontal:hover {{ background-color: {COLORS['primary']}; }}")

        log_group = ModernGroupBox("Transmission Log"); log_layout = QVBoxLayout()
        self.log_edit = QTextEdit(); self.log_edit.setReadOnly(True); self.log_edit.setFont(QFont("Courier", 9)); self.log_edit.setStyleSheet(f"QTextEdit {{ background-color: {COLORS['dark']}; color: {COLORS['light']}; border-radius: 4px; padding: 5px; }}")
        log_layout.addWidget(self.log_edit); log_group.setLayout(log_layout); splitter.addWidget(log_group)

        data_group = ModernGroupBox("Received Data / File Content"); data_layout = QVBoxLayout()
        self.data_display = QTextEdit(); self.data_display.setReadOnly(True); self.data_display.setFont(QFont("Courier", 9)); self.data_display.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap); self.data_display.setStyleSheet(f"QTextEdit {{ background-color: {COLORS['dark']}; color: {COLORS['light']}; border-radius: 4px; padding: 5px; }}")
        data_buttons_layout = QHBoxLayout(); data_buttons_layout.setSpacing(10)
        self.save_data_button = AnimatedButton("Save Displayed Text", color=COLORS['info']); self.save_data_button.setToolTip("Save the currently displayed text content to a new file."); self.save_data_button.clicked.connect(self.save_displayed_data)
        self.clear_data_button = AnimatedButton("Clear Display", color=COLORS['secondary']); self.clear_data_button.clicked.connect(self.clear_data_display)
        data_buttons_layout.addWidget(self.save_data_button); data_buttons_layout.addWidget(self.clear_data_button); data_buttons_layout.addStretch()
        data_layout.addWidget(self.data_display, 1); data_layout.addLayout(data_buttons_layout); data_group.setLayout(data_layout); splitter.addWidget(data_group)

        splitter.setSizes([int(self.width() * 0.5) if self.width() > 0 else 300, int(self.width() * 0.5) if self.width() > 0 else 300]) # Initial size
        main_layout.addWidget(splitter, 1) # Add splitter to scrollable content

        # Set container, final layout
        scroll_area.setWidget(container_widget)
        panel_layout = QVBoxLayout(self); panel_layout.setContentsMargins(0, 0, 0, 0); panel_layout.addWidget(scroll_area)
        self.setLayout(panel_layout)


    def populate_interfaces(self):
        current_selection = self.interface_combo.currentText()
        self.interface_combo.clear(); self.interface_combo.addItem("default"); selected_index = 0
        try:
            interfaces = netifaces.interfaces(); count = 1
            for iface in interfaces:
                if iface.startswith("lo"): continue
                display_text = iface
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs: ip = addrs[netifaces.AF_INET][0]['addr']; display_text = f"{iface} ({ip})"
                except Exception: pass
                self.interface_combo.addItem(display_text)
                if display_text == current_selection or iface == current_selection: selected_index = count
                count += 1
        except Exception as e: self.add_log_message(f"ERROR: Could not populate network interfaces: {str(e)}")
        self.interface_combo.setCurrentIndex(selected_index)

    # --- browse_output_file, browse_key_file, browse_output_dir unchanged ---
    def browse_output_file(self):
        default_name = f"received_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        start_path = self.output_file_edit.text() or os.path.join(QSettings("CrypticRoute", "ReceiverPanel").value("last_dir", ""), default_name)
        file_path, _ = QFileDialog.getSaveFileName(self, "Select Output File", start_path, "All Files (*)")
        if file_path: self.output_file_edit.setText(file_path); QSettings("CrypticRoute", "ReceiverPanel").setValue("last_dir", os.path.dirname(file_path))

    def browse_key_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", self.key_file_edit.text() or QSettings("CrypticRoute", "ReceiverPanel").value("last_dir", ""), "All Files (*)")
        if file_path: self.key_file_edit.setText(file_path); QSettings("CrypticRoute", "ReceiverPanel").setValue("last_dir", os.path.dirname(file_path))

    def browse_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory", self.output_dir_edit.text() or QSettings("CrypticRoute", "ReceiverPanel").value("last_dir", ""))
        if dir_path: self.output_dir_edit.setText(dir_path); QSettings("CrypticRoute", "ReceiverPanel").setValue("last_dir", dir_path)


    def add_log_message(self, message):
        if message.startswith("[DATA] "):
            try: data = message[7:]; self.data_queue.put(data)
            except Exception as e: print(f"Error queueing data: {e}")
            return # Don't log raw data

        styled_message = message
        if message.startswith("ERROR:"): styled_message = f'<span style="color:{COLORS["danger"]};">{message}</span>'
        elif "[COMPLETE]" in message or "Success" in message or "successfully" in message: styled_message = f'<span style="color:{COLORS["success"]};">{message}</span>'
        elif "[INFO]" in message: styled_message = f'<span style="color:{COLORS["info"]};">{message}</span>'
        elif "[WARNING]" in message or "Warning" in message: styled_message = f'<span style="color:{COLORS["warning"]};">{message}</span>'
        elif "[HANDSHAKE]" in message: styled_message = f'<span style="color:{COLORS["handshake"]};">{message}</span>'
        elif "[ACK]" in message: styled_message = f'<span style="color:{COLORS["ack"]}; font-style: italic;">{message}</span>'

        self.log_edit.append(styled_message)
        scrollbar = self.log_edit.verticalScrollBar()
        if scrollbar.value() >= scrollbar.maximum() - 15: self.log_edit.moveCursor(QTextCursor.MoveOperation.End); self.log_edit.ensureCursorVisible()

    # --- update_log, update_data_display, clear_log, clear_data_display, save_displayed_data unchanged ---
    def update_log(self):
        try:
            messages_processed = 0; max_messages_per_update = 50
            while not self.log_queue.empty() and messages_processed < max_messages_per_update:
                self.add_log_message(self.log_queue.get_nowait()); messages_processed += 1
        except queue.Empty: pass
        except Exception as e: print(f"Error updating receiver log: {e}")

    def update_data_display(self):
        try:
            data_batch = []; max_items = 50
            while not self.data_queue.empty() and len(data_batch) < max_items: data_batch.append(self.data_queue.get_nowait())
            if data_batch:
                new_data = '\n'.join(data_batch); cursor = self.data_display.textCursor(); at_end = cursor.atEnd()
                cursor.movePosition(QTextCursor.MoveOperation.End); cursor.insertText(new_data + '\n')
                if at_end: self.data_display.ensureCursorVisible()
        except queue.Empty: pass
        except Exception as e: print(f"Error updating data display: {e}")

    def clear_log(self): self.log_edit.clear()
    def clear_data_display(self): self.data_display.clear(); self.last_displayed_file = None

    def save_displayed_data(self):
        current_content = self.data_display.toPlainText()
        if not current_content.strip(): QMessageBox.information(self, "Info", "There is no data in the display to save."); return
        default_name = f"displayed_data_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        start_path = os.path.join(QSettings("CrypticRoute", "ReceiverPanel").value("last_dir", ""), default_name)
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Displayed Text", start_path, "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'w', errors='replace') as f: f.write(current_content)
                self.status_label.setText(f"Displayed text saved to {os.path.basename(file_path)}")
                QSettings("CrypticRoute", "ReceiverPanel").setValue("last_dir", os.path.dirname(file_path))
            except Exception as e: QMessageBox.critical(self, "Error", f"Failed to save displayed data: {str(e)}")

    def start_reception(self):
        output_file = self.output_file_edit.text().strip()
        if not output_file: QMessageBox.warning(self, "Input Error", "Output file path is required."); return
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
             response = QMessageBox.question(self, "Create Directory?", f"Output directory does not exist:\n{output_dir}\n\nCreate it?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)
             if response == QMessageBox.StandardButton.Yes:
                try: os.makedirs(output_dir, exist_ok=True)
                except Exception as e: QMessageBox.critical(self, "Error", f"Failed to create directory: {str(e)}"); return
             else: return
        key_file = self.key_file_edit.text().strip()
        if key_file and not os.path.exists(key_file): QMessageBox.warning(self, "Input Error", f"Key file does not exist: {key_file}"); return
        custom_output_dir = self.output_dir_edit.text().strip()
        if custom_output_dir and not os.path.exists(custom_output_dir):
            response = QMessageBox.question(self, "Create Directory?", f"Custom output directory does not exist:\n{custom_output_dir}\n\nCreate it?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes)
            if response == QMessageBox.StandardButton.Yes:
                try: os.makedirs(custom_output_dir, exist_ok=True)
                except Exception as e: QMessageBox.critical(self, "Error", f"Failed to create custom directory: {str(e)}"); return
            else: return

        args = {"output_file": output_file, "timeout": self.timeout_spin.value()}
        interface_text = self.interface_combo.currentText()
        if interface_text and interface_text != "default": interface = interface_text.split(' ')[0]; args["interface"] = interface
        if key_file: args["key_file"] = key_file
        if custom_output_dir: args["output_dir"] = custom_output_dir

        self.save_settings()
        self.clear_log(); self.clear_data_display()
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting reception...")
        self.last_displayed_file = None

        # Reset visualization components
        self.handshake_indicator.reset()

        self.receive_button.setEnabled(False); self.stop_button.setEnabled(True)

        self.worker_thread = WorkerThread("receive", args)
        self.worker_thread.update_signal.connect(self.add_log_message)
        self.worker_thread.progress_signal.connect(self.update_progress)
        self.worker_thread.status_signal.connect(self.update_status)
        self.worker_thread.finished_signal.connect(self.reception_finished)
        self.worker_thread.handshake_signal.connect(self.update_handshake)
        # No ACK panel to connect to total_chunks_signal

        self.worker_thread.start()

    def stop_reception(self):
        if self.worker_thread and self.worker_thread.isRunning():
            self.status_label.setText("Stopping reception...")
            self.worker_thread.stop()
            self.stop_button.setEnabled(False)

    def update_progress(self, current, total):
        try:
            if total <= 0 and current <= 0: self.progress_bar.setValue(0);
            if self.parent: self.parent.statusBar().showMessage("Receiving...")
            return
            effective_total = max(total, current, 1)
            percentage = min(100, (current / effective_total) * 100)
            self.progress_bar.setValue(int(percentage))
            if self.parent:
                status_msg = f"Receiving: {current}/{total} chunks ({percentage:.1f}%)" if total > 0 else f"Receiving: Chunk {current}..."
                self.parent.statusBar().showMessage(status_msg)
        except Exception as e: print(f"Error updating receiver progress: {e}")

    def update_status(self, status): self.status_label.setText(status)

    def update_handshake(self, stage):
        if stage == "syn_received": self.handshake_indicator.set_syn_sent()
        elif stage == "syn_ack_sent": self.handshake_indicator.set_syn_ack_sent()
        elif stage == "ack_received": self.handshake_indicator.set_ack_sent()
        elif stage == "established": self.handshake_indicator.set_connection_established()

    def reception_finished(self, success):
        self.receive_button.setEnabled(True); self.stop_button.setEnabled(False)
        final_status = "Reception completed successfully" if success else "Reception failed or was stopped"
        self.status_label.setText(final_status)
        if self.parent: self.parent.statusBar().showMessage(final_status)
        if success:
            output_file = self.output_file_edit.text().strip()
            if output_file and os.path.exists(output_file): self.display_received_file(output_file)
            else: self.add_log_message("[INFO] Output file not found or not specified, cannot display content.")
        self.worker_thread = None

    # --- save_settings, load_settings unchanged ---
    def save_settings(self):
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        settings.setValue("output_file", self.output_file_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        settings.setValue("interface", self.interface_combo.currentText())
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("timeout", self.timeout_spin.value())
        if self.output_file_edit.text(): settings.setValue("last_dir", os.path.dirname(self.output_file_edit.text()))
        elif self.output_dir_edit.text(): settings.setValue("last_dir", self.output_dir_edit.text())

    def load_settings(self):
        settings = QSettings("CrypticRoute", "ReceiverPanel")
        self.output_file_edit.setText(settings.value("output_file", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))
        interface = settings.value("interface", "default")
        index = self.interface_combo.findText(interface, Qt.MatchFlag.MatchExactly | Qt.MatchFlag.MatchCaseSensitive)
        if index == -1: index = self.interface_combo.findText(interface.split(' ')[0], Qt.MatchFlag.MatchStartsWith | Qt.MatchFlag.MatchCaseSensitive)
        if index >= 0: self.interface_combo.setCurrentIndex(index)
        else: self.interface_combo.setCurrentIndex(0)
        self.output_dir_edit.setText(settings.value("output_dir", ""))
        try: self.timeout_spin.setValue(int(settings.value("timeout", DEFAULT_TIMEOUT)))
        except: self.timeout_spin.setValue(DEFAULT_TIMEOUT)


# --- MainWindow Modified ---
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CrypticRoute - Network Steganography Tool")
        self.setMinimumSize(850, 600) # Adjusted min size
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: {COLORS['background']}; }}
            QTabWidget::pane {{ border: 1px solid {COLORS['secondary']}; border-radius: 8px; background-color: {COLORS['background']}; padding: 5px; }}
            QTabBar::tab {{ background-color: {COLORS['light']}; border: 1px solid {COLORS['secondary']}; border-bottom: none; border-top-left-radius: 4px; border-top-right-radius: 4px; padding: 10px 20px; margin-right: 2px; color: {COLORS['secondary']}; }}
            QTabBar::tab:selected {{ background-color: {COLORS['primary']}; color: white; font-weight: bold; }}
            QTabBar::tab:hover:!selected {{ background-color: #dbe4ff; }}
            QStatusBar {{ background-color: {COLORS['light']}; color: {COLORS['text']}; padding: 5px; font-size: 10pt; border-top: 1px solid {COLORS['secondary']}; }}
        """)
        self.central_widget = QTabWidget()
        self.setCentralWidget(self.central_widget)

        # Create panels
        self.sender_panel = SenderPanel(self)
        self.central_widget.addTab(self.sender_panel, "Send File")
        self.receiver_panel = ReceiverPanel(self)
        self.central_widget.addTab(self.receiver_panel, "Receive File")

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        self.central_widget.currentChanged.connect(self.update_status_on_tab_change)
        self.setup_menu() # Changed from setup_ui
        self.load_settings()

        # No initial ACK grid toggle needed here anymore

    def setup_menu(self): # Renamed from setup_ui
        menubar = self.menuBar()
        menubar.setStyleSheet(f"""
            QMenuBar {{ background-color: {COLORS['dark']}; color: {COLORS['light']}; padding: 5px; font-size: 10pt; }}
            QMenuBar::item {{ background-color: transparent; padding: 8px 15px; border-radius: 4px; }}
            QMenuBar::item:selected {{ background-color: {COLORS['primary']}; }}
            QMenu {{ background-color: {COLORS['light']}; color: {COLORS['text']}; border: 1px solid {COLORS['secondary']}; border-radius: 4px; }}
            QMenu::item {{ padding: 8px 25px; }}
            QMenu::item:selected {{ background-color: {COLORS['primary']}; color: white; border-radius: 2px; }}
            QMenu::separator {{ height: 1px; background-color: {COLORS['secondary']}; margin: 5px 10px; }}
        """)

        # File menu
        file_menu = menubar.addMenu("File")

        # --- Replaced ACK Grid Toggle with Details Window Action ---
        self.view_ack_details_action = QAction("View Acknowledgment Details", self)
        self.view_ack_details_action.triggered.connect(self.show_ack_details)
        # Initially disable if not on sender tab? Or let the slot handle it.
        # self.view_ack_details_action.setEnabled(self.central_widget.currentIndex() == 0)
        file_menu.addAction(self.view_ack_details_action)

        file_menu.addSeparator()

        exit_action = file_menu.addAction("Exit")
        exit_action.triggered.connect(self.close)

        # Help menu
        help_menu = menubar.addMenu("Help")
        about_action = help_menu.addAction("About")
        about_action.triggered.connect(self.show_about)

    # --- Removed toggle_ack_grid method ---

    def show_ack_details(self):
        """Opens the acknowledgment details window if the sender tab is active."""
        if self.central_widget.currentWidget() == self.sender_panel:
            self.sender_panel.open_ack_details_window()
        else:
            QMessageBox.information(self, "Info", "Acknowledgment details are only available on the Sender tab.")

    def update_status_on_tab_change(self, index):
        status = "Ready"
        if index == 0: # Sender
             status = "Sender: Ready"
             if self.sender_panel.worker_thread and self.sender_panel.worker_thread.isRunning():
                 status = self.sender_panel.status_label.text()
             # Enable/disable ACK details menu based on tab
             # self.view_ack_details_action.setEnabled(True)
        else: # Receiver
             status = "Receiver: Ready"
             if self.receiver_panel.worker_thread and self.receiver_panel.worker_thread.isRunning():
                 status = self.receiver_panel.status_label.text()
             # self.view_ack_details_action.setEnabled(False)

        self.status_bar.showMessage(status)


    def show_about(self):
        QMessageBox.about(self, "About CrypticRoute",
                          f"<h2 style='color: {COLORS['primary']};'>CrypticRoute</h2>"
                          "<p style='font-size: 11pt;'>Network Steganography Tool</p>"
                          "<p style='font-size: 10pt;'>Version 2.2 (ACK Details Window)</p>" # Updated version
                          "<p>A graphical interface for sending and receiving hidden data through network packets.</p>"
                          "<p>Enhanced with connection handshake visualization and detailed acknowledgment tracking.</p>"
                          "<hr>"
                          "<p><i>Note: Receiver requires appropriate network permissions.</i></p>")


    def closeEvent(self, event):
        print("Main window close event...")
        # Close details window first if open
        if self.sender_panel.ack_details_window:
             print("Closing ACK details window...")
             self.sender_panel.ack_details_window.close()

        # Stop worker threads
        if self.sender_panel.worker_thread and self.sender_panel.worker_thread.isRunning():
            print("Stopping sender thread...")
            self.sender_panel.stop_transmission()
        if self.receiver_panel.worker_thread and self.receiver_panel.worker_thread.isRunning():
            print("Stopping receiver thread...")
            self.receiver_panel.stop_reception()

        # Save settings
        print("Saving main window settings...")
        self.save_settings()
        print("Main window settings saved.")
        event.accept()
        print("Exiting application.")


    def save_settings(self):
        settings = QSettings("CrypticRoute", "MainWindow")
        settings.setValue("geometry", self.saveGeometry())
        # Avoid saving state as it can be problematic after UI changes
        # settings.setValue("state", self.saveState())
        settings.setValue("current_tab", self.central_widget.currentIndex())
        # No ACK grid visibility to save anymore

    def load_settings(self):
        settings = QSettings("CrypticRoute", "MainWindow")
        geometry = settings.value("geometry")
        if geometry: self.restoreGeometry(geometry)
        # state = settings.value("state"); # if state: self.restoreState(state)
        try:
            tab_index = int(settings.value("current_tab", 0))
            if 0 <= tab_index < self.central_widget.count(): self.central_widget.setCurrentIndex(tab_index)
            else: self.central_widget.setCurrentIndex(0)
        except ValueError: self.central_widget.setCurrentIndex(0)
        # Restore receiver splitter state if applicable
        if hasattr(self.receiver_panel, 'splitter'):
             splitter_state = settings.value("receiver_splitter_state")
             if splitter_state: self.receiver_panel.splitter.restoreState(splitter_state)
             # else: self.receiver_panel.splitter.setSizes([int(self.width()*0.5), int(self.width()*0.5)]) # Already handled in setup?


# --- check_environment, main unchanged ---
def check_environment():
    if os.environ.get("XDG_SESSION_TYPE") == "wayland" and os.geteuid() == 0:
         print("Warning: Running GUI applications as root under Wayland might cause issues.")
    if "XDG_RUNTIME_DIR" not in os.environ:
        runtime_dir_path = f"/run/user/{os.getuid()}"
        if not os.path.isdir(runtime_dir_path): runtime_dir_path = f"/tmp/runtime-{os.getuid()}"
        if not os.path.exists(runtime_dir_path):
            try:
                print(f"Attempting to create {runtime_dir_path}")
                os.makedirs(runtime_dir_path, mode=0o700, exist_ok=True)
                os.chmod(runtime_dir_path, 0o700)
                os.environ["XDG_RUNTIME_DIR"] = runtime_dir_path
                print(f"Set XDG_RUNTIME_DIR to {runtime_dir_path}")
            except Exception as e: print(f"Warning: Failed to create or set XDG_RUNTIME_DIR: {e}")
        elif os.path.exists(runtime_dir_path):
             os.environ["XDG_RUNTIME_DIR"] = runtime_dir_path

def main():
    check_environment()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    os.environ['QT_STYLE_OVERRIDE'] = 'Fusion' # Force style
    app = QApplication(sys.argv)
    app.setApplicationName("CrypticRoute")
    app.setApplicationVersion("2.2") # Updated version

    is_root = (os.geteuid() == 0)
    if is_root: print("INFO: CrypticRoute GUI is running with root privileges.")
    else: print("INFO: CrypticRoute GUI is running as a standard user. Receiver may require root/capabilities.")

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()