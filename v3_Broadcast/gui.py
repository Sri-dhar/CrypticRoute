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
							QMessageBox, QStyle, QStatusBar, QGridLayout, QScrollArea,
							QDialog) # Added QDialog if needed, QWidget used for now
from PyQt6.QtCore import (QThread, pyqtSignal, Qt, QTimer, QSettings, QPropertyAnimation,
						  QEasingCurve, QSize)
from PyQt6.QtGui import QIcon, QTextCursor, QFont, QPixmap, QColor, QPalette
import subprocess
import psutil
import netifaces
import signal
import re
import random

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
		self.status_label.setText("SYN-ACK Sent")
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

class IPExchangePanel(QWidget):
    """Widget to visualize IP exchange between sender and receiver"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.reset()
        # Initially hidden until IP discovery starts
        self.setVisible(False)

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)

        # Title
        title_label = QLabel("IP Exchange Status")
        title_label.setStyleSheet(f"""
            font-weight: bold;
            color: {COLORS['handshake']};
            font-size: 10pt;
        """)
        layout.addWidget(title_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Status grid
        grid_layout = QGridLayout()
        grid_layout.setSpacing(5)

        # Local IP
        grid_layout.addWidget(QLabel("Local:"), 0, 0, alignment=Qt.AlignmentFlag.AlignRight)
        self.local_ip_label = QLabel("Unknown")
        self.local_ip_label.setStyleSheet(f"color: {COLORS['text']};")
        grid_layout.addWidget(self.local_ip_label, 0, 1)

        # Remote IP
        grid_layout.addWidget(QLabel("Remote:"), 1, 0, alignment=Qt.AlignmentFlag.AlignRight)
        self.remote_ip_label = QLabel("Waiting for discovery...")
        self.remote_ip_label.setStyleSheet(f"color: {COLORS['secondary']};")
        grid_layout.addWidget(self.remote_ip_label, 1, 1)

        # Connection Status
        grid_layout.addWidget(QLabel("Status:"), 2, 0, alignment=Qt.AlignmentFlag.AlignRight)
        self.connection_status = QLabel("Not connected")
        self.connection_status.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold;")
        grid_layout.addWidget(self.connection_status, 2, 1)

        layout.addLayout(grid_layout)

        # Add a separator line
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setStyleSheet(f"background-color: {COLORS['secondary']};")
        layout.addWidget(line)

    def reset(self):
        """Reset all indicators to their initial state."""
        self.local_ip_label.setText("Unknown")
        self.local_ip_label.setStyleSheet(f"color: {COLORS['text']};")
        self.remote_ip_label.setText("Waiting for discovery...")
        self.remote_ip_label.setStyleSheet(f"color: {COLORS['secondary']};")
        self.connection_status.setText("Not connected")
        self.connection_status.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold;")
        self.setVisible(False)

    def set_local_ip(self, ip_port):
        """Set the local IP and port."""
        self.setVisible(True)
        self.local_ip_label.setText(ip_port)
        self.local_ip_label.setStyleSheet(f"color: {COLORS['info']}; font-weight: bold;")

    def set_remote_discovered(self, ip_port):
        """Set the remote IP and port after discovery."""
        self.setVisible(True)
        self.remote_ip_label.setText(ip_port)
        self.remote_ip_label.setStyleSheet(f"color: {COLORS['info']}; font-weight: bold;")
        self.connection_status.setText("Discovered")
        self.connection_status.setStyleSheet(f"color: {COLORS['warning']}; font-weight: bold;")

    def set_connection_requested(self):
        """Update status when connection is requested."""
        self.connection_status.setText("Connection requested")
        self.connection_status.setStyleSheet(f"color: {COLORS['handshake']}; font-weight: bold;")

    def set_connection_established(self):
        """Update status when connection is established."""
        self.connection_status.setText("Connected")
        self.connection_status.setStyleSheet(f"color: {COLORS['success']}; font-weight: bold;")

class AcknowledgmentPanel(QWidget):
	"""Panel to visualize packet acknowledgments"""

	def __init__(self, parent=None):
		super().__init__(parent)
		self.acked_chunks = set()
		self.total_chunks = 0
		self.setup_ui()

	def setup_ui(self):
		layout = QVBoxLayout(self)
		# No margins needed if it's the main widget in its own window
		# layout.setContentsMargins(0, 0, 0, 0)
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
		# scroll_area.setMaximumHeight(100) # Let it take available space
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
			widget = self.grid_layout.itemAt(i).widget()
			if widget is not None:
				widget.setParent(None)

	def set_total_chunks(self, total):
		"""Set the total number of chunks and initialize the grid."""
		if total <= 0:
			self.reset() # Reset if total is invalid
			return

		# Only rebuild grid if total changes
		if total != self.total_chunks:
			self.total_chunks = total
			ack_count = len(self.acked_chunks)
			self.ack_count_label.setText(f"{ack_count}/{total} packets acknowledged")

			# Clear the grid first
			for i in reversed(range(self.grid_layout.count())):
				widget = self.grid_layout.itemAt(i).widget()
				if widget is not None:
					widget.setParent(None)

			# Calculate grid dimensions
			cols = min(20, total)  # Maximum 20 columns
			rows = (total + cols - 1) // cols  # Ceiling division

			# Create the grid of packet indicators
			for i in range(total):
				row = i // cols
				col = i % cols

				indicator = QLabel(f"{i+1}")
				indicator.setAlignment(Qt.AlignmentFlag.AlignCenter)
				indicator.setFixedSize(QSize(25, 18))  # Smaller size
				indicator.setStyleSheet(f"""
					background-color: {COLORS['light']};
					color: {COLORS['text']};
					border: 1px solid {COLORS['secondary']};
					border-radius: 2px;
					font-size: 7pt;
				""")
				# Highlight if already acknowledged (e.g., window opened mid-transfer)
				if (i + 1) in self.acked_chunks:
					indicator.setStyleSheet(f"""
						background-color: {COLORS['ack']};
						color: {COLORS['text_light']};
						border: 1px solid {COLORS['ack']};
						border-radius: 2px;
						font-size: 7pt;
						font-weight: bold;
					""")

				self.grid_layout.addWidget(indicator, row, col)
			print(f"Created grid for {total} chunks with {rows} rows and {cols} columns")
		else:
			# If total hasn't changed, just update the count label
			ack_count = len(self.acked_chunks)
			self.ack_count_label.setText(f"{ack_count}/{total} packets acknowledged")

		# Update progress bar based on current state
		ack_count = len(self.acked_chunks)
		if self.total_chunks > 0:
			progress = (ack_count / self.total_chunks) * 100
			self.ack_progress.setValue(int(progress))
		else:
			self.ack_progress.setValue(0)


	def acknowledge_chunk(self, chunk_num):
		"""Mark a specific chunk as acknowledged."""
		if chunk_num <= 0 or chunk_num > self.total_chunks:
			print(f"Warning: Chunk number {chunk_num} out of bounds (total: {self.total_chunks})")
			return

		# Add to the set of acknowledged chunks only if it's new
		if chunk_num not in self.acked_chunks:
			self.acked_chunks.add(chunk_num)
		else:
			# Already acknowledged, no UI update needed for this chunk
			return

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

		# Get the widget at the position
		item = self.grid_layout.itemAtPosition(row, col)
		if item and item.widget():
			indicator = item.widget()
			# Apply highlighting style to indicate acknowledgment
			indicator.setStyleSheet(f"""
				background-color: {COLORS['ack']};
				color: {COLORS['text_light']};
				border: 1px solid {COLORS['ack']};
				border-radius: 2px;
				font-size: 7pt;
				font-weight: bold;
			""")
			print(f"Highlighted indicator for chunk {chunk_num} at position ({row}, {col})")
		else:
			# This might happen if the grid wasn't fully built yet, should be rare
			print(f"Warning: No indicator found for chunk {chunk_num} at position ({row}, {col}) during acknowledge")

# --- New AckStatusWindow Class ---
class AckStatusWindow(QWidget):
	"""A separate window to display the AcknowledgmentPanel."""
	def __init__(self, parent=None):
		super().__init__(parent)
		self.setWindowFlags(Qt.WindowType.Window)
		self.setWindowTitle("Acknowledgement Status")
		
		self.setMinimumSize(400, 250) # Set a reasonable minimum size
		self.setStyleSheet(f"background-color: {COLORS['background']};") # Match main window bg

		layout = QVBoxLayout(self)
		layout.setContentsMargins(10, 10, 10, 10) # Add some padding

		self.ack_panel = AcknowledgmentPanel()
		layout.addWidget(self.ack_panel)

		self.setLayout(layout)

	def set_total_chunks(self, total):
		"""Pass the total chunk count to the internal panel."""
		self.ack_panel.set_total_chunks(total)

	def acknowledge_chunk(self, chunk_num):
		"""Pass the acknowledged chunk number to the internal panel."""
		self.ack_panel.acknowledge_chunk(chunk_num)

	def reset(self):
		"""Reset the internal panel."""
		self.ack_panel.reset()

	def closeEvent(self, event):
		"""Handle the window close event."""
		print("AckStatusWindow closed.")
		# You might want to notify the SenderPanel or just let it be closed.
		# If SenderPanel holds the only reference, it should be garbage collected.
		super().closeEvent(event)

	def update_state(self, total_chunks, acknowledged_set):
		"""Update the entire state at once (useful when reopening)."""
		self.ack_panel.acked_chunks = acknowledged_set.copy() # Use a copy
		self.ack_panel.set_total_chunks(total_chunks) # This will rebuild grid if needed and update counts/progress


# --- End of New AckStatusWindow Class ---


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
		self.update_style() # Initial style set

	def setEnabled(self, enabled):
		super().setEnabled(enabled)
		self.update_style() # Update style when enabled state changes

	def update_style(self):
		"""Update button stylesheet based on color and enabled state."""
		color = self.base_color
		if not self.isEnabled():
			self.setStyleSheet(f"""
				QPushButton {{
					background-color: #cccccc;
					color: #666666;
					font-weight: bold;
					border: none;
					padding: 8px 16px;
					border-radius: 4px;
				}}
			""")
		else:
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
										universal_newlines=True, bufsize=1, # bufsize=1 for line buffering
										env=dict(os.environ, PYTHONUNBUFFERED="1"))
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
		self.ack_status_window = None # Reference to the separate ACK window
		self.total_chunks_for_ack = 0 # Store total chunks locally
		self.acknowledged_chunks_set = set() # Store received ACKs locally
		self.setup_ui()
		self.log_timer = QTimer(self)
		self.log_timer.timeout.connect(self.update_log)
		self.log_timer.start(50) # Check log queue every 50ms
		self.load_settings()
		
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
		except:
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
		self.chunk_size_spin.setRange(1, 8) # Keep range limited as per original design?
		self.chunk_size_spin.setValue(DEFAULT_CHUNK_SIZE)
		self.chunk_size_spin.setSuffix(" bytes")
		form_layout.addRow("Chunk Size:", self.chunk_size_spin)

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
		# --- Add Ack Status Button ---
		self.ack_status_button = AnimatedButton("Ack Status", color=COLORS['info'])
		self.ack_status_button.clicked.connect(self.show_ack_status_window)
		self.ack_status_button.setEnabled(False) # Initially disabled

		control_layout.addWidget(self.send_button)
		control_layout.addWidget(self.stop_button)
		control_layout.addWidget(self.clear_button)
		control_layout.addWidget(self.ack_status_button) # Add the new button
		control_layout.addStretch()
		main_layout.addLayout(control_layout)

		# Simplified Connection Status
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
		main_layout.addWidget(log_group, 1) # Give log area stretch factor

		# Set the container as the scroll area's widget
		scroll_area.setWidget(container_widget)

		# Main layout for this panel
		panel_layout = QVBoxLayout(self)
		panel_layout.setContentsMargins(0, 0, 0, 0)
		panel_layout.addWidget(scroll_area)
		self.setLayout(panel_layout)

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
		}

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
			if "stopping" in current_status:
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
		settings.setValue("target_ip", self.target_ip_edit.text())
		settings.setValue("input_file", self.input_file_edit.text())
		settings.setValue("key_file", self.key_file_edit.text())
		settings.setValue("output_dir", self.output_dir_edit.text())
		settings.setValue("delay", self.delay_spin.value())
		settings.setValue("chunk_size", self.chunk_size_spin.value())

	def load_settings(self):
		settings = QSettings("CrypticRoute", "SenderPanel")
		self.target_ip_edit.setText(settings.value("target_ip", ""))
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
		self.log_queue = queue.Queue()
		self.data_queue = queue.Queue()
		self.setup_ui()
		self.log_timer = QTimer(self)
		self.log_timer.timeout.connect(self.update_log)
		self.log_timer.start(25) # Faster log updates for receiver
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
		except:
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
		current_selection = self.interface_combo.currentText()
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

		# Try to restore previous selection
		index = self.interface_combo.findText(current_selection, Qt.MatchFlag.MatchContains) # More flexible matching
		if index >= 0:
			self.interface_combo.setCurrentIndex(index)
		else:
			self.interface_combo.setCurrentIndex(0) # Default to 'default'


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
		try:
			messages = []
			for _ in range(30): # Process more messages per tick if available
				if not self.log_queue.empty():
					messages.append(self.log_queue.get_nowait())
				else:
					break
			if messages:
				for message in messages:
					self.add_log_message(message)
				# Scroll only once after adding the batch
				self.log_edit.ensureCursorVisible()
		except queue.Empty:
			pass
		except Exception as e:
			print(f"Error updating log: {e}")

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
		self.worker_thread.update_signal.connect(self.log_queue.put) # Put raw messages in queue
		self.worker_thread.update_signal.connect(self.process_ip_exchange) # Process IP exchange messages
		self.worker_thread.progress_signal.connect(self.update_progress)
		self.worker_thread.status_signal.connect(self.update_status)
		self.worker_thread.finished_signal.connect(self.reception_finished)

		# Connect signals for handshake visualization
		self.worker_thread.handshake_signal.connect(self.update_handshake)
		# No ACK signal needed for receiver display

		self.worker_thread.start()

	def stop_reception(self):
		if self.worker_thread and self.worker_thread.isRunning():
			self.status_label.setText("Stopping reception...")
			self.worker_thread.stop()
			# Buttons re-enabled in reception_finished

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
			# Attempt to display the received file content
			output_file = self.output_file_edit.text().strip()
			if output_file:
				# Give file system a moment before reading
				QTimer.singleShot(200, lambda: self.display_received_file(output_file))
			else:
				self.add_log_message("Info: No output file specified, cannot display content.")
		else:
			current_status = self.status_label.text().lower()
			if "stopping" in current_status:
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
			# self.data_display.insertPlainText(f"--- Content from {os.path.basename(file_path)} ---\n\n")

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

class MainWindow(QMainWindow):
	def __init__(self):
		super().__init__()
		self.setWindowTitle("CrypticRoute - Network Steganography Tool")
		# Increased minimum size slightly
		self.setMinimumSize(950, 700)
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
				font-weight: bold; /* Make inactive tabs bold too */
			}}
			QTabBar::tab:selected {{
				background-color: {COLORS['primary']};
				color: white;
				font-weight: bold;
			}}
			QTabBar::tab:hover:!selected {{
				background-color: #e0e7ff; /* Lighter hover */
			}}
			QStatusBar {{
				background-color: {COLORS['light']};
				color: {COLORS['text']};
				padding: 5px;
				font-size: 10pt;
				font-weight: bold; /* Make status bar text bold */
			}}
		""")
		self.central_widget = QTabWidget()
		self.setCentralWidget(self.central_widget)

		# Pass self (MainWindow) as parent to panels
		self.sender_panel = SenderPanel(self)
		self.central_widget.addTab(self.sender_panel, "Send File")
		self.receiver_panel = ReceiverPanel(self)
		self.central_widget.addTab(self.receiver_panel, "Receive File")

		self.status_bar = QStatusBar()
		self.setStatusBar(self.status_bar)
		self.status_bar.showMessage("Ready")

		self.central_widget.currentChanged.connect(self.update_status_on_tab_change)

		self.setup_menus() # Renamed method
		self.load_window_settings() # Renamed method

	def setup_menus(self):
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
			QMenuBar::item:selected {{ /* Hover */
				background-color: {COLORS['primary']};
			}}
			QMenuBar::item:pressed {{ /* Click */
				background-color: {COLORS['info']};
			}}
			QMenu {{
				background-color: {COLORS['light']};
				color: {COLORS['text']};
				border: 1px solid {COLORS['secondary']};
				border-radius: 4px;
				padding: 5px; /* Padding for the menu itself */
			}}
			QMenu::item {{
				padding: 8px 20px; /* More horizontal padding */
			}}
			QMenu::item:selected {{
				background-color: {COLORS['primary']};
				color: white;
				border-radius: 2px;
			}}
			QMenu::separator {{
				height: 1px;
				background-color: {COLORS['secondary']};
				margin: 5px 0px; /* Reduced horizontal margin */
			}}
		""")
		file_menu = menubar.addMenu("&File") # Use mnemonics
		exit_action = file_menu.addAction("&Exit")
		exit_action.setShortcut("Ctrl+Q")
		exit_action.triggered.connect(self.close)

		help_menu = menubar.addMenu("&Help")
		about_action = help_menu.addAction("&About")
		about_action.triggered.connect(self.show_about)

	def update_status_on_tab_change(self, index):
		# Use the status labels within the panels if they are more informative
		if index == 0: # Sender tab
			status = self.sender_panel.status_label.text()
			if "Ready" in status or not self.sender_panel.worker_thread:
				self.status_bar.showMessage("Sender: Ready")
			# else keep the specific status from update_progress/update_status
		else: # Receiver tab
			status = self.receiver_panel.status_label.text()
			if "Ready" in status or not self.receiver_panel.worker_thread:
				self.status_bar.showMessage("Receiver: Ready")
			# else keep specific status


	def show_about(self):
		QMessageBox.about(self, "About CrypticRoute",
						  f"<h1 style='color: {COLORS['primary']};'>CrypticRoute</h1>"
						  "<p style='font-size: 12pt;'>Network Steganography Tool</p>"
						  "<p style='font-size: 11pt;'>Version 2.1 (GUI)</p>"
						  "<p style='font-size: 10pt;'>A graphical interface for sending and receiving hidden data through network packets.</p>"
						  "<p style='font-size: 10pt;'>Enhanced with connection handshake and packet acknowledgment visualization.</p>"
						  "<hr><p style='font-size: 9pt;'>Uses PyQt6 for the interface.</p>")

	def closeEvent(self, event):
		print("Close event triggered")
		# Attempt to stop worker threads gracefully
		stopped_sender = False
		if self.sender_panel.worker_thread and self.sender_panel.worker_thread.isRunning():
			print("Stopping sender thread...")
			self.sender_panel.stop_transmission()
			stopped_sender = True

		stopped_receiver = False
		if self.receiver_panel.worker_thread and self.receiver_panel.worker_thread.isRunning():
			print("Stopping receiver thread...")
			self.receiver_panel.stop_reception()
			stopped_receiver = True

		# Save settings before closing
		self.save_window_settings() # Renamed method
		self.sender_panel.save_settings()
		self.receiver_panel.save_settings()

		# If threads were running, give them a tiny moment to process stop signal
		# This might not be strictly necessary with how stop() is implemented now, but doesn't hurt
		if stopped_sender or stopped_receiver:
			QTimer.singleShot(100, event.accept) # Accept after a short delay
			print("Delaying close event acceptance.")
		else:
			event.accept() # Accept immediately if no threads were running
			print("Accepted close event immediately.")


	def save_window_settings(self):
		settings = QSettings("CrypticRoute", "MainWindow")
		settings.setValue("geometry", self.saveGeometry())
		settings.setValue("state", self.saveState())
		settings.setValue("current_tab", self.central_widget.currentIndex())

	def load_window_settings(self):
		settings = QSettings("CrypticRoute", "MainWindow")
		geometry = settings.value("geometry")
		if isinstance(geometry, QByteArray): # Check type
			self.restoreGeometry(geometry)
		state = settings.value("state")
		if isinstance(state, QByteArray): # Check type
			self.restoreState(state)
		tab = settings.value("current_tab", 0)
		try:
			self.central_widget.setCurrentIndex(int(tab))
		except (ValueError, TypeError):
			self.central_widget.setCurrentIndex(0)

def check_environment():
	# Simple check for Wayland/X11 display server for potential debugging info
	display_server = os.environ.get("XDG_SESSION_TYPE", "Unknown")
	print(f"Detected session type: {display_server}")

	# Check for XDG_RUNTIME_DIR existence and writability (common issue in some environments)
	runtime_dir = os.environ.get("XDG_RUNTIME_DIR")
	if not runtime_dir or not os.path.isdir(runtime_dir) or not os.access(runtime_dir, os.W_OK):
		print("Warning: XDG_RUNTIME_DIR environment variable not set or invalid.")
		# Attempt to create a fallback if possible (might fail due to permissions)
		fallback_dir = f"/tmp/runtime-{os.getuid()}"
		try:
			if not os.path.exists(fallback_dir):
				os.makedirs(fallback_dir, mode=0o700, exist_ok=True)
			if os.path.isdir(fallback_dir) and os.access(fallback_dir, os.W_OK):
				os.environ["XDG_RUNTIME_DIR"] = fallback_dir
				print(f"Set fallback XDG_RUNTIME_DIR to {fallback_dir}")
			else:
				print("Could not create or access fallback runtime directory.")
		except Exception as e:
			print(f"Error setting fallback runtime directory: {e}")


def main():
	# Handle SIGINT gracefully (Ctrl+C in terminal)
	signal.signal(signal.SIGINT, signal.SIG_DFL)

	# Basic environment checks
	check_environment()

	# Check for root privileges
	is_root = False
	try:
		is_root = (os.geteuid() == 0)
	except AttributeError: # os.geteuid() not available on Windows
		pass

	if is_root:
		print("--------------------------------------------------------------------")
		print("WARNING: Running CrypticRoute GUI as root.")
		print(" This is necessary for raw socket access but is generally discouraged.")
		print(" Consider using network capabilities instead for better security:")
		print("   sudo setcap cap_net_raw,cap_net_admin=eip $(realpath $(which python3))")
		print(" (Note: Path to python3 might vary)")
		print("--------------------------------------------------------------------")


	app = QApplication(sys.argv)
	app.setApplicationName("CrypticRoute")
	app.setApplicationVersion("2.1")

	# Apply a modern style if available
	available_styles = QStyleFactory.keys()
	if "Fusion" in available_styles:
		app.setStyle("Fusion")
	elif "WindowsVista" in available_styles: # Good fallback on Windows
		app.setStyle("WindowsVista")
	# Default otherwise

	# Set app icon (optional, requires an icon file)
	# icon_path = "crypticroute_icon.png" # Replace with actual path
	# if os.path.exists(icon_path):
	#	 app.setWindowIcon(QIcon(icon_path))

	window = MainWindow()
	window.show()

	sys.exit(app.exec())

if __name__ == "__main__":
	# Import QStyleFactory and QByteArray here if not already imported globally
	from PyQt6.QtWidgets import QStyleFactory
	from PyQt6.QtCore import QByteArray
	main()