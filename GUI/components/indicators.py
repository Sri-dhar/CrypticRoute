#!/usr/bin/env python3
"""
Status Indicators for CrypticRoute GUI
"""

from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
from PyQt6.QtCore import Qt

from ..utils.constants import COLORS

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
        grid_layout = QHBoxLayout()
        grid_layout.setSpacing(5)

        # Local IP
        grid_layout.addWidget(QLabel("Local:"), alignment=Qt.AlignmentFlag.AlignRight)
        self.local_ip_label = QLabel("Unknown")
        self.local_ip_label.setStyleSheet(f"color: {COLORS['text']};")
        grid_layout.addWidget(self.local_ip_label)

        # Remote IP
        grid_layout.addWidget(QLabel("Remote:"), alignment=Qt.AlignmentFlag.AlignRight)
        self.remote_ip_label = QLabel("Waiting for discovery...")
        self.remote_ip_label.setStyleSheet(f"color: {COLORS['secondary']};")
        grid_layout.addWidget(self.remote_ip_label)

        # Connection Status
        grid_layout.addWidget(QLabel("Status:"), alignment=Qt.AlignmentFlag.AlignRight)
        self.connection_status = QLabel("Not connected")
        self.connection_status.setStyleSheet(f"color: {COLORS['danger']}; font-weight: bold;")
        grid_layout.addWidget(self.connection_status)

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


class AnimatedStatusLabel(QLabel):
    """A status label with color changes based on content"""

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
