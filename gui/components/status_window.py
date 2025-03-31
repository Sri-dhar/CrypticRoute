#!/usr/bin/env python3
"""
Acknowledgment panel and status window for CrypticRoute GUI
"""

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QGridLayout, QScrollArea, QFrame)
from PyQt6.QtCore import Qt, QSize

from ..utils.constants import COLORS
from .progress_bars import AckProgressBar

class AcknowledgmentPanel(QWidget):
    """Panel to visualize packet acknowledgments"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.acked_chunks = set()
        self.total_chunks = 0
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
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