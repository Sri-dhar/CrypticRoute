#!/usr/bin/env python3
"""
CrypticRoute GUI - Session History Panel
Displays information about past sender and receiver sessions.
"""

import os
import json
import sys
import subprocess
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, 
                             QHeaderView, QPushButton, QLabel, QSizePolicy)
from PyQt6.QtCore import Qt, QTimer

from ..utils.constants import COLORS

# Define the path relative to this file's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..'))
STEALTH_OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'stealth_output')

class SessionHistoryPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SessionHistoryPanel") # For styling/identification

        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15) # Add padding
        layout.setSpacing(10) # Space between widgets

        # Title Label
        title_label = QLabel("Previous Sessions")
        title_label.setStyleSheet(f"""
            QLabel {{
                font-size: 16pt;
                font-weight: bold;
                color: {COLORS['primary']};
                padding-bottom: 10px;
                border-bottom: 2px solid {COLORS['light']};
            }}
        """)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_label)

        # Refresh Button
        self.refresh_button = QPushButton("Refresh History")
        self.refresh_button.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS['info']};
                color: white;
                padding: 8px 15px;
                border-radius: 5px;
                font-weight: bold;
                min-width: 120px; /* Ensure button isn't too small */
            }}
            QPushButton:hover {{
                background-color: #4cae4c; /* Darker green */
            }}
            QPushButton:pressed {{
                background-color: #398439; /* Even darker green */
            }}
        """)
        self.refresh_button.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.refresh_button.clicked.connect(self.populate_history)
        
        # Align button to the right
        button_layout = QVBoxLayout() # Use a layout to control alignment
        button_layout.addWidget(self.refresh_button, alignment=Qt.AlignmentFlag.AlignRight)
        layout.addLayout(button_layout)


        # History Table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6) # Increased columns
        self.history_table.setHorizontalHeaderLabels([
            "Type", "Timestamp", "Status", "File/Output", "Target/Source IP", "Details"
        ])
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers) # Read-only
        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setAlternatingRowColors(True) # Easier to read
        self.history_table.verticalHeader().setVisible(False) # Hide row numbers
        self.history_table.itemDoubleClicked.connect(self.open_session_folder) # Connect double-click signal

        # Style the table
        self.history_table.setStyleSheet(f"""
            QTableWidget {{
                gridline-color: {COLORS['light']};
                background-color: {COLORS['background']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['secondary']};
                border-radius: 5px;
            }}
            QHeaderView::section {{
                background-color: {COLORS['dark']};
                color: {COLORS['light']};
                padding: 6px;
                border: 1px solid {COLORS['secondary']};
                font-weight: bold;
            }}
            QTableWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {COLORS['light']}; /* Separator lines */
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS['primary']};
                color: white;
            }}
            QTableWidget::item:alternate {{ /* Alternating row color */
                 background-color: #f0f0f5; /* Very light grey/blue */
            }}
             QTableWidget::item:alternate:selected {{
                background-color: {COLORS['primary']};
                color: white;
            }}
        """)

        # Set column resize modes
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents) # Type
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # Timestamp
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents) # Status
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)          # File/Output
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents) # IP
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)          # Details

        layout.addWidget(self.history_table)

        # Initial population and setup auto-refresh timer
        self.populate_history()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.populate_history)
        self.timer.start(60000) # Refresh every 60 seconds

    def populate_history(self):
        self.history_table.setRowCount(0) # Clear existing rows
        sessions = []

        if not os.path.exists(STEALTH_OUTPUT_DIR):
            print(f"Warning: Stealth output directory not found: {STEALTH_OUTPUT_DIR}")
            # Optionally display a message in the table or a label
            self.history_table.setRowCount(1)
            no_dir_item = QTableWidgetItem(f"Output directory '{STEALTH_OUTPUT_DIR}' not found.")
            no_dir_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setSpan(0, 0, 1, self.history_table.columnCount()) # Span across columns
            self.history_table.setItem(0, 0, no_dir_item)
            return

        try:
            for item in os.listdir(STEALTH_OUTPUT_DIR):
                session_dir = os.path.join(STEALTH_OUTPUT_DIR, item)
                if os.path.isdir(session_dir) and (item.startswith("sender_session_") or item.startswith("receiver_session_")):
                    log_file = os.path.join(session_dir, "logs", "completion_info.json")
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, 'r') as f:
                                info = json.load(f)
                                info['type'] = "Sender" if item.startswith("sender_") else "Receiver"
                                info['dir_name'] = item # Store directory name for reference
                                # Attempt to get timestamp from directory name first as fallback
                                try:
                                    ts_str = item.split('_')[-2] + "_" + item.split('_')[-1]
                                    dt_obj = datetime.strptime(ts_str, '%Y%m%d_%H%M%S')
                                    info['parsed_timestamp'] = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                                except (IndexError, ValueError):
                                     info['parsed_timestamp'] = "Unknown Time"

                                # Override with more precise end time if available
                                if 'session_end_time' in info and isinstance(info['session_end_time'], (int, float)):
                                     info['parsed_timestamp'] = datetime.fromtimestamp(info['session_end_time']).strftime('%Y-%m-%d %H:%M:%S')

                                sessions.append(info)
                        except json.JSONDecodeError:
                            print(f"Warning: Could not decode JSON in {log_file}")
                        except Exception as e:
                            print(f"Warning: Error reading session info from {log_file}: {e}")
        except OSError as e:
             print(f"Error listing directory {STEALTH_OUTPUT_DIR}: {e}")
             # Handle error display in GUI if needed
             return # Stop processing if directory listing fails

        # Sort sessions by timestamp (descending - newest first)
        sessions.sort(key=lambda x: x.get('session_end_time', 0), reverse=True)

        self.history_table.setRowCount(len(sessions))
        for row, session in enumerate(sessions):
            session_type = session.get('type', 'Unknown')
            timestamp = session.get('parsed_timestamp', 'N/A')
            status_raw = session.get('final_status', 'unknown')
            status = status_raw.replace('_', ' ').title()
            
            # Determine file/output and IP based on type
            file_output = "N/A"
            ip_addr = "N/A"
            details = ""

            if session_type == "Sender":
                ip_addr = session.get('discovered_receiver_ip', 'N/A')
                if ip_addr and 'final_receiver_port' in session:
                    ip_addr += f":{session.get('final_receiver_port')}"
                
                # Try to find original filename (might need to look in other logs/data)
                # Placeholder: Check if original_data.bin exists
                original_data_path = os.path.join(STEALTH_OUTPUT_DIR, session['dir_name'], "data", "original_data.bin")
                if os.path.exists(original_data_path):
                     # This doesn't give the *name*, just that data was sent.
                     # A better approach would be to log the filename during sending.
                     file_output = "Data Sent (check logs)" # Placeholder
                else:
                     file_output = "No Data Found"

                chunks_gen = session.get('total_chunks_generated', 'N/A')
                chunks_ack = session.get('chunks_acknowledged', 'N/A')
                ack_rate = session.get('ack_rate_percent', 'N/A')
                details = f"Chunks: {chunks_gen} / ACKs: {chunks_ack} ({ack_rate}%)"

            elif session_type == "Receiver":
                 # Get Source IP/Port from completion_info
                 ip_addr = session.get('sender_ip_discovered') or session.get('sender_ip_connected', 'Source N/A')
                 port = session.get('sender_port_connected')
                 if ip_addr != 'Source N/A' and port:
                     ip_addr += f":{port}"

                 # Check for output file
                 output_file_path = os.path.join(STEALTH_OUTPUT_DIR, session['dir_name'], "data", "output_content.txt") # Or .bin etc.
                 if os.path.exists(output_file_path):
                     file_output = os.path.basename(output_file_path) + " (in session dir)"
                 else:
                     # Check for the generic received file name if logged
                     output_filename = session.get('output_filename', None)
                     if output_filename:
                         file_output = output_filename
                     else:
                         file_output = "No Output File Found"

                 # --- Gather Receiver Details ---
                 chunks_rec = session.get('chunks_received', '?')
                 chunks_exp = session.get('total_chunks_expected', '?')
                 missing_count = session.get('missing_chunk_count', None) # Use None to check if key exists

                 # Determine Reassembly Status
                 if missing_count == 0:
                     reassembled_status = "Complete"
                 elif missing_count is not None and missing_count > 0:
                     reassembled_status = f"Incomplete ({missing_count} missing)"
                 else:
                     # Fallback if missing_count key isn't present (older logs?)
                     if chunks_rec == chunks_exp and chunks_rec != '?':
                          reassembled_status = "Complete"
                     else:
                          reassembled_status = "Unknown"
                 
                 # Check checksum_verification.json for definitive checksum status
                 checksum_verification_file = os.path.join(STEALTH_OUTPUT_DIR, session['dir_name'], "logs", "checksum_verification.json")
                 checksum_ok_raw = None # Default to unknown
                 if os.path.exists(checksum_verification_file):
                     try:
                         with open(checksum_verification_file, 'r') as cs_f:
                             cs_info = json.load(cs_f)
                             checksum_ok_raw = cs_info.get('match') # Should be True or False
                     except (json.JSONDecodeError, OSError, KeyError) as cs_e:
                         print(f"Warning: Could not read/parse {checksum_verification_file}: {cs_e}")
                 
                 checksum_ok_str = "OK" if checksum_ok_raw is True else ("Failed" if checksum_ok_raw is False else "N/A")

                 # Construct Details String
                 details = f"Rcvd: {chunks_rec}/{chunks_exp} | Reassembly: {reassembled_status} | Checksum: {checksum_ok_str}"

                 # Refine Overall Status String
                 base_status = session.get('status', 'unknown').replace('_', ' ').title() # Use receiver's status field
                 
                 if "Completed" in base_status:
                     if checksum_ok_raw is True:
                         status = "Completed - Checksum OK"
                     elif checksum_ok_raw is False:
                         status = "Completed - Checksum Failed"
                     else: # Checksum N/A or file missing
                         status = "Completed - Checksum N/A"
                 elif reassembled_status != "Complete" and reassembled_status != "Unknown":
                      status = f"Incomplete ({missing_count} missing)"
                 else:
                      status = base_status # Use status from completion_info if not completed/incomplete


            # Create table items
            session_dir_path = os.path.join(STEALTH_OUTPUT_DIR, session['dir_name'])
            type_item = QTableWidgetItem(session_type)
            # Store the full path in the first item's UserRole for double-click
            type_item.setData(Qt.ItemDataRole.UserRole, session_dir_path) 
            
            timestamp_item = QTableWidgetItem(timestamp)
            status_item = QTableWidgetItem(status)
            file_output_item = QTableWidgetItem(file_output)
            ip_addr_item = QTableWidgetItem(ip_addr)
            details_item = QTableWidgetItem(details)

            # Set status color based on refined status
            if "ok" in status.lower() or "success" in status.lower():
                 status_item.setForeground(Qt.GlobalColor.darkGreen)
            elif "fail" in status.lower() or "error" in status.lower():
                 status_item.setForeground(Qt.GlobalColor.darkRed)
            elif "cancel" in status.lower():
                 status_item.setForeground(Qt.GlobalColor.darkYellow)
            else: # Default color for other statuses like Incomplete, Unknown
                 status_item.setForeground(Qt.GlobalColor.black)


            # Populate the row
            self.history_table.setItem(row, 0, type_item)
            self.history_table.setItem(row, 1, timestamp_item)
            self.history_table.setItem(row, 2, status_item)
            self.history_table.setItem(row, 3, file_output_item)
            self.history_table.setItem(row, 4, ip_addr_item)
            self.history_table.setItem(row, 5, details_item)

        # Resize columns after populating if needed (though Stretch should handle most)
        # self.history_table.resizeColumnsToContents()

    def open_session_folder(self, item):
        """Opens the session folder associated with the double-clicked row."""
        if not item:
            return
        
        # Retrieve the path stored in the first column (index 0) of the clicked row
        first_item = self.history_table.item(item.row(), 0)
        if not first_item:
             return
             
        session_path = first_item.data(Qt.ItemDataRole.UserRole)

        if session_path and os.path.isdir(session_path):
            print(f"Opening session folder: {session_path}")
            try:
                if sys.platform == "win32":
                    # Use os.startfile for better integration on Windows
                    os.startfile(session_path) 
                elif sys.platform == "darwin": # macOS
                    subprocess.run(["open", session_path], check=True)
                else: # Linux and other Unix-like
                    subprocess.run(["xdg-open", session_path], check=True)
            except FileNotFoundError:
                 print(f"Error: Could not find command to open folder (xdg-open/open/startfile).")
            except subprocess.CalledProcessError as e:
                 print(f"Error opening folder '{session_path}': {e}")
            except Exception as e:
                 print(f"An unexpected error occurred while opening folder: {e}")
        else:
            print(f"Error: Session path not found or invalid: {session_path}")
