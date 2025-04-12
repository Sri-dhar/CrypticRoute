#!/usr/bin/env python3
"""
CrypticRoute GUI - Session History Panel
Displays information about past sender and receiver sessions.
"""

import os
import json
import sys
import subprocess
import re # Import regex for filename parsing
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

    def _parse_reassembly_filename_timestamp(self, filename):
        """Extracts datetime object from reassembly_info_YYYYMMDD_HHMMSS_ffffff.json"""
        match = re.search(r'reassembly_info_(\d{8}_\d{6}_\d{6})\.json', filename)
        if match:
            try:
                ts_str = match.group(1)
                # Adjust format string to include microseconds
                return datetime.strptime(ts_str, '%Y%m%d_%H%M%S_%f')
            except (ValueError, IndexError):
                pass
        return None # Return None if parsing fails

    def populate_history(self):
        self.history_table.setRowCount(0) # Clear existing rows
        session_rows_data = [] # Store data for each row to be added

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
            for item_name in os.listdir(STEALTH_OUTPUT_DIR):
                session_dir = os.path.join(STEALTH_OUTPUT_DIR, item_name)
                if not os.path.isdir(session_dir):
                    continue

                session_type = "Unknown"
                if item_name.startswith("sender_session_"):
                    session_type = "Sender"
                elif item_name.startswith("receiver_session_"):
                    session_type = "Receiver"
                else:
                    continue # Skip non-session directories

                logs_dir = os.path.join(session_dir, "logs")
                if not os.path.exists(logs_dir):
                    continue # Skip if no logs directory

                # --- Common Session Info (Try completion_info first) ---
                completion_info = {}
                completion_info_path = os.path.join(logs_dir, "completion_info.json")
                if os.path.exists(completion_info_path):
                    try:
                        with open(completion_info_path, 'r') as f:
                            completion_info = json.load(f)
                    except (json.JSONDecodeError, OSError) as e:
                        print(f"Warning: Could not read/parse {completion_info_path}: {e}")

                # --- Sender Session Processing (Existing Logic) ---
                if session_type == "Sender":
                    if not completion_info: # Skip sender session if no completion info
                         print(f"Skipping sender session {item_name} due to missing completion_info.json")
                         continue

                    # Extract sender details from completion_info
                    timestamp = "Unknown Time"
                    try:
                        # Prefer session_end_time if available
                        if 'session_end_time' in completion_info and isinstance(completion_info['session_end_time'], (int, float)):
                            timestamp = datetime.fromtimestamp(completion_info['session_end_time']).strftime('%Y-%m-%d %H:%M:%S')
                        else: # Fallback to directory name
                            ts_str = item_name.split('_')[-2] + "_" + item_name.split('_')[-1]
                            dt_obj = datetime.strptime(ts_str, '%Y%m%d_%H%M%S')
                            timestamp = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                    except (IndexError, ValueError, KeyError):
                        pass # Keep "Unknown Time"

                    status_raw = completion_info.get('final_status', 'unknown')
                    status = status_raw.replace('_', ' ').title()
                    ip_addr = completion_info.get('discovered_receiver_ip', 'N/A')
                    if ip_addr and 'final_receiver_port' in completion_info:
                        ip_addr += f":{completion_info.get('final_receiver_port')}"

                    # Placeholder for file output - needs better logging in sender
                    original_data_path = os.path.join(session_dir, "data", "original_data.bin")
                    file_output = "Data Sent (check logs)" if os.path.exists(original_data_path) else "No Data Found"

                    chunks_gen = completion_info.get('total_chunks_generated', 'N/A')
                    chunks_ack = completion_info.get('chunks_acknowledged', 'N/A')
                    ack_rate = completion_info.get('ack_rate_percent', 'N/A')
                    details = f"Chunks: {chunks_gen} / ACKs: {chunks_ack} ({ack_rate}%)"

                    session_rows_data.append({
                        'type': session_type,
                        'timestamp': timestamp,
                        'status': status,
                        'file_output': file_output,
                        'ip_addr': ip_addr,
                        'details': details,
                        'dir_path': session_dir,
                        'sort_key': completion_info.get('session_end_time', 0) # Use end time for sorting
                    })

                # --- Receiver Session Processing (New Logic) ---
                elif session_type == "Receiver":
                    reassembly_files = []
                    checksum_info = {}
                    checksum_ok_raw = None
                    checksum_ok_str = "N/A"

                    # Find all reassembly logs and the checksum log
                    try:
                        for log_filename in os.listdir(logs_dir):
                            if log_filename.startswith("reassembly_info_") and log_filename.endswith(".json"):
                                file_path = os.path.join(logs_dir, log_filename)
                                timestamp_obj = self._parse_reassembly_filename_timestamp(log_filename)
                                if timestamp_obj:
                                    reassembly_files.append({'path': file_path, 'timestamp': timestamp_obj, 'filename': log_filename})
                            elif log_filename == "checksum_verification.json":
                                checksum_file_path = os.path.join(logs_dir, log_filename)
                                if os.path.exists(checksum_file_path):
                                    try:
                                        with open(checksum_file_path, 'r') as cs_f:
                                            checksum_info = json.load(cs_f)
                                            checksum_ok_raw = checksum_info.get('match') # True, False, or None
                                            checksum_ok_str = "OK" if checksum_ok_raw is True else ("Failed" if checksum_ok_raw is False else "N/A")
                                    except (json.JSONDecodeError, OSError, KeyError) as cs_e:
                                        print(f"Warning: Could not read/parse {checksum_file_path}: {cs_e}")
                    except OSError as e:
                        print(f"Error listing logs directory {logs_dir}: {e}")
                        continue # Skip this session if logs can't be listed

                    # Get base info from completion_info if available
                    base_sender_ip = completion_info.get('sender_ip_discovered') or completion_info.get('sender_ip_connected', 'Source N/A')
                    base_sender_port = completion_info.get('sender_port_connected')
                    ip_addr = base_sender_ip
                    if ip_addr != 'Source N/A' and base_sender_port:
                        ip_addr += f":{base_sender_port}"
                    
                    # Determine overall session timestamp (use latest reassembly if completion_info missing)
                    session_sort_key = completion_info.get('session_end_time', 0)


                    if reassembly_files:
                        # Sort files by timestamp
                        reassembly_files.sort(key=lambda x: x['timestamp'])
                        
                        if session_sort_key == 0 and reassembly_files: # Use latest reassembly time if no end_time
                             session_sort_key = reassembly_files[-1]['timestamp'].timestamp()


                        # Process each reassembled file
                        for i, file_info in enumerate(reassembly_files):
                            reassembly_data = {}
                            try:
                                with open(file_info['path'], 'r') as rf:
                                    reassembly_data = json.load(rf)
                            except (json.JSONDecodeError, OSError) as e:
                                print(f"Warning: Could not read/parse {file_info['path']}: {e}")
                                continue # Skip this file if unreadable

                            file_timestamp_str = file_info['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                            file_time_only_str = file_info['timestamp'].strftime('%H:%M:%S')

                            chunks_rec = reassembly_data.get('received_chunk_count', '?')
                            # Expected chunks might be in completion_info or need calculation
                            chunks_exp = completion_info.get('total_chunks_expected', '?') # Or derive if possible
                            missing_count = reassembly_data.get('missing_chunk_count', None)

                            # Determine Reassembly Status for this file
                            file_status = "Unknown"
                            if missing_count == 0:
                                file_status = "Complete"
                            elif missing_count is not None and missing_count > 0:
                                file_status = f"Incomplete ({missing_count} missing)"
                            
                            # Placeholder for filename - needs better logging
                            file_output = f"Received File @ {file_time_only_str}"

                            # Construct Details String
                            details = f"Rcvd Chunks: {chunks_rec}"
                            if missing_count is not None:
                                 details += f" (Missing: {missing_count})"

                            # Add checksum info only to the *last* file's row
                            if i == len(reassembly_files) - 1:
                                details += f" | Session Checksum: {checksum_ok_str}"

                            session_rows_data.append({
                                'type': session_type,
                                'timestamp': file_timestamp_str, # Use file's timestamp
                                'status': file_status,
                                'file_output': file_output,
                                'ip_addr': ip_addr, # Repeat sender IP for clarity
                                'details': details,
                                'dir_path': session_dir,
                                'sort_key': file_info['timestamp'].timestamp() # Sort by file time
                            })

                    elif completion_info: # No reassembly files, but completion_info exists (old format?)
                        # Fallback to old logic using completion_info only
                        timestamp = "Unknown Time"
                        try:
                            if 'session_end_time' in completion_info and isinstance(completion_info['session_end_time'], (int, float)):
                                timestamp = datetime.fromtimestamp(completion_info['session_end_time']).strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                ts_str = item_name.split('_')[-2] + "_" + item_name.split('_')[-1]
                                dt_obj = datetime.strptime(ts_str, '%Y%m%d_%H%M%S')
                                timestamp = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                        except (IndexError, ValueError, KeyError):
                            pass

                        status_raw = completion_info.get('final_status', 'unknown')
                        status = status_raw.replace('_', ' ').title()
                        
                        # Check for output file based on completion_info or default name
                        output_filename = completion_info.get('output_filename')
                        output_file_path = os.path.join(session_dir, "data", "output_content.txt") # Default guess
                        if output_filename:
                             file_output = output_filename
                        elif os.path.exists(output_file_path):
                             file_output = os.path.basename(output_file_path) + " (in session dir)"
                        else:
                             file_output = "No Output File Found"

                        chunks_rec = completion_info.get('chunks_received', '?')
                        chunks_exp = completion_info.get('total_chunks_expected', '?')
                        missing_count = completion_info.get('missing_chunk_count', None)
                        reassembled_status = "Unknown"
                        if missing_count == 0: reassembled_status = "Complete"
                        elif missing_count is not None: reassembled_status = f"Incomplete ({missing_count} missing)"

                        details = f"Rcvd: {chunks_rec}/{chunks_exp} | Reassembly: {reassembled_status} | Checksum: {checksum_ok_str}"
                        
                        # Refine status based on checksum if completed
                        if "Completed" in status:
                             status = f"Completed - Checksum {checksum_ok_str}"
                        elif reassembled_status != "Complete" and reassembled_status != "Unknown":
                             status = reassembled_status # Show incomplete status

                        session_rows_data.append({
                            'type': session_type,
                            'timestamp': timestamp,
                            'status': status,
                            'file_output': file_output,
                            'ip_addr': ip_addr,
                            'details': details,
                            'dir_path': session_dir,
                            'sort_key': session_sort_key
                        })
                    else:
                         # No reassembly files and no completion_info
                         timestamp = "Unknown Time"
                         try: # Get time from dir name as last resort
                             ts_str = item_name.split('_')[-2] + "_" + item_name.split('_')[-1]
                             dt_obj = datetime.strptime(ts_str, '%Y%m%d_%H%M%S')
                             timestamp = dt_obj.strftime('%Y-%m-%d %H:%M:%S')
                             session_sort_key = dt_obj.timestamp()
                         except (IndexError, ValueError):
                             pass

                         session_rows_data.append({
                            'type': session_type,
                            'timestamp': timestamp,
                            'status': "Incomplete Logs",
                            'file_output': "N/A",
                            'ip_addr': ip_addr,
                            'details': "Missing completion_info and reassembly logs",
                            'dir_path': session_dir,
                            'sort_key': session_sort_key
                         })


        except OSError as e:
             print(f"Error listing directory {STEALTH_OUTPUT_DIR}: {e}")
             self.history_table.setRowCount(1)
             error_item = QTableWidgetItem(f"Error accessing output directory: {e}")
             error_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
             self.history_table.setSpan(0, 0, 1, self.history_table.columnCount())
             self.history_table.setItem(0, 0, error_item)
             return # Stop processing

        # Sort all collected rows by timestamp (descending - newest first)
        session_rows_data.sort(key=lambda x: x.get('sort_key', 0), reverse=True)

        # Populate the table
        self.history_table.setRowCount(len(session_rows_data))
        for row, row_data in enumerate(session_rows_data):
            # Create table items from row_data dictionary
            type_item = QTableWidgetItem(row_data['type'])
            type_item.setData(Qt.ItemDataRole.UserRole, row_data['dir_path']) # Store dir path for double-click

            timestamp_item = QTableWidgetItem(row_data['timestamp'])
            status_item = QTableWidgetItem(row_data['status'])
            file_output_item = QTableWidgetItem(row_data['file_output'])
            ip_addr_item = QTableWidgetItem(row_data['ip_addr'])
            details_item = QTableWidgetItem(row_data['details'])

            # Set status color
            status_lower = row_data['status'].lower()
            if "ok" in status_lower or "complete" in status_lower and "fail" not in status_lower:
                 status_item.setForeground(Qt.GlobalColor.darkGreen)
            elif "fail" in status_lower or "error" in status_lower or "incomplete logs" in status_lower:
                 status_item.setForeground(Qt.GlobalColor.darkRed)
            elif "cancel" in status_lower or "incomplete" in status_lower:
                 status_item.setForeground(Qt.GlobalColor.darkOrange) # Changed from yellow for better visibility
            else: # Default color
                 status_item.setForeground(Qt.GlobalColor.black)

            # Populate the row
            self.history_table.setItem(row, 0, type_item)
            self.history_table.setItem(row, 1, timestamp_item)
            self.history_table.setItem(row, 2, status_item)
            self.history_table.setItem(row, 3, file_output_item)
            self.history_table.setItem(row, 4, ip_addr_item)
            self.history_table.setItem(row, 5, details_item)

        # Optional: Resize columns after populating if needed
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
