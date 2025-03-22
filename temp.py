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
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout()
        
        # Create form for input fields
        form_group = QGroupBox("Reception Settings")
        form_layout = QFormLayout()
        
        # Output file
        output_layout = QHBoxLayout()
        self.output_file_edit = QLineEdit()
        self.output_file_edit.setPlaceholderText("Path to save received data")
        self.output_file_button = QPushButton("Browse...")
        self.output_file_button.clicked.connect(self.browse_output_file)
        output_layout.addWidget(self.output_file_edit)
        output_layout.addWidget(self.output_file_button)
        form_layout.addRow("Output File:", output_layout)
        
        # Key file
        key_layout = QHBoxLayout()
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("Path to decryption key file (optional)")
        self.key_file_button = QPushButton("Browse...")
        self.key_file_button.clicked.connect(self.browse_key_file)
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
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Custom output directory (optional)")
        self.output_dir_button = QPushButton("Browse...")
        self.output_dir_button.clicked.connect(self.browse_output_dir)
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
        
        self.receive_button = QPushButton("Start Listening")
        self.receive_button.clicked.connect(self.start_reception)
        self.receive_button.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold;")
        
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_reception)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("background-color: #f44336; color: white; font-weight: bold;")
        
        self.clear_button = QPushButton("Clear Log")
        self.clear_button.clicked.connect(self.clear_log)
        
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self.populate_interfaces)
        
        control_layout.addWidget(self.receive_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        control_layout.addWidget(self.refresh_button)
        
        main_layout.addLayout(control_layout)
        
        # Add progress bar
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        self.status_label = QLabel("Ready")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        progress_group.setLayout(progress_layout)
        main_layout.addWidget(progress_group)
        
        # Create a splitter for log and data display
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        
        # Log area
        log_group = QGroupBox("Transmission Log")
        log_layout = QVBoxLayout()
        
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Courier", 9))
        
        log_layout.addWidget(self.log_edit)
        log_group.setLayout(log_layout)
        splitter.addWidget(log_group)
        
        # Data display area (new)
        data_group = QGroupBox("Received Data")
        data_layout = QVBoxLayout()
        
        self.data_display = QTextEdit()
        self.data_display.setReadOnly(True)
        self.data_display.setFont(QFont("Courier", 9))
        
        # Add a save button for the received data
        self.save_data_button = QPushButton("Save Displayed Data")
        self.save_data_button.clicked.connect(self.save_displayed_data)
        
        # Add a clear button for the data display
        self.clear_data_button = QPushButton("Clear Display")
        self.clear_data_button.clicked.connect(self.clear_data_display)
        
        data_buttons_layout = QHBoxLayout()
        data_buttons_layout.addWidget(self.save_data_button)
        data_buttons_layout.addWidget(self.clear_data_button)
        
        data_layout.addWidget(self.data_display)
        data_layout.addLayout(data_buttons_layout)
        data_group.setLayout(data_layout)
        splitter.addWidget(data_group)
        
        # Set initial sizes for the splitter (50% each)
        splitter.setSizes([500, 500])
        
        main_layout.addWidget(splitter, 1)  # Give splitter more vertical space
        
        self.setLayout(main_layout)
    
    def add_log_message(self, message):
        """Add a message to the log."""
        self.log_edit.append(message)
        self.log_edit.moveCursor(QTextCursor.End)
        
        # Check for data-related messages and update data display
        try:
            # Check for received data markers in log messages
            if "[DATA]" in message or "[CHUNK] Data:" in message or "Decoded data:" in message:
                # Extract just the data part after the marker
                if "[DATA]" in message:
                    data = message.split("[DATA]", 1)[1].strip()
                elif "[CHUNK] Data:" in message:
                    data = message.split("[CHUNK] Data:", 1)[1].strip()
                elif "Decoded data:" in message:
                    data = message.split("Decoded data:", 1)[1].strip()
                else:
                    data = message
                    
                # Queue the data for display
                self.data_queue.put(data)
        except Exception as e:
            print(f"Error processing data display: {e}")
    
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
            while not self.data_queue.empty():
                data_batch.append(self.data_queue.get())
                
            if data_batch:
                # Combine all new data
                new_data = '\n'.join(data_batch)
                
                # Add to display
                cursor = self.data_display.textCursor()
                cursor.movePosition(QTextCursor.End)
                cursor.insertText(new_data + '\n')
                self.data_display.setTextCursor(cursor)
                self.data_display.ensureCursorVisible()
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

# Modify the WorkerThread.run_receiver method to handle data display
