# --- Modify the SenderPanel UI setup ---
# Update the setup_ui method in SenderPanel to change the target_ip field

def setup_ui(self):
    # [Keep existing code up to the form layout section]
    
    # Transmission Settings Group
    form_group = ModernGroupBox("Transmission Settings")
    form_layout = QFormLayout()
    form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
    form_layout.setSpacing(10)

    # Change target_ip to interface selection (similar to ReceiverPanel)
    self.interface_combo = QComboBox()
    self.interface_combo.addItem("default")
    self.populate_interfaces() # Add this method to SenderPanel (copy from ReceiverPanel)
    form_layout.addRow("Network Interface:", self.interface_combo)

    # [Keep the rest of the existing UI setup code]

# --- Add populate_interfaces method to SenderPanel ---
# Copy this method from the ReceiverPanel class

def populate_interfaces(self):
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

# --- Update the start_transmission method ---
# Modify the command construction to use the correct sender.py arguments

def start_transmission(self):
    # [Keep existing code at the start of the function]
    
    # Remove this validation since target_ip is no longer required
    # target_ip = self.target_ip_edit.text().strip()
    # if not target_ip:
    #     QMessageBox.warning(self, "Input Error", "Target IP address is required.")
    #     return
    
    # [Keep validation for input_file, key_file, and output_dir]
    
    # Construct the arguments differently
    args = {
        "input_file": input_file,
        "delay": self.delay_spin.value(),
        "chunk_size": self.chunk_size_spin.value(),
    }
    
    # Get the interface if it's not default
    interface_text = self.interface_combo.currentText()
    if interface_text and interface_text != "default":
        # Extract only the interface name (before parenthesis if present)
        interface = interface_text.split('(')[0].strip()
        args["interface"] = interface
        print(f"Using interface: {interface}")
    
    if key_file:
        args["key_file"] = key_file
    if output_dir:
        args["output_dir"] = output_dir
    
    # [Continue with the rest of the existing code]

# --- Update the construct_command in WorkerThread.run_sender method ---
# Modify how the command is constructed for the sender process

def run_sender(self):
    # Update the command construction for sender.py
    input_file = self.args.get("input_file")
    key_file = self.args.get("key_file")
    delay = self.args.get("delay", DEFAULT_DELAY)
    chunk_size = self.args.get("chunk_size", DEFAULT_CHUNK_SIZE)
    interface = self.args.get("interface")
    output_dir = self.args.get("output_dir")

    # Build command with proper arguments (no more --target)
    cmd = ["python3", "sender.py", "--input", input_file, "--key", key_file]
    if interface:
        cmd.extend(["--interface", interface])
    if output_dir:
        cmd.extend(["--output-dir", output_dir])
    cmd.extend(["--delay", str(delay), "--chunk-size", str(chunk_size)])

    self.status_signal.emit(f"Starting sender with command: {' '.join(cmd)}")
    
    # [Continue with the rest of the run_sender method]

# --- Update the save/load settings for SenderPanel ---
# Modify to save/load interface instead of target_ip

def save_settings(self):
    settings = QSettings("CrypticRoute", "SenderPanel")
    settings.setValue("interface", self.interface_combo.currentText())
    settings.setValue("input_file", self.input_file_edit.text())
    settings.setValue("key_file", self.key_file_edit.text())
    settings.setValue("output_dir", self.output_dir_edit.text())
    settings.setValue("delay", self.delay_spin.value())
    settings.setValue("chunk_size", self.chunk_size_spin.value())

def load_settings(self):
    settings = QSettings("CrypticRoute", "SenderPanel")
    interface = settings.value("interface", "default")
    # FindText might be slow if many interfaces, but fine here
    index = self.interface_combo.findText(interface, Qt.MatchFlag.MatchContains)
    if index >= 0:
        self.interface_combo.setCurrentIndex(index)
    else:
        self.interface_combo.setCurrentIndex(0) # Fallback to default
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