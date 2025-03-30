#!/usr/bin/env python3
"""
CrypticRoute GUI - Main Window implementation
Network Steganography Tool
"""

import os
import sys
import signal

from PyQt6.QtWidgets import (QMainWindow, QTabWidget, QStatusBar, QMessageBox, 
                             QStyleFactory, QApplication)
from PyQt6.QtCore import QSettings, QByteArray, QTimer
from PyQt6.QtGui import QIcon

from .components.panels import SenderPanel, ReceiverPanel
from .utils.constants import COLORS

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

        self.setup_menus()
        self.load_window_settings()

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
        self.save_window_settings()
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
    #     app.setWindowIcon(QIcon(icon_path))

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
