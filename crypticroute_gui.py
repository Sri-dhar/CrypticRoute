#!/usr/bin/env python3
"""
Launcher script for CrypticRoute GUI
"""

import sys
import os

# Add the current directory to path so we can import the GUI package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from GUI.main import main
    main()
except ImportError as e:
    print(f"Error: {e}")
    print("Make sure all dependencies are installed:")
    print("pip install PyQt6 netifaces")
    sys.exit(1)