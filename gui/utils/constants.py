#!/usr/bin/env python3
"""
Constants for the CrypticRoute GUI
"""
from crypticroute.config_loader import get_config
# Import the core chunk size from the common constants, which reads from config
from crypticroute.common.constants import MAX_CHUNK_SIZE as CORE_CHUNK_SIZE

# Default configuration values (read from config.toml with fallbacks)
# Use the core chunk size as the default for the GUI
DEFAULT_CHUNK_SIZE = CORE_CHUNK_SIZE
DEFAULT_TIMEOUT = get_config('gui', 'default_timeout', 120)
DEFAULT_DELAY = get_config('gui', 'default_delay', 0.1)


# Modern color scheme (kept in code for easier UI development)
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
