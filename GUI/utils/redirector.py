#!/usr/bin/env python3
"""
Log redirector for CrypticRoute GUI
"""

class LogRedirector:
    """Redirects logs to a queue for processing in the GUI"""
    
    def __init__(self, log_queue):
        self.log_queue = log_queue

    def write(self, text):
        if text.strip():
            self.log_queue.put(text)

    def flush(self):
        pass
