#!/usr/bin/env python3
"""
Log redirector for CrypticRoute GUI
"""
import sys # Make sure sys is imported for stderr fallback

class LogRedirector:
    """
    Redirects logs (stdout/stderr) to a primary callable (e.g., signal emitter)
    and optionally passes the line to a secondary processing callable.
    """

    def __init__(self, write_callable, process_line_callback=None):
        """
        Initialize with a primary callable for writing/emitting the log line,
        and an optional secondary callable for internal processing.
        """
        self.write_callable = write_callable
        self.process_line_callback = process_line_callback

    def write(self, text):
        # Don't process or emit empty strings or just newlines
        stripped_text = text.strip()
        if stripped_text:
            # Optionally process the line internally first
            if self.process_line_callback:
                try:
                    # Pass stripped text for easier parsing
                    self.process_line_callback(stripped_text)
                except Exception as e:
                    print(f"LogRedirector Error: Failed to call process_line_callback: {e}", file=sys.__stderr__)

            # Then, emit the original (unstripped) text via the primary callable
            try:
                # Pass the original text, not stripped, to the main log display
                self.write_callable(text)
            except Exception as e:
                # Avoid crashing the redirector itself if the callable fails
                print(f"LogRedirector Error: Failed to call write_callable: {e}", file=sys.__stderr__)

    def flush(self):
        # Usually called by context managers, no action needed for signals
        pass
