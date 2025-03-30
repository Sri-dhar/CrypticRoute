#!/usr/bin/env python3
"""
Progress tracking utilities for CrypticRoute GUI
"""

import time
import threading

class ProgressTracker:
    """Tracks progress and emits signals for UI updates"""
    
    def __init__(self, progress_signal):
        self.progress_signal = progress_signal
        self.current = 0
        self.total = 100
        self.percentage = 0
        self.has_direct_percentage = False
        self.lock = threading.Lock()
        self.last_update_time = 0
        self.update_interval = 0.03
        self.last_emitted_value = -1

    def update_from_percentage(self, percentage):
        with self.lock:
            if percentage < self.percentage - 5 and self.percentage > 20:
                print(f"Warning: Progress went backward from {self.percentage:.1f}% to {percentage:.1f}%")
                return
            self.percentage = min(100, percentage)
            self.has_direct_percentage = True
            self._emit_update()

    def update_from_counts(self, current, total):
        with self.lock:
            if total <= 0:
                return
            new_percentage = min(100, (current / total * 100))
            if not self.has_direct_percentage or new_percentage > self.percentage:
                self.current = current
                self.total = total
                self.percentage = new_percentage
                self._emit_update()

    def _emit_update(self):
        current_time = time.time()
        int_percentage = int(self.percentage)
        if (current_time - self.last_update_time >= self.update_interval or
                abs(int_percentage - self.last_emitted_value) >= 1):
            if self.has_direct_percentage:
                self.progress_signal.emit(int_percentage, 100)
            else:
                self.progress_signal.emit(self.current, self.total)
            self.last_update_time = current_time
            self.last_emitted_value = int_percentage
