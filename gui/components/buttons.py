#!/usr/bin/env python3
"""
Button Components for CrypticRoute GUI
"""

from PyQt6.QtWidgets import QPushButton
from PyQt6.QtGui import QColor

from ..utils.constants import COLORS

class AnimatedButton(QPushButton):
    """A button with hover and click effects"""

    def __init__(self, text, parent=None, color=COLORS['primary']):
        super().__init__(text, parent)
        self.base_color = color
        self.update_style() # Initial style set

    def setEnabled(self, enabled):
        super().setEnabled(enabled)
        self.update_style() # Update style when enabled state changes

    def update_style(self):
        """Update button stylesheet based on color and enabled state."""
        color = self.base_color
        if not self.isEnabled():
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: #cccccc;
                    color: #666666;
                    font-weight: bold;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color};
                    color: white;
                    font-weight: bold;
                    border: none;
                    padding: 8px 16px;
                    border-radius: 4px;
                }}
                QPushButton:hover {{
                    background-color: {self._lighten_color(color, 0.1)};
                }}
                QPushButton:pressed {{
                    background-color: {self._darken_color(color, 0.1)};
                }}
            """)

    def _lighten_color(self, color, amount=0.2):
        c = QColor(color)
        h, s, l, a = c.getHsl()
        l = min(255, int(l * (1 + amount)))
        c.setHsl(h, s, l, a)
        return c.name()

    def _darken_color(self, color, amount=0.2):
        c = QColor(color)
        h, s, l, a = c.getHsl()
        l = max(0, int(l * (1 - amount)))
        c.setHsl(h, s, l, a)
        return c.name()
