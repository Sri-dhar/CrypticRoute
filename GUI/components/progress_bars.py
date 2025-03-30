#!/usr/bin/env python3
"""
Progress Bar Components for CrypticRoute GUI
"""

from PyQt6.QtWidgets import QProgressBar
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve

from ..utils.constants import COLORS

class AnimatedProgressBar(QProgressBar):
    """A progress bar with value animation effects"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.animation = QPropertyAnimation(self, b"value")
        self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.animation.setDuration(300)
        self.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 5px;
                text-align: center;
                background-color: {COLORS['light']};
                height: 25px;
            }}
            QProgressBar::chunk {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 {COLORS['primary']},
                                                stop:1 {COLORS['info']});
                border-radius: 4px;
            }}
        """)

    def setValue(self, value):
        if self.animation.state() == QPropertyAnimation.State.Running:
            self.animation.stop()
        self.animation.setStartValue(self.value())
        self.animation.setEndValue(value)
        self.animation.start()


class AckProgressBar(AnimatedProgressBar):
    """Progress bar specifically for ACK visualization"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid {COLORS['secondary']};
                border-radius: 5px;
                text-align: center;
                background-color: {COLORS['light']};
                height: 25px;
            }}
            QProgressBar::chunk {{
                background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                                stop:0 {COLORS['ack']},
                                                stop:1 {COLORS['success']});
                border-radius: 4px;
            }}
        """)
