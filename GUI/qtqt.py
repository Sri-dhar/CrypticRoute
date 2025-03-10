import sys
import os
import random
import time
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                              QLabel, QLineEdit, QPushButton, QFileDialog, QTextEdit, 
                              QComboBox, QSpinBox, QGraphicsView, QGraphicsScene, QGraphicsOpacityEffect,
                              QStackedWidget, QFrame, QSizePolicy, QCheckBox, QProgressBar)
from PySide6.QtCore import Qt, QSize, QPropertyAnimation, QEasingCurve, QRect, QTimer, QThread, Signal, Property, QPoint
from PySide6.QtGui import QPalette, QColor, QFont, QIcon, QPainter, QPen, QBrush, QLinearGradient, QPainterPath
from PySide6.QtGui import QPixmap, QRadialGradient, QCursor, QTransform, QImage

# Mock core steganography module (replace with your actual implementation)
class StegoCore:
    def send_data(self, target_ip, target_port, file_path, key):
        return f"Sending data to {target_ip}:{target_port} from {file_path} with key {key}"

    def receive_data(self, listen_port, save_path, key):
        return f"Receiving data on port {listen_port}, saving to {save_path} with key {key}"

class PulseAnimation(QThread):
    pulse_signal = Signal(float)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.running = True
        
    def run(self):
        value = 0
        step = 0.05
        direction = 1
        
        while self.running:
            if value >= 1.0:
                direction = -1
            elif value <= 0.0:
                direction = 1
                
            value += step * direction
            self.pulse_signal.emit(value)
            time.sleep(0.05)
            
    def stop(self):
        self.running = False

class HexagonButton(QPushButton):
    def __init__(self, text, color, parent=None):
        super().__init__(text, parent)
        self.base_color = color
        self.hover_color = self._lighten_color(color, 20)
        self.pressed_color = self._darken_color(color, 20)
        self.current_color = self.base_color
        self.setMinimumSize(120, 100)
        self.setMaximumSize(120, 100)
        
        # Set font
        font = QFont("Segoe UI", 10, QFont.Bold)
        self.setFont(font)
        
        # No border
        self.setStyleSheet(f"""
            QPushButton {{
                border: none;
                color: white;
                background-color: transparent;
            }}
        """)

    def _lighten_color(self, color, amount=30):
        r, g, b, a = color.getRgb()
        r = min(255, r + amount)
        g = min(255, g + amount)
        b = min(255, b + amount)
        return QColor(r, g, b, a)
        
    def _darken_color(self, color, amount=30):
        r, g, b, a = color.getRgb()
        r = max(0, r - amount)
        g = max(0, g - amount)
        b = max(0, b - amount)
        return QColor(r, g, b, a)
        
    def enterEvent(self, event):
        self.current_color = self.hover_color
        self.update()
        super().enterEvent(event)
        
    def leaveEvent(self, event):
        self.current_color = self.base_color
        self.update()
        super().leaveEvent(event)
        
    def mousePressEvent(self, event):
        self.current_color = self.pressed_color
        self.update()
        super().mousePressEvent(event)
        
    def mouseReleaseEvent(self, event):
        self.current_color = self.hover_color if self.rect().contains(event.pos()) else self.base_color
        self.update()
        super().mouseReleaseEvent(event)
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Draw hexagon
        path = QPainterPath()
        w, h = self.width(), self.height()
        center_x, center_y = w / 2, h / 2
        radius = min(w, h) / 2 - 5
        
        # Calculate hexagon points
        points = []
        for i in range(6):
            angle_deg = 60 * i - 30
            angle_rad = angle_deg * 3.14159 / 180
            x = center_x + radius * 0.95 * (1 if i % 2 == 0 else 0.9) * math.cos(angle_rad)
            y = center_y + radius * (1 if i % 2 == 0 else 0.9) * math.sin(angle_rad)
            points.append(QPoint(int(x), int(y)))
            
        path.moveTo(points[0])
        for i in range(1, 6):
            path.lineTo(points[i])
        path.lineTo(points[0])
        
        # Fill with gradient
        gradient = QLinearGradient(0, 0, w, h)
        gradient.setColorAt(0, self.current_color)
        gradient.setColorAt(1, self._darken_color(self.current_color, 40))
        painter.fillPath(path, gradient)
        
        # Add highlight for 3D effect
        highlight_path = QPainterPath()
        highlight_path.moveTo(points[0])
        highlight_path.lineTo(points[1])
        highlight_path.lineTo(points[2])
        
        highlight_color = self._lighten_color(self.current_color, 60)
        highlight_color.setAlpha(100)
        painter.strokePath(highlight_path, QPen(highlight_color, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        
        # Add shadow for 3D effect
        shadow_path = QPainterPath()
        shadow_path.moveTo(points[3])
        shadow_path.lineTo(points[4])
        shadow_path.lineTo(points[5])
        shadow_path.lineTo(points[0])
        
        shadow_color = self._darken_color(self.current_color, 60)
        shadow_color.setAlpha(100)
        painter.strokePath(shadow_path, QPen(shadow_color, 2, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
        
        # Draw text
        painter.setPen(Qt.white)
        painter.setFont(self.font())
        painter.drawText(self.rect(), Qt.AlignCenter, self.text())

import math

class NetworkVisualization(QGraphicsView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRenderHint(QPainter.Antialiasing)
        self.scene = QGraphicsScene(self)
        self.setScene(self.scene)
        
        # Set up visualization properties
        self.setMinimumHeight(200)
        self.setStyleSheet("background: transparent; border: none;")
        
        # Animation
        self.pulse_thread = PulseAnimation()
        self.pulse_thread.pulse_signal.connect(self.update_pulse)
        self.pulse_thread.start()
        
        # Setup visualization
        self.setup_visualization()
        
        # Initial packet count
        self.packet_count = 0
        self.packets = []
        
        # Particle timer
        self.particle_timer = QTimer()
        self.particle_timer.timeout.connect(self.update_packets)
        self.particle_timer.start(50)
        
    def setup_visualization(self):
        self.active = False
        self.pulse_value = 0.0
        
        # Source node
        self.source_node = self.scene.addEllipse(0, 0, 40, 40, QPen(QColor(52, 152, 219)), QBrush(QColor(52, 152, 219)))
        self.source_node.setPos(50, 80)
        
        # Source label
        source_text = self.scene.addText("Source")
        source_text.setDefaultTextColor(QColor(200, 200, 200))
        source_text.setPos(40, 40)
        
        # Target node
        self.target_node = self.scene.addEllipse(0, 0, 40, 40, QPen(QColor(231, 76, 60)), QBrush(QColor(231, 76, 60)))
        self.target_node.setPos(410, 80) 
        
        # Target label
        target_text = self.scene.addText("Target")
        target_text.setDefaultTextColor(QColor(200, 200, 200))
        target_text.setPos(400, 40)
        
        # Connection line
        self.connection = self.scene.addLine(70, 100, 430, 100, QPen(QColor(127, 140, 141, 100), 2, Qt.DashLine))
        
    def toggle_active(self, active):
        self.active = active
        
    def add_packet(self):
        # Create a new packet
        packet = self.scene.addEllipse(0, 0, 10, 10, QPen(Qt.transparent), QBrush(QColor(46, 204, 113)))
        packet.setPos(70, 95)
        
        # Add a glow effect
        glow = QGraphicsOpacityEffect()
        glow.setOpacity(0.8)
        packet.setGraphicsEffect(glow)
        
        # Store packet data
        self.packets.append({
            'item': packet,
            'pos': 0.0,
            'speed': 0.01 + random.uniform(-0.002, 0.005),
            'effect': glow
        })
        
        self.packet_count += 1
        
    def update_packets(self):
        if not self.active:
            return
            
        # Randomly add new packets
        if random.random() < 0.2:
            self.add_packet()
            
        # Update existing packets
        to_remove = []
        for i, packet_data in enumerate(self.packets):
            packet = packet_data['item']
            packet_data['pos'] += packet_data['speed']
            
            if packet_data['pos'] >= 1.0:
                to_remove.append(i)
                continue
                
            # Update position
            start_x, start_y = 70, 95
            end_x, end_y = 430, 95
            x = start_x + (end_x - start_x) * packet_data['pos']
            packet.setPos(x, start_y)
            
            # Update opacity for fade out near end
            opacity = 1.0
            if packet_data['pos'] > 0.8:
                opacity = 1.0 - (packet_data['pos'] - 0.8) * 5
            packet_data['effect'].setOpacity(opacity)
            
        # Remove packets that have reached the end
        for i in sorted(to_remove, reverse=True):
            self.scene.removeItem(self.packets[i]['item'])
            del self.packets[i]
                
    def update_pulse(self, value):
        self.pulse_value = value
        
        # Update source and target nodes with pulse effect
        if self.active:
            pulse_size = 40 + value * 5
            pulse_opacity = 0.7 + value * 0.3
            
            # Source pulse
            self.source_node.setRect(0, 0, pulse_size, pulse_size)
            self.source_node.setPos(50 - (pulse_size - 40)/2, 80 - (pulse_size - 40)/2)
            
            # Target pulse
            self.target_node.setRect(0, 0, pulse_size, pulse_size)
            self.target_node.setPos(410 - (pulse_size - 40)/2, 80 - (pulse_size - 40)/2)
        
    def resizeEvent(self, event):
        self.fitInView(self.scene.sceneRect(), Qt.KeepAspectRatio)
        super().resizeEvent(event)
        
    def cleanup(self):
        if self.pulse_thread.isRunning():
            self.pulse_thread.stop()
            self.pulse_thread.wait()

class StylishTextField(QWidget):
    def __init__(self, label_text, default_text="", parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        
        # Label
        self.label = QLabel(label_text)
        self.label.setStyleSheet("""
            QLabel {
                color: #aaaaaa;
                font-size: 12px;
                font-weight: bold;
            }
        """)
        
        # Text field
        self.text_field = QLineEdit(default_text)
        self.text_field.setStyleSheet("""
            QLineEdit {
                background-color: #2a2a2a;
                color: #e0e0e0;
                border: none;
                border-bottom: 2px solid #444444;
                padding: 8px;
                font-size: 14px;
                selection-background-color: #2980b9;
            }
            QLineEdit:focus {
                border-bottom: 2px solid #1e88e5;
            }
            QLineEdit:hover {
                background-color: #353535;
            }
        """)
        
        layout.addWidget(self.label)
        layout.addWidget(self.text_field)
        
    def text(self):
        return self.text_field.text()
        
    def setText(self, text):
        self.text_field.setText(text)
        
    def setEchoMode(self, mode):
        self.text_field.setEchoMode(mode)

class HexBackground(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.hexagons = []
        self.setStyleSheet("background-color: transparent;")
        
        # Generate initial hexagons
        self.generate_hexagons()
        
        # Animation timer
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate_hexagons)
        self.timer.start(50)
        
    def generate_hexagons(self):
        for i in range(15):  # Number of hexagons
            self.hexagons.append({
                'x': random.uniform(0, 1),
                'y': random.uniform(0, 1),
                'size': random.uniform(0.03, 0.1),
                'opacity': random.uniform(0.05, 0.15),
                'speed_x': random.uniform(-0.0002, 0.0002),
                'speed_y': random.uniform(-0.0002, 0.0002),
                'color': QColor(random.randint(20, 40), random.randint(30, 70), random.randint(50, 100), 50)
            })
            
    def animate_hexagons(self):
        for hex in self.hexagons:
            # Move hexagons
            hex['x'] += hex['speed_x']
            hex['y'] += hex['speed_y']
            
            # Wrap around edges
            if hex['x'] < -0.2: hex['x'] = 1.2
            if hex['x'] > 1.2: hex['x'] = -0.2
            if hex['y'] < -0.2: hex['y'] = 1.2
            if hex['y'] > 1.2: hex['y'] = -0.2
        
        self.update()
            
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        w, h = self.width(), self.height()
        
        for hex in self.hexagons:
            # Calculate position and size based on widget dimensions
            x = hex['x'] * w
            y = hex['y'] * h
            size = hex['size'] * min(w, h)
            
            # Draw hexagon
            path = QPainterPath()
            
            for i in range(6):
                angle_deg = 60 * i
                angle_rad = angle_deg * 3.14159 / 180
                point_x = x + size * math.cos(angle_rad)
                point_y = y + size * math.sin(angle_rad)
                
                if i == 0:
                    path.moveTo(point_x, point_y)
                else:
                    path.lineTo(point_x, point_y)
            
            path.closeSubpath()
            
            # Fill with color
            color = hex['color']
            color.setAlphaF(hex['opacity'])
            painter.fillPath(path, color)
            
            # Stroke with lighter color
            stroke_color = QColor(color)
            stroke_color.setAlphaF(hex['opacity'] * 1.5)
            painter.strokePath(path, QPen(stroke_color, 1))

class MetroPanel(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        
        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Title with accent line
        title_layout = QHBoxLayout()
        
        accent_line = QFrame()
        accent_line.setFrameShape(QFrame.VLine)
        accent_line.setLineWidth(3)
        accent_line.setFixedWidth(3)
        accent_line.setStyleSheet("background-color: #1e88e5;")
        
        title_label = QLabel(title)
        title_label.setStyleSheet("""
            QLabel {
                color: #ffffff;
                font-size: 18px;
                font-weight: bold;
            }
        """)
        
        title_layout.addWidget(accent_line)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        
        # Content area
        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(10, 10, 10, 0)
        self.content_layout.setSpacing(15)
        
        # Add to main layout
        layout.addLayout(title_layout)
        layout.addWidget(self.content_widget)
        layout.addStretch()
        
        # Set up styling
        self.setStyleSheet("""
            MetroPanel {
                background-color: #333333;
                border-radius: 8px;
            }
        """)
        
        # Add drop shadow effect
        shadow = QGraphicsOpacityEffect()
        shadow.setOpacity(0.8)
        self.setGraphicsEffect(shadow)
        
    def add_widget(self, widget):
        self.content_layout.addWidget(widget)
        
    def add_layout(self, layout):
        self.content_layout.addLayout(layout)

class ActionButton(QPushButton):
    def __init__(self, text, icon_path=None, accent_color=None, parent=None):
        super().__init__(text, parent)
        self.accent_color = accent_color or QColor(30, 136, 229)  # Default blue
        
        # Set icon if provided
        if icon_path and os.path.exists(icon_path):
            self.setIcon(QIcon(icon_path))
            self.setIconSize(QSize(18, 18))
        
        # Set minimum size
        self.setMinimumHeight(45)
        
        # Set stylesheet
        color_str = f"rgba({self.accent_color.red()}, {self.accent_color.green()}, {self.accent_color.blue()}, {self.accent_color.alpha() / 255.0})"
        hover_color = self._adjust_color(self.accent_color, 1.1)
        hover_color_str = f"rgba({hover_color.red()}, {hover_color.green()}, {hover_color.blue()}, {hover_color.alpha() / 255.0})"
        
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color_str};
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
                font-weight: bold;
                font-size: 14px;
            }}
            QPushButton:hover {{
                background-color: {hover_color_str};
            }}
            QPushButton:pressed {{
                background-color: {color_str};
                padding-top: 12px;
                padding-bottom: 8px;
            }}
        """)
        
    def _adjust_color(self, color, factor):
        """Lighten or darken a color by the given factor"""
        r = min(255, max(0, int(color.red() * factor)))
        g = min(255, max(0, int(color.green() * factor)))
        b = min(255, max(0, int(color.blue() * factor)))
        return QColor(r, g, b, color.alpha())

class FadingStatusLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QLabel {
                color: #00ff00;
                font-size: 14px;
                font-weight: bold;
                background-color: rgba(0, 60, 0, 80);
                border-radius: 4px;
                padding: 8px;
            }
        """)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedHeight(40)
        self.setHidden(True)
        
        # Animation
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.opacity_effect.setOpacity(0)
        self.setGraphicsEffect(self.opacity_effect)
        
        self.fade_animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_animation.setDuration(300)  # Duration in milliseconds
        self.fade_animation.setStartValue(0)
        self.fade_animation.setEndValue(1)
        self.fade_animation.setEasingCurve(QEasingCurve.OutCubic)
        
        # Auto-hide timer
        self.hide_timer = QTimer(self)
        self.hide_timer.timeout.connect(self.start_fade_out)
        
    def show_message(self, message, status="success", duration=3000):
        # Set style based on status
        if status == "success":
            self.setStyleSheet("""
                QLabel {
                    color: #00ff00;
                    font-size: 14px;
                    font-weight: bold;
                    background-color: rgba(0, 60, 0, 80);
                    border-radius: 4px;
                    padding: 8px;
                }
            """)
        elif status == "error":
            self.setStyleSheet("""
                QLabel {
                    color: #ff5555;
                    font-size: 14px;
                    font-weight: bold;
                    background-color: rgba(60, 0, 0, 80);
                    border-radius: 4px;
                    padding: 8px;
                }
            """)
        elif status == "info":
            self.setStyleSheet("""
                QLabel {
                    color: #55aaff;
                    font-size: 14px;
                    font-weight: bold;
                    background-color: rgba(0, 30, 60, 80);
                    border-radius: 4px;
                    padding: 8px;
                }
            """)
            
        # Set message
        self.setText(message)
        
        # Show with fade-in
        self.setHidden(False)
        self.fade_animation.setDirection(QPropertyAnimation.Forward)
        self.fade_animation.start()
        
        # Start auto-hide timer
        self.hide_timer.start(duration)
        
    def start_fade_out(self):
        self.fade_animation.setDirection(QPropertyAnimation.Backward)
        self.fade_animation.finished.connect(self.hide_after_fade)
        self.fade_animation.start()
        
    def hide_after_fade(self):
        if self.fade_animation.direction() == QPropertyAnimation.Backward:
            self.setHidden(True)
            self.fade_animation.finished.disconnect(self.hide_after_fade)

class SideNavigationMenu(QWidget):
    page_changed = Signal(int)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(80)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 20, 0, 20)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignCenter)
        
        # Logo/brand at top
        logo_label = QLabel()
        logo_label.setFixedSize(60, 60)
        logo_label.setStyleSheet("""
            QLabel {
                background-color: #1e88e5;
                border-radius: 30px;
            }
        """)
        logo_label.setAlignment(Qt.AlignCenter)
        font = QFont("Arial", 24, QFont.Bold)
        logo_label.setFont(font)
        logo_label.setText("S")
        logo_label.setStyleSheet("""
            QLabel {
                color: white;
                background-color: #1e88e5;
                border-radius: 30px;
            }
        """)
        
        # Navigation buttons
        self.send_btn = self.create_nav_button("Send", 0, QColor(46, 204, 113))
        self.receive_btn = self.create_nav_button("Receive", 1, QColor(52, 152, 219))
        self.settings_btn = self.create_nav_button("Settings", 2, QColor(155, 89, 182))
        
        # Initial selection
        self.current_index = 0
        self.send_btn.setProperty("selected", True)
        self.send_btn.setStyleSheet(self.send_btn.styleSheet())
        
        # Add widgets to layout
        layout.addWidget(logo_label, 0, Qt.AlignCenter)
        layout.addSpacing(20)
        layout.addWidget(self.send_btn, 0, Qt.AlignCenter)
        layout.addWidget(self.receive_btn, 0, Qt.AlignCenter)
        layout.addWidget(self.settings_btn, 0, Qt.AlignCenter)
        layout.addStretch()
        
        # Set background style
        self.setStyleSheet("""
            SideNavigationMenu {
                background-color: #222222;
            }
        """)
        
    def create_nav_button(self, text, index, color):
        button = QPushButton(text)
        button.setFixedSize(64, 64)
        button.setCheckable(True)
        
        # Convert QColor to string for stylesheet
        color_str = f"rgba({color.red()}, {color.green()}, {color.blue()}, {color.alpha() / 255.0})"
        
        # Set up the stylesheet
        button.setStyleSheet(f"""
            QPushButton {{
                color: white;
                background-color: #333333;
                border: none;
                border-radius: 10px;
                font-weight: bold;
                font-size: 12px;
            }}
            QPushButton:hover {{
                background-color: #444444;
            }}
            QPushButton[selected="true"] {{
                background-color: {color_str};
            }}
        """)
        
        # Connect click event
        button.clicked.connect(lambda: self.change_page(index))
        
        return button
        
    def change_page(self, index):
        if index == self.current_index:
            return
            
        # Update button styles
        self.send_btn.setProperty("selected", index == 0)
        self.receive_btn.setProperty("selected", index == 1)
        self.settings_btn.setProperty("selected", index == 2)
        
        # Force style update
        self.send_btn.setStyleSheet(self.send_btn.styleSheet())
        self.receive_btn.setStyleSheet(self.receive_btn.styleSheet())
        self.settings_btn.setStyleSheet(self.settings_btn.styleSheet())
        
        # Update current index and emit signal
        self.current_index = index
        self.page_changed.emit(index)

class RoundProgressBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(70, 70)
        self.setMaximumSize(70, 70)
        self.value = 0
        self.max_value = 100
        
    def setValue(self, value):
        self.value = value
        self.update()
        
    def setMaximum(self, max_value):
        self.max_value = max_value
        self.update()
        
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        # Size and center
        width = min(self.width(), self.height())
        center_x = self.width() / 2
        center_y = self.height() / 2
        
        # Calculate arc parameters
        outer_radius = width / 2 - 5
        inner_radius = outer_radius - 6
        
        # Background track
        painter.setPen(QPen(QColor(60, 60, 60), 6, Qt.SolidLine, Qt.FlatCap))
        painter.drawEllipse(QRect(int(center_x - outer_radius), 
                                 int(center_y - outer_radius),
                                 int(outer_radius * 2),
                                 int(outer_radius * 2)))
        
        # Determine progress angle
        # Determine progress angle
        angle = 360 * (self.value / self.max_value) if self.max_value > 0 else 0
        
        # Choose color based on progress
        if angle <= 120:
            color = QColor(46, 204, 113)  # Green
        elif angle <= 240:
            color = QColor(241, 196, 15)  # Yellow
        else:
            color = QColor(231, 76, 60)   # Red
        
        # Draw progress arc
        painter.setPen(QPen(color, 6, Qt.SolidLine, Qt.RoundCap))
        rect = QRect(int(center_x - outer_radius), 
                     int(center_y - outer_radius),
                     int(outer_radius * 2),
                     int(outer_radius * 2))
        
        # QT angles are:
        # - Measured in 1/16th of a degree
        # - 0 is at 3 o'clock
        # - Positive values counter-clockwise
        start_angle = 90 * 16  # Start at 12 o'clock (90°)
        span_angle = -angle * 16  # Go clockwise (negative)
        
        painter.drawArc(rect, start_angle, span_angle)
        
        # Draw text in center
        painter.setPen(Qt.white)
        painter.setFont(QFont("Arial", 12, QFont.Bold))
        
        # Format depends on the max value
        if self.max_value == 100:
            text = f"{int(self.value)}%"
        else:
            text = f"{int(self.value)}/{int(self.max_value)}"
            
        painter.drawText(self.rect(), Qt.AlignCenter, text)

class EncryptionProgressDialog(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Processing Data")
        self.setMinimumSize(500, 300)
        self.setWindowFlag(Qt.Dialog)
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setStyleSheet("""
            EncryptionProgressDialog {
                background-color: #333333;
                border-radius: 10px;
                border: 1px solid #444444;
            }
        """)
        
        # Create layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header_layout = QHBoxLayout()
        title_label = QLabel("Processing Data")
        title_label.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        close_btn = QPushButton("×")
        close_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                color: #aaaaaa;
                font-size: 20px;
                font-weight: bold;
                border: none;
            }
            QPushButton:hover {
                color: white;
            }
        """)
        close_btn.setFixedSize(30, 30)
        close_btn.clicked.connect(self.hide)
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(close_btn)
        
        # Progress bar and status
        self.progress = RoundProgressBar()
        self.status_label = QLabel("Initializing...")
        self.status_label.setStyleSheet("color: #cccccc; font-size: 14px;")
        self.status_label.setAlignment(Qt.AlignCenter)
        
        progress_layout = QHBoxLayout()
        progress_layout.addStretch()
        progress_layout.addWidget(self.progress)
        progress_layout.addStretch()
        
        # Step indicators
        steps_widget = QWidget()
        steps_layout = QHBoxLayout(steps_widget)
        
        self.step1 = self.create_step_indicator("Reading", 1)
        self.step2 = self.create_step_indicator("Encrypting", 2)
        self.step3 = self.create_step_indicator("Chunking", 3)
        self.step4 = self.create_step_indicator("Sending", 4)
        
        steps_layout.addWidget(self.step1)
        steps_layout.addWidget(self.create_step_connector())
        steps_layout.addWidget(self.step2)
        steps_layout.addWidget(self.create_step_connector())
        steps_layout.addWidget(self.step3)
        steps_layout.addWidget(self.create_step_connector())
        steps_layout.addWidget(self.step4)
        
        # Cancel button
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 10px 20px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
        """)
        
        # Add everything to main layout
        main_layout.addLayout(header_layout)
        main_layout.addSpacing(20)
        main_layout.addLayout(progress_layout)
        main_layout.addSpacing(10)
        main_layout.addWidget(self.status_label, 0, Qt.AlignCenter)
        main_layout.addSpacing(30)
        main_layout.addWidget(steps_widget)
        main_layout.addStretch()
        main_layout.addWidget(self.cancel_btn, 0, Qt.AlignCenter)
        
        # Set initial state
        self.current_step = 0
        self.update_steps()
        
    def create_step_indicator(self, text, step):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        circle = QLabel()
        circle.setFixedSize(30, 30)
        circle.setAlignment(Qt.AlignCenter)
        circle.setText(str(step))
        circle.setStyleSheet("""
            QLabel {
                background-color: #555555;
                color: white;
                border-radius: 15px;
                font-weight: bold;
            }
        """)
        
        label = QLabel(text)
        label.setStyleSheet("color: #aaaaaa; font-size: 12px;")
        label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(circle, 0, Qt.AlignCenter)
        layout.addWidget(label, 0, Qt.AlignCenter)
        
        return widget
        
    def create_step_connector(self):
        connector = QFrame()
        connector.setFrameShape(QFrame.HLine)
        connector.setFixedWidth(40)
        connector.setStyleSheet("background-color: #555555;")
        return connector
        
    def set_progress(self, value, max_value=100):
        self.progress.setMaximum(max_value)
        self.progress.setValue(value)
        
    def set_status(self, text):
        self.status_label.setText(text)
        
    def set_step(self, step):
        self.current_step = step
        self.update_steps()
        
    def update_steps(self):
        # Update step indicators based on current step
        for i, step in enumerate([self.step1, self.step2, self.step3, self.step4]):
            circle = step.findChild(QLabel)
            if i < self.current_step:
                # Completed
                circle.setStyleSheet("""
                    QLabel {
                        background-color: #27ae60;
                        color: white;
                        border-radius: 15px;
                        font-weight: bold;
                    }
                """)
            elif i == self.current_step:
                # Current
                circle.setStyleSheet("""
                    QLabel {
                        background-color: #2980b9;
                        color: white;
                        border-radius: 15px;
                        font-weight: bold;
                    }
                """)
            else:
                # Pending
                circle.setStyleSheet("""
                    QLabel {
                        background-color: #555555;
                        color: white;
                        border-radius: 15px;
                        font-weight: bold;
                    }
                """)

class LoadingIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(40, 40)
        
        self.animation_step = 0
        self.animation_active = False
        
        self.animation_timer = QTimer(self)
        self.animation_timer.timeout.connect(self.update_animation)
        
    def start_animation(self):
        self.animation_active = True
        self.animation_timer.start(50)
        self.show()
        
    def stop_animation(self):
        self.animation_active = False
        self.animation_timer.stop()
        self.hide()
        
    def update_animation(self):
        self.animation_step = (self.animation_step + 1) % 12
        self.update()
        
    def paintEvent(self, event):
        if not self.animation_active:
            return
            
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        
        center_x = self.width() / 2
        center_y = self.height() / 2
        radius = min(self.width(), self.height()) / 2 - 5
        
        for i in range(12):
            # Calculate dot position
            angle = i * 30 * math.pi / 180
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            # Calculate opacity based on animation step
            distance = (i - self.animation_step) % 12
            opacity = 1.0 - (distance / 12.0)
            
            # Draw the dot
            color = QColor(255, 255, 255, int(opacity * 255))
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QPoint(int(x), int(y)), 3, 3)

class StegoGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stealth Data Transfer")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize core steganography module
        self.stego_core = StegoCore()
        
        # Set up the main window style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a1a;
            }
        """)
        
        # Create central widget
        central_widget = QWidget()
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create navigation menu
        self.nav_menu = SideNavigationMenu()
        self.nav_menu.page_changed.connect(self.change_page)
        
        # Create stacked widget for pages
        self.pages = QStackedWidget()
        
        # Create pages
        self.send_page = self.create_send_page()
        self.receive_page = self.create_receive_page()
        self.settings_page = self.create_settings_page()
        
        # Add pages to stack
        self.pages.addWidget(self.send_page)
        self.pages.addWidget(self.receive_page)
        self.pages.addWidget(self.settings_page)
        
        # Add background animation
        self.hex_background = HexBackground()
        
        # Set up layout
        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.addWidget(self.hex_background)
        
        # Stack the pages on top of the background
        content_widget = QWidget()
        content_widget.setLayout(content_layout)
        self.pages.setParent(content_widget)
        self.pages.setGeometry(0, 0, 1120, 800)
        
        # Add navigation and content to main layout
        main_layout.addWidget(self.nav_menu)
        main_layout.addWidget(content_widget)
        
        # Status message overlay
        self.status_label = FadingStatusLabel(self)
        
        # Set central widget
        self.setCentralWidget(central_widget)
        
        # Create progress dialog
        self.progress_dialog = EncryptionProgressDialog()
        
        # Set up default interface state
        self.update_status_overlay()
        
    def change_page(self, index):
        # Animate page transition
        self.pages.setCurrentIndex(index)
        
    def create_send_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title_label = QLabel("Send Encrypted Data")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
            }
        """)
        
        # Create panels
        connection_panel = self.create_connection_panel()
        file_panel = self.create_file_panel()
        visualization_panel = self.create_visualization_panel()
        
        # Add everything to layout
        layout.addWidget(title_label)
        layout.addSpacing(20)
        
        # Create horizontal layout for panels
        panels_layout = QHBoxLayout()
        panels_layout.addWidget(connection_panel)
        panels_layout.addWidget(file_panel)
        
        layout.addLayout(panels_layout)
        layout.addWidget(visualization_panel)
        layout.addStretch()
        
        return page
        
    def create_receive_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title_label = QLabel("Receive Encrypted Data")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
            }
        """)
        
        # Create receive panel
        receive_panel = MetroPanel("Listen Configuration")
        receive_layout = QVBoxLayout()
        
        self.listen_port_field = StylishTextField("Listen Port", "5555")
        self.save_path_field = StylishTextField("Save Location", "")
        
        # Browse button
        browse_layout = QHBoxLayout()
        browse_layout.addWidget(self.save_path_field)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
        """)
        browse_btn.clicked.connect(self.select_save_location)
        browse_layout.addWidget(browse_btn)
        
        self.decryption_key_field = StylishTextField("Decryption Key", "")
        self.decryption_key_field.setEchoMode(QLineEdit.Password)
        
        # Add fields to panel
        receive_panel.add_layout(browse_layout)
        receive_panel.add_widget(self.listen_port_field)
        receive_panel.add_widget(self.decryption_key_field)
        
        # Control buttons
        control_layout = QHBoxLayout()
        
        receive_btn = ActionButton("Start Receiving", accent_color=QColor(46, 204, 113))
        receive_btn.clicked.connect(self.start_receiving)
        
        stop_btn = ActionButton("Stop", accent_color=QColor(231, 76, 60))
        
        control_layout.addWidget(receive_btn)
        control_layout.addWidget(stop_btn)
        
        receive_panel.add_layout(control_layout)
        
        # Received files panel
        received_panel = MetroPanel("Received Files")
        
        # Create a log text area
        self.received_log = QTextEdit()
        self.received_log.setReadOnly(True)
        self.received_log.setStyleSheet("""
            QTextEdit {
                background-color: #222222;
                color: #e0e0e0;
                border: none;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Consolas', monospace;
            }
        """)
        self.received_log.setMinimumHeight(200)
        
        received_panel.add_widget(self.received_log)
        
        # Add everything to layout
        layout.addWidget(title_label)
        layout.addSpacing(20)
        layout.addWidget(receive_panel)
        layout.addWidget(received_panel)
        layout.addStretch()
        
        return page
        
    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        
        # Title
        title_label = QLabel("Settings")
        title_label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
            }
        """)
        
        # Network settings panel
        network_panel = MetroPanel("Network Settings")
        
        # Protocol selector
        protocol_label = QLabel("Protocol")
        protocol_label.setStyleSheet("color: #aaaaaa; font-size: 14px;")
        
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["UDP", "TCP"])
        self.protocol_combo.setStyleSheet("""
            QComboBox {
                background-color: #2a2a2a;
                color: #e0e0e0;
                border: none;
                border-radius: 4px;
                padding: 8px;
                min-width: 150px;
            }
            QComboBox::drop-down {
                width: 20px;
                border: none;
                border-left: 1px solid #555;
            }
            QComboBox QAbstractItemView {
                background-color: #2a2a2a;
                color: #e0e0e0;
                selection-background-color: #1e88e5;
            }
        """)
        
        # Timeout setting
        timeout_label = QLabel("Connection Timeout (sec)")
        timeout_label.setStyleSheet("color: #aaaaaa; font-size: 14px;")
        
        self.timeout_spinner = QSpinBox()
        self.timeout_spinner.setRange(1, 60)
        self.timeout_spinner.setValue(30)
        self.timeout_spinner.setStyleSheet("""
            QSpinBox {
                background-color: #2a2a2a;
                color: #e0e0e0;
                border: none;
                border-radius: 4px;
                padding: 8px;
                min-width: 150px;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                width: 20px;
                border: none;
                background-color: #444;
            }
        """)
        
        # Chunking settings
        chunk_label = QLabel("Chunk Size (bytes)")
        chunk_label.setStyleSheet("color: #aaaaaa; font-size: 14px;")
        
        self.chunk_spinner = QSpinBox()
        self.chunk_spinner.setRange(1, 16)
        self.chunk_spinner.setValue(8)
        self.chunk_spinner.setStyleSheet(self.timeout_spinner.styleSheet())
        
        # Add fields to panel
        network_panel.add_widget(protocol_label)
        network_panel.add_widget(self.protocol_combo)
        network_panel.add_widget(timeout_label)
        network_panel.add_widget(self.timeout_spinner)
        network_panel.add_widget(chunk_label)
        network_panel.add_widget(self.chunk_spinner)
        
        # Additional options panel
        options_panel = MetroPanel("Additional Options")
        
        # Auto-start option
        self.auto_start = QCheckBox("Start receiving on application launch")
        self.auto_start.setStyleSheet("""
            QCheckBox {
                color: #e0e0e0;
                font-size: 14px;
            }
            QCheckBox::indicator {
                width: 18px;
                height: 18px;
                background-color: #2a2a2a;
                border: 1px solid #555;
                border-radius: 4px;
            }
            QCheckBox::indicator:checked {
                background-color: #1e88e5;
                border: 1px solid #1e88e5;
                image: url('checkmark.png');
            }
        """)
        
        # Encryption option
        self.encryption_check = QCheckBox("Use additional encryption")
        self.encryption_check.setStyleSheet(self.auto_start.styleSheet())
        self.encryption_check.setChecked(True)
        
        # Log option
        self.log_check = QCheckBox("Save detailed logs")
        self.log_check.setStyleSheet(self.auto_start.styleSheet())
        
        # Add options to panel
        options_panel.add_widget(self.auto_start)
        options_panel.add_widget(self.encryption_check)
        options_panel.add_widget(self.log_check)
        
        # Save button
        save_btn = ActionButton("Save Settings", accent_color=QColor(155, 89, 182))
        save_btn.clicked.connect(self.save_settings)
        
        # Add everything to layout
        layout.addWidget(title_label)
        layout.addSpacing(20)
        
        # Create horizontal layout for panels
        panels_layout = QHBoxLayout()
        panels_layout.addWidget(network_panel)
        panels_layout.addWidget(options_panel)
        
        layout.addLayout(panels_layout)
        layout.addSpacing(20)
        layout.addWidget(save_btn, 0, Qt.AlignCenter)
        layout.addStretch()
        
        return page
        
    def create_connection_panel(self):
        panel = MetroPanel("Connection")
        
        self.target_ip_field = StylishTextField("Target IP", "192.168.1.10")
        self.target_port_field = StylishTextField("Target Port", "5555")
        self.encryption_key_field = StylishTextField("Encryption Key", "")
        self.encryption_key_field.setEchoMode(QLineEdit.Password)
        
        # Add widgets to panel
        panel.add_widget(self.target_ip_field)
        panel.add_widget(self.target_port_field)
        panel.add_widget(self.encryption_key_field)
        
        return panel
        
    def create_file_panel(self):
        panel = MetroPanel("File")
        
        # File selection field
        self.file_path_field = StylishTextField("File to Send", "")
        
        # Browse button
        browse_layout = QHBoxLayout()
        browse_layout.addWidget(self.file_path_field)
        
        browse_btn = QPushButton("Browse")
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #555555;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #666666;
            }
        """)
        browse_btn.clicked.connect(self.select_file)
        browse_layout.addWidget(browse_btn)
        
        # Send button
        send_btn = ActionButton("Encrypt & Send", accent_color=QColor(52, 152, 219))
        send_btn.clicked.connect(self.process_and_send)
        
        # Add everything to panel
        panel.add_layout(browse_layout)
        panel.add_widget(send_btn)
        
        return panel
        
    def create_visualization_panel(self):
        panel = MetroPanel("Network Visualization")
        
        # Create network visualization
        self.network_viz = NetworkVisualization()
        
        # Log output
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setStyleSheet("""
            QTextEdit {
                background-color: #222222;
                color: #e0e0e0;
                border: none;
                border-radius: 4px;
                padding: 10px;
                font-family: 'Consolas', monospace;
            }
        """)
        self.log.setMinimumHeight(150)
        
        # Add widgets to panel
        panel.add_widget(self.network_viz)
        panel.add_widget(self.log)
        
        return panel
        
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Send")
        if file_path:
            self.file_path_field.setText(file_path)
            self.log.append(f"Selected file: {file_path}")
            
    def select_save_location(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Received Data")
        if file_path:
            self.save_path_field.setText(file_path)
            self.received_log.append(f"Will save to: {file_path}")
            
    def process_and_send(self):
        # Get input values
        target_ip = self.target_ip_field.text()
        target_port = self.target_port_field.text()
        key = self.encryption_key_field.text()
        file_path = self.file_path_field.text()
        
        # Validate inputs
        if not all([target_ip, target_port, key, file_path]):
            self.status_label.show_message("Error: All fields are required", "error")
            return
            
        if not os.path.exists(file_path):
            self.status_label.show_message("Error: File not found", "error")
            return
            
        # Show progress dialog
        self.progress_dialog.set_status("Preparing for encryption...")
        self.progress_dialog.set_progress(0)
        self.progress_dialog.set_step(0)
        self.progress_dialog.show()
        
        # Simulate progress
        QTimer.singleShot(500, lambda: self.update_send_progress(0, file_path, target_ip, target_port))
        
        # Activate visualization
        self.network_viz.toggle_active(True)
        
    def update_send_progress(self, step, file_path, target_ip, target_port):
        if step == 0:
            # Reading file
            self.progress_dialog.set_step(0)
            self.progress_dialog.set_status("Reading file...")
            self.progress_dialog.set_progress(20)
            QTimer.singleShot(700, lambda: self.update_send_progress(1, file_path, target_ip, target_port))
            
        elif step == 1:
            # Encrypting
            self.progress_dialog.set_step(1)
            self.progress_dialog.set_status("Encrypting data...")
            self.progress_dialog.set_progress(50)
            self.log.append("Encrypting file data...")
            QTimer.singleShot(1000, lambda: self.update_send_progress(2, file_path, target_ip, target_port))
            
        elif step == 2:
            # Chunking
            self.progress_dialog.set_step(2)
            self.progress_dialog.set_status("Chunking encrypted data...")
            self.progress_dialog.set_progress(75)
            self.log.append("Splitting data into chunks...")
            QTimer.singleShot(800, lambda: self.update_send_progress(3, file_path, target_ip, target_port))
            
        elif step == 3:
            # Sending
            self.progress_dialog.set_step(3)
            self.progress_dialog.set_status("Sending data to target...")
            self.progress_dialog.set_progress(90)
            self.log.append(f"Sending data to {target_ip}:{target_port}")
            QTimer.singleShot(1200, lambda: self.update_send_progress(4, file_path, target_ip, target_port))
            
        elif step == 4:
            # Complete
            self.progress_dialog.set_progress(100)
            self.progress_dialog.set_status("Transfer complete!")
            self.log.append("Data successfully sent!")
            
            # Hide progress dialog after delay
            QTimer.singleShot(1000, self.progress_dialog.hide)
            
            # Show success message
            self.status_label.show_message("Data successfully sent!", "success")
            
            # Continue visualization for a bit before stopping
            QTimer.singleShot(3000, lambda: self.network_viz.toggle_active(False))
            
    def start_receiving(self):
        port = self.listen_port_field.text()
        save_path = self.save_path_field.text()
        key = self.decryption_key_field.text()
        
        if not all([port, save_path, key]):
            self.status_label.show_message("Error: All fields are required", "error")
            return
            
        # Start receiving simulation
        self.received_log.append(f"Listening on port {port}...")
        self.received_log.append("Waiting for incoming connections...")
        self.status_label.show_message("Listening for incoming data", "info")
        
    def save_settings(self):
        protocol = self.protocol_combo.currentText()
        timeout = self.timeout_spinner.value()
        chunk_size = self.chunk_spinner.value()
        auto_start = self.auto_start.isChecked()
        use_encryption = self.encryption_check.isChecked()
        save_logs = self.log_check.isChecked()
        
        # Log settings
        # Log settings
        settings_log = f"""Settings saved:
- Protocol: {protocol}
- Timeout: {timeout} seconds
- Chunk Size: {chunk_size} bytes
- Auto-start: {auto_start}
- Use Encryption: {use_encryption}
- Save Logs: {save_logs}
"""
        
        self.log.append(settings_log)
        self.status_label.show_message("Settings saved successfully", "success")
        
    def update_status_overlay(self):
        # Position the status label at the bottom of the window
        x = (self.width() - self.status_label.width()) / 2
        y = self.height() - self.status_label.height() - 20
        self.status_label.move(int(x), int(y))
        
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_status_overlay()
        
    def closeEvent(self, event):
        # Clean up resources
        self.network_viz.cleanup()
        super().closeEvent(event)

class SplashScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stealth Data Transfer")
        self.setWindowFlag(Qt.FramelessWindowHint)
        self.setGeometry(100, 100, 600, 400)
        
        # Set up the background
        self.setStyleSheet("""
            SplashScreen {
                background-color: #1a1a1a;
                border: 1px solid #333333;
                border-radius: 10px;
            }
        """)
        
        # Create layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setAlignment(Qt.AlignCenter)
        
        # Logo placeholder
        logo_label = QLabel()
        logo_label.setFixedSize(120, 120)
        logo_label.setStyleSheet("""
            QLabel {
                background-color: #1e88e5;
                border-radius: 60px;
            }
        """)
        logo_label.setAlignment(Qt.AlignCenter)
        
        # Application name
        app_name = QLabel("StealthData")
        app_name.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 36px;
                font-weight: bold;
            }
        """)
        
        # Description
        description = QLabel("Secure Network Steganography Tool")
        description.setStyleSheet("""
            QLabel {
                color: #aaaaaa;
                font-size: 16px;
            }
        """)
        
        # Progress bar
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(4)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: #333333;
                border: none;
            }
            QProgressBar::chunk {
                background-color: #1e88e5;
            }
        """)
        
        # Status label
        self.status = QLabel("Initializing...")
        self.status.setStyleSheet("""
            QLabel {
                color: #aaaaaa;
                font-size: 14px;
            }
        """)
        
        # Add widgets to layout
        layout.addStretch()
        layout.addWidget(logo_label, 0, Qt.AlignCenter)
        layout.addSpacing(30)
        layout.addWidget(app_name, 0, Qt.AlignCenter)
        layout.addWidget(description, 0, Qt.AlignCenter)
        layout.addSpacing(50)
        layout.addWidget(self.progress)
        layout.addSpacing(10)
        layout.addWidget(self.status, 0, Qt.AlignCenter)
        layout.addStretch()
        
        # Start initialization
        QTimer.singleShot(200, self.initialize_app)
        
    def initialize_app(self):
        # Simulate initialization steps
        steps = [
            ("Loading core modules...", 20),
            ("Initializing network components...", 40),
            ("Loading encryption libraries...", 60),
            ("Preparing interface...", 80),
            ("Ready!", 100)
        ]
        
        for i, (status, progress) in enumerate(steps):
            QTimer.singleShot(i * 800, lambda s=status, p=progress: self.update_progress(s, p))
            
        # Launch main app after all steps
        QTimer.singleShot(len(steps) * 800 + 500, self.launch_main_app)
        
    def update_progress(self, status, progress):
        self.status.setText(status)
        self.progress.setValue(progress)
        
    def launch_main_app(self):
        self.main_app = StegoGUI()
        self.main_app.show()
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Set app-wide font
    app.setFont(QFont("Segoe UI", 10))
    
    # Set dark palette for native elements
    palette = app.palette()
    palette.setColor(QPalette.Window, QColor(26, 26, 26))
    palette.setColor(QPalette.WindowText, QColor(234, 234, 234))
    palette.setColor(QPalette.Base, QColor(51, 51, 51))
    palette.setColor(QPalette.AlternateBase, QColor(56, 56, 56))
    palette.setColor(QPalette.Text, QColor(234, 234, 234))
    palette.setColor(QPalette.Button, QColor(59, 59, 59))
    palette.setColor(QPalette.ButtonText, QColor(234, 234, 234))
    palette.setColor(QPalette.BrightText, QColor(255, 255, 255))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
    app.setPalette(palette)
    
    # Show splash screen
    splash = SplashScreen()
    splash.show()
    
    sys.exit(app.exec())