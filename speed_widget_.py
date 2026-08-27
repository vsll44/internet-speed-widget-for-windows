\
\
\
\
\
\
\
\
\
\
\
\
\
\


import sys
import os
import time
import socket
import sqlite3
import subprocess
from datetime import datetime
from collections import deque

import psutil
import requests
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QSystemTrayIcon, QMenu, QGraphicsDropShadowEffect, QSizeGrip,
    QDialog, QTextEdit, QFrame
)
from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QPointF
from PyQt6.QtGui import QPainter, QPen, QColor, QFont, QIcon, QPixmap, QAction, QRegion

ACTIVE_TEST_INTERVAL = 10_000
PASSIVE_UPDATE_INTERVAL = 1_000
PING_INTERVAL = 2_000
NET_INFO_INTERVAL = 15_000
SUSPICIOUS_CHECK_INTERVAL = 30_000
ACTIVE_TEST_SIZE = 8_000_000
GRAPH_POINTS = 30
LOW_SPEED_THRESHOLD = 2.0
SUSPICIOUS_CONN_THRESHOLD = 60

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "speed_history.db")

THEMES = [
    {"name": "Narıncı", "accent": "#FF6B1A", "bg": "#0a0c12"},
    {"name": "Mavi", "accent": "#3B9DFF", "bg": "#0a0e14"},
    {"name": "Yaşıl", "accent": "#39FF88", "bg": "#0a120c"},
    {"name": "Bənövşəyi", "accent": "#B24BFF", "bg": "#0c0a14"},
    {"name": "Qırmızı", "accent": "#FF3B5C", "bg": "#120a0c"},
]

STARTUP_REG_NAME = "InternetSpeedWidget"




def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except OSError:
        ip = "Naməlum"
    finally:
        s.close()
    return ip


def get_connection_type(local_ip):
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    lname = name.lower()
                    if "wi-fi" in lname or "wlan" in lname or "wireless" in lname:
                        return "Wi-Fi"
                    elif "ethernet" in lname or "lan" in lname:
                        return "Ethernet"
                    return name
    except Exception:
        pass
    return "Naməlum"


def get_hotspot_info():
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, if_stats in stats.items():
            lname = name.lower()
            is_hotspot_adapter = (
                "local area connection*" in lname
                or "wi-fi direct" in lname
                or "microsoft hosted network" in lname
            )
            if is_hotspot_adapter and if_stats.isup:
                ipv4 = next((a.address for a in addrs.get(name, []) if a.family == socket.AF_INET), None)
                if not ipv4:
                    continue
                subnet_prefix = ".".join(ipv4.split(".")[:3])
                count = _count_arp_in_subnet(subnet_prefix, ipv4)
                return True, count
        return False, 0
    except Exception:
        return False, 0


def _get_arp_table():

    entries = []
    try:
        output = subprocess.check_output(
            "arp -a", shell=True, text=True, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        for line in output.splitlines():
            line = line.strip()
            parts = line.split()
            if len(parts) >= 2 and parts[0].count(".") == 3:
                ip, mac = parts[0], parts[1]
                if mac.lower() != "ff-ff-ff-ff-ff-ff" and "static" not in line.lower():
                    entries.append((ip, mac))
    except Exception:
        pass
    return entries


def _count_arp_in_subnet(subnet_prefix, own_ip):
    count = 0
    for ip, mac in _get_arp_table():
        if ip.startswith(subnet_prefix) and ip != own_ip:
            count += 1
    return count


def get_lan_devices(local_ip):

    subnet_prefix = ".".join(local_ip.split(".")[:3])
    devices = []
    for ip, mac in _get_arp_table():
        if ip.startswith(subnet_prefix) and ip != local_ip:
            devices.append((ip, mac))
    return devices


def measure_ping(host="8.8.8.8", port=53, timeout=1.5):
    start = time.time()
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return (time.time() - start) * 1000
    except OSError:
        return -1


def get_suspicious_processes():

    counts = {}
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid:
                counts[conn.pid] = counts.get(conn.pid, 0) + 1
    except (psutil.AccessDenied, PermissionError):
        return []

    suspicious = []
    for pid, count in counts.items():
        if count >= SUSPICIOUS_CONN_THRESHOLD:
            try:
                name = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = f"PID {pid}"
            suspicious.append((name, count))
    return suspicious


def get_taskbar_rect_qt(app):
\
\
\
\

    screen = app.primaryScreen()
    full = screen.geometry()
    avail = screen.availableGeometry()

    if avail.bottom() < full.bottom():
        return full.left(), avail.bottom() + 1, full.right() + 1, full.bottom() + 1
    elif avail.top() > full.top():
        return full.left(), full.top(), full.right() + 1, avail.top()
    elif avail.left() > full.left():
        return full.left(), full.top(), avail.left(), full.bottom() + 1
    elif avail.right() < full.right():
        return avail.right() + 1, full.top(), full.right() + 1, full.bottom() + 1
    return None




def is_in_startup():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Run",
                             0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, STARTUP_REG_NAME)
            return True
    except Exception:
        return False


def set_startup(enabled):
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                pythonw = sys.executable.replace("python.exe", "pythonw.exe")
                script = os.path.abspath(__file__)
                winreg.SetValueEx(key, STARTUP_REG_NAME, 0, winreg.REG_SZ, f'"{pythonw}" "{script}"')
            else:
                try:
                    winreg.DeleteValue(key, STARTUP_REG_NAME)
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False




def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(\
                                                   )
    conn.commit()
    conn.close()


def save_speed_record(mbps):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("INSERT INTO history VALUES (?, ?)",
                      (datetime.now().isoformat(), mbps))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_today_stats():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.execute(
            "SELECT AVG(mbps), MIN(mbps), MAX(mbps), COUNT(*) FROM history "
            "WHERE date(timestamp) = date('now', 'localtime')"
        )
        row = cur.fetchone()
        conn.close()
        return row
    except Exception:
        return (None, None, None, 0)




class ActiveSpeedTestThread(QThread):
    result_ready = pyqtSignal(float, int)

    def run(self):
        try:
            url = f"https://speed.cloudflare.com/__down?bytes={ACTIVE_TEST_SIZE}"
            start = time.time()
            response = requests.get(url, stream=True, timeout=15)
            total = 0
            for chunk in response.iter_content(chunk_size=1024 * 64):
                total += len(chunk)
            elapsed = time.time() - start
            if elapsed > 0:
                mbps = (total * 8) / elapsed / 1_000_000
                self.result_ready.emit(mbps, total)
            else:
                self.result_ready.emit(-1, 0)
        except requests.exceptions.RequestException:
            self.result_ready.emit(-1, 0)


class NetworkInfoThread(QThread):
    info_ready = pyqtSignal(str, str, bool, int)

    def run(self):
        ip = get_local_ip()
        conn_type = get_connection_type(ip)
        hotspot_active, device_count = get_hotspot_info()
        self.info_ready.emit(ip, conn_type, hotspot_active, device_count)


class PingThread(QThread):
    ping_ready = pyqtSignal(float)

    def run(self):
        self.ping_ready.emit(measure_ping())


class SuspiciousCheckThread(QThread):
    result_ready = pyqtSignal(list)

    def run(self):
        self.result_ready.emit(get_suspicious_processes())




class SpeedGraph(QWidget):
    def __init__(self, accent_color):
        super().__init__()
        self.setMinimumHeight(36)
        self.values = deque([0] * GRAPH_POINTS, maxlen=GRAPH_POINTS)
        self.accent_color = accent_color

    def set_accent(self, color):
        self.accent_color = color
        self.update()

    def add_value(self, val):
        self.values.append(val)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()

        grid_pen = QPen(QColor(255, 255, 255, 15), 1)
        painter.setPen(grid_pen)
        for gx in range(0, w, 20):
            painter.drawLine(gx, 0, gx, h)
        for gy in range(0, h, 12):
            painter.drawLine(0, gy, w, gy)

        max_val = max(max(self.values), 1)
        points, step = [], w / (GRAPH_POINTS - 1)
        for i, val in enumerate(self.values):
            x = i * step
            y = h - (val / max_val) * (h - 4) - 2
            points.append(QPointF(x, y))

        pen = QPen(QColor(self.accent_color), 2)
        painter.setPen(pen)
        for i in range(len(points) - 1):
            painter.drawLine(points[i], points[i + 1])




class InfoDialog(QDialog):
    def __init__(self, title, text, theme, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setFixedSize(320, 260)
        self.setStyleSheet(f"background-color: {theme['bg']}; color: #ddd;")
        layout = QVBoxLayout()
        box = QTextEdit()
        box.setReadOnly(True)
        box.setFont(QFont("Consolas", 9))
        box.setStyleSheet(f"background-color: #111; color: {theme['accent']}; border: none;")
        box.setText(text)
        layout.addWidget(box)
        self.setLayout(layout)




class SpeedWidget(QWidget):
    def __init__(self):
        super().__init__()
        init_db()
        self.total_used = 0
        self.theme_index = 0
        self.compact = False
        self.taskbar_mode = False
        self.pre_taskbar_geometry = None
        self.disconnected_alerted = False
        self.low_speed_alerted = False
        self.alerted_processes = set()
        self.full_size = (250, 300)

        self.init_ui()
        self.apply_theme()
        self.init_timers()


    def init_ui(self):
        self.setWindowTitle("Sürət Monitoru")
        self.resize(*self.full_size)
        self.setMinimumSize(90, 90)
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
        self.drag_pos = None
        self.init_tray()

        self.mono_font = QFont("Consolas", 9)
        self.label_font = QFont("Consolas", 8)


        outer = QVBoxLayout()
        outer.setContentsMargins(14, 14, 14, 14)
        self.setLayout(outer)
        self.outer_layout = outer


        self.card = QWidget()
        self.card.setObjectName("card")
        outer.addWidget(self.card)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(35)
        shadow.setOffset(0, 6)
        shadow.setColor(QColor(0, 0, 0, 180))
        self.card.setGraphicsEffect(shadow)

        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(16, 14, 16, 10)
        self.main_layout.setSpacing(7)
        self.card.setLayout(self.main_layout)


        top_row = QHBoxLayout()
        top_row.setSpacing(4)
        self.title_label = QLabel("● LIVE")
        self.title_label.setFont(self.mono_font)
        top_row.addWidget(self.title_label)
        top_row.addStretch()

        self.devices_btn = self._make_icon_btn("🖧", self.show_devices)
        self.history_btn = self._make_icon_btn("📈", self.show_history)
        self.theme_btn = self._make_icon_btn("🎨", self.next_theme)
        self.compact_btn = self._make_icon_btn("⭘", self.toggle_compact)
        self.taskbar_btn = self._make_icon_btn("▭", self.toggle_taskbar_mode)
        self.hide_btn = self._make_icon_btn("—", self.hide_to_tray)

        for b in [self.devices_btn, self.history_btn, self.theme_btn, self.compact_btn,
                  self.taskbar_btn, self.hide_btn]:
            top_row.addWidget(b)

        self.main_layout.addLayout(top_row)
        self.main_layout.addWidget(self._divider())


        speed_row = QHBoxLayout()
        speed_row.setSpacing(6)
        speed_row.setAlignment(Qt.AlignmentFlag.AlignBottom)
        self.speed_value_label = QLabel("--")
        self.speed_value_label.setFont(QFont("Consolas", 30, QFont.Weight.Bold))
        self.speed_unit_label = QLabel("Mbps")
        self.speed_unit_label.setFont(QFont("Consolas", 11))
        speed_row.addWidget(self.speed_value_label)
        speed_row.addWidget(self.speed_unit_label)
        speed_row.addStretch()
        self.main_layout.addLayout(speed_row)


        self.graph = SpeedGraph(THEMES[0]["accent"])
        self.main_layout.addWidget(self.graph)
        self.main_layout.addWidget(self._divider())


        self.taskbar_container = QWidget()
        tb_layout = QHBoxLayout()
        tb_layout.setContentsMargins(0, 0, 0, 0)
        tb_layout.setSpacing(8)
        self.taskbar_speed_label = QLabel("--")
        self.taskbar_speed_label.setFont(QFont("Consolas", 13, QFont.Weight.Bold))
        self.taskbar_graph = SpeedGraph(THEMES[0]["accent"])
        self.taskbar_graph.setFixedSize(60, 22)
        tb_layout.addWidget(self.taskbar_speed_label)
        tb_layout.addWidget(self.taskbar_graph)
        tb_layout.addStretch()
        self.taskbar_container.setLayout(tb_layout)
        self.taskbar_container.setVisible(False)
        self.main_layout.addWidget(self.taskbar_container)


        self.ping_label = QLabel("🏓  Ping  --  ms")
        self.ping_label.setFont(self.label_font)
        self.main_layout.addWidget(self.ping_label)


        self.conn_label = QLabel("📶  --  ·  IP --")
        self.conn_label.setFont(self.label_font)
        self.main_layout.addWidget(self.conn_label)


        self.hotspot_label = QLabel("🔥  Hotspot  --")
        self.hotspot_label.setFont(self.label_font)
        self.main_layout.addWidget(self.hotspot_label)

        self.main_layout.addWidget(self._divider())


        bottom_layout = QHBoxLayout()
        self.data_label = QLabel("0 MB istifadə")
        self.data_label.setFont(self.label_font)
        self.status_label = QLabel("●")
        bottom_layout.addWidget(self.data_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.status_label)
        self.main_layout.addLayout(bottom_layout)


        grip_row = QHBoxLayout()
        grip_row.addStretch()
        self.size_grip = QSizeGrip(self.card)
        grip_row.addWidget(self.size_grip)
        self.main_layout.addLayout(grip_row)


        self.full_mode_widgets = [
            self.graph, self.ping_label, self.conn_label,
            self.hotspot_label, self.data_label, self.status_label,
            self.devices_btn, self.history_btn, self.title_label, self.size_grip,
            self.speed_unit_label, self.taskbar_btn
        ]

        self.full_mode_widgets.extend(self.dividers)


        self.taskbar_hide_widgets = list(self.full_mode_widgets) + [
            self.theme_btn, self.compact_btn, self.hide_btn
        ]

    def _divider(self):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFixedHeight(1)
        if not hasattr(self, "dividers"):
            self.dividers = []
        self.dividers.append(line)
        return line

    def _make_icon_btn(self, text, callback):
        btn = QLabel(text)
        btn.setFixedSize(20, 20)
        btn.setAlignment(Qt.AlignmentFlag.AlignCenter)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.mousePressEvent = lambda e: callback()
        return btn

    def apply_theme(self):
        theme = THEMES[self.theme_index]
        accent, bg = theme["accent"], theme["bg"]
        if self.taskbar_mode:
            radius = f"{self.height() // 2}px"
            self.card.setStyleSheet(f"""
                #card {{
                    background-color: rgba(18, 18, 22, 235);
                    border: 1px solid rgba(255, 255, 255, 25);
                    border-radius: {radius};
                }}
            """)
        else:
            radius = "50px" if self.compact else "18px"
            self.card.setStyleSheet(f"""
                #card {{
                    background-color: {bg};
                    border: 1px solid {accent}55;
                    border-radius: {radius};
                }}
            """)

        muted = "#8a8f98"
        chip_style = (
            f"background-color: rgba(255,255,255,12); border-radius: 6px; "
            f"font-size: 11px; color: {muted};"
        )
        for btn in [self.devices_btn, self.history_btn, self.theme_btn,
                    self.compact_btn, self.taskbar_btn, self.hide_btn]:
            btn.setStyleSheet(chip_style)

        self.title_label.setStyleSheet(
            f"color: {accent}; font-size: 9px; font-weight: bold; letter-spacing: 1px;"
        )
        self.speed_value_label.setStyleSheet(f"color: {accent};")
        self.taskbar_speed_label.setStyleSheet(f"color: {accent};")
        self.speed_unit_label.setStyleSheet(f"color: {muted};")
        self.conn_label.setStyleSheet(f"color: {muted}; font-size: 10px;")
        self.hotspot_label.setStyleSheet(f"color: {muted}; font-size: 10px;")
        self.ping_label.setStyleSheet(f"color: {muted}; font-size: 10px;")
        self.data_label.setStyleSheet(f"color: {muted}; font-size: 9px;")
        self.status_label.setStyleSheet("color: #4CAF50; font-size: 10px;")

        for line in self.dividers:
            line.setStyleSheet(f"background-color: {accent}30; border: none;")

        self.graph.set_accent(accent)
        self.taskbar_graph.set_accent(accent)

        glow = QGraphicsDropShadowEffect()
        glow.setBlurRadius(25)
        glow.setColor(QColor(accent))
        glow.setOffset(0, 0)
        self.speed_value_label.setGraphicsEffect(glow)

    def next_theme(self):
        self.theme_index = (self.theme_index + 1) % len(THEMES)
        self.apply_theme()


    def toggle_compact(self):
        self.compact = not self.compact
        for w in self.full_mode_widgets:
            w.setVisible(not self.compact)

        if self.compact:
            self.full_size = (self.width(), self.height())
            self.resize(110, 110)
            self.setMinimumSize(110, 110)
            self.setMaximumSize(110, 110)
            self.speed_value_label.setFont(QFont("Consolas", 15, QFont.Weight.Bold))
            self.speed_value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setMask(QRegion(self.rect(), QRegion.RegionType.Ellipse))
        else:
            self.clearMask()
            self.setMaximumSize(16777215, 16777215)
            self.setMinimumSize(90, 90)
            self.resize(*self.full_size)
            self.speed_value_label.setFont(QFont("Consolas", 30, QFont.Weight.Bold))
            self.speed_value_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.apply_theme()

    def toggle_taskbar_mode(self):
        if not self.taskbar_mode:
            rect = get_taskbar_rect_qt(QApplication.instance())
            if rect is None:
                self.tray.showMessage(
                    "Xəta", "Taskbar tapılmadı (yalnız Windows-da işləyir).",
                    QSystemTrayIcon.MessageIcon.Warning, 2500
                )
                return

            self.pre_taskbar_geometry = (self.pos(), self.size(), self.compact)
            if self.compact:
                self.toggle_compact()

            left, top, right, bottom = rect
            height = bottom - top
            width = 190

            for w in self.taskbar_hide_widgets:
                w.setVisible(False)
            self.speed_value_label.setVisible(False)

            self.taskbar_mode = True
            self.taskbar_y = top
            self.outer_layout.setContentsMargins(0, 0, 0, 0)
            self.card.setGraphicsEffect(None)
            self.main_layout.setContentsMargins(14, 2, 14, 2)
            self.main_layout.setSpacing(0)
            self.taskbar_container.setVisible(True)


            start_x = min(left + 520, right - width - 10)
            self.setMinimumSize(110, height)
            self.setMaximumSize(600, height)
            self.resize(width, height)
            self.move(start_x, top)
        else:
            self.taskbar_mode = False
            self.taskbar_container.setVisible(False)
            self.speed_value_label.setVisible(True)
            self.outer_layout.setContentsMargins(14, 14, 14, 14)
            self.main_layout.setContentsMargins(16, 14, 16, 10)
            self.main_layout.setSpacing(7)
            shadow = QGraphicsDropShadowEffect()
            shadow.setBlurRadius(35)
            shadow.setOffset(0, 6)
            shadow.setColor(QColor(0, 0, 0, 180))
            self.card.setGraphicsEffect(shadow)
            self.speed_value_label.setFont(QFont("Consolas", 30, QFont.Weight.Bold))
            self.speed_value_label.setAlignment(Qt.AlignmentFlag.AlignLeft)

            for w in self.taskbar_hide_widgets:
                w.setVisible(True)

            self.setMaximumSize(16777215, 16777215)
            self.setMinimumSize(90, 90)
            if self.pre_taskbar_geometry:
                pos, size, was_compact = self.pre_taskbar_geometry
                self.resize(size)
                self.move(pos)

        self.apply_theme()

    def resizeEvent(self, event):
        if self.compact:
            self.setMask(QRegion(self.rect(), QRegion.RegionType.Ellipse))
        super().resizeEvent(event)


    def init_tray(self):
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor(THEMES[0]["accent"]))
        icon = QIcon(pixmap)

        self.tray = QSystemTrayIcon(icon, self)
        self.tray.setToolTip("İnternet Sürəti Monitoru")

        menu = QMenu()
        show_action = QAction("Göstər", self)
        show_action.triggered.connect(self.show_from_tray)

        self.startup_action = QAction("Başlanğıca əlavə et", self)
        self.startup_action.setCheckable(True)
        self.startup_action.setChecked(is_in_startup())
        self.startup_action.triggered.connect(self.toggle_startup)

        quit_action = QAction("Çıx", self)
        quit_action.triggered.connect(QApplication.instance().quit)

        menu.addAction(show_action)
        menu.addAction(self.startup_action)
        menu.addAction(quit_action)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.show()

    def toggle_startup(self, checked):
        success = set_startup(checked)
        if not success:
            self.startup_action.setChecked(not checked)
            self.tray.showMessage("Xəta", "Başlanğıc tənzimlənə bilmədi.",
                                   QSystemTrayIcon.MessageIcon.Warning, 2000)

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible():
                self.hide()
            else:
                self.show_from_tray()

    def hide_to_tray(self):
        self.hide()
        self.tray.showMessage("Sürət Monitoru", "Arxa planda işləyir.",
                               QSystemTrayIcon.MessageIcon.Information, 1500)

    def show_from_tray(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, event):
        event.ignore()
        self.hide_to_tray()


    def show_devices(self):
        ip = get_local_ip()
        devices = get_lan_devices(ip)
        theme = THEMES[self.theme_index]
        if not devices:
            text = "Heç bir cihaz tapılmadı.\n(Yalnız son vaxtlarda əlaqədə\nolan cihazlar görünür)"
        else:
            text = f"Sənin IP: {ip}\n\nTapılan cihazlar ({len(devices)}):\n\n"
            for ip_addr, mac in devices:
                text += f"  {ip_addr}   {mac}\n"
        dlg = InfoDialog("Şəbəkədəki Cihazlar", text, theme, self)
        dlg.exec()

    def show_history(self):
        avg, mn, mx, count = get_today_stats()
        theme = THEMES[self.theme_index]
        if count == 0:
            text = "Bu gün üçün hələ məlumat yoxdur.\nBir az gözlə, testlər toplanır."
        else:
            text = (
                f"BU GÜNKÜ STATİSTİKA\n\n"
                f"  Ortalama sürət: {avg:.1f} Mbps\n"
                f"  Ən aşağı:       {mn:.1f} Mbps\n"
                f"  Ən yüksək:      {mx:.1f} Mbps\n"
                f"  Test sayı:      {count}\n"
            )
        dlg = InfoDialog("Sürət Tarixçəsi", text, theme, self)
        dlg.exec()


    def init_timers(self):
        counters = psutil.net_io_counters()
        self.prev_recv = counters.bytes_recv
        self.prev_time = time.time()

        self.passive_timer = QTimer()
        self.passive_timer.timeout.connect(self.update_passive)
        self.passive_timer.start(PASSIVE_UPDATE_INTERVAL)

        self.active_timer = QTimer()
        self.active_timer.timeout.connect(self.run_active_test)
        self.active_timer.start(ACTIVE_TEST_INTERVAL)

        self.ping_timer = QTimer()
        self.ping_timer.timeout.connect(self.run_ping)
        self.ping_timer.start(PING_INTERVAL)

        self.net_info_timer = QTimer()
        self.net_info_timer.timeout.connect(self.run_network_info)
        self.net_info_timer.start(NET_INFO_INTERVAL)

        self.suspicious_timer = QTimer()
        self.suspicious_timer.timeout.connect(self.run_suspicious_check)
        self.suspicious_timer.start(SUSPICIOUS_CHECK_INTERVAL)

        self.run_active_test()
        self.run_network_info()
        self.run_ping()

    def update_passive(self):
        counters = psutil.net_io_counters()
        curr_recv, curr_time = counters.bytes_recv, time.time()
        time_diff = curr_time - self.prev_time
        recv_diff = curr_recv - self.prev_recv
        if time_diff > 0:
            mbps = (recv_diff * 8) / time_diff / 1_000_000
            self.graph.add_value(mbps)
            self.taskbar_graph.add_value(mbps)
        self.prev_recv, self.prev_time = curr_recv, curr_time

    def run_active_test(self):
        self.status_label.setStyleSheet("color: #FFA500; font-size: 10px;")
        self.thread = ActiveSpeedTestThread()
        self.thread.result_ready.connect(self.on_active_result)
        self.thread.start()

    def on_active_result(self, mbps, used_bytes):
        if mbps < 0:
            self.speed_value_label.setText("--")
            self.speed_unit_label.setText("xəta")
            self.taskbar_speed_label.setText("--")
            self.status_label.setStyleSheet("color: #F44336; font-size: 10px;")
            if not self.disconnected_alerted:
                self.tray.showMessage("⚠ İnternet kəsildi!",
                                       "Bağlantı itdi və ya çox zəifdir.",
                                       QSystemTrayIcon.MessageIcon.Warning, 3000)
                self.disconnected_alerted = True
            return

        if self.disconnected_alerted:
            self.tray.showMessage("✓ Bağlantı bərpa olundu", f"{mbps:.1f} Mbps",
                                   QSystemTrayIcon.MessageIcon.Information, 2000)
            self.disconnected_alerted = False

        if mbps < LOW_SPEED_THRESHOLD:
            if not self.low_speed_alerted:
                self.tray.showMessage("⚠ Sürət çox aşağıdır",
                                       f"Hazırkı sürət: {mbps:.1f} Mbps",
                                       QSystemTrayIcon.MessageIcon.Warning, 3000)
                self.low_speed_alerted = True
        else:
            self.low_speed_alerted = False

        self.speed_value_label.setText(f"{mbps:.1f}")
        self.speed_unit_label.setText("Mbps")
        self.taskbar_speed_label.setText(f"{mbps:.1f}")
        self.status_label.setStyleSheet("color: #4CAF50; font-size: 10px;")

        self.total_used += used_bytes
        data_str = f"{self.total_used / 1024:.0f} KB" if self.total_used < 1024 ** 2 else f"{self.total_used / (1024 ** 2):.1f} MB"
        self.data_label.setText(f"{data_str} istifadə")

        save_speed_record(mbps)

    def run_ping(self):
        self.ping_thread = PingThread()
        self.ping_thread.ping_ready.connect(self.on_ping_result)
        self.ping_thread.start()

    def on_ping_result(self, ms):
        if ms < 0:
            self.ping_label.setText("🏓 Ping: -- ms")
        else:
            quality = "🟢" if ms < 50 else ("🟡" if ms < 150 else "🔴")
            self.ping_label.setText(f"🏓 Ping: {ms:.0f} ms {quality}")

    def run_network_info(self):
        self.net_thread = NetworkInfoThread()
        self.net_thread.info_ready.connect(self.on_network_info)
        self.net_thread.start()

    def on_network_info(self, ip, conn_type, hotspot_active, device_count):
        icon = "📶" if conn_type == "Wi-Fi" else ("🔌" if conn_type == "Ethernet" else "🌐")
        self.conn_label.setText(f"{icon} {conn_type} | IP: {ip}")
        if hotspot_active:
            self.hotspot_label.setText(f"🔥 Hotspot: Aktiv | {device_count} cihaz")
        else:
            self.hotspot_label.setText("🔥 Hotspot: Deaktiv")

    def run_suspicious_check(self):
        self.susp_thread = SuspiciousCheckThread()
        self.susp_thread.result_ready.connect(self.on_suspicious_result)
        self.susp_thread.start()

    def on_suspicious_result(self, suspicious_list):
        for name, count in suspicious_list:
            if name not in self.alerted_processes:
                self.tray.showMessage(
                    "⚠ Şübhəli trafik aktivliyi",
                    f"'{name}' prosesi {count} bağlantı açıb.",
                    QSystemTrayIcon.MessageIcon.Warning, 3000
                )
                self.alerted_processes.add(name)


    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.drag_pos is not None and event.buttons() == Qt.MouseButton.LeftButton:
            new_pos = event.globalPosition().toPoint() - self.drag_pos
            if self.taskbar_mode:

                self.move(new_pos.x(), self.taskbar_y)
            else:
                self.move(new_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.drag_pos = None

    def mouseDoubleClickEvent(self, event):
        if self.taskbar_mode:
            self.toggle_taskbar_mode()

    def wheelEvent(self, event):
        if self.taskbar_mode:
            delta = event.angleDelta().y()
            step = 15 if delta > 0 else -15
            new_width = max(110, min(600, self.width() + step))
            self.resize(new_width, self.height())
            event.accept()


def main():
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    widget = SpeedWidget()
    widget.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
