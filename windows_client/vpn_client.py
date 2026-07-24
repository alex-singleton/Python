"""
VPN Client - Windows proqrami.
PyQt5 esasli GUI, login, connect/disconnect, system tray.
"""
import sys
import os
import time
import threading
import requests

# Config import
if getattr(sys, 'frozen', False):
    # PyInstaller EXE rejimi
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, app_dir)

from config import *

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSystemTrayIcon, QMenu,
    QAction, QFrame
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt5.QtGui import QIcon


class APIClient:
    """Server API ile elaqe."""

    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.session.timeout = 10

    def login(self, username, password):
        try:
            resp = self.session.post(
                SERVER_URL + API_LOGIN,
                json={"username": username, "password": password}
            )
            data = resp.json()
            if data.get("success"):
                self.token = data["token"]
            return data
        except requests.ConnectionError:
            return {"success": False, "message": "Servere qosulmaq mumkun olmadi"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def connect(self):
        try:
            resp = self.session.post(
                SERVER_URL + API_CONNECT,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            return resp.json()
        except requests.ConnectionError:
            return {"success": False, "message": "Server elcatan deyil"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def disconnect(self):
        try:
            resp = self.session.post(
                SERVER_URL + API_DISCONNECT,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            self.token = None
            return resp.json()
        except Exception:
            self.token = None
            return {"success": True, "message": "Baglanti kesildi"}

    def get_status(self):
        try:
            resp = self.session.get(
                SERVER_URL + API_STATUS,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            return resp.json()
        except Exception:
            return {"success": False, "connected": False}

    def ping(self):
        try:
            resp = self.session.get(SERVER_URL + API_PING, timeout=5)
            return resp.json().get("success", False)
        except Exception:
            return False


class ProxyThread(QThread):
    """Windows system proxy tenzimleme."""

    def __init__(self, proxy_host, proxy_port):
        super().__init__()
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def run(self):
        self.set_system_proxy(True)

    def stop(self):
        self.set_system_proxy(False)

    def set_system_proxy(self, enable):
        if sys.platform != "win32":
            return
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                                winreg.KEY_SET_VALUE)
            if enable:
                proxy_str = f"socks={self.proxy_host}:{self.proxy_port}"
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy_str)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except Exception:
            pass


class LoginWindow(QWidget):
    """Login penceresi."""
    login_success = pyqtSignal(dict)

    def __init__(self, api_client):
        super().__init__()
        self.api = api_client
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle(f"{APP_NAME} - Giris")
        self.setFixedSize(380, 480)
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a2e;
                color: #eaeaea;
                font-family: 'Segoe UI', Arial;
            }
            QLineEdit {
                background-color: #16213e;
                border: 1px solid #0f3460;
                border-radius: 8px;
                padding: 10px 15px;
                color: #eaeaea;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #e94560;
            }
            QPushButton#loginBtn {
                background-color: #e94560;
                border: none;
                border-radius: 8px;
                padding: 12px;
                color: white;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton#loginBtn:hover {
                background-color: #d63851;
            }
            QLabel#title {
                font-size: 24px;
                font-weight: bold;
                color: #e94560;
            }
            QLabel#subtitle {
                font-size: 12px;
                color: #888;
            }
            QLabel#error {
                color: #e94560;
                font-size: 12px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(15)

        layout.addSpacing(20)
        title = QLabel("VPN Client")
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Tehlukesiz baglanti")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        layout.addSpacing(30)

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Istifadeci adi")
        layout.addWidget(self.username_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Parol")
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)

        layout.addSpacing(10)
        self.login_btn = QPushButton("Daxil Ol")
        self.login_btn.setObjectName("loginBtn")
        self.login_btn.clicked.connect(self.do_login)
        layout.addWidget(self.login_btn)

        self.error_label = QLabel("")
        self.error_label.setObjectName("error")
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        self.status_label = QLabel("")
        self.status_label.setObjectName("subtitle")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        layout.addStretch()

        server_label = QLabel(f"Server: {SERVER_URL}")
        server_label.setObjectName("subtitle")
        server_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(server_label)

        self.setLayout(layout)
        self.password_input.returnPressed.connect(self.do_login)
        self.username_input.returnPressed.connect(
            lambda: self.password_input.setFocus()
        )
        self.check_server()

    def check_server(self):
        if self.api.ping():
            self.status_label.setText("Server: Elcatan")
            self.status_label.setStyleSheet("color: #4caf50;")
        else:
            self.status_label.setText("Server: Elcatmaz")
            self.status_label.setStyleSheet("color: #e94560;")

    def do_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if not username or not password:
            self.error_label.setText("Istifadeci adi ve parol daxil edin")
            return

        self.login_btn.setEnabled(False)
        self.login_btn.setText("Gozleyin...")
        self.error_label.setText("")

        result = self.api.login(username, password)

        self.login_btn.setEnabled(True)
        self.login_btn.setText("Daxil Ol")

        if result.get("success"):
            self.login_success.emit(result)
        else:
            self.error_label.setText(result.get("message", "Xeta bas verdi"))


class MainWindow(QWidget):
    """Esas VPN penceresi."""

    def __init__(self, api_client, user_data):
        super().__init__()
        self.api = api_client
        self.user_data = user_data
        self.connected = False
        self.proxy_thread = None
        self.connect_time = None
        self.parent_app = None
        self.init_ui()
        self.init_tray()
        self.start_timers()

    def init_ui(self):
        self.setWindowTitle(APP_NAME)
        self.setFixedSize(380, 520)
        self.setStyleSheet("""
            QWidget {
                background-color: #1a1a2e;
                color: #eaeaea;
                font-family: 'Segoe UI', Arial;
            }
            QPushButton#connectBtn {
                background-color: #4caf50;
                border: none;
                border-radius: 40px;
                color: white;
                font-size: 16px;
                font-weight: bold;
                min-width: 120px;
                min-height: 120px;
            }
            QPushButton#connectBtn:hover {
                background-color: #45a049;
            }
            QPushButton#disconnectBtn {
                background-color: #e94560;
                border: none;
                border-radius: 40px;
                color: white;
                font-size: 16px;
                font-weight: bold;
                min-width: 120px;
                min-height: 120px;
            }
            QPushButton#disconnectBtn:hover {
                background-color: #d63851;
            }
            QLabel#statusLabel {
                font-size: 18px;
                font-weight: bold;
            }
            QLabel#infoLabel {
                font-size: 12px;
                color: #888;
            }
            QFrame#infoFrame {
                background-color: #16213e;
                border-radius: 10px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Header
        header = QHBoxLayout()
        user_info = self.user_data.get("user", {})
        user_label = QLabel(f"Salam, {user_info.get('username', '')}")
        user_label.setStyleSheet("font-size: 14px; color: #888;")
        header.addWidget(user_label)
        header.addStretch()

        logout_btn = QPushButton("Cixis")
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #e94560;
                border-radius: 5px;
                padding: 5px 15px;
                color: #e94560; font-size: 12px;
            }
            QPushButton:hover { background-color: #e94560; color: white; }
        """)
        logout_btn.clicked.connect(self.do_logout)
        header.addWidget(logout_btn)
        layout.addLayout(header)

        # Status
        self.status_label = QLabel("Baglanti Kesik")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #e94560;")
        layout.addWidget(self.status_label)

        layout.addSpacing(10)

        # Connect button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.connect_btn = QPushButton("QOSUL")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.clicked.connect(self.toggle_connection)
        btn_layout.addWidget(self.connect_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addSpacing(15)

        # Info panel
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(15, 15, 15, 15)

        traffic_limit = user_info.get("traffic_limit_gb", 0)
        traffic_used = user_info.get("traffic_used_mb", 0)
        expire = user_info.get("expire_date", "Limitsiz")

        self.traffic_label = QLabel(
            f"Trafik: {traffic_used:.1f} MB"
            + (f" / {traffic_limit} GB" if traffic_limit > 0 else " (Limitsiz)")
        )
        self.traffic_label.setObjectName("infoLabel")
        info_layout.addWidget(self.traffic_label)

        expire_label = QLabel(f"Muddet: {expire or 'Limitsiz'}")
        expire_label.setObjectName("infoLabel")
        info_layout.addWidget(expire_label)

        self.time_label = QLabel("Baglanti muddeti: --:--:--")
        self.time_label.setObjectName("infoLabel")
        info_layout.addWidget(self.time_label)

        server_label = QLabel(f"Server: {SERVER_URL}")
        server_label.setObjectName("infoLabel")
        info_layout.addWidget(server_label)

        layout.addWidget(info_frame)
        layout.addStretch()

        version_label = QLabel(f"{APP_NAME} v{APP_VERSION}")
        version_label.setObjectName("infoLabel")
        version_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(version_label)

        self.setLayout(layout)

    def init_tray(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip(APP_NAME)

        tray_menu = QMenu()
        show_action = QAction("Goster", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)

        self.tray_connect_action = QAction("Qosul", self)
        self.tray_connect_action.triggered.connect(self.toggle_connection)
        tray_menu.addAction(self.tray_connect_action)

        tray_menu.addSeparator()
        quit_action = QAction("Bagla", self)
        quit_action.triggered.connect(self.quit_app)
        tray_menu.addAction(quit_action)

        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_activated)
        self.tray_icon.show()

    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()

    def start_timers(self):
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_status)
        self.timer.start(STATUS_CHECK_INTERVAL * 1000)

        self.time_timer = QTimer()
        self.time_timer.timeout.connect(self.update_time)
        self.time_timer.start(1000)

    def toggle_connection(self):
        if self.connected:
            self.do_disconnect()
        else:
            self.do_connect()

    def do_connect(self):
        self.connect_btn.setEnabled(False)
        self.status_label.setText("Qosulur...")
        self.status_label.setStyleSheet("color: #ffa726;")

        result = self.api.connect()

        if result.get("success"):
            self.connected = True
            self.connect_time = time.time()
            proxy = result.get("proxy", {})

            self.proxy_thread = ProxyThread(
                proxy.get("host", ""),
                proxy.get("port", 1080)
            )
            self.proxy_thread.start()

            self.status_label.setText("Qosulub")
            self.status_label.setStyleSheet("color: #4caf50;")
            self.connect_btn.setText("AYRIL")
            self.connect_btn.setObjectName("disconnectBtn")
            self.connect_btn.setStyle(self.connect_btn.style())
            self.tray_connect_action.setText("Ayril")
            self.tray_icon.setToolTip(f"{APP_NAME} - Qosulub")
        else:
            self.status_label.setText(result.get("message", "Xeta"))
            self.status_label.setStyleSheet("color: #e94560;")

        self.connect_btn.setEnabled(True)

    def do_disconnect(self):
        self.api.disconnect()
        self.connected = False
        self.connect_time = None

        if self.proxy_thread:
            self.proxy_thread.stop()
            self.proxy_thread = None

        self.status_label.setText("Baglanti Kesik")
        self.status_label.setStyleSheet("color: #e94560;")
        self.connect_btn.setText("QOSUL")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setStyle(self.connect_btn.style())
        self.tray_connect_action.setText("Qosul")
        self.tray_icon.setToolTip(f"{APP_NAME} - Ayrilib")
        self.time_label.setText("Baglanti muddeti: --:--:--")

    def do_logout(self):
        if self.connected:
            self.do_disconnect()
        self.tray_icon.hide()
        self.close()
        if self.parent_app:
            self.parent_app.show_login()

    def update_status(self):
        if not self.connected:
            return
        result = self.api.get_status()
        if result.get("success"):
            traffic = result.get("traffic_used_mb", 0)
            self.traffic_label.setText(f"Trafik: {traffic:.1f} MB istifade olunub")

    def update_time(self):
        if self.connect_time:
            elapsed = int(time.time() - self.connect_time)
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            s = elapsed % 60
            self.time_label.setText(f"Baglanti muddeti: {h:02d}:{m:02d}:{s:02d}")

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            APP_NAME, "Proqram arxa planda isleyir",
            QSystemTrayIcon.Information, 2000
        )

    def quit_app(self):
        if self.connected:
            self.do_disconnect()
        self.tray_icon.hide()
        QApplication.quit()


class VPNApp:
    """Esas proqram."""

    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setQuitOnLastWindowClosed(False)
        self.api = APIClient()
        self.login_window = None
        self.main_window = None
        self.show_login()

    def show_login(self):
        if self.main_window:
            self.main_window.close()
            self.main_window = None
        self.login_window = LoginWindow(self.api)
        self.login_window.login_success.connect(self.on_login_success)
        self.login_window.show()

    def on_login_success(self, data):
        self.login_window.close()
        self.main_window = MainWindow(self.api, data)
        self.main_window.parent_app = self
        self.main_window.show()

    def run(self):
        return self.app.exec_()


if __name__ == "__main__":
    vpn = VPNApp()
    sys.exit(vpn.run())
