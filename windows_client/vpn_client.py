"""
NylonWall VPN Client - Windows proqrami.
PyQt5 GUI, login, WireGuard config yukle/qur.
Rust backend ile islenir.
"""
import sys
import os
import time
import subprocess
import tempfile
import requests

# Config import
if getattr(sys, 'frozen', False):
    app_dir = os.path.dirname(sys.executable)
else:
    app_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, app_dir)

from config import *

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QSystemTrayIcon, QMenu,
    QAction, QFrame, QComboBox, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QIcon, QFont


# WireGuard Windows yolu
WG_PATH = r"C:\Program Files\WireGuard\wireguard.exe"
WG_CLI = r"C:\Program Files\WireGuard\wg.exe"
TUNNEL_NAME = "nylonwall"
CONFIG_DIR = os.path.join(os.environ.get("APPDATA", app_dir), "NylonWall")


class APIClient:
    """Server API ile elaqe."""

    def __init__(self):
        self.token = None
        self.session = requests.Session()
        self.session.timeout = 10

    def health_check(self):
        try:
            resp = self.session.get(SERVER_URL + API_HEALTH, timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def login(self, email, password):
        try:
            resp = self.session.post(
                SERVER_URL + API_LOGIN,
                json={"email": email, "password": password}
            )
            data = resp.json()
            if data.get("access_token"):
                self.token = data["access_token"]
                return {"success": True, "user": data.get("user", {}), "token": self.token}
            elif data.get("error"):
                return {"success": False, "message": data["error"].get("message", "Giris ugursuz")}
            else:
                return {"success": False, "message": "Giris ugursuz oldu"}
        except requests.ConnectionError:
            return {"success": False, "message": "Servere qosulmaq mumkun olmadi"}
        except ValueError:
            return {"success": False, "message": "Server cavabi duzgun deyil"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_peers(self):
        try:
            resp = self.session.get(
                SERVER_URL + API_VPN_PEERS,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            data = resp.json()
            if isinstance(data, list):
                return {"success": True, "peers": data}
            elif data.get("error"):
                return {"success": False, "message": data["error"].get("message", "Xeta")}
            return {"success": True, "peers": []}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_peer_config(self, peer_id):
        try:
            resp = self.session.get(
                SERVER_URL + API_VPN_PEERS + f"/{peer_id}/config",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            data = resp.json()
            if data.get("config"):
                return {"success": True, "config": data["config"]}
            elif data.get("error"):
                return {"success": False, "message": data["error"].get("message", "Config alinmadi")}
            return {"success": False, "message": "Config tapilmadi"}
        except Exception as e:
            return {"success": False, "message": str(e)}

    def get_vpn_status(self):
        try:
            resp = self.session.get(
                SERVER_URL + API_VPN_STATUS,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            return resp.json()
        except Exception:
            return {}


class WireGuardManager:
    """WireGuard tunnel idareetmesi."""

    @staticmethod
    def is_installed():
        return os.path.exists(WG_PATH)

    @staticmethod
    def save_config(config_text):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        config_path = os.path.join(CONFIG_DIR, f"{TUNNEL_NAME}.conf")
        with open(config_path, "w") as f:
            f.write(config_text)
        return config_path

    @staticmethod
    def install_tunnel(config_path):
        try:
            result = subprocess.run(
                [WG_PATH, "/installtunnelservice", config_path],
                capture_output=True, text=True, timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def uninstall_tunnel():
        try:
            result = subprocess.run(
                [WG_PATH, "/uninstalltunnelservice", TUNNEL_NAME],
                capture_output=True, text=True, timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def is_connected():
        try:
            result = subprocess.run(
                [WG_CLI, "show", TUNNEL_NAME],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0 and "interface" in result.stdout.lower()
        except Exception:
            return False

    @staticmethod
    def get_transfer():
        try:
            result = subprocess.run(
                [WG_CLI, "show", TUNNEL_NAME, "transfer"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split("\t")
                if len(parts) >= 3:
                    rx = int(parts[1]) / (1024 * 1024)
                    tx = int(parts[2]) / (1024 * 1024)
                    return rx, tx
        except Exception:
            pass
        return 0, 0


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
                background-color: #0f172a;
                color: #eaeaea;
                font-family: 'Segoe UI', Arial;
            }
            QLineEdit {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 10px 15px;
                color: #eaeaea;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 1px solid #6366f1;
            }
            QPushButton#loginBtn {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #6366f1, stop:1 #8b5cf6);
                border: none;
                border-radius: 8px;
                padding: 12px;
                color: white;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton#loginBtn:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #4f46e5, stop:1 #7c3aed);
            }
            QLabel#title {
                font-size: 24px;
                font-weight: bold;
                color: #818cf8;
            }
            QLabel#subtitle {
                font-size: 12px;
                color: #64748b;
            }
            QLabel#error {
                color: #f87171;
                font-size: 12px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(15)

        layout.addSpacing(20)
        title = QLabel(APP_NAME)
        title.setObjectName("title")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("VPN Firewall Platform")
        subtitle.setObjectName("subtitle")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)
        layout.addSpacing(30)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email")
        layout.addWidget(self.email_input)

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Sifre")
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
        self.email_input.returnPressed.connect(lambda: self.password_input.setFocus())
        self.check_server()

    def check_server(self):
        if self.api.health_check():
            self.status_label.setText("Server: Elcatan")
            self.status_label.setStyleSheet("color: #4ade80;")
        else:
            self.status_label.setText("Server: Elcatmaz")
            self.status_label.setStyleSheet("color: #f87171;")

    def do_login(self):
        email = self.email_input.text().strip()
        password = self.password_input.text().strip()

        if not email or not password:
            self.error_label.setText("Email ve sifre daxil edin")
            return

        self.login_btn.setEnabled(False)
        self.login_btn.setText("Gozleyin...")
        self.error_label.setText("")

        result = self.api.login(email, password)

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
        self.connect_time = None
        self.current_peer_id = None
        self.parent_app = None
        self.wg = WireGuardManager()
        self.init_ui()
        self.init_tray()
        self.start_timers()
        self.load_peers()

    def init_ui(self):
        self.setWindowTitle(APP_NAME)
        self.setFixedSize(400, 560)
        self.setStyleSheet("""
            QWidget {
                background-color: #0f172a;
                color: #eaeaea;
                font-family: 'Segoe UI', Arial;
            }
            QPushButton#connectBtn {
                background-color: #059669;
                border: none;
                border-radius: 40px;
                color: white;
                font-size: 16px;
                font-weight: bold;
                min-width: 120px;
                min-height: 120px;
            }
            QPushButton#connectBtn:hover {
                background-color: #047857;
            }
            QPushButton#disconnectBtn {
                background-color: #dc2626;
                border: none;
                border-radius: 40px;
                color: white;
                font-size: 16px;
                font-weight: bold;
                min-width: 120px;
                min-height: 120px;
            }
            QPushButton#disconnectBtn:hover {
                background-color: #b91c1c;
            }
            QLabel#statusLabel {
                font-size: 18px;
                font-weight: bold;
            }
            QLabel#infoLabel {
                font-size: 12px;
                color: #64748b;
            }
            QFrame#infoFrame {
                background-color: #1e293b;
                border-radius: 10px;
                border: 1px solid #334155;
            }
            QComboBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 8px 12px;
                color: #eaeaea;
                font-size: 13px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        user = self.user_data.get("user", {})
        user_label = QLabel(f"Salam, {user.get('full_name', user.get('email', ''))}")
        user_label.setStyleSheet("font-size: 13px; color: #94a3b8;")
        header.addWidget(user_label)
        header.addStretch()

        logout_btn = QPushButton("Cixis")
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: 1px solid #ef4444;
                border-radius: 5px;
                padding: 5px 15px;
                color: #ef4444; font-size: 12px;
            }
            QPushButton:hover { background-color: #ef4444; color: white; }
        """)
        logout_btn.clicked.connect(self.do_logout)
        header.addWidget(logout_btn)
        layout.addLayout(header)

        # Peer selection
        peer_layout = QHBoxLayout()
        peer_label = QLabel("Profil:")
        peer_label.setStyleSheet("font-size: 13px; color: #94a3b8;")
        peer_layout.addWidget(peer_label)
        self.peer_combo = QComboBox()
        self.peer_combo.setMinimumWidth(200)
        peer_layout.addWidget(self.peer_combo)
        peer_layout.addStretch()
        layout.addLayout(peer_layout)

        # Status
        self.status_label = QLabel("Baglanti Kesik")
        self.status_label.setObjectName("statusLabel")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #f87171;")
        layout.addWidget(self.status_label)

        layout.addSpacing(5)

        # Connect button
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.connect_btn = QPushButton("QOSUL")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.clicked.connect(self.toggle_connection)
        btn_layout.addWidget(self.connect_btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        layout.addSpacing(10)

        # Info panel
        info_frame = QFrame()
        info_frame.setObjectName("infoFrame")
        info_layout = QVBoxLayout(info_frame)
        info_layout.setContentsMargins(15, 15, 15, 15)
        info_layout.setSpacing(8)

        self.transfer_label = QLabel("Trafik: -- MB yukle / -- MB gonder")
        self.transfer_label.setObjectName("infoLabel")
        info_layout.addWidget(self.transfer_label)

        self.time_label = QLabel("Baglanti muddeti: --:--:--")
        self.time_label.setObjectName("infoLabel")
        info_layout.addWidget(self.time_label)

        self.peer_info_label = QLabel("IP: --")
        self.peer_info_label.setObjectName("infoLabel")
        info_layout.addWidget(self.peer_info_label)

        server_label = QLabel(f"Server: {SERVER_URL}")
        server_label.setObjectName("infoLabel")
        info_layout.addWidget(server_label)

        layout.addWidget(info_frame)

        # WireGuard warning
        if not self.wg.is_installed():
            wg_warn = QLabel("WireGuard qurasdirilib? wireguard.com/install")
            wg_warn.setStyleSheet("color: #fbbf24; font-size: 11px;")
            wg_warn.setAlignment(Qt.AlignCenter)
            layout.addWidget(wg_warn)

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
        self.timer.timeout.connect(self.update_transfer)
        self.timer.start(STATUS_CHECK_INTERVAL * 1000)

        self.time_timer = QTimer()
        self.time_timer.timeout.connect(self.update_time)
        self.time_timer.start(1000)

        # Check if already connected
        if self.wg.is_connected():
            self.connected = True
            self.connect_time = time.time()
            self.set_connected_ui()

    def load_peers(self):
        result = self.api.get_peers()
        if result.get("success"):
            peers = result.get("peers", [])
            self.peer_combo.clear()
            for peer in peers:
                self.peer_combo.addItem(
                    f"{peer['name']} ({peer['assigned_ip']})",
                    peer['id']
                )
                if peer.get("assigned_ip"):
                    self.peer_info_label.setText(f"IP: {peer['assigned_ip']}")

    def toggle_connection(self):
        if self.connected:
            self.do_disconnect()
        else:
            self.do_connect()

    def do_connect(self):
        if not self.wg.is_installed():
            QMessageBox.warning(self, "WireGuard tapilmadi",
                "WireGuard qurasdirin: https://wireguard.com/install\n\nYukleyin ve yeniden cehd edin.")
            return

        peer_id = self.peer_combo.currentData()
        if not peer_id:
            QMessageBox.warning(self, "Profil secin", "VPN profil secilmeyib.")
            return

        self.connect_btn.setEnabled(False)
        self.status_label.setText("Qosulur...")
        self.status_label.setStyleSheet("color: #fbbf24;")

        # Get config from server
        result = self.api.get_peer_config(peer_id)
        if not result.get("success"):
            self.status_label.setText(result.get("message", "Config alinmadi"))
            self.status_label.setStyleSheet("color: #f87171;")
            self.connect_btn.setEnabled(True)
            return

        # Save config file
        config_path = self.wg.save_config(result["config"])

        # Install and start tunnel
        success = self.wg.install_tunnel(config_path)
        if success:
            time.sleep(2)
            if self.wg.is_connected():
                self.connected = True
                self.connect_time = time.time()
                self.current_peer_id = peer_id
                self.set_connected_ui()
            else:
                self.status_label.setText("Tunnel basladilmadi")
                self.status_label.setStyleSheet("color: #f87171;")
        else:
            self.status_label.setText("Tunnel qurasdirila bilmedi")
            self.status_label.setStyleSheet("color: #f87171;")

        self.connect_btn.setEnabled(True)

    def do_disconnect(self):
        self.wg.uninstall_tunnel()
        self.connected = False
        self.connect_time = None
        self.current_peer_id = None
        self.set_disconnected_ui()

    def set_connected_ui(self):
        self.status_label.setText("Qosulub")
        self.status_label.setStyleSheet("color: #4ade80;")
        self.connect_btn.setText("AYRIL")
        self.connect_btn.setObjectName("disconnectBtn")
        self.connect_btn.setStyle(self.connect_btn.style())
        self.tray_connect_action.setText("Ayril")
        self.tray_icon.setToolTip(f"{APP_NAME} - Qosulub")

    def set_disconnected_ui(self):
        self.status_label.setText("Baglanti Kesik")
        self.status_label.setStyleSheet("color: #f87171;")
        self.connect_btn.setText("QOSUL")
        self.connect_btn.setObjectName("connectBtn")
        self.connect_btn.setStyle(self.connect_btn.style())
        self.tray_connect_action.setText("Qosul")
        self.tray_icon.setToolTip(f"{APP_NAME} - Ayrilib")
        self.time_label.setText("Baglanti muddeti: --:--:--")
        self.transfer_label.setText("Trafik: -- MB yukle / -- MB gonder")

    def update_transfer(self):
        if not self.connected:
            return
        rx, tx = self.wg.get_transfer()
        self.transfer_label.setText(f"Trafik: {rx:.1f} MB yukle / {tx:.1f} MB gonder")

    def update_time(self):
        if self.connect_time:
            elapsed = int(time.time() - self.connect_time)
            h = elapsed // 3600
            m = (elapsed % 3600) // 60
            s = elapsed % 60
            self.time_label.setText(f"Baglanti muddeti: {h:02d}:{m:02d}:{s:02d}")

    def do_logout(self):
        if self.connected:
            self.do_disconnect()
        self.tray_icon.hide()
        self.close()
        if self.parent_app:
            self.parent_app.show_login()

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
