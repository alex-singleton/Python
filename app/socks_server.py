"""
SOCKS5 Proxy Server - VPN tuneli üçün.
İstifadəçi autentifikasiyası ilə SOCKS5 proxy.
Firewall qaydalarını tətbiq edir.
"""
import socket
import struct
import select
import threading
import logging
from app.vpn_users import vpn_users
from app.firewall_core import firewall

logger = logging.getLogger("firewall.socks5")

SOCKS5_VERSION = 0x05
AUTH_NONE = 0x00
AUTH_USERPASS = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REPLY_SUCCESS = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_NOT_ALLOWED = 0x02
REPLY_HOST_UNREACHABLE = 0x04
REPLY_REFUSED = 0x05

BUFFER_SIZE = 8192


class SOCKS5Handler(threading.Thread):
    """Tək SOCKS5 bağlantısını idarə edir."""

    def __init__(self, client_socket, client_addr):
        super().__init__(daemon=True)
        self.client = client_socket
        self.client_addr = client_addr
        self.username = None

    def run(self):
        try:
            if not self.handle_greeting():
                return
            if not self.handle_auth():
                return
            self.handle_request()
        except Exception as e:
            logger.debug(f"SOCKS5 xətası: {e}")
        finally:
            self.client.close()

    def handle_greeting(self):
        """SOCKS5 greeting - auth method seçimi."""
        data = self.client.recv(256)
        if not data or len(data) < 3:
            return False

        version = data[0]
        if version != SOCKS5_VERSION:
            return False

        # Username/password auth tələb et
        self.client.sendall(struct.pack("BB", SOCKS5_VERSION, AUTH_USERPASS))
        return True

    def handle_auth(self):
        """İstifadəçi adı/parol autentifikasiyası."""
        data = self.client.recv(256)
        if not data or len(data) < 5:
            self.client.sendall(struct.pack("BB", 0x01, 0x01))
            return False

        version = data[0]  # Auth sub-version (0x01)
        ulen = data[1]
        username = data[2:2 + ulen].decode("utf-8", errors="ignore")
        plen = data[2 + ulen]
        password = data[3 + ulen:3 + ulen + plen].decode("utf-8", errors="ignore")

        # Token əsaslı auth (API-dən gələn token parol kimi istifadə olunur)
        success, msg, _ = vpn_users.authenticate(username, password)

        if success:
            self.username = username
            self.client.sendall(struct.pack("BB", 0x01, 0x00))  # Success
            logger.info(f"SOCKS5 auth: {username} @ {self.client_addr[0]}")
            return True
        else:
            self.client.sendall(struct.pack("BB", 0x01, 0x01))  # Failure
            logger.warning(f"SOCKS5 auth uğursuz: {username} @ {self.client_addr[0]}")
            return False

    def handle_request(self):
        """SOCKS5 connect sorğusu."""
        data = self.client.recv(256)
        if not data or len(data) < 7:
            return

        version = data[0]
        cmd = data[1]
        atyp = data[3]

        if cmd != CMD_CONNECT:
            self.send_reply(REPLY_GENERAL_FAILURE)
            return

        # Hədəf ünvanı oxu
        if atyp == ATYP_IPV4:
            dst_addr = socket.inet_ntoa(data[4:8])
            dst_port = struct.unpack("!H", data[8:10])[0]
        elif atyp == ATYP_DOMAIN:
            domain_len = data[4]
            dst_addr = data[5:5 + domain_len].decode("utf-8")
            dst_port = struct.unpack("!H", data[5 + domain_len:7 + domain_len])[0]
        elif atyp == ATYP_IPV6:
            dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            dst_port = struct.unpack("!H", data[20:22])[0]
        else:
            self.send_reply(REPLY_GENERAL_FAILURE)
            return

        # Firewall yoxlaması - domain bloklanıbmı?
        if firewall.is_domain_blocked(dst_addr):
            logger.info(f"BLOKLANIB: {self.username} -> {dst_addr}:{dst_port}")
            self.send_reply(REPLY_NOT_ALLOWED)
            return

        # Firewall yoxlaması - IP bloklanıbmı?
        if firewall.is_ip_blocked(dst_addr):
            logger.info(f"BLOKLANIB (IP): {self.username} -> {dst_addr}:{dst_port}")
            self.send_reply(REPLY_NOT_ALLOWED)
            return

        # Uzaq serverə qoşul
        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((dst_addr, dst_port))
            remote.settimeout(None)
        except socket.error:
            self.send_reply(REPLY_HOST_UNREACHABLE)
            return

        # Uğurlu cavab göndər
        bind_addr = remote.getsockname()
        self.send_reply(REPLY_SUCCESS, bind_addr[0], bind_addr[1])

        # Trafik relay
        self.relay(self.client, remote)
        remote.close()

    def relay(self, client, remote):
        """İki socket arasında trafik ötür."""
        total_bytes = 0
        try:
            while True:
                readable, _, _ = select.select([client, remote], [], [], 60)
                if not readable:
                    break

                for sock in readable:
                    data = sock.recv(BUFFER_SIZE)
                    if not data:
                        return

                    if sock is client:
                        remote.sendall(data)
                    else:
                        client.sendall(data)

                    total_bytes += len(data)
        except Exception:
            pass
        finally:
            # Trafik sayğacını yenilə
            if self.username and total_bytes > 0:
                vpn_users.add_traffic(self.username, total_bytes)

    def send_reply(self, reply_code, bind_addr="0.0.0.0", bind_port=0):
        """SOCKS5 cavab göndər."""
        addr_bytes = socket.inet_aton(bind_addr)
        reply = struct.pack("!BBBB", SOCKS5_VERSION, reply_code, 0x00, ATYP_IPV4)
        reply += addr_bytes + struct.pack("!H", bind_port)
        self.client.sendall(reply)


class SOCKS5Server:
    """SOCKS5 proxy serveri."""

    def __init__(self, host="0.0.0.0", port=1080):
        self.host = host
        self.port = port
        self.running = False
        self.server_socket = None
        self.thread = None

    def start(self):
        """Serveri başlat (arxa plan thread-ində)."""
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        logger.info(f"SOCKS5 server başladıldı: {self.host}:{self.port}")

    def _run(self):
        """Server loop."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        self.server_socket.settimeout(1)

        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                handler = SOCKS5Handler(client_socket, client_addr)
                handler.start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"SOCKS5 accept xətası: {e}")

    def stop(self):
        """Serveri dayandır."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("SOCKS5 server dayandırıldı")


# Singleton
socks_server = SOCKS5Server()
