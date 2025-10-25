import base64
import socket
import sys
import threading
import time
from dataclasses import dataclass
from typing import Optional, Tuple

from PySide6 import QtCore, QtWidgets, QtGui


# ----------------------------
# Networking worker threads
# ----------------------------
class TcpServerThread(QtCore.QThread):
    log = QtCore.Signal(str)
    listening = QtCore.Signal(bool)

    def __init__(self, host: str, port: int, echo: bool = True, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.echo = echo
        self._stop_event = threading.Event()
        self._srv_sock: Optional[socket.socket] = None

    def run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(5)
            srv.settimeout(0.5)
            self._srv_sock = srv
            self.listening.emit(True)
            self.log.emit(f"TCP server listening on {self.host}:{self.port} (echo={'on' if self.echo else 'off'})")
            while not self._stop_event.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._stop_event.is_set():
                        break
                    self.log.emit(f"TCP accept error: {e}")
                    continue

                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            self.log.emit(f"TCP server error: {e}")
        finally:
            self.listening.emit(False)
            self._close_server()
            self.log.emit("TCP server stopped")

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        with conn:
            conn.settimeout(0.5)
            self.log.emit(f"TCP client connected: {addr[0]}:{addr[1]}")
            try:
                while not self._stop_event.is_set():
                    try:
                        data = conn.recv(4096)
                    except socket.timeout:
                        continue
                    if not data:
                        break
                    try:
                        text = data.decode('utf-8', errors='replace')
                    except Exception:
                        text = str(data)
                    self.log.emit(f"TCP recv from {addr[0]}:{addr[1]} -> {text}")
                    if self.echo:
                        try:
                            conn.sendall(data)
                        except Exception as e:
                            self.log.emit(f"TCP echo send error: {e}")
                            break
            except Exception as e:
                self.log.emit(f"TCP client handler error: {e}")
            finally:
                self.log.emit(f"TCP client disconnected: {addr[0]}:{addr[1]}")

    def stop(self):
        self._stop_event.set()
        self._close_server()

    def _close_server(self):
        if self._srv_sock:
            try:
                self._srv_sock.close()
            except Exception:
                pass
            self._srv_sock = None


class UdpListenerThread(QtCore.QThread):
    log = QtCore.Signal(str)
    listening = QtCore.Signal(bool)

    def __init__(self, host: str, port: int, echo: bool = True, parent=None):
        super().__init__(parent)
        self.host = host
        self.port = port
        self.echo = echo
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(0.5)
            self._sock = sock
            self.listening.emit(True)
            self.log.emit(f"UDP listener on {self.host}:{self.port} (echo={'on' if self.echo else 'off'})")
            while not self._stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as e:
                    if self._stop_event.is_set():
                        break
                    self.log.emit(f"UDP recv error: {e}")
                    continue
                try:
                    text = data.decode('utf-8', errors='replace')
                except Exception:
                    text = str(data)
                self.log.emit(f"UDP recv from {addr[0]}:{addr[1]} -> {text}")
                if self.echo:
                    try:
                        sock.sendto(data, addr)
                    except Exception as e:
                        self.log.emit(f"UDP echo send error: {e}")
        except Exception as e:
            self.log.emit(f"UDP listener error: {e}")
        finally:
            self.listening.emit(False)
            self._close_sock()
            self.log.emit("UDP listener stopped")

    def stop(self):
        self._stop_event.set()
        self._close_sock()

    def _close_sock(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


# ----------------------------
# Client helper functions
# ----------------------------

def send_tcp(host: str, port: int, data: bytes, timeout: float = 3.0) -> Tuple[bool, Optional[bytes], Optional[str]]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(data)
            try:
                echo = s.recv(65535)
            except socket.timeout:
                echo = None
        return True, echo, None
    except Exception as e:
        return False, None, str(e)


def send_udp(host: str, port: int, data: bytes, timeout: float = 2.0, expect_reply: bool = False) -> Tuple[bool, Optional[bytes], Optional[str]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(data, (host, port))
            if expect_reply:
                try:
                    resp, _ = s.recvfrom(65535)
                    return True, resp, None
                except socket.timeout:
                    return False, None, "timeout waiting for UDP reply"
            return True, None, None
    except Exception as e:
        return False, None, str(e)


# ----------------------------
# GUI
# ----------------------------
class ServerTab(QtWidgets.QWidget):
    def __init__(self, log_append_fn, parent=None):
        super().__init__(parent)
        self.log_append = log_append_fn
        self.tcp_thread: Optional[TcpServerThread] = None
        self.udp_thread: Optional[UdpListenerThread] = None
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # TCP controls
        tcp_group = QtWidgets.QGroupBox("TCP Server")
        tcp_form = QtWidgets.QFormLayout()
        self.tcp_host = QtWidgets.QLineEdit("0.0.0.0")
        self.tcp_port = QtWidgets.QSpinBox()
        self.tcp_port.setRange(1, 65535)
        self.tcp_port.setValue(5000)
        self.tcp_echo = QtWidgets.QCheckBox("Echo")
        self.tcp_echo.setChecked(True)
        self.btn_tcp_start = QtWidgets.QPushButton("Start TCP")
        self.btn_tcp_stop = QtWidgets.QPushButton("Stop TCP")
        self.btn_tcp_stop.setEnabled(False)
        tcp_form.addRow("Host", self.tcp_host)
        tcp_form.addRow("Port", self.tcp_port)
        tcp_form.addRow("", self.tcp_echo)
        tcp_btns = QtWidgets.QHBoxLayout()
        tcp_btns.addWidget(self.btn_tcp_start)
        tcp_btns.addWidget(self.btn_tcp_stop)
        tcp_wrap = QtWidgets.QVBoxLayout()
        tcp_wrap.addLayout(tcp_form)
        tcp_wrap.addLayout(tcp_btns)
        tcp_group.setLayout(tcp_wrap)

        # UDP controls
        udp_group = QtWidgets.QGroupBox("UDP Listener")
        udp_form = QtWidgets.QFormLayout()
        self.udp_host = QtWidgets.QLineEdit("0.0.0.0")
        self.udp_port = QtWidgets.QSpinBox()
        self.udp_port.setRange(1, 65535)
        self.udp_port.setValue(5001)
        self.udp_echo = QtWidgets.QCheckBox("Echo")
        self.udp_echo.setChecked(True)
        self.btn_udp_start = QtWidgets.QPushButton("Start UDP")
        self.btn_udp_stop = QtWidgets.QPushButton("Stop UDP")
        self.btn_udp_stop.setEnabled(False)
        udp_form.addRow("Host", self.udp_host)
        udp_form.addRow("Port", self.udp_port)
        udp_form.addRow("", self.udp_echo)
        udp_btns = QtWidgets.QHBoxLayout()
        udp_btns.addWidget(self.btn_udp_start)
        udp_btns.addWidget(self.btn_udp_stop)
        udp_wrap = QtWidgets.QVBoxLayout()
        udp_wrap.addLayout(udp_form)
        udp_wrap.addLayout(udp_btns)
        udp_group.setLayout(udp_wrap)

        layout.addWidget(tcp_group)
        layout.addWidget(udp_group)
        layout.addStretch()

        # Signals
        self.btn_tcp_start.clicked.connect(self.start_tcp)
        self.btn_tcp_stop.clicked.connect(self.stop_tcp)
        self.btn_udp_start.clicked.connect(self.start_udp)
        self.btn_udp_stop.clicked.connect(self.stop_udp)

    def start_tcp(self):
        if self.tcp_thread and self.tcp_thread.isRunning():
            return
        host = self.tcp_host.text().strip()
        port = int(self.tcp_port.value())
        echo = self.tcp_echo.isChecked()
        self.tcp_thread = TcpServerThread(host, port, echo)
        self.tcp_thread.log.connect(self.log_append)
        self.tcp_thread.listening.connect(self._on_tcp_listen)
        self.tcp_thread.start()

    def _on_tcp_listen(self, ok: bool):
        self.btn_tcp_start.setEnabled(not ok)
        self.btn_tcp_stop.setEnabled(ok)

    def stop_tcp(self):
        if self.tcp_thread:
            self.tcp_thread.stop()
            self.tcp_thread.wait(1000)
            self.btn_tcp_start.setEnabled(True)
            self.btn_tcp_stop.setEnabled(False)

    def start_udp(self):
        if self.udp_thread and self.udp_thread.isRunning():
            return
        host = self.udp_host.text().strip()
        port = int(self.udp_port.value())
        echo = self.udp_echo.isChecked()
        self.udp_thread = UdpListenerThread(host, port, echo)
        self.udp_thread.log.connect(self.log_append)
        self.udp_thread.listening.connect(self._on_udp_listen)
        self.udp_thread.start()

    def _on_udp_listen(self, ok: bool):
        self.btn_udp_start.setEnabled(not ok)
        self.btn_udp_stop.setEnabled(ok)

    def stop_udp(self):
        if self.udp_thread:
            self.udp_thread.stop()
            self.udp_thread.wait(1000)
            self.btn_udp_start.setEnabled(True)
            self.btn_udp_stop.setEnabled(False)

    def close(self):
        self.stop_tcp()
        self.stop_udp()
        super().close()


class ClientTab(QtWidgets.QWidget):
    log = QtCore.Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QtWidgets.QVBoxLayout(self)

        # Target
        target_group = QtWidgets.QGroupBox("Target")
        form = QtWidgets.QFormLayout()
        self.host = QtWidgets.QLineEdit("127.0.0.1")
        self.tcp_port = QtWidgets.QSpinBox(); self.tcp_port.setRange(1, 65535); self.tcp_port.setValue(5000)
        self.udp_port = QtWidgets.QSpinBox(); self.udp_port.setRange(1, 65535); self.udp_port.setValue(5001)
        form.addRow("Host", self.host)
        form.addRow("TCP Port", self.tcp_port)
        form.addRow("UDP Port", self.udp_port)
        target_group.setLayout(form)

        # Message
        msg_group = QtWidgets.QGroupBox("Message")
        v = QtWidgets.QVBoxLayout()
        self.message = QtWidgets.QPlainTextEdit()
        self.message.setPlaceholderText("Enter message to send...")
        self.base64_encode = QtWidgets.QCheckBox("Base64 encode before send")
        v.addWidget(self.message)
        v.addWidget(self.base64_encode)
        msg_group.setLayout(v)

        # Buttons
        btns = QtWidgets.QGridLayout()
        self.btn_std_hello = QtWidgets.QPushButton("Std: Hello")
        self.btn_std_ping = QtWidgets.QPushButton("Std: Ping")
        self.btn_send_tcp = QtWidgets.QPushButton("Send TCP")
        self.btn_send_udp = QtWidgets.QPushButton("Send UDP")
        self.btn_test_tcp = QtWidgets.QPushButton("Test TCP Port")
        self.btn_test_udp = QtWidgets.QPushButton("UDP Ping Test")
        btns.addWidget(self.btn_std_hello, 0, 0)
        btns.addWidget(self.btn_std_ping, 0, 1)
        btns.addWidget(self.btn_send_tcp, 1, 0)
        btns.addWidget(self.btn_send_udp, 1, 1)
        btns.addWidget(self.btn_test_tcp, 2, 0)
        btns.addWidget(self.btn_test_udp, 2, 1)

        layout.addWidget(target_group)
        layout.addWidget(msg_group)
        layout.addLayout(btns)
        layout.addStretch()

        # Signals
        self.btn_std_hello.clicked.connect(lambda: self.message.setPlainText("Hello"))
        self.btn_std_ping.clicked.connect(lambda: self.message.setPlainText("Ping"))
        self.btn_send_tcp.clicked.connect(self._on_send_tcp)
        self.btn_send_udp.clicked.connect(self._on_send_udp)
        self.btn_test_tcp.clicked.connect(self._on_test_tcp)
        self.btn_test_udp.clicked.connect(self._on_test_udp)

    def _get_payload(self) -> bytes:
        text = self.message.toPlainText()
        data = text.encode('utf-8')
        if self.base64_encode.isChecked():
            data = base64.b64encode(data)
        return data

    def _on_send_tcp(self):
        host = self.host.text().strip()
        port = int(self.tcp_port.value())
        data = self._get_payload()
        threading.Thread(target=self._send_tcp_thread, args=(host, port, data), daemon=True).start()

    def _send_tcp_thread(self, host, port, data):
        ok, echo, err = send_tcp(host, port, data, timeout=3.0)
        if ok:
            msg = f"TCP sent to {host}:{port}, bytes={len(data)}"
            if echo is not None:
                try:
                    text = echo.decode('utf-8', errors='replace')
                except Exception:
                    text = str(echo)
                msg += f", echo: {text}"
            self.log.emit(msg)
        else:
            self.log.emit(f"TCP send error: {err}")

    def _on_send_udp(self):
        host = self.host.text().strip()
        port = int(self.udp_port.value())
        data = self._get_payload()
        threading.Thread(target=self._send_udp_thread, args=(host, port, data), daemon=True).start()

    def _send_udp_thread(self, host, port, data):
        ok, _, err = send_udp(host, port, data, timeout=2.0, expect_reply=False)
        if ok:
            self.log.emit(f"UDP sent to {host}:{port}, bytes={len(data)}")
        else:
            self.log.emit(f"UDP send error: {err}")

    def _on_test_tcp(self):
        host = self.host.text().strip()
        port = int(self.tcp_port.value())
        threading.Thread(target=self._test_tcp_thread, args=(host, port), daemon=True).start()

    def _test_tcp_thread(self, host, port):
        try:
            with socket.create_connection((host, port), timeout=2.0):
                pass
            self.log.emit(f"TCP port OPEN at {host}:{port}")
        except Exception as e:
            self.log.emit(f"TCP port CLOSED at {host}:{port} ({e})")

    def _on_test_udp(self):
        host = self.host.text().strip()
        port = int(self.udp_port.value())
        payload = b"ping"
        threading.Thread(target=self._test_udp_thread, args=(host, port, payload), daemon=True).start()

    def _test_udp_thread(self, host, port, payload: bytes):
        ok, resp, err = send_udp(host, port, payload, timeout=2.0, expect_reply=True)
        if ok and resp is not None:
            try:
                text = resp.decode('utf-8', errors='replace')
            except Exception:
                text = str(resp)
            self.log.emit(f"UDP ping reply from {host}:{port} -> {text}")
        else:
            self.log.emit(f"UDP ping failed to {host}:{port}: {err or 'no reply'}")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UDP/TCP Port Tester")
        self.resize(900, 600)

        self.log_view = QtWidgets.QTextEdit()
        self.log_view.setReadOnly(True)

        self.tabs = QtWidgets.QTabWidget()
        self.server_tab = ServerTab(self.append_log)
        self.client_tab = ClientTab()
        self.client_tab.log.connect(self.append_log)
        self.tabs.addTab(self.server_tab, "Server")
        self.tabs.addTab(self.client_tab, "Client")

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.addWidget(self.tabs)
        layout.addWidget(self.log_view)
        self.setCentralWidget(central)

        toolbar = self.addToolBar("Main")
        clear_action = QtGui.QAction("Clear Log", self)
        clear_action.triggered.connect(lambda: self.log_view.clear())
        toolbar.addAction(clear_action)

    @QtCore.Slot(str)
    def append_log(self, line: str):
        ts = time.strftime('%H:%M:%S')
        self.log_view.append(f"[{ts}] {line}")

    def closeEvent(self, event):
        self.server_tab.close()
        return super().closeEvent(event)


def main():
    app = QtWidgets.QApplication(sys.argv)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
