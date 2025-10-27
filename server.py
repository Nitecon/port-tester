import argparse
import base64
import signal
import socket
import sys
import threading
import time
from typing import Tuple, Optional


class TcpEchoServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._srv_sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    def start(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(5)
        srv.settimeout(0.5)
        self._srv_sock = srv
        print(f"[TCP] Listening on {self.host}:{self.port}", flush=True)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        self._close()
        print("[TCP] Stopped", flush=True)

    def _handle_client(self, conn: socket.socket, addr: Tuple[str, int]):
        with conn:
            conn.settimeout(0.5)
            print(f"[TCP] Client connected {addr[0]}:{addr[1]}", flush=True)
            while not self._stop.is_set():
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                # Log received data (as utf-8 best-effort)
                try:
                    text = data.decode('utf-8', errors='replace')
                except Exception:
                    text = str(data)
                print(f"[TCP] Recv from {addr[0]}:{addr[1]} -> {text}", flush=True)
                try:
                    conn.sendall(data)
                except Exception:
                    break
            print(f"[TCP] Client disconnected {addr[0]}:{addr[1]}", flush=True)

    def stop(self):
        self._stop.set()
        self._close()

    def _close(self):
        if self._srv_sock:
            try:
                self._srv_sock.close()
            except Exception:
                pass
            self._srv_sock = None


class UdpEchoServer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        print(f"[UDP] Listening on {self.host}:{self.port}", flush=True)
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            try:
                text = data.decode('utf-8', errors='replace')
            except Exception:
                text = str(data)
            print(f"[UDP] Recv from {addr[0]}:{addr[1]} -> {text}", flush=True)
            try:
                sock.sendto(data, addr)
            except Exception:
                pass
        self._close()
        print("[UDP] Stopped", flush=True)

    def stop(self):
        self._stop.set()
        self._close()

    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


def run_servers(bind_host: str, tcp_port: int, udp_port: int):
    threads = []
    servers = []

    if tcp_port and tcp_port > 0:
        tcp_srv = TcpEchoServer(bind_host, tcp_port)
        t = threading.Thread(target=tcp_srv.start, daemon=True)
        t.start()
        servers.append(tcp_srv)
        threads.append(t)

    if udp_port and udp_port > 0:
        udp_srv = UdpEchoServer(bind_host, udp_port)
        t = threading.Thread(target=udp_srv.start, daemon=True)
        t.start()
        servers.append(udp_srv)
        threads.append(t)

    if not threads:
        print("No servers started. Specify --tcp-port and/or --udp-port > 0", flush=True)
        return 1

    stop_event = threading.Event()

    def handle_signal(signum, frame):
        print(f"Received signal {signum}, shutting down...", flush=True)
        stop_event.set()
        for s in servers:
            s.stop()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        while not stop_event.is_set():
            time.sleep(0.25)
    except KeyboardInterrupt:
        handle_signal(signal.SIGINT, None)

    for t in threads:
        t.join(timeout=1.0)
    return 0


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Port Tester Headless Echo Server")
    p.add_argument("--bind-host", default="0.0.0.0", help="Bind address for servers (default: 0.0.0.0)")
    p.add_argument("--tcp-port", type=int, default=0, help="TCP port to listen and echo (0 to disable)")
    p.add_argument("--udp-port", type=int, default=0, help="UDP port to listen and echo (0 to disable)")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    return run_servers(args.bind_host, args.tcp_port, args.udp_port)


if __name__ == "__main__":
    sys.exit(main())
