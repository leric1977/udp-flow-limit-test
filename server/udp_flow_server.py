#!/usr/bin/env python3
"""UDP 5-tuple flow-limit server with automatic discovery and 10 test ports."""
from __future__ import annotations

import argparse
import json
import logging
import signal
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Set, Tuple

Address = Tuple[str, int]
StateKey = Tuple[int, str]
MAX_PACKET = 65535
STATE_TTL_SECONDS = 3600
PROTOCOL_VERSION = 2


@dataclass
class TestState:
    server_port: int
    token: str
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    uplink_received: Set[int] = field(default_factory=set)
    uplink_declared_total: int = 0
    uplink_client: Address | None = None
    hello_received: Set[int] = field(default_factory=set)
    hello_expected: int = 0
    down_declared_total: int = 0
    down_packet_size: int = 64
    down_interval_ms: int = 50
    down_client: Address | None = None
    down_started: bool = False
    down_sent: int = 0
    down_send_errors: int = 0


class MultiPortUDPFlowServer:
    def __init__(self, host: str, discovery_port: int, test_ports: list[int]) -> None:
        self.host = host
        self.discovery_port = discovery_port
        self.test_ports = test_ports
        self.all_ports = [discovery_port, *test_ports]
        self.sockets: dict[int, socket.socket] = {}
        self.states: Dict[StateKey, TestState] = {}
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.threads: list[threading.Thread] = []

        for port in self.all_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.settimeout(1.0)
            self.sockets[port] = sock

    @staticmethod
    def decode_packet(data: bytes) -> list[str]:
        text = data.split(b"\0", 1)[0].decode("ascii", errors="replace")
        return text.split("|")

    @staticmethod
    def padded(payload: str, size: int) -> bytes:
        raw = payload.encode("ascii")
        size = max(size, len(raw))
        if size > MAX_PACKET:
            raise ValueError("packet too large")
        return raw + (b"\0" * (size - len(raw)))

    @staticmethod
    def valid_token(token: str) -> bool:
        return 8 <= len(token) <= 64 and all(c in "0123456789abcdefABCDEF-" for c in token)

    def get_state(self, server_port: int, token: str) -> TestState:
        key = (server_port, token)
        with self.lock:
            state = self.states.get(key)
            if state is None:
                state = TestState(server_port=server_port, token=token)
                self.states[key] = state
            state.updated_at = time.time()
            return state

    def cleanup(self) -> None:
        cutoff = time.time() - STATE_TTL_SECONDS
        with self.lock:
            expired = [key for key, state in self.states.items() if state.updated_at < cutoff]
            for key in expired:
                del self.states[key]

    def discovery_payload(self, observer: Address) -> bytes:
        payload = {
            "ok": True,
            "service": "udp-flow-limit-test",
            "protocol_version": PROTOCOL_VERSION,
            "discovery_port": self.discovery_port,
            "test_count": len(self.test_ports),
            "test_ports": self.test_ports,
            "observer_ip": observer[0],
            "observer_port": observer[1],
            "server_unix_time": int(time.time()),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def status_payload(self, server_port: int, token: str, observer: Address) -> bytes:
        key = (server_port, token)
        with self.lock:
            state = self.states.get(key)
            if state is None:
                payload = {
                    "ok": False,
                    "error": "unknown token",
                    "server_port": server_port,
                    "token": token,
                    "observer_ip": observer[0],
                    "observer_port": observer[1],
                }
            else:
                received = sorted(state.uplink_received)
                declared = state.uplink_declared_total
                missing: list[int] = []
                if declared and declared <= 5000:
                    missing = [i for i in range(1, declared + 1) if i not in state.uplink_received]
                payload = {
                    "ok": True,
                    "server_port": server_port,
                    "token": token,
                    "observer_ip": observer[0],
                    "observer_port": observer[1],
                    "uplink": {
                        "client_ip": state.uplink_client[0] if state.uplink_client else None,
                        "client_port": state.uplink_client[1] if state.uplink_client else None,
                        "declared_total": declared,
                        "received_count": len(received),
                        "first_seq": received[0] if received else None,
                        "last_seq": received[-1] if received else None,
                        "missing_count": len(missing),
                        "missing_first_100": missing[:100],
                    },
                    "downlink": {
                        "client_ip": state.down_client[0] if state.down_client else None,
                        "client_port": state.down_client[1] if state.down_client else None,
                        "hello_expected": state.hello_expected,
                        "hello_received": len(state.hello_received),
                        "declared_total": state.down_declared_total,
                        "sent_count": state.down_sent,
                        "send_errors": state.down_send_errors,
                        "started": state.down_started,
                    },
                }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def send_downlink(self, server_port: int, token: str) -> None:
        time.sleep(0.12)
        key = (server_port, token)
        with self.lock:
            state = self.states.get(key)
            if state is None or state.down_client is None:
                return
            client = state.down_client
            total = state.down_declared_total
            packet_size = state.down_packet_size
            interval = state.down_interval_ms / 1000.0
            sock = self.sockets[server_port]

        logging.info(
            "DOWN start port=%d token=%s client=%s:%d count=%d size=%d interval_ms=%d",
            server_port, token, client[0], client[1], total, packet_size, int(interval * 1000),
        )
        for seq in range(1, total + 1):
            if self.stop_event.is_set():
                break
            packet = self.padded(f"DOWN|{token}|{seq}|{total}", packet_size)
            try:
                sock.sendto(packet, client)
                with self.lock:
                    current = self.states.get(key)
                    if current:
                        current.down_sent += 1
                        current.updated_at = time.time()
            except OSError as exc:
                logging.warning(
                    "DOWN send error port=%d token=%s seq=%d error=%r",
                    server_port, token, seq, exc,
                )
                with self.lock:
                    current = self.states.get(key)
                    if current:
                        current.down_send_errors += 1
            if interval > 0:
                time.sleep(interval)
        logging.info("DOWN complete port=%d token=%s sent=%d", server_port, token, total)

    def handle_discovery(self, data: bytes, addr: Address) -> None:
        parts = self.decode_packet(data)
        command = parts[0].upper() if parts else ""
        sock = self.sockets[self.discovery_port]
        if command == "PING":
            sock.sendto(f"PONG|udp-flow-limit-test|{PROTOCOL_VERSION}|discovery".encode("ascii"), addr)
        elif command == "DISCOVER":
            sock.sendto(self.discovery_payload(addr), addr)

    def handle_test(self, server_port: int, data: bytes, addr: Address) -> None:
        parts = self.decode_packet(data)
        if not parts:
            return
        command = parts[0].upper()
        sock = self.sockets[server_port]

        if command == "PING":
            sock.sendto(
                f"PONG|udp-flow-limit-test|{PROTOCOL_VERSION}|{server_port}".encode("ascii"),
                addr,
            )
            return

        if command == "UP" and len(parts) >= 4:
            token = parts[1]
            if not self.valid_token(token):
                return
            try:
                seq = int(parts[2])
                total = int(parts[3])
            except ValueError:
                return
            state = self.get_state(server_port, token)
            with self.lock:
                state.uplink_received.add(seq)
                state.uplink_declared_total = max(state.uplink_declared_total, total)
                state.uplink_client = addr
                state.updated_at = time.time()
            return

        if command == "HELLO" and len(parts) >= 8:
            token = parts[1]
            if not self.valid_token(token):
                return
            try:
                hello_seq = int(parts[2])
                hello_expected = int(parts[3])
                down_total = int(parts[4])
                packet_size = int(parts[5])
                interval_ms = int(parts[6])
                protocol_version = int(parts[7])
            except ValueError:
                return
            if protocol_version != PROTOCOL_VERSION:
                return

            packet_size = min(max(packet_size, 48), MAX_PACKET)
            interval_ms = min(max(interval_ms, 0), 60000)
            down_total = min(max(down_total, 1), 100000)
            hello_expected = min(max(hello_expected, 1), 1000)

            state = self.get_state(server_port, token)
            start_thread = False
            with self.lock:
                state.hello_received.add(hello_seq)
                state.hello_expected = hello_expected
                state.down_declared_total = down_total
                state.down_packet_size = packet_size
                state.down_interval_ms = interval_ms
                state.down_client = addr
                state.updated_at = time.time()
                if len(state.hello_received) >= hello_expected and not state.down_started:
                    state.down_started = True
                    start_thread = True
            if start_thread:
                threading.Thread(
                    target=self.send_downlink,
                    args=(server_port, token),
                    name=f"down-{server_port}-{token[:8]}",
                    daemon=True,
                ).start()
            return

        if command == "STATUS" and len(parts) >= 2:
            token = parts[1]
            if self.valid_token(token):
                sock.sendto(self.status_payload(server_port, token, addr), addr)
            return

        if command == "RESET" and len(parts) >= 2:
            token = parts[1]
            key = (server_port, token)
            with self.lock:
                removed = self.states.pop(key, None) is not None
            sock.sendto(
                json.dumps({"ok": True, "removed": removed, "server_port": server_port, "token": token}).encode(),
                addr,
            )

    def listener(self, port: int) -> None:
        sock = self.sockets[port]
        logging.info("Listening on %s:%d/udp", self.host, port)
        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(MAX_PACKET)
            except socket.timeout:
                continue
            except OSError:
                if self.stop_event.is_set():
                    break
                raise
            try:
                if port == self.discovery_port:
                    self.handle_discovery(data, addr)
                else:
                    self.handle_test(port, data, addr)
            except Exception:
                logging.exception("Packet error on port=%d from %s:%d", port, addr[0], addr[1])

    def serve(self) -> None:
        for port in self.all_ports:
            thread = threading.Thread(target=self.listener, args=(port,), name=f"udp-{port}", daemon=True)
            thread.start()
            self.threads.append(thread)

        logging.info("Discovery port: %d", self.discovery_port)
        logging.info("Test ports: %s", ",".join(map(str, self.test_ports)))
        try:
            while not self.stop_event.wait(60):
                self.cleanup()
        finally:
            self.stop()
            for thread in self.threads:
                thread.join(timeout=2)
            logging.info("Server stopped")

    def stop(self, *_args: object) -> None:
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        for sock in self.sockets.values():
            try:
                sock.close()
            except OSError:
                pass


def load_ports(path: Path, discovery_port: int) -> list[int]:
    ports: list[int] = []
    for raw in path.read_text(encoding="ascii").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        port = int(raw)
        if not 1024 <= port <= 65535:
            raise ValueError(f"invalid test port: {port}")
        if port == discovery_port:
            raise ValueError("test port duplicates discovery port")
        if port not in ports:
            ports.append(port)
    if len(ports) != 10:
        raise ValueError(f"ports file must contain exactly 10 unique ports, found {len(ports)}")
    return ports


def main() -> int:
    parser = argparse.ArgumentParser(description="UDP flow limit test server with 10 random ports")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--discovery-port", type=int, default=62970)
    parser.add_argument("--ports-file", type=Path, default=Path("/etc/udp-flow-limit-test/ports.conf"))
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    if not 1024 <= args.discovery_port <= 65535:
        raise SystemExit("discovery port must be 1024..65535")
    test_ports = load_ports(args.ports_file, args.discovery_port)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    server = MultiPortUDPFlowServer(args.host, args.discovery_port, test_ports)
    signal.signal(signal.SIGINT, server.stop)
    signal.signal(signal.SIGTERM, server.stop)
    server.serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
