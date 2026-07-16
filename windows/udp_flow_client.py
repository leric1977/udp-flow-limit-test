#!/usr/bin/env python3
"""Windows client: discovers 10 server ports and tests every port automatically."""
from __future__ import annotations

import argparse
import json
import os
import platform
import random
import secrets
import socket
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = 2
DISCOVERY_PORT = 62970
EXPECTED_TEST_PORTS = 10
DEFAULT_PACKET_COUNT = 100
MAX_TEST_ATTEMPTS = 3


def ask(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def ask_int(prompt: str, default: int, minimum: int, maximum: int) -> int:
    while True:
        raw = ask(prompt, str(default))
        try:
            value = int(raw)
        except ValueError:
            print("Введите целое число.")
            continue
        if minimum <= value <= maximum:
            return value
        print(f"Допустимый диапазон: {minimum}..{maximum}")


def parse_hello_list(raw: str) -> list[int]:
    result: list[int] = []
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item)
        if not 1 <= value <= 1000:
            raise ValueError
        if value not in result:
            result.append(value)
    if len(result) < 2:
        raise ValueError
    return result


def resolve_ipv4(host: str, port: int) -> tuple[str, int]:
    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    if not infos:
        raise RuntimeError(f"IPv4-адрес не найден: {host}")
    return infos[0][4]


def padded(payload: str, packet_size: int) -> bytes:
    raw = payload.encode("ascii")
    if packet_size < len(raw):
        raise ValueError(
            f"Размер пакета {packet_size} слишком мал для заголовка длиной {len(raw)} байт."
        )
    return raw + (b"\0" * (packet_size - len(raw)))


def bind_unique_socket(used_local_ports: set[int], timeout: float | None = None) -> socket.socket:
    for _ in range(200):
        port = random.SystemRandom().randint(30000, 65000)
        if port in used_local_ports:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            sock.close()
            continue
        used_local_ports.add(port)
        if timeout is not None:
            sock.settimeout(timeout)
        return sock
    raise RuntimeError("Не удалось выбрать свободный уникальный локальный UDP-порт")


def request_json(
    target: tuple[str, int],
    message: str,
    used_local_ports: set[int],
    retries: int = 4,
    timeout: float = 2.5,
) -> dict[str, Any]:
    sock = bind_unique_socket(used_local_ports, timeout)
    last_error: Exception | None = None
    try:
        for attempt in range(1, retries + 1):
            try:
                sock.sendto(message.encode("ascii"), target)
                data, _ = sock.recvfrom(65535)
                return json.loads(data.decode("utf-8"))
            except (socket.timeout, ConnectionResetError, json.JSONDecodeError) as exc:
                last_error = exc
                time.sleep(0.25 * attempt)
    finally:
        sock.close()
    raise RuntimeError(f"Нет корректного ответа от {target[0]}:{target[1]}: {last_error!r}")


def ping_server(target: tuple[str, int], used_local_ports: set[int]) -> str:
    sock = bind_unique_socket(used_local_ports, 2.5)
    try:
        sock.sendto(b"PING", target)
        data, _ = sock.recvfrom(2048)
        text = data.decode("ascii", errors="replace")
        if not text.startswith("PONG|udp-flow-limit-test|2|"):
            raise RuntimeError(f"Неожиданный ответ: {text!r}")
        return text
    finally:
        sock.close()


def discover_ports(host: str, used_local_ports: set[int], discovery_port: int) -> tuple[str, list[int], dict[str, Any]]:
    target = resolve_ipv4(host, discovery_port)
    payload = request_json(target, f"DISCOVER|{PROTOCOL_VERSION}", used_local_ports)
    if not payload.get("ok"):
        raise RuntimeError(f"Сервер отклонил обнаружение: {payload}")
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise RuntimeError(
            f"Несовместимая версия протокола: {payload.get('protocol_version')} вместо {PROTOCOL_VERSION}"
        )
    ports = payload.get("test_ports")
    if not isinstance(ports, list) or len(ports) != EXPECTED_TEST_PORTS:
        raise RuntimeError(f"Ожидалось {EXPECTED_TEST_PORTS} тестовых портов, получено: {ports!r}")
    cleaned = []
    for value in ports:
        port = int(value)
        if not 1024 <= port <= 65535 or port == discovery_port or port in cleaned:
            raise RuntimeError(f"Некорректный список тестовых портов: {ports!r}")
        cleaned.append(port)
    return target[0], cleaned, payload


def contiguous_prefix(sequences: set[int]) -> int:
    seq = 1
    while seq in sequences:
        seq += 1
    return seq - 1


def control_query(target: tuple[str, int], token: str, used_local_ports: set[int]) -> dict[str, Any]:
    return request_json(target, f"STATUS|{token}", used_local_ports, retries=5, timeout=2.0)


def run_uplink(
    target: tuple[str, int],
    packet_count: int,
    packet_size: int,
    interval_ms: int,
    used_local_ports: set[int],
) -> dict[str, Any]:
    token = secrets.token_hex(8)
    sock = bind_unique_socket(used_local_ports)
    local = sock.getsockname()
    started = time.time()
    for seq in range(1, packet_count + 1):
        sock.sendto(padded(f"UP|{token}|{seq}|{packet_count}", packet_size), target)
        if interval_ms:
            time.sleep(interval_ms / 1000.0)
    sock.close()

    time.sleep(max(0.5, interval_ms / 1000 * 3))
    status = control_query(target, token, used_local_ports)
    uplink = status.get("uplink", {})
    return {
        "token": token,
        "local_ip": local[0],
        "local_port": local[1],
        "sent": packet_count,
        "server_received": uplink.get("received_count"),
        "server_first_seq": uplink.get("first_seq"),
        "server_last_seq": uplink.get("last_seq"),
        "server_missing_count": uplink.get("missing_count"),
        "server_missing_first_100": uplink.get("missing_first_100", []),
        "public_ip_seen_by_server": uplink.get("client_ip"),
        "public_port_seen_by_server": uplink.get("client_port"),
        "elapsed_seconds": round(time.time() - started, 3),
    }


def run_downlink(
    target: tuple[str, int],
    packet_count: int,
    packet_size: int,
    interval_ms: int,
    hello_count: int,
    receive_timeout: float,
    used_local_ports: set[int],
) -> dict[str, Any]:
    token = secrets.token_hex(8)
    sock = bind_unique_socket(used_local_ports, 0.35)
    local = sock.getsockname()

    for hello_seq in range(1, hello_count + 1):
        payload = (
            f"HELLO|{token}|{hello_seq}|{hello_count}|{packet_count}|"
            f"{packet_size}|{interval_ms}|{PROTOCOL_VERSION}"
        )
        sock.sendto(padded(payload, packet_size), target)
        time.sleep(0.04)

    received: set[int] = set()
    deadline = time.monotonic() + receive_timeout
    while time.monotonic() < deadline:
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except ConnectionResetError:
            continue
        text = data.split(b"\0", 1)[0].decode("ascii", errors="replace")
        parts = text.split("|")
        if len(parts) >= 4 and parts[0] == "DOWN" and parts[1] == token:
            try:
                received.add(int(parts[2]))
            except ValueError:
                pass
        if len(received) >= packet_count:
            break
    sock.close()

    time.sleep(0.3)
    status = control_query(target, token, used_local_ports)
    down = status.get("downlink", {})
    missing = [seq for seq in range(1, packet_count + 1) if seq not in received]
    return {
        "token": token,
        "hello_sent": hello_count,
        "local_ip": local[0],
        "local_port": local[1],
        "server_hello_received": down.get("hello_received"),
        "server_down_sent": down.get("sent_count"),
        "server_send_errors": down.get("send_errors"),
        "client_received": len(received),
        "client_contiguous_prefix": contiguous_prefix(received),
        "client_last_seq": max(received) if received else None,
        "client_missing_count": len(missing),
        "client_missing_first_100": missing[:100],
        "total_datagrams_observed_on_test_tuple": hello_count + len(received),
        "public_ip_seen_by_server": down.get("client_ip"),
        "public_port_seen_by_server": down.get("client_port"),
    }


def uplink_is_100_percent(item: dict[str, Any], packet_count: int) -> bool:
    return bool(
        item.get("server_received") == packet_count
        and item.get("server_first_seq") == 1
        and item.get("server_last_seq") == packet_count
        and item.get("server_missing_count") in (0, None)
    )


def downlink_is_100_percent(
    item: dict[str, Any], packet_count: int, hello_count: int
) -> bool:
    return bool(
        item.get("server_hello_received") == hello_count
        and item.get("server_down_sent") == packet_count
        and item.get("server_send_errors") in (0, None)
        and item.get("client_received") == packet_count
        and item.get("client_missing_count") == 0
    )


def representative_attempt(
    attempts: list[dict[str, Any]],
    success_predicate,
    signature,
) -> dict[str, Any]:
    """Select a successful attempt, otherwise the most repeated failure pattern."""
    for item in attempts:
        if success_predicate(item):
            return item

    signatures = [signature(item) for item in attempts]
    most_common_signature, _ = Counter(signatures).most_common(1)[0]
    for item in reversed(attempts):
        if signature(item) == most_common_signature:
            return item
    return attempts[-1]


def summarize_attempt_values(attempts: list[dict[str, Any]], field: str) -> str:
    values = [item.get(field) for item in attempts]
    return ",".join("?" if value is None else str(value) for value in values)


def analyze_port(port_result: dict[str, Any], packet_count: int) -> dict[str, Any]:
    uplink_attempts = port_result["uplink_attempts"]
    down_groups = port_result["downlink"]

    uplink_full = any(uplink_is_100_percent(item, packet_count) for item in uplink_attempts)
    downlink_full = all(
        any(
            downlink_is_100_percent(attempt, packet_count, group["hello_sent"])
            for attempt in group["attempts"]
        )
        for group in down_groups
    )

    up_counts = [item.get("server_received") for item in uplink_attempts]
    up_repeated_failure = bool(
        len(uplink_attempts) == MAX_TEST_ATTEMPTS
        and not uplink_full
        and all(isinstance(value, int) and 0 < value < packet_count for value in up_counts)
        and len(set(up_counts)) == 1
        and all(
            item.get("server_first_seq") == 1
            and item.get("server_last_seq") == item.get("server_received")
            and item.get("server_missing_count") == packet_count - item.get("server_received")
            for item in uplink_attempts
        )
    )

    repeated_down_totals: list[int] = []
    down_repeated_failure = True
    for group in down_groups:
        attempts = group["attempts"]
        hello_count = group["hello_sent"]
        totals = [item.get("total_datagrams_observed_on_test_tuple") for item in attempts]
        group_full = any(
            downlink_is_100_percent(item, packet_count, hello_count) for item in attempts
        )
        group_consistent = bool(
            len(attempts) == MAX_TEST_ATTEMPTS
            and not group_full
            and all(isinstance(value, int) and 0 < value < packet_count + hello_count for value in totals)
            and len(set(totals)) == 1
            and all(
                item.get("server_hello_received") == hello_count
                and item.get("server_down_sent") == packet_count
                and item.get("server_send_errors") in (0, None)
                for item in attempts
            )
        )
        if not group_consistent:
            down_repeated_failure = False
        elif totals:
            repeated_down_totals.append(int(totals[0]))

    confirmed = bool(
        up_repeated_failure
        and down_repeated_failure
        and len(repeated_down_totals) == len(down_groups)
        and len(set(repeated_down_totals + [int(up_counts[0])])) == 1
    )

    limit = int(up_counts[0]) if confirmed else None

    if confirmed:
        verdict = f"CONFIRMED_LIMIT_{limit}"
        text = (
            f"Подтверждён двунаправленный лимит {limit} датаграмм: "
            f"одинаковый результат получен во всех {MAX_TEST_ATTEMPTS} попытках каждого подтеста."
        )
    elif uplink_full and downlink_full:
        verdict = "NO_LIMIT_WITHIN_TEST"
        retry_note = max(
            [len(uplink_attempts)] + [len(group["attempts"]) for group in down_groups]
        )
        text = (
            f"Ограничение не обнаружено в пределах {packet_count} пакетов; "
            f"все подтесты достигли 100%; максимальное число использованных попыток: {retry_note}."
        )
    else:
        selected_up = port_result["uplink"].get("server_received")
        selected_totals = [
            group.get("total_datagrams_observed_on_test_tuple") for group in down_groups
        ]
        same_selected_total = (
            isinstance(selected_up, int)
            and selected_totals
            and all(value == selected_up for value in selected_totals)
        )
        if same_selected_total and selected_up < packet_count:
            verdict = f"POSSIBLE_BIDIRECTIONAL_LIMIT_{selected_up}"
            text = (
                f"Возможен лимит {selected_up}, но три попытки дали недостаточно "
                "однородный результат для подтверждения."
            )
        else:
            verdict = "LOSS_OR_INCONCLUSIVE"
            text = (
                "После автоматических повторов остались потери или неоднозначный результат; "
                "фиксированный лимит не подтверждён."
            )

    return {
        "verdict": verdict,
        "text": text,
        "confirmed": confirmed,
        "limit": limit,
        "uplink_attempt_counts": up_counts,
        "uplink_100_percent": uplink_full,
        "downlink_attempt_totals": {
            str(group["hello_sent"]): [
                item.get("total_datagrams_observed_on_test_tuple")
                for item in group["attempts"]
            ]
            for group in down_groups
        },
        "downlink_100_percent": {
            str(group["hello_sent"]): any(
                downlink_is_100_percent(item, packet_count, group["hello_sent"])
                for item in group["attempts"]
            )
            for group in down_groups
        },
    }

def aggregate(port_results: list[dict[str, Any]], packet_count: int) -> dict[str, Any]:
    limits = [item["analysis"]["limit"] for item in port_results if item["analysis"]["confirmed"]]
    counter = Counter(limits)
    most_common_limit = None
    most_common_count = 0
    if counter:
        most_common_limit, most_common_count = counter.most_common(1)[0]

    no_limit_count = sum(item["analysis"]["verdict"] == "NO_LIMIT_WITHIN_TEST" for item in port_results)
    inconclusive_count = len(port_results) - len(limits) - no_limit_count

    if most_common_count == len(port_results):
        summary = (
            f"На всех {len(port_results)} случайных портах подтверждён одинаковый лимит "
            f"{most_common_limit} UDP-датаграмм на один 5-tuple."
        )
    elif most_common_count >= 8:
        summary = (
            f"На {most_common_count} из {len(port_results)} портов подтверждён лимит "
            f"{most_common_limit}; результат устойчивый, отдельные порты дали потери или иной результат."
        )
    elif no_limit_count == len(port_results):
        summary = (
            f"На всех {len(port_results)} случайных портах ограничение не обнаружено "
            f"в пределах {packet_count} пакетов."
        )
    else:
        summary = (
            f"Результаты неоднородны: подтверждённые лимиты={dict(counter)}, "
            f"без лимита={no_limit_count}, неоднозначно={inconclusive_count}."
        )

    return {
        "confirmed_limit_counts": {str(k): v for k, v in sorted(counter.items())},
        "most_common_limit": most_common_limit,
        "most_common_count": most_common_count,
        "no_limit_count": no_limit_count,
        "inconclusive_count": inconclusive_count,
        "summary": summary,
    }


def render_text(results: dict[str, Any]) -> str:
    settings = results["settings"]
    lines = [
        "=" * 118,
        "UDP FLOW LIMIT TEST — 10 RANDOM SERVER PORTS, AUTO-RETRY",
        "=" * 118,
        f"Дата: {results['timestamp']}",
        f"Компьютер: {results['computer']}",
        f"Сервер: {settings['server_label']}",
        f"Адрес: {settings['resolved_ip']}",
        f"Discovery: UDP/{settings['discovery_port']}",
        f"Тестовые порты: {', '.join(map(str, settings['test_ports']))}",
        f"Пакетов: {settings['packet_count']} (фиксировано); размер: {settings['packet_size']} байт; "
        f"интервал: {settings['interval_ms']} мс; HELLO: {settings['hello_tests']}; "
        f"максимум попыток: {settings['max_attempts']}",
        "",
        "ПОРТ      UPLINK ПОПЫТКИ       DOWN H=1 ПОПЫТКИ        DOWN H=3 ПОПЫТКИ        РЕЗУЛЬТАТ",
        "-" * 118,
    ]

    for item in results["ports"]:
        down_map = {group["hello_sent"]: group for group in item["downlink"]}
        d1 = down_map.get(1)
        d3 = down_map.get(3)
        up_text = summarize_attempt_values(item["uplink_attempts"], "server_received")
        d1_text = "-" if not d1 else summarize_attempt_values(d1["attempts"], "client_received")
        d3_text = "-" if not d3 else summarize_attempt_values(d3["attempts"], "client_received")
        lines.append(
            f"{item['port']:<9} "
            f"{up_text:<21} "
            f"{d1_text:<24} "
            f"{d3_text:<24} "
            f"{item['analysis']['verdict']}"
        )

    lines += [
        "",
        "ОБЩИЙ ВЫВОД",
        "-" * 118,
        results["aggregate"]["summary"],
        "",
    ]

    for item in results["ports"]:
        lines.append(f"UDP/{item['port']}: {item['analysis']['text']}")
        lines.append(
            "  Uplink получено по попыткам: "
            + summarize_attempt_values(item["uplink_attempts"], "server_received")
        )
        for group in item["downlink"]:
            lines.append(
                f"  Downlink HELLO={group['hello_sent']}, получено по попыткам: "
                + summarize_attempt_values(group["attempts"], "client_received")
                + "; HELLO+DOWN: "
                + summarize_attempt_values(
                    group["attempts"], "total_datagrams_observed_on_test_tuple"
                )
            )

    lines.append("=" * 118)
    return "\n".join(lines)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Test UDP flow limits on 10 auto-discovered ports")
    parser.add_argument("--host", help="server IP or DNS name")
    parser.add_argument("--label", help="server label in reports")
    parser.add_argument("--packet-count", type=int, default=DEFAULT_PACKET_COUNT, help=argparse.SUPPRESS)
    parser.add_argument("--packet-size", type=int, default=64)
    parser.add_argument("--interval-ms", type=int, default=50)
    parser.add_argument("--hello", default="1,3")
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--output-dir", default=r"C:\2" if os.name == "nt" else ".")
    parser.add_argument("--discovery-port", type=int, default=DISCOVERY_PORT, help=argparse.SUPPRESS)
    parser.add_argument("--non-interactive", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    print("=" * 76)
    print("ПРОВЕРКА UDP 5-TUPLE НА 10 АВТОМАТИЧЕСКИ ВЫБРАННЫХ ПОРТАХ")
    print("=" * 76)

    if args.non_interactive:
        if not args.host:
            raise RuntimeError("Для --non-interactive требуется --host")
        host = args.host
        server_label = args.label or args.host
        packet_count = args.packet_count
        packet_size = args.packet_size
        interval_ms = args.interval_ms
        hello_tests = parse_hello_list(args.hello)
        receive_timeout = args.timeout
        output_dir = Path(args.output_dir)
    else:
        server_label = ask("Имя сервера для отчёта", args.label or "test-server")
        host = ask("IP-адрес или DNS-имя сервера", args.host or "198.13.37.119")
        packet_count = DEFAULT_PACKET_COUNT
        print(f"Количество пакетов в каждом подтесте: {packet_count} (фиксировано)")
        packet_size = ask_int("Размер UDP payload, байт", args.packet_size, 48, 65000)
        interval_ms = ask_int("Интервал между пакетами, мс", args.interval_ms, 0, 60000)
        while True:
            try:
                hello_tests = parse_hello_list(ask("Количество HELLO через запятую", args.hello))
                break
            except (ValueError, TypeError):
                print("Укажите минимум два значения, например: 1,3")
        default_timeout = max(args.timeout, int(packet_count * interval_ms / 1000) + 3)
        receive_timeout = ask_int("Тайм-аут каждого downlink-подтеста, сек", default_timeout, 2, 3600)
        output_dir = Path(ask("Каталог результатов", args.output_dir))

    if not 30 <= packet_count <= 100000:
        raise RuntimeError("Количество пакетов должно быть 30..100000")
    if not 48 <= packet_size <= 65000:
        raise RuntimeError("Размер пакета должен быть 48..65000")
    if not 0 <= interval_ms <= 60000:
        raise RuntimeError("Интервал должен быть 0..60000 мс")

    output_dir.mkdir(parents=True, exist_ok=True)
    used_local_ports: set[int] = set()

    print(f"\nОбнаружение конфигурации {host}:UDP/{args.discovery_port} ...")
    resolved_ip, ports, discovery = discover_ports(host, used_local_ports, args.discovery_port)
    print(f"Получено 10 портов: {', '.join(map(str, ports))}")

    port_results: list[dict[str, Any]] = []
    for index, port in enumerate(ports, start=1):
        target = (resolved_ip, port)
        print("\n" + "=" * 76)
        print(f"ТЕСТ {index}/{len(ports)} — UDP/{port}")
        print("=" * 76)
        pong = ping_server(target, used_local_ports)
        print(f"PING: {pong}")

        uplink_attempts: list[dict[str, Any]] = []
        for attempt_no in range(1, MAX_TEST_ATTEMPTS + 1):
            print(
                f"  Uplink Windows -> Server, попытка {attempt_no}/{MAX_TEST_ATTEMPTS} ...",
                end="",
                flush=True,
            )
            attempt = run_uplink(
                target, packet_count, packet_size, interval_ms, used_local_ports
            )
            uplink_attempts.append(attempt)
            success = uplink_is_100_percent(attempt, packet_count)
            print(
                f" {attempt['server_received']}/{packet_count}"
                + (" — 100%" if success else " — повтор требуется")
            )
            if success:
                break

        uplink = representative_attempt(
            uplink_attempts,
            lambda item: uplink_is_100_percent(item, packet_count),
            lambda item: (
                item.get("server_received"),
                item.get("server_first_seq"),
                item.get("server_last_seq"),
                item.get("server_missing_count"),
            ),
        )

        downlink: list[dict[str, Any]] = []
        for hello_count in hello_tests:
            attempts: list[dict[str, Any]] = []
            for attempt_no in range(1, MAX_TEST_ATTEMPTS + 1):
                print(
                    f"  Downlink Server -> Windows, HELLO={hello_count}, "
                    f"попытка {attempt_no}/{MAX_TEST_ATTEMPTS} ...",
                    end="",
                    flush=True,
                )
                attempt = run_downlink(
                    target,
                    packet_count,
                    packet_size,
                    interval_ms,
                    hello_count,
                    float(receive_timeout),
                    used_local_ports,
                )
                attempts.append(attempt)
                success = downlink_is_100_percent(
                    attempt, packet_count, hello_count
                )
                print(
                    f" {attempt['client_received']}/{packet_count}; "
                    f"HELLO+DOWN={attempt['total_datagrams_observed_on_test_tuple']}"
                    + (" — 100%" if success else " — повтор требуется")
                )
                if success:
                    break

            selected = representative_attempt(
                attempts,
                lambda item, hc=hello_count: downlink_is_100_percent(
                    item, packet_count, hc
                ),
                lambda item: (
                    item.get("client_received"),
                    item.get("total_datagrams_observed_on_test_tuple"),
                    item.get("server_hello_received"),
                    item.get("server_down_sent"),
                    item.get("server_send_errors"),
                ),
            ).copy()
            selected["attempts"] = attempts
            selected["attempt_count"] = len(attempts)
            selected["passed_100_percent"] = any(
                downlink_is_100_percent(item, packet_count, hello_count)
                for item in attempts
            )
            downlink.append(selected)

        port_result = {
            "port": port,
            "pong": pong,
            "uplink": uplink,
            "uplink_attempts": uplink_attempts,
            "uplink_attempt_count": len(uplink_attempts),
            "uplink_passed_100_percent": any(
                uplink_is_100_percent(item, packet_count) for item in uplink_attempts
            ),
            "downlink": downlink,
        }
        port_result["analysis"] = analyze_port(port_result, packet_count)
        print(f"  Итог UDP/{port}: {port_result['analysis']['text']}")
        port_results.append(port_result)

    results: dict[str, Any] = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "computer": platform.node(),
        "python": sys.version.split()[0],
        "settings": {
            "server_label": server_label,
            "host": host,
            "resolved_ip": resolved_ip,
            "discovery_port": args.discovery_port,
            "test_ports": ports,
            "packet_count": packet_count,
            "packet_size": packet_size,
            "interval_ms": interval_ms,
            "hello_tests": hello_tests,
            "receive_timeout": receive_timeout,
            "test_repetitions": len(ports),
            "max_attempts": MAX_TEST_ATTEMPTS,
        },
        "discovery": discovery,
        "ports": port_results,
    }
    results["aggregate"] = aggregate(port_results, packet_count)

    text = render_text(results)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_label = "".join(c if c.isalnum() or c in "-_" else "_" for c in server_label)[:40]
    base = output_dir / f"udp-flow-random10-{safe_label}-{stamp}"
    txt_path = base.with_suffix(".txt")
    json_path = base.with_suffix(".json")
    txt_path.write_text(text, encoding="utf-8")
    json_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")

    print("\n" + text)
    print(f"\nТекстовый отчёт: {txt_path}")
    print(f"JSON-отчёт:      {json_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nОстановлено пользователем.")
        raise SystemExit(130)
    except Exception as exc:
        print(f"\nОШИБКА: {exc}", file=sys.stderr)
        raise SystemExit(1)
