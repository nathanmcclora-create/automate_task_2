"""Continuously monitor DNS settings and send email alerts for failures."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import re
import socket
import subprocess
import sys
import time
from collections import OrderedDict
from datetime import datetime
from pathlib import Path

import paramiko


CSV_FILE = Path(__file__).with_name("network_devices.csv")
ALERT_SCRIPT = Path(__file__).with_name("t2_c4_2_send_dns_alert_email.py")
DNS1 = "10.10.10.10"
DNS2 = "10.10.10.20"
APPROVED_DNS = {DNS1, DNS2}
CHECK_INTERVAL_SECONDS = 15
SSH_TIMEOUT_SECONDS = 15
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5

DEFAULT_USERNAME = "ubuntu"
DEFAULT_PASSWORD = "ubuntu"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor DNS every 15 seconds for eligible devices and email on failures."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=CHECK_INTERVAL_SECONDS,
        help="Seconds between monitoring passes (default: 15).",
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Run one pass and exit.",
    )
    return parser.parse_args()


def should_exclude(device_name: str) -> bool:
    name = (device_name or "").strip().lower()
    return name.startswith("router") or name.startswith("sw") or "switch" in name or name == "smtp"


def load_devices() -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    with CSV_FILE.open(newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            name = (row.get("Device Name") or "").strip()
            if should_exclude(name):
                continue

            inventory_address = (row.get("Device Address") or "").strip()
            if not inventory_address or inventory_address.lower() == "none":
                continue

            devices.append(
                {
                    "name": name,
                    "inventory_address": inventory_address,
                    "access_port": (row.get("Access Port") or "").strip(),
                    "username": (row.get("Username") or DEFAULT_USERNAME).strip() or DEFAULT_USERNAME,
                    "password": (row.get("Password") or DEFAULT_PASSWORD).strip() or DEFAULT_PASSWORD,
                }
            )
    return devices


def receive_console_output(console: socket.socket, pause_seconds: float = 0.4) -> str:
    time.sleep(pause_seconds)
    chunks: list[bytes] = []
    while True:
        try:
            chunk = console.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


def unique_ipv4_values(text: str) -> list[str]:
    values = OrderedDict()
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            parsed = ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            continue
        values[str(parsed)] = None
    return list(values)


def resolve_dhcp_ip(device: dict[str, str]) -> tuple[str, str]:
    access_port = device.get("access_port", "")
    if not access_port:
        return "", "Missing access port for DHCP device"

    try:
        access_port_number = int(access_port)
    except ValueError:
        return "", f"Invalid access port: {access_port}"

    try:
        with socket.create_connection((CONSOLE_HOST, access_port_number), timeout=CONSOLE_TIMEOUT_SECONDS) as console:
            console.settimeout(0.5)
            receive_console_output(console, pause_seconds=0.2)
            console.sendall(b"\n")
            receive_console_output(console, pause_seconds=0.2)
            console.sendall(f"{DEFAULT_USERNAME}\n".encode())
            receive_console_output(console, pause_seconds=0.2)
            console.sendall(f"{DEFAULT_PASSWORD}\n".encode())
            receive_console_output(console, pause_seconds=0.6)
            console.sendall(b"hostname -I\n")
            output = receive_console_output(console, pause_seconds=0.8)
    except OSError as exc:
        return "", str(exc)

    for candidate in unique_ipv4_values(output):
        if candidate.startswith("127."):
            continue
        return candidate, ""

    return "", "No IPv4 address discovered for DHCP device"


def connect_ssh(hostname: str, username: str, password: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=hostname,
        username=username,
        password=password,
        timeout=SSH_TIMEOUT_SECONDS,
        banner_timeout=SSH_TIMEOUT_SECONDS,
        auth_timeout=SSH_TIMEOUT_SECONDS,
    )
    return client


def parse_dns_from_text(text: str) -> list[str]:
    values = OrderedDict()

    for match in re.findall(r"^\s*nameserver\s+(\S+)", text, flags=re.IGNORECASE | re.MULTILINE):
        values[match.strip()] = None

    for line in text.splitlines():
        if "dns server" not in line.lower() and "dns servers" not in line.lower():
            continue
        for candidate in unique_ipv4_values(line):
            values[candidate] = None

    if not values:
        for candidate in unique_ipv4_values(text):
            values[candidate] = None

    return [value for value in values.keys() if not value.startswith("127.")]


def read_dns_settings(hostname: str, username: str, password: str) -> tuple[list[str], str]:
    client = connect_ssh(hostname, username, password)
    try:
        command = "sh -lc 'cat /etc/resolv.conf 2>/dev/null; echo; resolvectl dns 2>/dev/null; echo; systemd-resolve --status 2>/dev/null'"
        _, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT_SECONDS)
        output = stdout.read().decode("utf-8", errors="replace")
        error_text = stderr.read().decode("utf-8", errors="replace").strip()
        return parse_dns_from_text(output), error_text
    finally:
        client.close()


def canonical_dns(dns_servers: list[str]) -> str:
    if not dns_servers:
        return "None"
    return ", ".join(dns_servers)


def evaluate_dns(dns_servers: list[str]) -> tuple[str, str]:
    if not dns_servers:
        return "FAIL", "No DNS servers found"

    unique = set(dns_servers)
    if not unique.intersection(APPROVED_DNS):
        return "FAIL", "DNS does not include DNS1 or DNS2"

    unexpected = sorted(server for server in unique if server not in APPROVED_DNS)
    if unexpected:
        return "FAIL", f"Unexpected DNS server(s): {', '.join(unexpected)}"

    return "SUCCESS", "DNS points to approved DNS1/DNS2"


def send_failure_email(hostname: str, device_ip: str, dns_servers: str, reason: str, timestamp: str) -> bool:
    if not ALERT_SCRIPT.exists():
        print(f"Alert script missing: {ALERT_SCRIPT}")
        return False

    command = [
        sys.executable,
        str(ALERT_SCRIPT),
        "--device-name",
        hostname,
        "--ip-address",
        device_ip,
        "--detected-dns",
        dns_servers,
        "--expected-dns",
        f"{DNS1}, {DNS2}",
        "--timestamp",
        timestamp,
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    return result.returncode == 0


def inspect_device(device: dict[str, str]) -> dict[str, str]:
    runtime_ip = device["inventory_address"]
    if runtime_ip.lower() == "dhcp":
        runtime_ip, error = resolve_dhcp_ip(device)
        if not runtime_ip:
            return {
                "name": device["name"],
                "ip_address": "DHCP",
                "status": "FAIL",
                "dns": "Unknown",
                "reason": error,
            }

    try:
        dns_servers, stderr_text = read_dns_settings(runtime_ip, device["username"], device["password"])
    except Exception as exc:
        return {
            "name": device["name"],
            "ip_address": runtime_ip,
            "status": "FAIL",
            "dns": "Unknown",
            "reason": f"DNS read failed: {exc}",
        }

    status, reason = evaluate_dns(dns_servers)
    if status == "SUCCESS" and stderr_text:
        reason = f"DNS check success (with stderr: {stderr_text})"

    return {
        "name": device["name"],
        "ip_address": runtime_ip,
        "status": status,
        "dns": canonical_dns(dns_servers),
        "reason": reason,
    }


def print_dns_result(timestamp: str, result: dict[str, str]) -> None:
    print(
        f"{timestamp} | Hostname: {result['name']} | IP address: {result['ip_address']} | "
        f"Status: {result['status']} | DNS IP address: {result['dns']}"
    )
    if result["status"] == "FAIL":
        print(f"{timestamp} | Hostname: {result['name']} | Reason: {result['reason']}")


def monitor_devices(interval_seconds: int, one_shot: bool = False) -> None:
    print("Starting DNS monitor-only loop. Press Ctrl+C to stop.")
    if one_shot:
        print("One-shot mode enabled.")

    failure_signatures: dict[str, str] = {}

    while True:
        devices = load_devices()
        print(f"Monitoring {len(devices)} eligible device(s).")

        for device in devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = inspect_device(device)
            print_dns_result(timestamp, result)

            if result["status"] == "SUCCESS":
                failure_signatures.pop(device["name"], None)
                continue

            signature = f"{result['ip_address']}|{result['dns']}|{result['reason']}"
            if failure_signatures.get(device["name"]) == signature:
                continue

            email_sent = send_failure_email(
                hostname=result["name"],
                device_ip=result["ip_address"],
                dns_servers=result["dns"],
                reason=result["reason"],
                timestamp=timestamp,
            )
            failure_signatures[device["name"]] = signature
            print(
                f"{timestamp} | Hostname: {result['name']} | "
                f"Email alert: {'SENT' if email_sent else 'FAILED'}"
            )

        if one_shot:
            return

        time.sleep(interval_seconds)


def main() -> int:
    args = parse_args()

    if not CSV_FILE.exists():
        print(f"Inventory file not found: {CSV_FILE}")
        return 1

    try:
        monitor_devices(interval_seconds=args.interval, one_shot=args.one_shot)
    except KeyboardInterrupt:
        print("DNS monitor stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
