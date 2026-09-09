"""Continuously monitor device DNS settings and email on misconfiguration."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import re
import smtplib
import socket
import time
from collections import OrderedDict
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import paramiko


CSV_CANDIDATES = (
    Path(__file__).with_name("network_device.csv"),
    Path(__file__).with_name("network_devices.csv"),
)
DNS1 = "10.10.10.10"
DNS2 = "10.10.10.20"
APPROVED_DNS = {DNS1, DNS2}
DEFAULT_INTERVAL_SECONDS = 15
SSH_TIMEOUT_SECONDS = 15
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5

DHCP_USERNAME = "ubuntu"
DHCP_PASSWORD = "ubuntu"

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.d522.wgu.internal")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_TIMEOUT_SECONDS = 10
FROM_ADDRESS = os.getenv("DNS_ALERT_FROM", "network-monitoring@localdomain")
TO_ADDRESS = os.getenv("DNS_ALERT_TO", "stakeholders@localdomain")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Continuously check device DNS settings and send alert emails on failures."
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
        help="Seconds to wait between DNS checks. Default: 15",
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Run a single DNS check pass and exit.",
    )
    return parser.parse_args()


def should_exclude(device_name: str) -> bool:
    name = (device_name or "").strip().lower()
    return name.startswith("router") or name.startswith("sw") or "switch" in name or name == "smtp"


def get_csv_path() -> Path:
    for candidate in CSV_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find network_device.csv or network_devices.csv in the script directory.")


def load_devices() -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    with get_csv_path().open(newline="", encoding="utf-8") as csv_file:
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
                    "username": (row.get("Username") or DHCP_USERNAME).strip() or DHCP_USERNAME,
                    "password": (row.get("Password") or DHCP_PASSWORD).strip() or DHCP_PASSWORD,
                }
            )
    return devices


def unique_ipv4_values(text: str) -> list[str]:
    values = OrderedDict()
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            parsed = ipaddress.IPv4Address(match)
        except ipaddress.AddressValueError:
            continue
        values[str(parsed)] = None
    return list(values)


def preferred_dns_servers(dns_servers: list[str]) -> list[str]:
    non_loopback_servers = [server for server in dns_servers if not server.startswith("127.")]
    if non_loopback_servers:
        return non_loopback_servers
    return dns_servers


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


def resolve_dhcp_ip(device: dict[str, str]) -> tuple[str, str]:
    access_port = device.get("access_port", "")
    if not access_port:
        return "", "Missing access port for DHCP device"

    try:
        access_port_number = int(access_port)
    except ValueError:
        return "", f"Invalid access port: {access_port}"

    try:
        with socket.create_connection(
            (CONSOLE_HOST, access_port_number),
            timeout=CONSOLE_TIMEOUT_SECONDS,
        ) as console:
            console.settimeout(0.5)
            receive_console_output(console, pause_seconds=0.2)
            console.sendall(b"\n")
            receive_console_output(console, pause_seconds=0.2)
            console.sendall(f"{DHCP_USERNAME}\n".encode())
            receive_console_output(console, pause_seconds=0.2)
            console.sendall(f"{DHCP_PASSWORD}\n".encode())
            receive_console_output(console, pause_seconds=0.6)
            console.sendall(b"hostname -I\n")
            output = receive_console_output(console, pause_seconds=0.8)
    except OSError as exc:
        return "", str(exc)

    for candidate in unique_ipv4_values(output):
        if candidate.startswith("127."):
            continue
        return candidate, ""
    return "", "No IPv4 address found in console output"


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


def read_dns_settings(hostname: str, username: str, password: str) -> tuple[list[str], str]:
    client = connect_ssh(hostname, username, password)
    try:
        _, stdout, stderr = client.exec_command(
            "sh -lc 'cat /etc/resolv.conf 2>/dev/null; printf '\\n'; resolvectl dns 2>/dev/null; printf '\\n'; systemd-resolve --status 2>/dev/null'",
            timeout=SSH_TIMEOUT_SECONDS,
        )
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace").strip()
        return preferred_dns_servers(unique_ipv4_values(output)), error
    finally:
        client.close()


def canonical_dns(dns_servers: list[str]) -> str:
    if not dns_servers:
        return "None"
    return ", ".join(dns_servers)


def evaluate_dns_servers(dns_servers: list[str]) -> tuple[str, str]:
    if not dns_servers:
        return "FAIL", "No DNS servers found"
    unexpected = [server for server in dns_servers if server not in APPROVED_DNS]
    if unexpected:
        return "FAIL", f"Unexpected DNS server(s): {', '.join(unexpected)}"
    return "SUCCESS", "Approved DNS settings detected"


def send_failure_email(
    device_name: str,
    device_ip: str,
    detected_dns: str,
    reason: str,
    timestamp: str,
) -> bool:
    message = EmailMessage()
    message["Subject"] = f"DNS Configuration Alert: {device_name} ({device_ip})"
    message["From"] = FROM_ADDRESS
    message["To"] = TO_ADDRESS
    message.set_content(
        "Automated DNS monitoring detected a device with incorrect DNS settings.\n\n"
        f"Hostname: {device_name}\n"
        f"IP address: {device_ip}\n"
        f"Detected DNS: {detected_dns}\n"
        f"Expected DNS: {DNS1}, {DNS2}\n"
        f"Status: FAIL\n"
        f"Reason: {reason}\n"
        f"Timestamp: {timestamp}\n"
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.ehlo()
            failures = server.send_message(message)
            return not failures
    except (OSError, smtplib.SMTPException):
        return False


def inspect_device(device: dict[str, str]) -> dict[str, str]:
    runtime_ip = device["inventory_address"]
    if runtime_ip.lower() == "dhcp":
        runtime_ip, ip_error = resolve_dhcp_ip(device)
        if not runtime_ip:
            return {
                "name": device["name"],
                "ip_address": "DHCP",
                "status": "FAIL",
                "dns": "Unknown",
                "reason": ip_error,
            }

    try:
        dns_servers, stderr_output = read_dns_settings(
            runtime_ip,
            device["username"],
            device["password"],
        )
    except Exception as exc:
        return {
            "name": device["name"],
            "ip_address": runtime_ip,
            "status": "FAIL",
            "dns": "Unknown",
            "reason": f"DNS read failed: {exc}",
        }

    status, reason = evaluate_dns_servers(dns_servers)
    if stderr_output and status == "SUCCESS":
        reason = f"Approved DNS settings detected ({stderr_output})"

    return {
        "name": device["name"],
        "ip_address": runtime_ip,
        "status": status,
        "dns": canonical_dns(dns_servers),
        "reason": reason,
    }


def print_result(result: dict[str, str], timestamp: str) -> None:
    print(
        f"{timestamp} | Hostname: {result['name']} | IP address: {result['ip_address']} | "
        f"Status: {result['status']} | DNS IP address: {result['dns']}"
    )
    if result["status"] == "FAIL":
        print(f"{timestamp} | Hostname: {result['name']} | Reason: {result['reason']}")


def monitor_devices(interval_seconds: int, one_shot: bool = False) -> None:
    print("Starting DNS settings monitor. Press Ctrl+C to stop.")
    if one_shot:
        print("One-shot mode enabled: one DNS pass will be executed.")

    active_failure_signatures: dict[str, str] = {}

    while True:
        devices = load_devices()
        print(f"Monitoring {len(devices)} eligible device(s).")

        for device in devices:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result = inspect_device(device)
            print_result(result, timestamp)

            if result["status"] == "SUCCESS":
                active_failure_signatures.pop(device["name"], None)
                continue

            signature = f"{result['ip_address']}|{result['dns']}|{result['reason']}"
            if active_failure_signatures.get(device["name"]) == signature:
                continue

            email_sent = send_failure_email(
                result["name"],
                result["ip_address"],
                result["dns"],
                result["reason"],
                timestamp,
            )
            active_failure_signatures[device["name"]] = signature
            print(
                f"{timestamp} | Hostname: {result['name']} | Email alert: "
                f"{'SENT' if email_sent else 'FAILED'}"
            )

        if one_shot:
            return

        time.sleep(interval_seconds)


def main() -> int:
    args = parse_args()
    try:
        monitor_devices(interval_seconds=args.interval, one_shot=args.one_shot)
    except KeyboardInterrupt:
        print("DNS settings monitor stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
