"""Fix DNS for failing devices and run break/fix email-ticket workflow."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import re
import shlex
import smtplib
import socket
import subprocess
import sys
from collections import OrderedDict
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import paramiko


CSV_FILE = Path(__file__).with_name("network_devices.csv")
LEGACY_WORKFLOW_SCRIPT = Path(__file__).with_name("t2_c4_create_dns_email_break_fix.py")
CORRECTED_EMAIL_SCRIPT = Path(__file__).with_name("t2_c4_4_send_dns_corrected_email.py")
DNS1 = "10.10.10.10"
DNS2 = "10.10.10.20"
APPROVED_DNS = {DNS1, DNS2}
SSH_TIMEOUT_SECONDS = 45
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5

DEFAULT_USERNAME = "ubuntu"
DEFAULT_PASSWORD = "ubuntu"

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.d522.wgu.internal")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_TIMEOUT_SECONDS = 10
FROM_ADDRESS = os.getenv("DNS_ALERT_FROM", "network-monitoring@localdomain")
TO_ADDRESS = os.getenv("DNS_ALERT_TO", "stakeholders@localdomain")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fix failing DNS settings for eligible devices, verify results, and run "
            "the t2_c4_create_dns_email_break_fix.py workflow."
        )
    )
    parser.add_argument(
        "--workflow-device-name",
        default="DB",
        help="Device name used by t2_c4_create_dns_email_break_fix.py (default: DB).",
    )
    parser.add_argument(
        "--skip-legacy-workflow",
        action="store_true",
        help="Only perform fix/verify for failing devices and skip legacy break/fix workflow.",
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
    import time

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

    if not values:
        for candidate in unique_ipv4_values(text):
            values[candidate] = None

    return [value for value in values.keys() if not value.startswith("127.")]


def read_dns_settings(hostname: str, username: str, password: str) -> list[str]:
    client = connect_ssh(hostname, username, password)
    try:
        command = "sh -lc 'cat /etc/resolv.conf 2>/dev/null; echo; resolvectl dns 2>/dev/null; echo; systemd-resolve --status 2>/dev/null'"
        _, stdout, _ = client.exec_command(command, timeout=SSH_TIMEOUT_SECONDS)
        output = stdout.read().decode("utf-8", errors="replace")
        return parse_dns_from_text(output)
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


def send_email(subject: str, body: str) -> bool:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = FROM_ADDRESS
    message["To"] = TO_ADDRESS
    message.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.ehlo()
            failures = server.send_message(message)
            return not failures
    except (OSError, smtplib.SMTPException):
        return False


def send_corrected_email(device_name: str, ip_address: str, corrected_dns: str, timestamp: str) -> bool:
    if not CORRECTED_EMAIL_SCRIPT.exists():
        print(f"Corrected email script missing: {CORRECTED_EMAIL_SCRIPT}")
        return False

    command = [
        sys.executable,
        str(CORRECTED_EMAIL_SCRIPT),
        "--device-name",
        device_name,
        "--ip-address",
        ip_address,
        "--expected-dns",
        corrected_dns,
        "--timestamp",
        timestamp,
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    return result.returncode == 0


def run_remote_sudo(client: paramiko.SSHClient, password: str, command: str) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(
        f"sudo -S -p '' sh -c {shlex.quote(command)}",
        get_pty=True,
        timeout=SSH_TIMEOUT_SECONDS,
    )
    stdin.write(f"{password}\n")
    stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    exit_code = stdout.channel.recv_exit_status()
    out = "\n".join(line for line in out.splitlines() if line.strip() != password).strip()
    err = "\n".join(line for line in err.splitlines() if line.strip() != password).strip()
    return exit_code, out, err


def remediate_dns(hostname: str, username: str, password: str) -> tuple[bool, str]:
    command = (
        f"printf '%s\\n' 'nameserver {DNS1}' 'nameserver {DNS2}' "
        "'options timeout:2 attempts:2' > /etc/resolv.conf"
    )
    client = connect_ssh(hostname, username, password)
    try:
        code, out, err = run_remote_sudo(client, password, command)
        details = [value for value in (out, err) if value]
        return code == 0, " | ".join(details) if details else "No command output"
    finally:
        client.close()


def ensure_hostname_resolution(hostname: str, username: str, password: str) -> tuple[bool, str]:
    """Ensure local hostname exists in /etc/hosts to avoid sudo resolution warnings."""
    client = connect_ssh(hostname, username, password)
    try:
        check_command = (
            "sh -lc 'hn=$(hostname -s 2>/dev/null || hostname); "
            "if grep -Eq \"(^|[[:space:]])${hn}([[:space:]]|$)\" /etc/hosts; "
            "then echo OK:${hn}; else echo MISSING:${hn}; fi'"
        )
        _, stdout, stderr = client.exec_command(check_command, timeout=SSH_TIMEOUT_SECONDS)
        check_out = stdout.read().decode("utf-8", errors="replace").strip()
        check_err = stderr.read().decode("utf-8", errors="replace").strip()

        if check_out.startswith("OK:"):
            return True, f"Hostname mapping present ({check_out[3:]})"

        if not check_out.startswith("MISSING:"):
            details = check_out or check_err or "Unknown pre-check output"
            return False, f"Pre-check could not determine hostname mapping: {details}"

        add_command = (
            "hn=$(hostname -s 2>/dev/null || hostname); "
            "grep -Eq \"(^|[[:space:]])${hn}([[:space:]]|$)\" /etc/hosts "
            "|| printf '127.0.1.1 %s\\n' \"${hn}\" >> /etc/hosts"
        )
        code, out, err = run_remote_sudo(client, password, add_command)
        details = [value for value in (out, err) if value]
        detail_text = " | ".join(details) if details else "No command output"
        if code != 0:
            return False, f"Failed to add hostname mapping: {detail_text}"

        return True, f"Added hostname mapping for {check_out[8:]}"
    finally:
        client.close()


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
        dns_servers = read_dns_settings(runtime_ip, device["username"], device["password"])
    except Exception as exc:
        return {
            "name": device["name"],
            "ip_address": runtime_ip,
            "status": "FAIL",
            "dns": "Unknown",
            "reason": f"DNS read failed: {exc}",
        }

    status, reason = evaluate_dns(dns_servers)
    return {
        "name": device["name"],
        "ip_address": runtime_ip,
        "status": status,
        "dns": canonical_dns(dns_servers),
        "reason": reason,
    }


def fix_failed_devices() -> int:
    print("Starting DNS remediation for failing eligible devices.")
    devices = load_devices()
    print(f"Checking {len(devices)} eligible device(s).")

    fixed_count = 0
    failed_count = 0

    for device in devices:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        result = inspect_device(device)
        print(
            f"{timestamp} | Hostname: {result['name']} | IP address: {result['ip_address']} | "
            f"Status: {result['status']} | DNS IP address: {result['dns']}"
        )

        if result["status"] == "SUCCESS":
            continue

        failed_count += 1
        subject = f"DNS ALERT: {result['name']} ({result['ip_address']})"
        body = (
            "DNS remediation script detected a failing DNS configuration.\n\n"
            f"Hostname: {result['name']}\n"
            f"IP address: {result['ip_address']}\n"
            f"Current DNS: {result['dns']}\n"
            f"Expected DNS: {DNS1}, {DNS2}\n"
            f"Reason: {result['reason']}\n"
            f"Timestamp: {timestamp}\n"
        )
        email_sent = send_email(subject, body)
        print(f"{timestamp} | Hostname: {result['name']} | Email alert: {'SENT' if email_sent else 'FAILED'}")

        runtime_ip = result["ip_address"]
        if runtime_ip in {"", "DHCP"}:
            print(f"{timestamp} | Hostname: {result['name']} | Remediation skipped: no runtime IP")
            continue

        try:
            host_ok, host_details = ensure_hostname_resolution(runtime_ip, device["username"], device["password"])
        except Exception as exc:
            host_ok, host_details = False, f"Pre-check error: {exc!r}"
        print(
            f"{timestamp} | Hostname: {result['name']} | Hostname resolution pre-check: "
            f"{'SUCCESS' if host_ok else 'FAIL'} | {host_details}"
        )

        try:
            changed, details = remediate_dns(runtime_ip, device["username"], device["password"])
        except Exception as exc:
            print(f"{timestamp} | Hostname: {result['name']} | Remediation failed: {exc!r}")
            continue

        print(
            f"{timestamp} | Hostname: {result['name']} | Remediation command: "
            f"{'SUCCESS' if changed else 'FAIL'} | {details}"
        )

        verify_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        verify_result = inspect_device(device)
        print(
            f"{verify_timestamp} | Hostname: {verify_result['name']} | IP address: {verify_result['ip_address']} | "
            f"Post-fix status: {verify_result['status']} | DNS IP address: {verify_result['dns']}"
        )

        if verify_result["status"] == "SUCCESS":
            fixed_count += 1
            corrected_email_sent = send_corrected_email(
                device_name=verify_result["name"],
                ip_address=verify_result["ip_address"],
                corrected_dns=f"{DNS1}, {DNS2}",
                timestamp=verify_timestamp,
            )
            print(
                f"{verify_timestamp} | Hostname: {verify_result['name']} | "
                f"Correction email: {'SENT' if corrected_email_sent else 'FAILED'}"
            )

    print(f"DNS remediation summary: failing devices found = {failed_count}, fixed = {fixed_count}")
    return 0


def run_legacy_break_fix_workflow(device_name: str) -> int:
    if not LEGACY_WORKFLOW_SCRIPT.exists():
        print(f"Legacy workflow script not found: {LEGACY_WORKFLOW_SCRIPT}")
        return 1

    print(
        "Running legacy break/fix workflow script "
        f"for device '{device_name}' to perform alert + Helpdesk ticket lifecycle."
    )
    command = [sys.executable, str(LEGACY_WORKFLOW_SCRIPT), "--device-name", device_name]
    result = subprocess.run(command, check=False)
    print(f"Legacy workflow exit code: {result.returncode}")
    return result.returncode


def main() -> int:
    args = parse_args()

    if not CSV_FILE.exists():
        print(f"Inventory file not found: {CSV_FILE}")
        return 1

    remediation_code = fix_failed_devices()

    if args.skip_legacy_workflow:
        return remediation_code

    workflow_code = run_legacy_break_fix_workflow(args.workflow_device_name)
    return remediation_code if workflow_code == 0 else workflow_code


if __name__ == "__main__":
    raise SystemExit(main())
