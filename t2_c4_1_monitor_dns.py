"""Continuously verify DNS settings for monitored devices, fix misconfigurations, and alert on failures.

Run t2_c4_create_dns_email_break_fix.py during monitoring to exercise break/fix alert and ticket flow.
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import ipaddress
import os
import re
import smtplib
import socket
import threading
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any


CSV_CANDIDATES = (
    Path(__file__).with_name("network_device.csv"),
    Path(__file__).with_name("network_devices.csv"),
)
PING_INTERVAL_SECONDS = 15
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5
VNC_PORT_RANGE = range(5900, 6000)

DHCP_USERNAME = "ubuntu"
DHCP_PASSWORD = "ubuntu"
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.d522.wgu.internal")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_TIMEOUT_SECONDS = 10
FROM_ADDRESS = os.getenv("DNS_ALERT_FROM", "network-monitoring@localdomain")
TO_ADDRESS = os.getenv("DNS_ALERT_TO", "stakeholders@localdomain")


def load_dns_module() -> Any:
    file_path = Path(__file__).resolve().parent / "d522-Task-1-revision" / "d4_verify_new_dns.py"
    spec = importlib.util.spec_from_file_location("d4_verify_new_dns", file_path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError("Could not load d4_verify_new_dns.py from d522-Task-1-revision")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DNS_FIXER = load_dns_module()
DNS1 = DNS_FIXER.DNS1
DNS2 = DNS_FIXER.DNS2
APPROVED_DNS = {DNS1, DNS2}


def should_exclude(device_name: str) -> bool:
    name = (device_name or "").strip().lower()
    return name.startswith("router") or name.startswith("sw") or "switch" in name or name == "smtp"


def get_csv_path() -> Path:
    for candidate in CSV_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find network_device.csv or network_devices.csv in the script directory.")


def load_devices() -> list[dict[str, str]]:
    csv_file = get_csv_path()
    with csv_file.open(newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        devices: list[dict[str, str]] = []
        for row in reader:
            device_name = (row.get("Device Name") or "").strip()
            if should_exclude(device_name):
                continue

            address = (row.get("Device Address") or "").strip()
            if not address or address.lower() == "none":
                continue

            devices.append(
                {
                    "name": device_name,
                    "address": address,
                    "access_port": (row.get("Access Port") or "").strip(),
                    "os": (row.get("OS") or "").strip(),
                    "username": (row.get("Username") or DHCP_USERNAME).strip() or DHCP_USERNAME,
                    "password": (row.get("Password") or DHCP_PASSWORD).strip() or DHCP_PASSWORD,
                }
            )
    return devices


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Monitor DNS settings, alert on misconfiguration, and auto-correct to internal DNS."
    )
    parser.add_argument(
        "--one-shot",
        action="store_true",
        help="Run one DNS inspection pass and exit.",
    )
    parser.add_argument(
        "--with-icmp",
        action="store_true",
        help="Run DNS monitoring concurrently with t2_c2_monitor_icmp.py logic.",
    )
    parser.add_argument(
        "--icmp-stop-after-first-failure",
        action="store_true",
        help="When used with --with-icmp, stop ICMP monitor after first handled failure.",
    )
    parser.add_argument(
        "--icmp-simulate-outage-device",
        default="",
        help="When used with --with-icmp, force one ICMP outage by device name or IP.",
    )
    return parser.parse_args()


def resolve_dhcp_ip(device: dict[str, str]) -> tuple[str, str]:
    access_port = device.get("access_port", "")
    if not access_port:
        return "", "Missing access port"

    device_name = (device.get("name") or "").lower()
    device_os = (device.get("os") or "").lower()
    try:
        access_port_int = int(access_port)
    except ValueError:
        return "", f"Invalid access port: {access_port}"

    if (
        access_port_int in VNC_PORT_RANGE
        or "vnc" in device_name
        or "webterm" in device_name
        or "vnc" in device_os
    ):
        return "", "Non-CLI console endpoint (VNC/Webterm)"

    try:
        with socket.create_connection((CONSOLE_HOST, access_port_int), timeout=CONSOLE_TIMEOUT_SECONDS) as console:
            console.settimeout(0.5)
            output = b""

            def receive() -> None:
                nonlocal output
                while True:
                    try:
                        output += console.recv(4096)
                    except socket.timeout:
                        return

            receive()
            console.sendall(b"\n")
            time.sleep(0.2)
            console.sendall(f"{DHCP_USERNAME}\n".encode())
            time.sleep(0.2)
            console.sendall(f"{DHCP_PASSWORD}\n".encode())
            time.sleep(0.6)
            console.sendall(b"hostname -I\n")
            time.sleep(0.8)
            receive()

        text = output.decode("utf-8", errors="replace")
        matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        for candidate in reversed(matches):
            try:
                ipaddress.IPv4Address(candidate)
            except ipaddress.AddressValueError:
                continue
            if not candidate.startswith("127."):
                return candidate, ""
        return "", "No IPv4 address found in console output"
    except (OSError, ValueError) as exc:
        return "", str(exc)


def build_device_context(device: dict[str, str]) -> tuple[str, dict[str, str]]:
    name = device["name"]
    address = device["address"]
    username = device.get("username") or DHCP_USERNAME
    password = device.get("password") or DHCP_PASSWORD

    if address.lower() == "dhcp":
        current_ip, error = resolve_dhcp_ip(device)
        if not current_ip:
            return name, {"name": name, "address": "DHCP", "username": username, "password": password, "_error": error}
        return name, {"name": name, "address": current_ip, "username": username, "password": password}

    return name, {"name": name, "address": address, "username": username, "password": password}


def send_dns_email(device_name: str, ip_address: str, detected_dns: str, expected_dns: str, timestamp: str) -> bool:
    message = EmailMessage()
    message["Subject"] = f"DNS Configuration Alert: {device_name} ({ip_address})"
    message["From"] = FROM_ADDRESS
    message["To"] = TO_ADDRESS
    message.set_content(
        "Dear Network Administrator,\n\n"
        "This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:\n\n"
        f"Device Name: {device_name}\n"
        f"IP Address: {ip_address}\n"
        f"Detected DNS Setting: {detected_dns}\n"
        f"Expected DNS Setting: {expected_dns}\n"
        f"Time Detected: {timestamp}\n\n"
        "The system will attempt to automatically correct this configuration.\n\n"
        "Best regards,\n"
        "Network Monitoring System"
    )

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.ehlo()
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        print(f"EMAIL FAILED: {device_name} ({ip_address}) - {exc}")
        return False


def canonical_dns(dns_values: list[str]) -> str:
    if not dns_values:
        return "None"
    return ", ".join(sorted(set(dns_values)))


def check_dns_for_device(device: dict[str, str]) -> tuple[bool, str, str, str]:
    """Return success flag, current_dns, expected_dns, and reason for a device."""
    name = device["name"]
    ip_address = device["address"]
    device_for_dns = {
        "name": name,
        "address": ip_address,
        "username": device.get("username") or DHCP_USERNAME,
        "password": device.get("password") or DHCP_PASSWORD,
    }

    current_dns = DNS_FIXER.read_dns_settings(device_for_dns)
    detected_dns = canonical_dns(current_dns)
    expected_dns = ", ".join(sorted(APPROVED_DNS))

    if current_dns and set(current_dns) == APPROVED_DNS:
        ok, _ = DNS_FIXER.verify_dns(device_for_dns)
        if ok:
            return True, detected_dns, expected_dns, ""
        return False, detected_dns, expected_dns, "DNS verification failed"

    if not current_dns:
        return False, "None", expected_dns, "No DNS server configured"

    return False, detected_dns, expected_dns, "DNS does not match approved internal DNS"


def start_icmp_monitor_in_background(
    one_shot: bool = False,
    simulate_outage_device: str = "",
    stop_after_first_failure: bool = False,
) -> threading.Thread:
    from t2_c2_monitor_icmp import monitor_devices as monitor_icmp_devices

    thread = threading.Thread(
        target=monitor_icmp_devices,
        kwargs={
            "one_shot": one_shot,
            "simulate_outage_device": simulate_outage_device,
            "stop_after_first_failure": stop_after_first_failure,
        },
        name="icmp-monitor-thread",
        daemon=True,
    )
    thread.start()
    return thread


def monitor_dns_configuration(one_shot: bool = False) -> None:
    print("Starting DNS monitoring loop. Press Ctrl+C to stop.")
    if one_shot:
        print("One-shot mode enabled: script will run one DNS pass and exit.")
    open_alerts: set[str] = set()
    last_detected_dns: dict[str, str] = {}
    try:
        while True:
            devices = load_devices()
            for row in devices:
                name, context = build_device_context(row)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ip_address = context["address"]
                should_alert = False

                if context.get("_error"):
                    status = "FAIL"
                    detected_dns = "Unknown"
                    print(f"{timestamp} | Hostname: {name} | IP address: DHCP | Status: {status}")
                    previous_dns = last_detected_dns.get(name)
                    if previous_dns != detected_dns:
                        should_alert = True
                    if name not in open_alerts or should_alert:
                        email_ok = send_dns_email(name, "DHCP", detected_dns, ", ".join(sorted(APPROVED_DNS)), timestamp)
                        if email_ok:
                            open_alerts.add(name)
                            print(f"ALERT SENT: {name} DHCP resolution failed. DNS check skipped.")
                    last_detected_dns[name] = detected_dns
                    continue

                ok, detected_dns, expected_dns, reason = check_dns_for_device(context)
                previous_dns = last_detected_dns.get(name)
                dns_changed = previous_dns is not None and previous_dns != detected_dns
                status = "SUCCESS" if ok and not dns_changed else "FAIL"
                print(f"{timestamp} | Hostname: {name} | IP address: {ip_address} | Status: {status}")
                last_detected_dns[name] = detected_dns

                if ok and not dns_changed:
                    open_alerts.discard(name)
                    continue

                if dns_changed and not reason:
                    reason = "DNS setting changed since previous inspection"

                if name not in open_alerts or dns_changed:
                    send_dns_email(name, ip_address, detected_dns, expected_dns, timestamp)
                    open_alerts.add(name)
                    print(f"ALERT SENT: {name} DNS configuration alert emailed to administrator")
                    print(f"Detected DNS: {detected_dns}")
                    print(f"Expected DNS: {expected_dns}")
                    print(f"Reason: {reason}")
                    # Attempt to automatically correct the misconfiguration using the provided helper.
                    try:
                        corrected = DNS_FIXER.set_internal_dns(context)
                        if corrected:
                            print(f"AUTO-CORRECT: {name} DNS settings corrected.")
                            verified, _, _, _ = check_dns_for_device(context)
                            print(f"VERIFY: {name} status after correction = {'SUCCESS' if verified else 'FAIL'}")
                    except Exception as exc:
                        print(f"AUTO-CORRECT FAILED: {name} - {exc}")
                else:
                    print(f"ALERT SKIPPED: {name} already has an open DNS misconfiguration alert")

            if one_shot:
                print("One-shot DNS pass complete.")
                break

            time.sleep(PING_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("DNS monitoring stopped by user.")
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")


if __name__ == "__main__":
    args = parse_args()
    if args.with_icmp:
        start_icmp_monitor_in_background(
            one_shot=args.one_shot,
            simulate_outage_device=args.icmp_simulate_outage_device,
            stop_after_first_failure=args.icmp_stop_after_first_failure,
        )
        print("ICMP monitor started in background thread.")
    monitor_dns_configuration(one_shot=args.one_shot)
