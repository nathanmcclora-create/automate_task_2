"""Send DNS corrected email notification and create a Helpdesk ticket."""

from __future__ import annotations

import argparse
import csv
import json
import os
import smtplib
import sys
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.d522.wgu.internal")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_TIMEOUT_SECONDS = 15
FROM_ADDRESS = os.getenv("DNS_ALERT_FROM", "network-monitoring@localdomain")
TO_ADDRESS = os.getenv("DNS_ALERT_TO", "stakeholders@localdomain")

API_HOST = os.getenv("HELPDESK_API_HOST", "api.d522.wgu.internal")
API_PORT = int(os.getenv("HELPDESK_API_PORT", "5000"))
API_PATH = os.getenv("HELPDESK_API_PATH", "/api/tickets")
API_TOKEN = os.getenv("HELPDESK_API_TOKEN", "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE")

CSV_CANDIDATES = (
    Path(__file__).with_name("network_device.csv"),
    Path(__file__).with_name("network_devices.csv"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate and send DNS corrected emails, then create a Helpdesk ticket."
    )
    parser.add_argument("--device-name", help="Device name for the corrected email.")
    parser.add_argument("--ip-address", help="Device IP address for the corrected email.")
    parser.add_argument(
        "--expected-dns",
        default="10.10.10.10, 10.10.10.20",
        help="Expected DNS setting text (default: 10.10.10.10, 10.10.10.20).",
    )
    parser.add_argument(
        "--timestamp",
        default="",
        help="Timestamp text for the email body. If omitted, current time is used.",
    )
    parser.add_argument(
        "--priority",
        default="medium",
        choices=("low", "medium", "high"),
        help="Helpdesk ticket priority.",
    )
    parser.add_argument(
        "--no-auto-defaults",
        action="store_true",
        help="Require explicit --device-name and --ip-address instead of resolving from inventory.",
    )
    return parser.parse_args()


def should_exclude(device_name: str) -> bool:
    name = (device_name or "").strip().lower()
    return name.startswith("router") or name.startswith("sw") or "switch" in name or name == "smtp"


def get_csv_path() -> Path:
    for candidate in CSV_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError(
        "Could not find network_device.csv or network_devices.csv in the script directory."
    )


def find_first_default_device() -> tuple[str, str]:
    csv_path = get_csv_path()
    with csv_path.open(newline="", encoding="utf-8") as csvfile:
        for row in csv.DictReader(csvfile):
            device_name = (row.get("Device Name") or "").strip()
            ip_address = (row.get("Device Address") or "").strip()
            if should_exclude(device_name):
                continue
            if not ip_address or ip_address.lower() in {"dhcp", "none"}:
                continue
            return device_name, ip_address
    raise ValueError("No eligible static-IP device found in inventory for default ticket creation.")


def find_device_ip_by_name(device_name: str) -> str:
    target = device_name.strip().lower()
    csv_path = get_csv_path()
    with csv_path.open(newline="", encoding="utf-8") as csvfile:
        for row in csv.DictReader(csvfile):
            name = (row.get("Device Name") or "").strip()
            ip_address = (row.get("Device Address") or "").strip()
            if name.lower() != target:
                continue
            if not ip_address or ip_address.lower() in {"dhcp", "none"}:
                raise ValueError(f"Device '{device_name}' does not have a usable static IP address.")
            return ip_address
    raise ValueError(f"Device '{device_name}' was not found in the inventory CSV.")


def resolve_incident_target(args: argparse.Namespace) -> tuple[str, str]:
    device_name = (args.device_name or "").strip()
    ip_address = (args.ip_address or "").strip()

    if device_name and ip_address:
        return device_name, ip_address

    if args.no_auto_defaults:
        raise ValueError("Both --device-name and --ip-address are required when --no-auto-defaults is used.")

    if device_name and not ip_address:
        return device_name, find_device_ip_by_name(device_name)

    if ip_address and not device_name:
        return "Unknown Device", ip_address

    return find_first_default_device()


def build_email(device_name: str, ip_address: str, expected_dns: str, timestamp: str) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = f"DNS Configuration Corrected: {device_name} ({ip_address})"
    message["From"] = FROM_ADDRESS
    message["To"] = TO_ADDRESS
    message.set_content(
        "Dear Network Administrator,\n\n"
        "The DNS configuration issue previously detected on the following device has been automatically corrected:\n\n"
        f"Device Name: {device_name}\n"
        f"IP Address: {ip_address}\n"
        f"Corrected DNS Setting: {expected_dns}\n"
        f"Time Corrected: {timestamp}\n\n"
        "No further action is required at this time.\n\n"
        "Best regards,\n"
        "Network Monitoring System"
    )
    return message


def send_email_and_verify(message: EmailMessage) -> tuple[bool, str]:
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            code, banner = server.ehlo()
            if code >= 400:
                return False, f"SMTP EHLO failed with code {code} and banner {banner!r}"

            failures = server.send_message(message)
            if failures:
                return False, f"SMTP rejected recipient(s): {failures}"

            return True, f"SMTP accepted message via {SMTP_HOST}:{SMTP_PORT}"
    except (OSError, smtplib.SMTPException) as exc:
        return False, f"SMTP send failed: {exc}"


def api_request(payload: dict[str, object]) -> tuple[int, object]:
    url = f"http://{API_HOST}:{API_PORT}{API_PATH}"
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
            parsed = json.loads(body) if body else {}
            return response.status, parsed
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed_error = json.loads(error_body)
        except json.JSONDecodeError:
            parsed_error = {"error": error_body}
        return exc.code, parsed_error
    except URLError as exc:
        raise RuntimeError(f"Could not connect to Helpdesk API: {exc.reason}") from exc


def create_ticket(device_name: str, ip_address: str, expected_dns: str, timestamp: str, priority: str) -> tuple[int, object]:
    payload: dict[str, object] = {
        "title": f"DNS Configuration Corrected: {device_name} ({ip_address})",
        "description": (
            "Dear Network Administrator,\n\n"
            "The DNS configuration issue previously detected on the following device has been automatically corrected:\n\n"
            f"Device Name: {device_name}\n"
            f"IP Address: {ip_address}\n"
            f"Corrected DNS Setting: {expected_dns}\n"
            f"Time Corrected: {timestamp}\n\n"
            "No further action is required at this time.\n\n"
            "Best regards,\n"
            "Network Monitoring System"
        ),
        "priority": priority,
    }
    return api_request(payload)


def main() -> int:
    try:
        args = parse_args()
        device_name, ip_address = resolve_incident_target(args)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    timestamp = args.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    email_message = build_email(
        device_name=device_name,
        ip_address=ip_address,
        expected_dns=args.expected_dns,
        timestamp=timestamp,
    )

    print(f"Using incident target: {device_name} ({ip_address})")

    sent, details = send_email_and_verify(email_message)
    print(f"Email subject: {email_message['Subject']}")
    print(f"SMTP verification: {'SUCCESS' if sent else 'FAIL'}")
    print(f"Details: {details}")

    if not sent:
        return 1

    print("Creating Helpdesk API ticket after SMTP verification...")
    try:
        status_code, response = create_ticket(
            device_name=device_name,
            ip_address=ip_address,
            expected_dns=args.expected_dns,
            timestamp=timestamp,
            priority=args.priority,
        )
    except RuntimeError as exc:
        print(f"API ERROR: {exc}", file=sys.stderr)
        return 1

    success = 200 <= status_code < 300 and isinstance(response, dict) and "id" in response
    print(f"Ticket API HTTP status: {status_code}")
    print("Ticket API response:")
    print(json.dumps(response, indent=2))

    if success:
        print("Verification passed: Ticket was created successfully.")
        return 0

    print("Verification failed: Ticket was not created successfully.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
