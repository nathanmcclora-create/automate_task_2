"""Generate and send urgent compromise emails for failing DNS devices."""
"""Verify that the SMTP server accepted the email for each device."""

import re
import smtplib
import subprocess
import sys
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path


SMTP_HOST = "smtp.d522.wgu.internal"
SMTP_PORT = 1025
FROM_ADDR = "network-monitoring@localdomain"
TO_ADDR = "stakeholders@localdomain"
SMTP_TIMEOUT_SECONDS = 10


def run_dns_status() -> str:
    """Run the DNS validation script and return its full output."""
    script = Path(__file__).with_name("b2_dns_status.py")
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(script.parent),
    )
    return result.stdout + result.stderr


def parse_problem_devices(output: str) -> list[dict[str, str]]:
    """Extract the device name, DNS IP, and status from the DNS status output."""
    pattern = re.compile(
        r"Device name:\s*(?P<device>.+?)\s*\n"
        r"IP address of DNS:\s*(?P<dns>.+?)\s*\n"
        r"Status:\s*(?P<status>.+?)(?:\n\n|$)",
        re.DOTALL,
    )

    devices = []
    for match in pattern.finditer(output):
        device_name = match.group("device").strip()
        dns_ip = match.group("dns").strip()
        status = match.group("status").strip()
        if device_name and dns_ip:
            devices.append(
                {
                    "device_name": device_name,
                    "ip_address": dns_ip,
                    "status": status,
                }
            )
    return devices


def build_email_message(device_name: str, ip_address: str, timestamp: str) -> EmailMessage:
    """Build the urgent compromise email based on the required template."""
    body = (
        "Dear Stakeholders,\n\n"
        "This is an automated alert to inform you that the following device(s) have been identified as compromised during the recent network scan:\n\n"
        f"Device Name: {device_name}\n"
        f"IP Address: {ip_address}\n"
        f"Last Checked: {timestamp}\n\n"
        "Immediate investigation and remediation are recommended to prevent further impact.\n\n"
        "If you have any questions or require additional information, please contact the IT support team.\n\n"
        "Best regards,  \n"
        "Network Monitoring System  \n\n"
        "Resolution Notification Email"
    )

    message = EmailMessage()
    message["Subject"] = "URGENT: Device Compromise Detected—Immediate Attention Required"
    message["From"] = FROM_ADDR
    message["To"] = TO_ADDR
    message.set_content(body)
    return message


def send_email(device_name: str, ip_address: str) -> None:
    """Send the urgent email to the SMTP server and verify the server accepted it."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    message = build_email_message(device_name, ip_address, timestamp)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.ehlo()
            server.send_message(message)
            print(f"Email sent to SMTP server inbox for {device_name} ({ip_address})")
            print(f"Verified: SMTP server accepted the email for {device_name} ({ip_address})")
    except (OSError, smtplib.SMTPException) as exc:
        print(f"Could not send email for {device_name} ({ip_address}) to {SMTP_HOST}:{SMTP_PORT}: {exc}")
        raise


def main() -> int:
    output = run_dns_status()
    devices = parse_problem_devices(output)

    if not devices:
        print("No compromised devices were reported by b2_dns_status.py.")
        return 0

    for device in devices:
        send_email(device["device_name"], device["ip_address"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
