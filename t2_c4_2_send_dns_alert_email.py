"""Send DNS misconfiguration alert email and verify SMTP acceptance."""

from __future__ import annotations

import argparse
import os
import smtplib
import sys
from datetime import datetime
from email.message import EmailMessage


SMTP_HOST = os.getenv("SMTP_HOST", "smtp.d522.wgu.internal")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_TIMEOUT_SECONDS = 15
FROM_ADDRESS = os.getenv("DNS_ALERT_FROM", "network-monitoring@localdomain")
TO_ADDRESS = os.getenv("DNS_ALERT_TO", "stakeholders@localdomain")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate and send DNS configuration alert emails with SMTP verification."
    )
    parser.add_argument("--device-name", required=True, help="Device name for the alert email.")
    parser.add_argument("--ip-address", required=True, help="Device IP address for the alert email.")
    parser.add_argument(
        "--detected-dns",
        required=True,
        help="Detected current DNS setting (for example: 203.0.113.10).",
    )
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
    return parser.parse_args()


def build_email(
    device_name: str,
    ip_address: str,
    detected_dns: str,
    expected_dns: str,
    timestamp: str,
) -> EmailMessage:
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


def main() -> int:
    args = parse_args()
    timestamp = args.timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    email_message = build_email(
        device_name=args.device_name,
        ip_address=args.ip_address,
        detected_dns=args.detected_dns,
        expected_dns=args.expected_dns,
        timestamp=timestamp,
    )

    sent, details = send_email_and_verify(email_message)
    print(f"Email subject: {email_message['Subject']}")
    print(f"SMTP verification: {'SUCCESS' if sent else 'FAIL'}")
    print(f"Details: {details}")

    return 0 if sent else 1


if __name__ == "__main__":
    raise SystemExit(main())
