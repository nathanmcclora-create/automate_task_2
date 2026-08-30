"""Email stakeholders after verifying that device DNS settings were resolved."""

import smtplib
import sys
from email.message import EmailMessage

from d4_verify_new_dns import load_devices, verify_dns


SMTP_HOST = "smtp.d522.wgu.internal"
SMTP_PORT = 1025
FROM_ADDRESS = "network-monitoring@localdomain"
TO_ADDRESS = "stakeholders@localdomain"
SMTP_TIMEOUT_SECONDS = 10
SUBJECT = "RESOLVED: DNS Service Issue and Device Compromise—All Issues Remediated"


def get_resolved_devices() -> list[dict[str, str]]:
    """Use d4_verify_new_dns.py's inventory and verification logic to generate the resolved device list."""
    resolved_devices: list[dict[str, str]] = []
    for device in load_devices():
        try:
            is_resolved, _ = verify_dns(device)
        except Exception as exc:
            print(f"Could not verify {device['name']} ({device['address']}): {exc}")
            continue

        if is_resolved:
            resolved_devices.append(device)
    return resolved_devices


def build_email(devices: list[dict[str, str]]) -> EmailMessage:
    """Build one resolution email containing all successfully remediated devices."""
    device_list = "\n".join(
        f"- Hostname: {device['name']} | IP address: {device['address']}"
        for device in devices
    )
    body = (
        "Dear Stakeholders,\n\n"
        "This is an automated notification to inform you that the DNS service issue and all related device compromises have been successfully resolved.\n\n"
        "The following devices were affected and have now been remediated:\n\n"
        f"{device_list}\n\n"
        "No further action is required at this time. If you have any questions or concerns, please contact the IT support team.\n\n"
        "Thank you for your attention.\n\n"
        "Best regards,\n"
        "Network Monitoring System"
    )
    message = EmailMessage()
    message["Subject"] = SUBJECT
    message["From"] = FROM_ADDRESS
    message["To"] = TO_ADDRESS
    message.set_content(body)
    return message


def send_resolution_emails(devices: list[dict[str, str]]) -> bool:
    """Send a resolution email for the resolved devices and verify the SMTP server accepted it."""
    if not devices:
        print("No devices with resolved DNS settings were found; no emails sent.")
        return True

    all_sent = True
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
            server.ehlo()
            print(f"Connected to email server {SMTP_HOST}:{SMTP_PORT}")
            message = build_email(devices)
            refused = server.send_message(message)
            accepted = not refused
            status = "SUCCESS" if accepted else "FAILED"
            print(
                f"{status}: resolution email for {len(devices)} device(s) accepted by the email server"
            )
            all_sent = all_sent and accepted
    except (OSError, smtplib.SMTPException) as exc:
        print(f"FAILED: could not connect to {SMTP_HOST}:{SMTP_PORT}: {exc}", file=sys.stderr)
        return False
    return all_sent


def main() -> int:
    devices = get_resolved_devices()
    print(f"Found {len(devices)} device(s) with resolved DNS settings.")
    return 0 if send_resolution_emails(devices) else 1


if __name__ == "__main__":
    raise SystemExit(main())
