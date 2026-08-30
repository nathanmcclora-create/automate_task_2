""" Created a script to send email alerts to stakeholders when DNS connectivity issues are detected. """

import json
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_HOST = "api.d522.wgu.internal"
API_PORT = 5000
API_PATH = "/api/tickets"
API_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"
API_URL = f"http://{API_HOST}:{API_PORT}{API_PATH}"
SMTP_FALLBACK_HOST = os.getenv("SMTP_HOST", "api.d522.wgu.internal")
SMTP_FALLBACK_PORT = int(os.getenv("SMTP_PORT", "5000"))
DNS_STATUS_SCRIPT = Path(__file__).with_name("b2_dns_status.py")


def run_dns_status() -> str:
    """Run b2_dns_status.py and return its full output."""
    result = subprocess.run(
        [sys.executable, str(DNS_STATUS_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(DNS_STATUS_SCRIPT.parent),
    )
    return result.stdout + result.stderr


def parse_bad_devices(output: str) -> list[dict[str, str]]:
    """Parse the DNS status script output into device/email alerts."""
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
        if device_name and dns_ip and status:
            devices.append(
                {
                    "device_name": device_name,
                    "dns_ip": dns_ip,
                    "status": status,
                }
            )
    return devices


def build_email_body(device: dict[str, str]) -> str:
    """Build the stakeholder email body for one device."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return (
        "Dear Stakeholders,\n\n"
        "This is an automated alert from the DNS monitoring service.\n\n"
        f"Device name: {device['device_name']}\n"
        f"IP address of DNS: {device['dns_ip']}\n"
        f"Status: {device['status']}\n"
        f"Last checked: {timestamp}\n\n"
        "Please investigate and remediate the reported DNS issue as soon as possible.\n\n"
        "Regards,\n"
        "Network Monitoring Team"
    )


def api_request(method: str, payload: dict | None = None) -> tuple[int, object]:
    """Send a request to the mail/helpdesk API using the bearer token."""
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        API_URL,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {API_TOKEN}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )

    try:
        with urlopen(request, timeout=15) as response:
            response_body = response.read().decode("utf-8")
            return response.status, json.loads(response_body) if response_body else {}
    except HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        try:
            return exc.code, json.loads(error_body)
        except json.JSONDecodeError:
            return exc.code, {"error": error_body}
    except URLError as exc:
        raise RuntimeError(f"Could not reach {API_URL}: {exc.reason}") from exc


def send_alert_email(device: dict[str, str]) -> None:
    """Send a notification through the HTTP API with bearer token auth."""
    email_body = build_email_body(device)
    payload = {
        "title": f"DNS connection issue: {device['device_name']}",
        "description": email_body,
        "priority": "medium",
        "metadata": {
            "device_name": device['device_name'],
            "dns_ip": device['dns_ip'],
            "status": device['status'],
            "type": "dns_alert",
        },
    }

    status, response = api_request("POST", payload)
    if 200 <= status < 300:
        print(f"Email/API alert created for {device['device_name']} (status={status})")
        print(json.dumps(response, indent=2))
    else:
        print(f"Failed to create alert for {device['device_name']}: HTTP {status}")
        print(json.dumps(response, indent=2))


if __name__ == "__main__":
    output = run_dns_status()
    alerts = parse_bad_devices(output)

    if not alerts:
        print("No devices were reported as failing DNS connectivity.")
        raise SystemExit(0)

    for alert in alerts:
        send_alert_email(alert)
