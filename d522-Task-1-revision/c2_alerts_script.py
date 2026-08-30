"""Create Helpdesk API tickets for DNS alerts and print the API responses."""

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


API_HOSTS = [
    "api.d522.wgu.internal",
    "helpdesk.d522.wgu.internal",
]
API_PORT = 5000
TICKETS_PATH = "/api/tickets"
API_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"
DNS_CHECK_SCRIPT = Path(__file__).with_name("b2_dns_status.py")


def api_url_for(host: str) -> str:
    return f"http://{host}:{API_PORT}{TICKETS_PATH}"


def api_request(method: str, payload: dict | None = None, host: str = API_HOSTS[0]) -> tuple[int, object]:
    """Send a Bearer-token authenticated request and return its HTTP status and JSON body."""
    url = api_url_for(host)
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
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
            details = json.loads(error_body)
        except json.JSONDecodeError:
            details = {"error": error_body}
        return exc.code, details
    except URLError as exc:
        raise RuntimeError(f"Could not connect to {url}: {exc.reason}") from exc


def verify_api_access() -> str:
    """Verify access with a harmless test ticket and return the working host."""
    last_error = None
    for host in API_HOSTS:
        try:
            status, response = api_request(
                "POST",
                {
                    "title": "Helpdesk API connectivity test",
                    "description": "Test ticket created by c2_alerts_script.py to verify Helpdesk API access.",
                    "priority": "medium",
                },
                host=host,
            )
            print(f"API connectivity test: host={host} HTTP {status}")
            print(json.dumps(response, indent=2))
            if 200 <= status < 300 and isinstance(response, dict) and "id" in response:
                return host
            last_error = response
        except RuntimeError as exc:
            last_error = str(exc)
            print(f"Host {host} failed: {exc}")
    raise RuntimeError(f"Helpdesk API connectivity test was not successful. Last error: {last_error}")


def run_dns_check() -> str:
    """Run b2_dns_status.py and return the full output."""
    result = subprocess.run(
        [sys.executable, str(DNS_CHECK_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(DNS_CHECK_SCRIPT.parent),
    )
    return result.stdout + result.stderr


def parse_alert_devices(output: str) -> list[dict[str, str]]:
    """Extract the devices reported by b2_dns_status.py as failing DNS connectivity."""
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


def create_alert_ticket(device: dict[str, str], host: str) -> tuple[int, object]:
    """Create one Helpdesk ticket for a device alert."""
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    payload = {
        "title": f"DNS connection issue: {device['device_name']}",
        "description": (
            "The device has a DNS connectivity or DNS configuration issue.\n\n"
            f"Device: {device['device_name']}\n"
            f"DNS IP: {device['dns_ip']}\n"
            f"Status: {device['status']}\n"
            f"Checked at: {checked_at}"
        ),
        "priority": "medium",
    }
    return api_request("POST", payload, host=host)


def main() -> int:
    try:
        host = verify_api_access()
        output = run_dns_check()
        devices = parse_alert_devices(output)
        if not devices:
            print("No devices were reported as failing DNS connectivity; no alert tickets were created.")
            return 0

        all_successful = True
        for device in devices:
            status, response = create_alert_ticket(device, host)
            successful = 200 <= status < 300 and isinstance(response, dict) and "id" in response
            all_successful = all_successful and successful
            result = "SUCCESS" if successful else "FAILED"
            print(f"\n{result}: {device['device_name']} ({device['dns_ip']}) - HTTP {status}")
            print(json.dumps(response, indent=2))
        return 0 if all_successful else 1
    except (RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
