# """Create a Helpdesk API ticket for an unavailable network device."""

# from __future__ import annotations

# import argparse
# import json
# import sys
# from datetime import datetime, timezone
# from urllib.error import HTTPError, URLError
# from urllib.request import Request, urlopen


# API_HOSTS = [
# 	"api.d522.wgu.internal",
# 	"helpdesk.d522.wgu.internal",
# ]
# API_PORT = 5000
# TICKETS_PATH = "/api/tickets"
# API_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"


# def api_url_for(host: str) -> str:
# 	return f"http://{host}:{API_PORT}{TICKETS_PATH}"


# def api_request(method: str, payload: dict | None = None, host: str = API_HOSTS[0]) -> tuple[int, object]:
# 	"""Send an authenticated API request and return the HTTP status and JSON body."""
# 	url = api_url_for(host)
# 	body = None if payload is None else json.dumps(payload).encode("utf-8")
# 	request = Request(
# 		url,
# 		data=body,
# 		method=method,
# 		headers={
# 			"Authorization": f"Bearer {API_TOKEN}",
# 			"Accept": "application/json",
# 			"Content-Type": "application/json",
# 		},
# 	)

# 	try:
# 		with urlopen(request, timeout=15) as response:
# 			response_body = response.read().decode("utf-8")
# 			return response.status, json.loads(response_body) if response_body else {}
# 	except HTTPError as exc:
# 		error_body = exc.read().decode("utf-8", errors="replace")
# 		try:
# 			details = json.loads(error_body)
# 		except json.JSONDecodeError:
# 			details = {"error": error_body}
# 		return exc.code, details
# 	except URLError as exc:
# 		raise RuntimeError(f"Could not connect to {url}: {exc.reason}") from exc


# def create_ticket(device_name: str, ip_address: str, reason: str, host: str = API_HOSTS[0]) -> tuple[int, object]:
# 	"""Create one helpdesk ticket for an unavailable device."""
# 	checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
# 	payload = {
# 		"title": f"Network Device Unavailable: {device_name} ({ip_address})",
# 		"description": (
# 			"Dear Network Administrator,\n\n"
# 			"This is an automated notification that the following network device is currently unavailable:\n\n"
# 			f"Device Name: {device_name}\n"
# 			f"IP Address: {ip_address}\n"
# 			f"Last Checked: {checked_at}\n"
# 			f"Failure Reason: {reason}\n\n"
# 			"Please investigate this issue at your earliest convenience.\n\n"
# 			"Best regards,\n"
# 			"Network Monitoring System"
# 		),
# 		"priority": "medium",
# 	}
# 	return api_request("POST", payload, host=host)


# def parse_args() -> argparse.Namespace:
# 	parser = argparse.ArgumentParser(
# 		description="Create a Helpdesk ticket for an unavailable network device."
# 	)
# 	parser.add_argument("--device-name", required=True, help="Hostname of the unavailable device")
# 	parser.add_argument("--ip-address", required=True, help="Current IP address of the device")
# 	parser.add_argument("--reason", required=True, help="Reason the device is unavailable")
# 	parser.add_argument(
# 		"--host",
# 		choices=API_HOSTS,
# 		default=API_HOSTS[0],
# 		help="Helpdesk API host to send the ticket to",
# 	)
# 	return parser.parse_args()


# def main() -> int:
# 	try:
# 		args = parse_args()
# 		status, response = create_ticket(args.device_name, args.ip_address, args.reason, host=args.host)
# 		success = 200 <= status < 300 and isinstance(response, dict) and "id" in response
# 		result = "SUCCESS" if success else "FAILED"
# 		print(f"{result}: HTTP {status}")
# 		print(json.dumps(response, indent=2))
# 		return 0 if success else 1
# 	except (RuntimeError, OSError) as exc:
# 		print(f"ERROR: {exc}", file=sys.stderr)
# 		return 1


# if __name__ == "__main__":
# 	raise SystemExit(main())
