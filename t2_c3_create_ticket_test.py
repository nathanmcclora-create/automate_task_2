"""Send a network-unavailable SMTP email and create a Helpdesk API ticket."""

from __future__ import annotations

import argparse
import json
import smtplib
import sys
from datetime import datetime
from email.message import EmailMessage
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SMTP_HOST = "smtp.d522.wgu.internal"
SMTP_PORT = 1025
SMTP_TIMEOUT_SECONDS = 10
FROM_ADDRESS = "network-monitoring@localdomain"
TO_ADDRESS = "network-administrator@localdomain"

API_HOST = "api.d522.wgu.internal"
API_PORT = 5000
API_PATH = "/api/tickets"
API_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description=(
			"Generate the network-unavailable email, send it to SMTP, "
			"and create a Helpdesk ticket when accepted."
		)
	)
	parser.add_argument("--device-name", required=True, help="Unavailable device name")
	parser.add_argument("--ip-address", required=True, help="Unavailable device IP address")
	parser.add_argument(
		"--priority",
		default="medium",
		choices=("low", "medium", "high"),
		help="Helpdesk ticket priority",
	)
	return parser.parse_args()


def build_email_message(device_name: str, ip_address: str, timestamp: str) -> EmailMessage:
	message = EmailMessage()
	message["Subject"] = f"Network Device Unavailable: {device_name} ({ip_address})"
	message["From"] = FROM_ADDRESS
	message["To"] = TO_ADDRESS
	message.set_content(
		"Dear Network Administrator,\n\n"
		"This is an automated notification that the following network device is currently unavailable:\n\n"
		f"Device Name: {device_name}\n"
		f"IP Address: {ip_address}\n"
		f"Last Checked: {timestamp}\n\n"
		"Please investigate this issue at your earliest convenience.\n\n"
		"Best regards,\n"
		"Network Monitoring System"
	)
	return message


def send_network_alert_email(device_name: str, ip_address: str, timestamp: str) -> bool:
	message = build_email_message(device_name, ip_address, timestamp)
	try:
		with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
			code, banner = server.ehlo()
			print(f"SMTP EHLO response: {code} {banner.decode(errors='replace')}")
			send_failures = server.send_message(message)
			if send_failures:
				print("SMTP send failures:")
				print(json.dumps(send_failures, indent=2))
				return False
			print(
				"SMTP verification: Email accepted by "
				f"{SMTP_HOST}:{SMTP_PORT} for subject '{message['Subject']}'"
			)
			return True
	except (OSError, smtplib.SMTPException) as exc:
		print(f"SMTP ERROR: {exc}", file=sys.stderr)
		return False


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


def create_ticket(device_name: str, ip_address: str, timestamp: str, priority: str) -> tuple[int, object]:
	payload: dict[str, object] = {
		"title": f"Network Device Unavailable: {device_name} ({ip_address})",
		"description": (
			"Dear Network Administrator,\n\n"
			"This is an automated notification that the following network device is currently unavailable:\n\n"
			f"Device Name: {device_name}\n"
			f"IP Address: {ip_address}\n"
			f"Last Checked: {timestamp}\n\n"
			"Please investigate this issue at your earliest convenience.\n\n"
			"Best regards,\n"
			"Network Monitoring System"
		),
		"priority": priority,
	}
	return api_request(payload)


def submit_network_unavailable_incident(
	device_name: str,
	ip_address: str,
	priority: str = "medium",
	timestamp: str | None = None,
) -> bool:
	"""Send outage email first, then create a helpdesk ticket and print verification output."""
	timestamp_value = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

	print("Step 1/2: Sending network-unavailable email to SMTP server...")
	email_sent = send_network_alert_email(device_name, ip_address, timestamp_value)
	if not email_sent:
		print("Verification failed: Email was not accepted by SMTP server.")
		return False

	print("Step 2/2: Creating Helpdesk API ticket after SMTP verification...")
	try:
		status_code, response = create_ticket(
			device_name,
			ip_address,
			timestamp_value,
			priority,
		)
	except RuntimeError as exc:
		print(f"API ERROR: {exc}", file=sys.stderr)
		return False

	success = 200 <= status_code < 300 and isinstance(response, dict) and "id" in response
	print(f"Ticket API HTTP status: {status_code}")
	print("Ticket API response:")
	print(json.dumps(response, indent=2))

	if success:
		print("Verification passed: Ticket was created successfully.")
		return True

	print("Verification failed: Ticket was not created successfully.")
	return False


def main() -> int:
	args = parse_args()
	success = submit_network_unavailable_incident(
		args.device_name,
		args.ip_address,
		priority=args.priority,
	)
	return 0 if success else 1


if __name__ == "__main__":
	raise SystemExit(main())
