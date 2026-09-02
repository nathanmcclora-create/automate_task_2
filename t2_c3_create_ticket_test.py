"""Send a network-unavailable SMTP email and create a Helpdesk API ticket."""

from __future__ import annotations

import argparse
import csv
import json
import smtplib
import sys
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
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

CSV_CANDIDATES = (
	Path(__file__).with_name("network_device.csv"),
	Path(__file__).with_name("network_devices.csv"),
)


def should_exclude(device_name: str) -> bool:
	name = (device_name or "").strip().lower()
	return (
		name.startswith("router")
		or name.startswith("sw")
		or "switch" in name
		or name == "smtp"
	)


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


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description=(
			"Generate the network-unavailable email, send it to SMTP, "
			"and create a Helpdesk ticket when accepted."
		)
	)
	parser.add_argument("--device-name", help="Unavailable device name")
	parser.add_argument("--ip-address", help="Unavailable device IP address")
	parser.add_argument(
		"--priority",
		default="medium",
		choices=("low", "medium", "high"),
		help="Helpdesk ticket priority",
	)
	parser.add_argument(
		"--no-auto-defaults",
		action="store_true",
		help="Require explicit --device-name and --ip-address instead of resolving from inventory.",
	)
	return parser.parse_args()


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
	try:
		args = parse_args()
		device_name, ip_address = resolve_incident_target(args)
	except (FileNotFoundError, ValueError) as exc:
		print(f"ERROR: {exc}", file=sys.stderr)
		return 1

	print(f"Using incident target: {device_name} ({ip_address})")
	success = submit_network_unavailable_incident(
		device_name,
		ip_address,
		priority=args.priority,
	)
	return 0 if success else 1


if __name__ == "__main__":
	raise SystemExit(main())
