"""Break and fix DNS settings, send stakeholder emails, and manage Helpdesk ticket lifecycle."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import smtplib
import sys
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import paramiko


CSV_CANDIDATES = (
	Path(__file__).with_name("network_device.csv"),
	Path(__file__).with_name("network_devices.csv"),
)
BREAK_BIN = Path(__file__).with_name("Test_DNS") / "break_dns.bin"
FIX_BIN = Path(__file__).with_name("Test_DNS") / "fix_dns.bin"

SMTP_HOST = "smtp.d522.wgu.internal"
SMTP_PORT = 1025
SMTP_TIMEOUT_SECONDS = 10
FROM_ADDRESS = "network-monitoring@localdomain"
TO_ADDRESS = "stakeholders@localdomain"

API_HOST = "api.d522.wgu.internal"
API_PORT = 5000
API_TOKEN = "vGkbXkGLqQSo7YLflp9DutuG8st4xdPPF7wnTcwB0FE"
API_BASE = f"http://{API_HOST}:{API_PORT}/api/tickets"

SSH_TIMEOUT_SECONDS = 15
DHCP_USERNAME = "ubuntu"
DHCP_PASSWORD = "ubuntu"


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


def find_device(device_name: str) -> dict[str, str]:
	csv_file = get_csv_path()
	target = device_name.strip().lower()
	with csv_file.open(newline="", encoding="utf-8") as csvfile:
		for row in csv.DictReader(csvfile):
			name = (row.get("Device Name") or "").strip()
			if should_exclude(name):
				continue
			if name.strip().lower() != target:
				continue

			address = (row.get("Device Address") or "").strip()
			if not address or address.lower() == "none":
				raise ValueError(f"Device {name} does not have a usable address.")

			return {
				"name": name,
				"address": address,
				"access_port": (row.get("Access Port") or "").strip(),
				"username": (row.get("Username") or DHCP_USERNAME).strip() or DHCP_USERNAME,
				"password": (row.get("Password") or DHCP_PASSWORD).strip() or DHCP_PASSWORD,
			}

	raise ValueError(f"Device '{device_name}' was not found in inventory or is excluded.")


def canonical_dns(dns_values: list[str]) -> str:
	if not dns_values:
		return "None"
	return ", ".join(sorted(set(dns_values)))


def connect_ssh(device: dict[str, str]) -> paramiko.SSHClient:
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(
		hostname=device["address"],
		username=device["username"],
		password=device["password"],
		timeout=SSH_TIMEOUT_SECONDS,
		banner_timeout=SSH_TIMEOUT_SECONDS,
		auth_timeout=SSH_TIMEOUT_SECONDS,
	)
	return client


def run_remote_sudo(client: paramiko.SSHClient, password: str, command: str) -> tuple[int, str, str]:
	stdin, stdout, stderr = client.exec_command(
		f"sudo -S -p '' sh -c {json.dumps(command)}",
		get_pty=True,
		timeout=SSH_TIMEOUT_SECONDS,
	)
	stdin.write(f"{password}\n")
	stdin.flush()
	out = stdout.read().decode("utf-8", errors="replace").strip()
	err = stderr.read().decode("utf-8", errors="replace").strip()
	code = stdout.channel.recv_exit_status()
	return code, out, err


def run_dns_binary(device: dict[str, str], binary_path: Path) -> bool:
	if not binary_path.exists():
		raise FileNotFoundError(f"Required file not found: {binary_path}")

	remote_path = f"/tmp/{binary_path.name}"
	client = connect_ssh(device)
	try:
		sftp = client.open_sftp()
		try:
			sftp.put(str(binary_path), remote_path)
		finally:
			sftp.close()

		code, out, err = run_remote_sudo(
			client,
			device["password"],
			f"chmod +x {remote_path} && {remote_path}",
		)
		print(f"Executed {binary_path.name} on {device['name']} ({device['address']}) with exit code {code}")
		if out:
			print(out)
		if err:
			print(err)
		return code == 0
	finally:
		client.close()


def force_break_dns_fallback(device: dict[str, str]) -> bool:
	"""Fallback only when break_dns.bin does not produce a mismatch in this lab run."""
	client = connect_ssh(device)
	try:
		command = "printf '%s\\n' 'nameserver 1.1.1.1' 'nameserver 8.8.8.8' > /etc/resolv.conf"
		code, out, err = run_remote_sudo(client, device["password"], command)
		print(f"Fallback DNS break command exit code: {code}")
		if out:
			print(out)
		if err:
			print(err)
		return code == 0
	finally:
		client.close()


def force_fix_dns_fallback(device: dict[str, str]) -> bool:
	"""Fallback only when fix_dns.bin does not restore approved DNS settings."""
	client = connect_ssh(device)
	try:
		command = (
			f"printf '%s\\n' 'nameserver {DNS1}' 'nameserver {DNS2}' "
			"'options timeout:2 attempts:2' > /etc/resolv.conf"
		)
		code, out, err = run_remote_sudo(client, device["password"], command)
		print(f"Fallback DNS fix command exit code: {code}")
		if out:
			print(out)
		if err:
			print(err)
		return code == 0
	finally:
		client.close()


def send_email(subject: str, body: str) -> bool:
	message = EmailMessage()
	message["Subject"] = subject
	message["From"] = FROM_ADDRESS
	message["To"] = TO_ADDRESS
	message.set_content(body)

	try:
		with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
			code, banner = server.ehlo()
			print(f"SMTP EHLO response: {code} {banner.decode(errors='replace')}")
			failures = server.send_message(message)
			if failures:
				print("SMTP send failures:")
				print(json.dumps(failures, indent=2))
				return False
		print(f"SMTP verification: Email accepted for subject '{subject}'")
		return True
	except (OSError, smtplib.SMTPException) as exc:
		print(f"SMTP ERROR: {exc}", file=sys.stderr)
		return False


def api_request(method: str, path: str, payload: dict[str, object] | None = None) -> tuple[int, object]:
	body = None if payload is None else json.dumps(payload).encode("utf-8")
	request = Request(
		f"{API_BASE}{path}",
		data=body,
		method=method,
		headers={
			"Authorization": f"Bearer {API_TOKEN}",
			"Accept": "application/json",
			"Content-Type": "application/json",
		},
	)

	try:
		with urlopen(request, timeout=20) as response:
			raw = response.read().decode("utf-8")
			parsed = json.loads(raw) if raw else {}
			return response.status, parsed
	except HTTPError as exc:
		raw = exc.read().decode("utf-8", errors="replace")
		try:
			parsed_error = json.loads(raw)
		except json.JSONDecodeError:
			parsed_error = {"error": raw}
		return exc.code, parsed_error
	except URLError as exc:
		raise RuntimeError(f"Could not connect to Helpdesk API: {exc.reason}") from exc


def create_dns_ticket(device: dict[str, str], detected_dns: str, expected_dns: str, timestamp: str) -> tuple[bool, int, object]:
	payload: dict[str, object] = {
		"title": f"DNS configuration alert: {device['name']} ({device['address']})",
		"description": (
			"DNS misconfiguration detected and alert email sent.\n\n"
			f"Device Name: {device['name']}\n"
			f"IP Address: {device['address']}\n"
			f"Detected DNS Setting: {detected_dns}\n"
			f"Expected DNS Setting: {expected_dns}\n"
			f"Time Detected: {timestamp}"
		),
		"priority": "medium",
	}
	status, response = api_request("POST", "", payload)
	success = 200 <= status < 300 and isinstance(response, dict) and "id" in response
	return success, status, response


def close_dns_ticket(ticket_id: int, corrected_dns: str, timestamp: str) -> tuple[bool, int, object]:
	payloads = [
		{"status": "closed", "resolution": f"DNS corrected to {corrected_dns} at {timestamp}"},
		{"status": "resolved", "resolution": f"DNS corrected to {corrected_dns} at {timestamp}"},
	]
	attempts = [
		("PATCH", f"/{ticket_id}"),
		("PUT", f"/{ticket_id}"),
		("POST", f"/{ticket_id}/close"),
	]

	last_status = 0
	last_response: object = {"error": "No close attempt made"}
	for method, path in attempts:
		for payload in payloads:
			status, response = api_request(method, path, payload)
			last_status, last_response = status, response
			if 200 <= status < 300:
				return True, status, response
	return False, last_status, last_response


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Break DNS, send alert email and ticket, fix DNS, then send resolved email and close ticket."
	)
	parser.add_argument("--device-name", default="DB", help="Target device from network_devices.csv")
	return parser.parse_args()


def main() -> int:
	args = parse_args()

	try:
		device = find_device(args.device_name)
	except (FileNotFoundError, ValueError) as exc:
		print(f"ERROR: {exc}", file=sys.stderr)
		return 1

	print(f"Target device: {device['name']} ({device['address']})")

	print("Step 1/6: Break DNS settings using Test_DNS/break_dns.bin")
	if not run_dns_binary(device, BREAK_BIN):
		print("ERROR: Failed to execute break_dns.bin", file=sys.stderr)
		return 1

	detected_dns_list = DNS_FIXER.read_dns_settings(device)
	detected_dns = canonical_dns(detected_dns_list)
	expected_dns = ", ".join(sorted(APPROVED_DNS))
	mismatch = set(detected_dns_list) != APPROVED_DNS
	timestamp_detected = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print(f"Detected DNS after break: {detected_dns}")
	print(f"Expected DNS: {expected_dns}")
	print(f"DNS mismatch detected: {'YES' if mismatch else 'NO'}")

	if not mismatch:
		print("break_dns.bin did not produce a DNS mismatch; attempting fallback break command for validation.")
		if not force_break_dns_fallback(device):
			print("ERROR: Could not force DNS mismatch for alert workflow test.", file=sys.stderr)
			return 1
		detected_dns_list = DNS_FIXER.read_dns_settings(device)
		detected_dns = canonical_dns(detected_dns_list)
		mismatch = set(detected_dns_list) != APPROVED_DNS
		print(f"Detected DNS after fallback break: {detected_dns}")
		print(f"DNS mismatch detected after fallback: {'YES' if mismatch else 'NO'}")
		if not mismatch:
			print("ERROR: DNS mismatch still not detected after fallback.", file=sys.stderr)
			return 1

	subject_alert = f"DNS Configuration Alert: {device['name']} ({device['address']})"
	body_alert = (
		"Dear Network Administrator,\n\n"
		"This is an automated alert that the DNS configuration for the following device has been altered from the expected settings:\n\n"
		f"Device Name: {device['name']}\n"
		f"IP Address: {device['address']}\n"
		f"Detected DNS Setting: {detected_dns}\n"
		f"Expected DNS Setting: {expected_dns}\n"
		f"Time Detected: {timestamp_detected}\n\n"
		"The system will attempt to automatically correct this configuration.\n\n"
		"Best regards,\n"
		"Network Monitoring System"
	)

	print("Step 2/6: Send DNS misconfiguration email")
	alert_email_ok = send_email(subject_alert, body_alert)
	print(f"Verification: misconfiguration email sent = {alert_email_ok}")
	if not alert_email_ok:
		return 1

	print("Step 3/6: Create Helpdesk ticket for DNS misconfiguration")
	created, create_status, create_response = create_dns_ticket(device, detected_dns, expected_dns, timestamp_detected)
	print(f"Ticket create HTTP status: {create_status}")
	print("Ticket create response:")
	print(json.dumps(create_response, indent=2))
	if not created:
		print("ERROR: Ticket was not created successfully.", file=sys.stderr)
		return 1

	ticket_id = int(create_response["id"])

	print("Step 4/6: Fix DNS settings using Test_DNS/fix_dns.bin")
	if not run_dns_binary(device, FIX_BIN):
		print("ERROR: Failed to execute fix_dns.bin", file=sys.stderr)
		return 1

	ok, final_dns_list = DNS_FIXER.verify_dns(device)
	final_dns = canonical_dns(final_dns_list)
	timestamp_fixed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	print(f"Detected DNS after fix: {final_dns}")
	print(f"DNS verification after fix: {'SUCCESS' if ok else 'FAIL'}")

	if not ok:
		print("fix_dns.bin did not restore approved DNS settings; attempting fallback fix command.")
		if not force_fix_dns_fallback(device):
			print("ERROR: Could not force DNS correction.", file=sys.stderr)
			return 1
		ok, final_dns_list = DNS_FIXER.verify_dns(device)
		final_dns = canonical_dns(final_dns_list)
		timestamp_fixed = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
		print(f"Detected DNS after fallback fix: {final_dns}")
		print(f"DNS verification after fallback fix: {'SUCCESS' if ok else 'FAIL'}")
		if not ok:
			print("ERROR: DNS is still not corrected after fallback fix.", file=sys.stderr)
			return 1

	subject_fixed = f"DNS Configuration Restored: {device['name']} ({device['address']})"
	body_fixed = (
		"Dear Network Administrator,\n\n"
		"The DNS configuration issue previously detected on the following device has been automatically corrected:\n\n"
		f"Device Name: {device['name']}\n"
		f"IP Address: {device['address']}\n"
		f"Corrected DNS Setting: {expected_dns}\n"
		f"Time Corrected: {timestamp_fixed}\n\n"
		"No further action is required at this time.\n\n"
		"Best regards,\n"
		"Network Monitoring System"
	)

	print("Step 5/6: Send DNS correction email")
	fixed_email_ok = send_email(subject_fixed, body_fixed)
	print(f"Verification: correction email sent = {fixed_email_ok}")
	if not fixed_email_ok:
		return 1

	print("Step 6/6: Close Helpdesk ticket")
	closed, close_status, close_response = close_dns_ticket(ticket_id, final_dns, timestamp_fixed)
	print(f"Ticket close HTTP status: {close_status}")
	print("Ticket close response:")
	print(json.dumps(close_response, indent=2))
	print(f"Verification: ticket closed = {closed}")

	return 0 if closed else 1


if __name__ == "__main__":
	raise SystemExit(main())
