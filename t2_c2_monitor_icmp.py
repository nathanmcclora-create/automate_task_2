"""Continuously monitor devices with ICMP and send email alerts on failures."""

from __future__ import annotations

import csv
import json
import ipaddress
import os
import re
import smtplib
import socket
import subprocess
import time
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

from t2_c3_create_ticket import create_ticket


CSV_CANDIDATES = (
	Path(__file__).with_name("network_device.csv"),
	Path(__file__).with_name("network_devices.csv"),
)

PING_INTERVAL_SECONDS = 30
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5
VNC_PORT_RANGE = range(5900, 6000)

DHCP_USERNAME = "ubuntu"
DHCP_PASSWORD = "ubuntu"

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.d522.wgu.internal")
SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
SMTP_TIMEOUT_SECONDS = 10
FROM_ADDRESS = os.getenv("ALERT_FROM", "network-monitoring@localdomain")
TO_ADDRESS = os.getenv("ALERT_TO", "stakeholders@localdomain")


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


def load_devices() -> list[dict[str, str]]:
	"""Load monitorable devices from CSV, including DHCP clients."""
	csv_file = get_csv_path()
	with csv_file.open(newline="", encoding="utf-8") as csvfile:
		reader = csv.DictReader(csvfile)
		devices: list[dict[str, str]] = []
		for row in reader:
			device_name = (row.get("Device Name") or "").strip()
			if should_exclude(device_name):
				continue

			address = (row.get("Device Address") or "").strip()
			if not address or address.lower() == "none":
				continue

			devices.append(
				{
					"name": device_name,
					"address": address,
					"access_port": (row.get("Access Port") or "").strip(),
					"os": (row.get("OS") or "").strip(),
				}
			)
	return devices


def extract_valid_ipv4s(text: str) -> list[str]:
	matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
	valid: list[str] = []
	for ip in matches:
		try:
			ipaddress.IPv4Address(ip)
		except ipaddress.AddressValueError:
			continue
		valid.append(ip)
	return valid


def extract_tagged_ip(output_text: str, tag: str) -> str:
	pattern = rf"{re.escape(tag)}=([0-9.]+)"
	match = re.search(pattern, output_text)
	if not match:
		return ""
	ip = match.group(1)
	try:
		ipaddress.IPv4Address(ip)
		return ip
	except ipaddress.AddressValueError:
		return ""


def discover_dhcp_address(device: dict[str, str]) -> tuple[str, str]:
	"""Resolve current DHCP address by connecting to the device console."""
	access_port = device.get("access_port", "")
	if not access_port:
		return "", "Missing access port"

	device_name = (device.get("name") or "").lower()
	device_os = (device.get("os") or "").lower()
	try:
		access_port_int = int(access_port)
	except ValueError:
		return "", f"Invalid access port: {access_port}"

	if (
		access_port_int in VNC_PORT_RANGE
		or "vnc" in device_name
		or "webterm" in device_name
		or "vnc" in device_os
	):
		return "", "Non-CLI console endpoint (VNC/Webterm)"

	try:
		with socket.create_connection(
			(CONSOLE_HOST, access_port_int),
			timeout=CONSOLE_TIMEOUT_SECONDS,
		) as console:
			console.settimeout(0.5)
			output = b""

			def receive() -> None:
				nonlocal output
				while True:
					try:
						output += console.recv(4096)
					except socket.timeout:
						return

			receive()
			console.sendall(b"\n")
			time.sleep(0.2)
			console.sendall(f"{DHCP_USERNAME}\n".encode())
			time.sleep(0.2)
			console.sendall(f"{DHCP_PASSWORD}\n".encode())
			time.sleep(0.8)
			console.sendall(
				b"echo DHCP_PRIMARY_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \\([0-9.]*\\).*/\\1/p' | head -n1)\n"
			)
			time.sleep(0.5)
			console.sendall(b"echo DHCP_ALL_IPS=$(hostname -I 2>/dev/null)\n")
			time.sleep(0.6)
			receive()

		output_text = output.decode("utf-8", errors="replace")
		primary_ip = extract_tagged_ip(output_text, "DHCP_PRIMARY_IP")
		if primary_ip and not primary_ip.startswith("127."):
			return primary_ip, ""

		hostname_line_match = re.search(r"DHCP_ALL_IPS=([^\r\n]*)", output_text)
		if hostname_line_match:
			addresses = extract_valid_ipv4s(hostname_line_match.group(1))
		else:
			addresses = extract_valid_ipv4s(output_text)

		non_loopback = [ip for ip in addresses if not ip.startswith("127.")]
		if non_loopback:
			return non_loopback[-1], ""
		return "", "No IPv4 address found in console output"
	except (OSError, ValueError) as exc:
		return "", str(exc)


def ping_host(ip_address: str) -> bool:
	result = subprocess.run(
		["ping", "-c", "1", "-W", "1", ip_address],
		capture_output=True,
		text=True,
		check=False,
	)
	return result.returncode == 0


def send_failure_email(device_name: str, ip_address: str, reason: str, timestamp: str) -> bool:
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
		"Network Monitoring System\n"
	)

	try:
		with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=SMTP_TIMEOUT_SECONDS) as server:
			server.ehlo()
			server.send_message(message)
		return True
	except (OSError, smtplib.SMTPException) as exc:
		print(f"EMAIL FAILED: {device_name} ({ip_address}) - {exc}")
		return False


def create_failure_ticket(device_name: str, ip_address: str, reason: str, timestamp: str) -> bool:
	"""Create a helpdesk ticket for a failed device check and print the API response."""
	status, response = create_ticket(device_name, ip_address, reason)
	success = 200 <= status < 300 and isinstance(response, dict) and "id" in response
	result = "SUCCESS" if success else "FAILED"
	print(f"{result}: Ticket creation for {device_name} ({ip_address}) - HTTP {status}")
	print(json.dumps(response, indent=2))
	return success


def monitor_devices() -> None:
	print("Starting ICMP monitoring loop. Press Ctrl+C to stop.")
	open_incidents: set[str] = set()
	open_email_alerts: set[str] = set()
	try:
		while True:
			devices = load_devices()

			for device in devices:
				name = device["name"]
				configured_address = device["address"]
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

				ip_address = configured_address
				reason = ""
				if configured_address.lower() == "dhcp":
					ip_address, reason = discover_dhcp_address(device)
					if not ip_address:
						status = "FAIL"
						print(f"{timestamp} | Hostname: {name} | IP address: DHCP | Status: {status}")
						if name not in open_incidents:
							ticket_ok = create_failure_ticket(name, "DHCP", reason, timestamp)
							if ticket_ok:
								open_incidents.add(name)
								print(f"TICKET CREATED: {name} DHCP resolution failure was recorded in Helpdesk")
						else:
							print(f"TICKET SKIPPED: {name} already has an open outage ticket")
						if name not in open_email_alerts:
							email_ok = send_failure_email(name, "DHCP", reason, timestamp)
							if email_ok:
								open_email_alerts.add(name)
								print(f"ALERT SENT: {name} DHCP resolution failure email accepted by SMTP")
						else:
							print(f"ALERT SKIPPED: {name} already has an open email alert")
						continue

				try:
					success = ping_host(ip_address)
				except FileNotFoundError:
					print("ERROR: ping command not available on this system.")
					return

				status = "SUCCESS" if success else "FAIL"
				print(
					f"{timestamp} | Hostname: {name} | IP address: {ip_address} | Status: {status}"
				)

				if success:
					open_incidents.discard(name)
					open_email_alerts.discard(name)

				if not success:
					reason = "ICMP request timed out or host unreachable"
					if name not in open_incidents:
						ticket_ok = create_failure_ticket(name, ip_address, reason, timestamp)
						if ticket_ok:
							open_incidents.add(name)
							print(f"TICKET CREATED: {name} failure was recorded in Helpdesk")
					else:
						print(f"TICKET SKIPPED: {name} already has an open outage ticket")
					if name not in open_email_alerts:
						email_ok = send_failure_email(name, ip_address, reason, timestamp)
						if email_ok:
							open_email_alerts.add(name)
							print(f"ALERT SENT: {name} failure email accepted by SMTP")
					else:
						print(f"ALERT SKIPPED: {name} already has an open email alert")

			time.sleep(PING_INTERVAL_SECONDS)
	except FileNotFoundError as exc:
		print(f"ERROR: {exc}")
		return
	except KeyboardInterrupt:
		print("Monitoring stopped by user.")
		return


if __name__ == "__main__":
	monitor_devices()
 