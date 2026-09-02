"""Continuously monitor devices with ICMP and send email alerts on failures."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import socket
import subprocess
import time
from datetime import datetime
from pathlib import Path

from t2_c3_create_ticket_test import submit_network_unavailable_incident


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


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(description="Monitor devices with ICMP and auto-create outage incidents.")
	parser.add_argument(
		"--one-shot",
		action="store_true",
		help="Run one monitoring pass and exit.",
	)
	parser.add_argument(
		"--simulate-outage-device",
		default="",
		help="Force one device to fail by name or IP without taking it offline.",
	)
	return parser.parse_args()


def monitor_devices(one_shot: bool = False, simulate_outage_device: str = "") -> None:
	print("Starting ICMP monitoring loop. Press Ctrl+C to stop.")
	if one_shot:
		print("One-shot mode enabled: script will run one pass and exit.")
	open_incidents: set[str] = set()
	simulated_target = simulate_outage_device.strip().lower()
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
							incident_ok = submit_network_unavailable_incident(name, "DHCP", timestamp=timestamp)
							if incident_ok:
								open_incidents.add(name)
								print(f"INCIDENT CREATED: {name} DHCP resolution failure was recorded")
							else:
								print(f"INCIDENT FAILED: {name} DHCP resolution failure was not fully recorded")
						else:
							print(f"INCIDENT SKIPPED: {name} already has an open outage incident")
						continue

				try:
					success = ping_host(ip_address)
				except FileNotFoundError:
					print("ERROR: ping command not available on this system.")
					return

				simulated_outage = bool(
					simulated_target
					and (name.lower() == simulated_target or ip_address.lower() == simulated_target)
				)
				if simulated_outage:
					success = False
					print(
						f"SIMULATION: Forcing outage for {name} ({ip_address}) via --simulate-outage-device."
					)

				status = "SUCCESS" if success else "FAIL"
				print(
					f"{timestamp} | Hostname: {name} | IP address: {ip_address} | Status: {status}"
				)

				if success:
					open_incidents.discard(name)

				if not success:
					if name not in open_incidents:
						incident_ok = submit_network_unavailable_incident(name, ip_address, timestamp=timestamp)
						if incident_ok:
							open_incidents.add(name)
							print(f"INCIDENT CREATED: {name} network outage was recorded")
						else:
							print(f"INCIDENT FAILED: {name} network outage was not fully recorded")
					else:
						print(f"INCIDENT SKIPPED: {name} already has an open outage incident")

			if one_shot:
				print("One-shot pass complete.")
				break

			time.sleep(PING_INTERVAL_SECONDS)
	except FileNotFoundError as exc:
		print(f"ERROR: {exc}")
		return
	except KeyboardInterrupt:
		print("Monitoring stopped by user.")
		return


if __name__ == "__main__":
	args = parse_args()
	monitor_devices(one_shot=args.one_shot, simulate_outage_device=args.simulate_outage_device)
 