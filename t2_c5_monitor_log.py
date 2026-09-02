"""Log successful DNS checks while DNS monitoring is running.

Run this script in a separate terminal while t2_c4_1_monitor_dns.py is active.
"""


from __future__ import annotations

import argparse
import csv
import importlib.util
import ipaddress
import re
import socket
import time
from datetime import datetime
from pathlib import Path
from typing import Any


CSV_CANDIDATES = (
	Path(__file__).with_name("network_device.csv"),
	Path(__file__).with_name("network_devices.csv"),
)
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5
VNC_PORT_RANGE = range(5900, 6000)

DHCP_USERNAME = "ubuntu"
DHCP_PASSWORD = "ubuntu"

LOG_DIR = Path(__file__).with_name("monitor_logs")


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


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Log successful DNS checks with a configurable delay between monitoring passes."
	)
	parser.add_argument(
		"--interval-seconds",
		type=int,
		default=15,
		help="Delay between monitoring passes to avoid excessive logging (default: 15).",
	)
	parser.add_argument(
		"--one-shot",
		action="store_true",
		help="Run one monitoring pass and exit.",
	)
	return parser.parse_args()


def should_exclude(device_name: str) -> bool:
	name = (device_name or "").strip().lower()
	return name.startswith("router") or name.startswith("sw") or "switch" in name or name == "smtp"


def get_csv_path() -> Path:
	for candidate in CSV_CANDIDATES:
		if candidate.exists():
			return candidate
	raise FileNotFoundError("Could not find network_device.csv or network_devices.csv in the script directory.")


def load_devices() -> list[dict[str, str]]:
	csv_file = get_csv_path()
	with csv_file.open(newline="", encoding="utf-8") as csvfile:
		reader = csv.DictReader(csvfile)
		devices: list[dict[str, str]] = []
		for row in reader:
			name = (row.get("Device Name") or "").strip()
			if should_exclude(name):
				continue

			address = (row.get("Device Address") or "").strip()
			if not address or address.lower() == "none":
				continue

			devices.append(
				{
					"name": name,
					"address": address,
					"access_port": (row.get("Access Port") or "").strip(),
					"os": (row.get("OS") or "").strip(),
					"username": (row.get("Username") or DHCP_USERNAME).strip() or DHCP_USERNAME,
					"password": (row.get("Password") or DHCP_PASSWORD).strip() or DHCP_PASSWORD,
				}
			)
	return devices


def resolve_dhcp_ip(device: dict[str, str]) -> tuple[str, str]:
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
		with socket.create_connection((CONSOLE_HOST, access_port_int), timeout=CONSOLE_TIMEOUT_SECONDS) as console:
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
			time.sleep(0.6)
			console.sendall(b"hostname -I\n")
			time.sleep(0.8)
			receive()

		text = output.decode("utf-8", errors="replace")
		matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
		for candidate in reversed(matches):
			try:
				ipaddress.IPv4Address(candidate)
			except ipaddress.AddressValueError:
				continue
			if not candidate.startswith("127."):
				return candidate, ""
		return "", "No IPv4 address found in console output"
	except (OSError, ValueError) as exc:
		return "", str(exc)


def build_device_context(device: dict[str, str]) -> tuple[str, dict[str, str]]:
	name = device["name"]
	address = device["address"]
	username = device.get("username") or DHCP_USERNAME
	password = device.get("password") or DHCP_PASSWORD

	if address.lower() == "dhcp":
		current_ip, error = resolve_dhcp_ip(device)
		if not current_ip:
			return name, {"name": name, "address": "DHCP", "username": username, "password": password, "_error": error}
		return name, {"name": name, "address": current_ip, "username": username, "password": password}

	return name, {"name": name, "address": address, "username": username, "password": password}


def canonical_dns(dns_values: list[str]) -> str:
	if not dns_values:
		return "None"
	return ", ".join(sorted(set(dns_values)))


def check_dns_for_device(device: dict[str, str]) -> tuple[bool, str]:
	current_dns = DNS_FIXER.read_dns_settings(device)
	if not current_dns:
		return False, "None"

	matches_internal = set(current_dns) == APPROVED_DNS
	verified, _ = DNS_FIXER.verify_dns(device) if matches_internal else (False, current_dns)
	return verified, canonical_dns(current_dns)


def get_log_file_path() -> Path:
	LOG_DIR.mkdir(parents=True, exist_ok=True)
	date_tag = datetime.now().strftime("%Y%m%d")
	return LOG_DIR / f"dns_success_log_{date_tag}.log"


def write_success_log(log_file: Path, timestamp: str, hostname: str, ip_address: str, dns_setting: str) -> None:
	line = (
		f"{timestamp} | Hostname: {hostname} | IP address: {ip_address} | "
		f"Status: SUCCESS | DNS: {dns_setting}\n"
	)
	with log_file.open("a", encoding="utf-8") as handle:
		handle.write(line)


def run_logging_loop(interval_seconds: int, one_shot: bool) -> None:
	print("Starting DNS success logger. Press Ctrl+C to stop.")
	log_file = get_log_file_path()
	print(f"Log folder ready: {LOG_DIR}")
	print(f"Writing success checks to: {log_file}")
	if one_shot:
		print("One-shot mode enabled: script will run one pass and exit.")

	try:
		while True:
			devices = load_devices()
			for row in devices:
				name, context = build_device_context(row)
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				ip_address = context["address"]

				if context.get("_error"):
					print(f"{timestamp} | Hostname: {name} | IP address: DHCP | Status: FAIL")
					continue

				ok, detected_dns = check_dns_for_device(context)
				if ok:
					print(f"{timestamp} | Hostname: {name} | IP address: {ip_address} | Status: SUCCESS")
					write_success_log(log_file, timestamp, name, ip_address, detected_dns)
				else:
					print(f"{timestamp} | Hostname: {name} | IP address: {ip_address} | Status: FAIL")

			if one_shot:
				print("One-shot pass complete.")
				break

			time.sleep(interval_seconds)
	except FileNotFoundError as exc:
		print(f"ERROR: {exc}")
	except KeyboardInterrupt:
		print("DNS success logger stopped by user.")


def main() -> int:
	args = parse_args()
	interval = max(5, args.interval_seconds)
	run_logging_loop(interval_seconds=interval, one_shot=args.one_shot)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
