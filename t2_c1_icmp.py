"""Ping eligible inventory devices and resolve DHCP client addresses first."""

from __future__ import annotations

import csv
import ipaddress
import re
import socket
import subprocess
import time
from pathlib import Path


CSV_CANDIDATES = (
	Path(__file__).with_name("network_device.csv"),
	Path(__file__).with_name("network_devices.csv"),
)
USERNAME = "ubuntu"
PASSWORD = "ubuntu"
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5
VNC_PORT_RANGE = range(5900, 6000)


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


def get_devices() -> list[dict[str, str]]:
	"""Return eligible devices, including entries whose address is DHCP."""
	csv_file = get_csv_path()
	with csv_file.open(newline="", encoding="utf-8") as csvfile:
		reader = csv.DictReader(csvfile)
		devices = []
		for row in reader:
			device_name = row.get("Device Name", "")
			if should_exclude(device_name):
				continue

			address = (row.get("Device Address") or "").strip()
			if not address or address.lower() == "none":
				continue

			devices.append(
				{
					"name": device_name.strip(),
					"address": address,
					"access_port": (row.get("Access Port") or "").strip(),
					"os": (row.get("OS") or "").strip(),
				}
			)
	return devices


def extract_valid_ipv4s(text: str) -> list[str]:
	matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
	valid = []
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
	"""Use the GNS3 console and Ubuntu credentials to find a DHCP address."""
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
			console.sendall(f"{USERNAME}\n".encode())
			time.sleep(0.2)
			console.sendall(f"{PASSWORD}\n".encode())
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
	try:
		result = subprocess.run(
			["ping", "-c", "1", "-W", "1", ip_address],
			capture_output=True,
			text=True,
			check=False,
		)
		return result.returncode == 0
	except FileNotFoundError:
		print("ping command not available on this system.")
		return False


def main() -> None:
	try:
		devices = get_devices()
	except FileNotFoundError as exc:
		print(f"ERROR: {exc}")
		return

	for device in devices:
		name = device["name"]
		address = device["address"]

		if address.lower() == "dhcp":
			address, error = discover_dhcp_address(device)
			if not address:
				print(f"FAILED: {name} current DHCP address unavailable ({error})")
				continue
			print(f"{name} current DHCP address: {address}")

		print(f"Pinging {name} ({address})...")
		if ping_host(address):
			print(f"SUCCESS: {name} reachable at {address}")
		else:
			print(f"FAILED: {name} unreachable at {address}")


if __name__ == "__main__":
	main()
