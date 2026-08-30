"""Print connectivity and DNS settings for devices in the inventory CSV."""

import csv
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import paramiko


CSV_FILE = Path(__file__).with_name("network_devices.csv")
ICMP_SCRIPT = Path(__file__).with_name("b1_icmp.py")
PING_TIMEOUT_SECONDS = 1
SSH_TIMEOUT_SECONDS = 5


def load_devices() -> list[dict[str, str]]:
	"""Load all devices from the inventory file."""
	with CSV_FILE.open(newline="", encoding="utf-8") as csv_file:
		return [
			{
				"name": (row.get("Device Name") or "Unknown").strip(),
				"address": (row.get("Device Address") or "").strip(),
				"access_port": (row.get("Access Port") or "").strip(),
				"os": (row.get("OS") or "").strip(),
				"username": (row.get("Username") or "").strip(),
				"password": (row.get("Password") or "").strip(),
			}
			for row in csv.DictReader(csv_file)
		]


def run_icmp_script() -> str:
	"""Run b1_icmp.py and return its standard output and errors."""
	result = subprocess.run(
		[sys.executable, str(ICMP_SCRIPT)],
		capture_output=True,
		text=True,
		check=False,
		cwd=str(ICMP_SCRIPT.parent),
	)
	return result.stdout + result.stderr


def parse_icmp_output(output: str) -> dict[str, str]:
	"""Extract addresses from successful fixed and DHCP ping results."""
	addresses = {
		match.group("name"): match.group("address")
		for match in re.finditer(
			r"^SUCCESS: (?P<name>[^ ]+) reachable at (?P<address>\S+)$",
			output,
			re.MULTILINE,
		)
	}
	addresses.update(
		{
			match.group("name"): match.group("address")
			for match in re.finditer(
				r"^(?P<name>[^\s]+) current DHCP address: (?P<address>\S+)$",
				output,
				re.MULTILINE,
			)
		}
	)
	return addresses


def run_console_command(device: dict[str, str], command: str) -> tuple[str, str]:
	"""Run a command through the device's local GNS3 console."""
	try:
		with socket.create_connection(
			("127.0.0.1", int(device["access_port"])), timeout=SSH_TIMEOUT_SECONDS
		) as console:
			console.settimeout(0.5)
			output = b""
			try:
				while True:
					output += console.recv(4096)
			except (socket.timeout, ConnectionResetError):
				pass

			console.sendall(f"{device['username']}\n".encode())
			time.sleep(0.2)
			console.sendall(f"{device['password']}\n".encode())
			time.sleep(0.5)
			console.sendall(f"{command}\n".encode())
			time.sleep(0.5)
			while True:
				try:
					output += console.recv(4096)
				except socket.timeout:
					break

		return output.decode("utf-8", errors="replace"), ""
	except (OSError, ValueError) as exc:
		return "", str(exc)


def get_dhcp_details(device: dict[str, str]) -> tuple[str, list[str], str]:
	"""Discover a DHCP address and DNS settings through the GNS3 console."""
	output, error = run_console_command(
		device,
		"hostname -I; cat /etc/resolv.conf 2>/dev/null || resolvectl dns 2>/dev/null",
	)
	first_line = output.splitlines()[0] if output.splitlines() else ""
	address_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", first_line)
	address = address_match.group(0) if address_match else ""
	servers = re.findall(
		r"^\s*nameserver\s+(\S+)", output, flags=re.MULTILINE
	)
	return address, servers, error


def ping_device(address: str) -> tuple[bool | None, str]:
	"""Return the ping result and a reason when the address cannot be checked."""
	if not address or address.lower() in {"dhcp", "none"}:
		return None, "No fixed IP address"

	try:
		result = subprocess.run(
			["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), address],
			capture_output=True,
			text=True,
			check=False,
		)
	except FileNotFoundError:
		return None, "ping command is unavailable"

	return result.returncode == 0, ""


def dns_command(device_os: str) -> str:
	"""Return the DNS command appropriate for the device operating system."""
	if device_os.lower() == "vyos":
		return "show system name-server"
	return "cat /etc/resolv.conf 2>/dev/null || resolvectl dns 2>/dev/null"


def read_dns_settings(device: dict[str, str]) -> tuple[list[str], str]:
	"""Read DNS server entries over SSH and return entries plus an error message."""
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	try:
		client.connect(
			hostname=device["address"],
			username=device["username"],
			password=device["password"],
			timeout=SSH_TIMEOUT_SECONDS,
			banner_timeout=SSH_TIMEOUT_SECONDS,
			auth_timeout=SSH_TIMEOUT_SECONDS,
		)
		_, stdout, stderr = client.exec_command(
			dns_command(device["os"]), timeout=SSH_TIMEOUT_SECONDS
		)
		output = stdout.read().decode("utf-8", errors="replace")
		error = stderr.read().decode("utf-8", errors="replace").strip()
		servers = re.findall(
			r"^\s*nameserver\s+(\S+)", output, flags=re.MULTILINE
		)
		if not servers and device["os"].lower() == "vyos":
			servers = re.findall(r"(?:name-server|nameserver)\s+(\S+)", output)
		return servers, error
	except Exception as exc:
		return [], str(exc)
	finally:
		client.close()


def print_device_status(device: dict[str, str]) -> None:
	"""Print connectivity and DNS information for one inventory entry."""
	name = device["name"]
	is_dhcp = device["address"].lower() == "dhcp"
	dns_servers: list[str] = []
	dns_error = ""
	if is_dhcp:
		address, dns_servers, dns_error = get_dhcp_details(device)
		if not address:
			address = "Unknown"
	else:
		address = device["address"] or "N/A"

	reachable, reason = ping_device(address if address != "Unknown" else "")

	if reachable is True:
		connectivity = "ONLINE"
		if not is_dhcp:
			dns_servers, dns_error = read_dns_settings(device)
		dns_status = ", ".join(dns_servers) if dns_servers else "Unavailable"
		if dns_error:
			dns_status += f" ({dns_error})"
	elif reachable is False:
		connectivity = "OFFLINE"
		dns_status = ", ".join(dns_servers) if dns_servers else "Unavailable"
	else:
		connectivity = f"NOT CHECKED ({reason})"
		dns_status = ", ".join(dns_servers) if dns_servers else "Unavailable"
		if dns_error:
			dns_status += f" ({dns_error})"

	print(f"{name} ({address})")
	print(f"  Connectivity: {connectivity}")
	print(f"  DNS settings: {dns_status}")


def main() -> None:
	"""Print status for every device in network_devices.csv."""
	devices = {device["name"]: device for device in load_devices()}
	addresses = parse_icmp_output(run_icmp_script())
	if not addresses:
		print("No reachable devices were reported by b1_icmp.py.")
		return

	for name, address in addresses.items():
		device = devices.get(name)
		if device is None:
			continue
		device["address"] = address
		servers, error = read_dns_settings(device)
		print(f"{name} ({address})")
		print(f"  DNS settings: {', '.join(servers) if servers else 'Unavailable'}")
		if error:
			print(f"  SSH error: {error}")


if __name__ == "__main__":
	main()
