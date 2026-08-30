"""Ping inventory devices, including DHCP clients discovered through GNS3."""

import csv
import re
import socket
import subprocess
import time
from pathlib import Path


CSV_FILE = Path(__file__).with_name("network_devices.csv")
USERNAME = "ubuntu"
PASSWORD = "ubuntu"
CONSOLE_HOST = "127.0.0.1"
CONSOLE_TIMEOUT_SECONDS = 5


def should_exclude(device_name: str) -> bool:
    name = (device_name or "").strip().lower()
    return (
        name.startswith("router")
        or name.startswith("sw")
        or "switch" in name
        or name == "smtp"
    )


def get_devices() -> list[dict[str, str]]:
    """Return eligible devices, including entries whose address is DHCP."""
    with CSV_FILE.open(newline="", encoding="utf-8") as csvfile:
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
                }
            )
    return devices


def discover_dhcp_address(device: dict[str, str]) -> tuple[str, str]:
    """Use the GNS3 console and Ubuntu credentials to find a DHCP address."""
    try:
        with socket.create_connection(
            (CONSOLE_HOST, int(device["access_port"])),
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
            console.sendall(f"{USERNAME}\n".encode())
            time.sleep(0.2)
            console.sendall(f"{PASSWORD}\n".encode())
            time.sleep(0.5)
            console.sendall(b"hostname -I\n")
            time.sleep(0.5)
            receive()

        addresses = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output.decode(
            "utf-8", errors="replace"
        ))
        if addresses:
            return addresses[-1], ""
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


if __name__ == "__main__":
    for device in get_devices():
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
