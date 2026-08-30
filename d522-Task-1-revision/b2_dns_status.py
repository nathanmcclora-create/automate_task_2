# Creating a script to list devices whose DNS connection is not working properly.

import csv
import re
import socket
import time
from pathlib import Path

import paramiko


CSV_FILE = Path(__file__).with_name("network_devices.csv")
APPROVED_DNS = {"10.10.10.10", "10.10.10.20"}
USERNAME = "ubuntu"
PASSWORD = "ubuntu"
SSH_TIMEOUT = 10
CONSOLE_TIMEOUT = 5


def should_exclude(device_name: str) -> bool:
    name = (device_name or "").strip().lower()
    return (
        name.startswith("router")
        or name.startswith("sw")
        or "switch" in name
        or name == "smtp"
    )


def load_devices() -> list[dict[str, str]]:
    devices = []
    with CSV_FILE.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            name = (row.get("Device Name") or "").strip()
            if should_exclude(name):
                continue

            address = (row.get("Device Address") or "").strip()
            if not address or address.lower() in {"dhcp", "none"}:
                continue

            devices.append(
                {
                    "name": name,
                    "address": address,
                    "access_port": (row.get("Access Port") or "").strip(),
                    "username": (row.get("Username") or USERNAME).strip(),
                    "password": (row.get("Password") or PASSWORD).strip(),
                }
            )
    return devices


def run_console_command(device: dict[str, str], command: str) -> tuple[str, str]:
    try:
        with socket.create_connection(
            ("127.0.0.1", int(device["access_port"])),
            timeout=CONSOLE_TIMEOUT,
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


def get_dns_servers_from_device(device: dict[str, str]) -> list[str]:
    if device["address"].lower() == "dhcp":
        output, _ = run_console_command(device, "cat /etc/resolv.conf 2>/dev/null || resolvectl dns")
        return re.findall(r"^\s*nameserver\s+(\S+)", output, flags=re.MULTILINE)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=device["address"],
            username=device["username"],
            password=device["password"],
            timeout=SSH_TIMEOUT,
            banner_timeout=SSH_TIMEOUT,
            auth_timeout=SSH_TIMEOUT,
        )
        _, stdout, stderr = client.exec_command(
            "cat /etc/resolv.conf 2>/dev/null || resolvectl dns",
            timeout=SSH_TIMEOUT,
        )
        output = stdout.read().decode("utf-8", errors="replace")
        return re.findall(r"^\s*nameserver\s+(\S+)", output, flags=re.MULTILINE)
    except Exception:
        return []
    finally:
        client.close()


def dns_connection_ok(device: dict[str, str], dns_servers: list[str]) -> bool:
    if not dns_servers:
        return False

    for dns_server in dns_servers:
        if device["address"].lower() == "dhcp":
            output, _ = run_console_command(
                device,
                f'ping -c 1 -W 1 "{dns_server}" >/dev/null 2>&1 || echo FAIL',
            )
            if "FAIL" in output:
                return False
        else:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=device["address"],
                    username=device["username"],
                    password=device["password"],
                    timeout=SSH_TIMEOUT,
                    banner_timeout=SSH_TIMEOUT,
                    auth_timeout=SSH_TIMEOUT,
                )
                _, stdout, stderr = client.exec_command(
                    f'ping -c 1 -W 1 "{dns_server}" >/dev/null 2>&1 || echo FAIL',
                    timeout=SSH_TIMEOUT,
                )
                output = stdout.read().decode("utf-8", errors="replace")
                if "FAIL" in output:
                    return False
            finally:
                client.close()
    return True


def main() -> None:
    bad_devices = []
    for device in load_devices():
        servers = get_dns_servers_from_device(device)
        configured_ok = set(servers) == APPROVED_DNS
        connected_ok = dns_connection_ok(device, servers)
        if not configured_ok or not connected_ok:
            bad_devices.append({
                "name": device["name"],
                "address": device["address"],
                "dns": servers,
                "status": "OFFLINE" if not connected_ok else "MISCONFIGURED",
            })

    if not bad_devices:
        print("No devices are failing DNS connectivity.")
    else:
        print("Devices with DNS connection issues:")
        for entry in bad_devices:
            dns_value = entry["dns"][0] if entry["dns"] else "None"
            print(f"Device name: {entry['name']}")
            print(f"IP address of DNS: {dns_value}")
            print(f"Status: {entry['status']}")
            print()


if __name__ == "__main__":
    main()
