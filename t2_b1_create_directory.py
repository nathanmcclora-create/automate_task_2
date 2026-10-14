#!/usr/bin/env python3
"""Create DNS backup folders and export the DNS1/DNS2 configuration files."""

from __future__ import annotations

import csv
from pathlib import Path

import paramiko


USERNAME = "ubuntu"
PASSWORD = "ubuntu"


def get_csv_path() -> Path:
    """Resolve the device inventory CSV path, supporting csv/cvs variants."""
    workspace_root = Path(__file__).resolve().parents[1]
    candidates = [
        workspace_root / "network_devices.csv",
        workspace_root / "network_devices.cvs",
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "No inventory file was found. Expected one of: network_devices.csv, network_devices.cvs"
    )


def get_dns_servers(csv_path: Path) -> dict[str, str]:
    """Return the DNS1 and DNS2 devices and their IP addresses from the CSV."""
    dns_servers: dict[str, str] = {}

    with csv_path.open("r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            device_name = (row.get("Device Name") or "").strip()
            if device_name not in {"DNS1", "DNS2"}:
                continue

            address = (row.get("Device Address") or "").strip()
            if address and address not in {"DHCP", "None"}:
                dns_servers[device_name] = address

    return dns_servers


def create_backup_structure(base_dir: Path, dns_servers: dict[str, str]) -> dict[str, Path]:
    """Create the parent directory and per-server folders for DNS backups."""
    base_dir.mkdir(exist_ok=True)

    server_paths: dict[str, Path] = {}
    for device_name, ip_address in dns_servers.items():
        folder = base_dir / f"Server [{ip_address}]"
        folder.mkdir(exist_ok=True)
        server_paths[device_name] = folder

    return server_paths


def fetch_dns_config(server_ip: str, username: str = USERNAME, password: str = PASSWORD) -> str:
    """Connect to a DNS server and export its configuration content."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=server_ip,
            username=username,
            password=password,
            timeout=10,
            banner_timeout=10,
            auth_timeout=10,
        )

        command = (
            "sudo -S -p '' bash -lc '\n"
            "for file in /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local /etc/bind/named.conf.default-zones; do\n"
            "  if [ -f \"$file\" ]; then\n"
            "    echo \"===== $file =====\";\n"
            "    cat \"$file\";\n"
            "    echo;\n"
            "  fi;\n"
            "done;\n"
            "if [ ! -f /etc/bind/named.conf ] && [ -f /etc/named.conf ]; then\n"
            "  echo \"===== /etc/named.conf =====\";\n"
            "  cat /etc/named.conf;\n"
            "fi;\n"
            "if [ ! -f /etc/bind/named.conf ] && [ ! -f /etc/named.conf ]; then\n"
            "  echo \"No DNS config file was found on the server.\";\n"
            "fi\n'"
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=20)
        stdin.write(f"{password}\n")
        stdin.flush()

        config_output = stdout.read().decode("utf-8", errors="replace").strip()
        error_output = stderr.read().decode("utf-8", errors="replace").strip()

        if config_output:
            return config_output
        if error_output:
            return error_output
        return "No DNS configuration output was returned."
    finally:
        client.close()


def write_backup_file(target_dir: Path, server_name: str, server_ip: str) -> None:
    """Write a record-config.txt file for a single DNS server."""
    config_text = fetch_dns_config(server_ip)
    backup_file = target_dir / "record-config.txt"
    backup_file.write_text(
        f"DNS Server Backup\n"
        f"Server Name: {server_name}\n"
        f"Server IP: {server_ip}\n"
        f"Generated from: {server_ip}\n\n"
        f"{config_text}\n",
        encoding="utf-8",
    )


def main() -> None:
    """Create the DNS backup folders and save configuration backups for the DNS servers."""
    csv_file = get_csv_path()
    backup_root = csv_file.parent / "DNS Backup"

    dns_servers = get_dns_servers(csv_file)
    if not dns_servers:
        raise RuntimeError(f"No DNS1/DNS2 records were found in {csv_file}.")

    backup_locations = create_backup_structure(backup_root, dns_servers)

    for server_name, ip_address in dns_servers.items():
        folder = backup_locations[server_name]
        write_backup_file(folder, server_name, ip_address)
        print(f"Created backup for {server_name} at {folder / 'record-config.txt'}")

    print(f"\nDNS Backup directory ready: {backup_root}")


if __name__ == "__main__":
    main()