"""Connect to each device, fix incorrect DNS settings, and verify the internal DNS configuration."""

import csv
import re
import shlex
import subprocess
from pathlib import Path

import paramiko


CSV_FILE = Path(__file__).with_name("network_devices.csv")
DNS1 = "10.10.10.10"
DNS2 = "10.10.10.20"
APPROVED_DNS = {DNS1, DNS2}
USERNAME = "ubuntu"
PASSWORD = "ubuntu"
SSH_TIMEOUT_SECONDS = 10


def load_devices() -> list[dict[str, str]]:
    """Load eligible devices from the inventory CSV."""
    devices: list[dict[str, str]] = []
    with CSV_FILE.open(newline="", encoding="utf-8") as csv_file:
        for row in csv.DictReader(csv_file):
            name = (row.get("Device Name") or "").strip()
            address = (row.get("Device Address") or "").strip()
            if not address or address.lower() in {"dhcp", "none"}:
                continue
            lower_name = name.lower()
            if lower_name.startswith("router") or lower_name.startswith("sw") or "switch" in lower_name or lower_name == "smtp":
                continue
            devices.append(
                {
                    "name": name,
                    "address": address,
                    "username": (row.get("Username") or USERNAME).strip() or USERNAME,
                    "password": (row.get("Password") or PASSWORD).strip() or PASSWORD,
                }
            )
    return devices


def read_dns_settings(device: dict[str, str]) -> list[str]:
    """Read nameserver entries from /etc/resolv.conf on the device."""
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
        _, stdout, _ = client.exec_command(
            "cat /etc/resolv.conf 2>/dev/null || resolvectl dns",
            timeout=SSH_TIMEOUT_SECONDS,
        )
        output = stdout.read().decode("utf-8", errors="replace")
        return re.findall(r"^\s*nameserver\s+(\S+)", output, re.MULTILINE)
    except Exception:
        return []
    finally:
        client.close()


def set_internal_dns(device: dict[str, str]) -> bool:
    """Write the internal DNS servers to the device's resolv.conf file."""
    command = (
        f"printf '%s\\n' 'nameserver {DNS1}' 'nameserver {DNS2}' "
        "'options timeout:2 attempts:2' > /etc/resolv.conf"
    )
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
        stdin, stdout, stderr = client.exec_command(
            f"sudo -S -p '' sh -c {shlex.quote(command)}",
            get_pty=True,
            timeout=SSH_TIMEOUT_SECONDS,
        )
        stdin.write(f"{device['password']}\n")
        stdin.flush()
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        exit_code = stdout.channel.recv_exit_status()
        if output.strip():
            print(output.strip())
        if error.strip():
            print(error.strip())
        return exit_code == 0
    except Exception as exc:
        print(f"Failed to update DNS on {device['name']}: {exc}")
        return False
    finally:
        client.close()


def dns_is_reachable(dns_ip: str) -> bool:
    """Check whether a DNS server is reachable via ping."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "1", dns_ip],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0


def verify_dns(device: dict[str, str]) -> tuple[bool, list[str]]:
    """Verify the device points to the approved internal DNS servers and that they respond."""
    servers = read_dns_settings(device)
    reachable = all(dns_is_reachable(server) for server in servers) if servers else False
    correct = set(servers) == APPROVED_DNS and reachable
    return correct, servers


def main() -> None:
    """Fix misconfigured DNS settings and print the result for each affected device."""
    print("Connecting to devices with incorrect DNS settings...\n")

    for device in load_devices():
        current_dns = read_dns_settings(device)
        if set(current_dns) == APPROVED_DNS:
            success, final_dns = verify_dns(device)
            final_status = "SUCCESS" if success else "FAILED"
            print(f"Device name: {device['name']}")
            print(f"IP address of DNS: {', '.join(final_dns) if final_dns else 'None'}")
            print(f"Status: {final_status}")
            print()
            continue

        print(f"Updating DNS on {device['name']} ({device['address']})")
        changed = set_internal_dns(device)
        if changed:
            current_dns = read_dns_settings(device)
        success, final_dns = verify_dns(device)
        final_status = "SUCCESS" if success and changed else "FAILED"

        print(f"Device name: {device['name']}")
        print(f"IP address of DNS: {', '.join(final_dns) if final_dns else 'None'}")
        print(f"Status: {final_status}")
        print()


if __name__ == "__main__":
    main()
