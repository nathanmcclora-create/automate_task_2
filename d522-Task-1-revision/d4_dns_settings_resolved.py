"""Correct compromised DNS settings and verify the resulting configuration."""

import re
import shlex
import subprocess
import sys
from pathlib import Path

import paramiko


DNS1 = "10.10.10.10"
DNS2 = "10.10.10.20"
USERNAME = "ubuntu"
PASSWORD = "ubuntu"
SSH_TIMEOUT_SECONDS = 10
DNS_CHECK_SCRIPT = Path(__file__).with_name("d4_verify_dns_settings.py")


def load_devices() -> list[dict[str, str]]:
    """Load non-infrastructure devices from the inventory CSV."""
    csv_file = Path(__file__).with_name("network_devices.csv")
    devices = []
    with csv_file.open(newline="", encoding="utf-8") as handle:
        import csv

        for row in csv.DictReader(handle):
            name = (row.get("Device Name") or "").strip()
            address = (row.get("Device Address") or "").strip().lower()
            if not address or address in {"dhcp", "none"}:
                continue
            if name.lower().startswith("router") or name.lower().startswith("sw") or "switch" in name.lower() or name.lower() == "smtp":
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


def run_dns_check() -> str:
    """Run the DNS verification script and return its combined output."""
    if not DNS_CHECK_SCRIPT.exists():
        return ""
    result = subprocess.run(
        [sys.executable, str(DNS_CHECK_SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(DNS_CHECK_SCRIPT.parent),
    )
    return result.stdout + result.stderr


def find_misconfigured_devices(output: str) -> list[dict[str, str]]:
    """Return devices marked MISCONFIGURED by the DNS check."""
    pattern = re.compile(
        r"^(?P<name>.+?) \((?P<address>[^)]+)\) - MISCONFIGURED\s*$",
        re.MULTILINE,
    )
    return [
        {"name": match.group("name").strip(), "address": match.group("address").strip()}
        for match in pattern.finditer(output)
    ]


def run_remote_command(server: dict[str, str], command: str) -> tuple[int, str, str]:
    """Run a sudo command on a device and return exit code and output."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=server["address"],
            username=server["username"],
            password=server["password"],
            timeout=SSH_TIMEOUT_SECONDS,
            banner_timeout=SSH_TIMEOUT_SECONDS,
            auth_timeout=SSH_TIMEOUT_SECONDS,
        )
        stdin, stdout, stderr = client.exec_command(
            f"sudo -S -p '' sh -c {shlex.quote(command)}",
            get_pty=True,
            timeout=SSH_TIMEOUT_SECONDS,
        )
        stdin.write(f"{server['password']}\n")
        stdin.flush()
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        return stdout.channel.recv_exit_status(), output.strip(), error.strip()
    finally:
        client.close()


def configure_dns(server: dict[str, str]) -> bool:
    """Set both approved DNS servers in /etc/resolv.conf."""
    command = (
        f"printf '%s\\n' 'nameserver {DNS1}' 'nameserver {DNS2}' "
        "'options timeout:2 attempts:2' > /etc/resolv.conf"
    )
    status, output, error = run_remote_command(server, command)
    if output:
        print(output)
    if error:
        print(f"Command errors: {error}")
    return status == 0


def verify_dns(server: dict[str, str]) -> bool:
    """Verify that /etc/resolv.conf contains DNS1 and DNS2 only."""
    status, output, error = run_remote_command(server, "cat /etc/resolv.conf")
    servers = re.findall(r"^\s*nameserver\s+(\S+)", output, re.MULTILINE)
    correct = status == 0 and set(servers) == {DNS1, DNS2}
    result = "SUCCESS" if correct else "FAILED"
    print(f"{server['name']} ({server['address']}) - {result}")
    print(f"  DNS servers: {servers or 'None'}")
    if error:
        print(f"  Verification errors: {error}")
    return correct


def main() -> int:
    devices = load_devices()
    if not devices:
        print("No eligible devices were found in network_devices.csv.")
        return 0

    print("Checking DNS settings on all eligible devices...")
    check_output = run_dns_check()
    misconfigured_devices = find_misconfigured_devices(check_output)
    if not misconfigured_devices:
        print("No devices are currently misconfigured; all DNS settings are already correct.")
        return 0

    print(f"Found {len(misconfigured_devices)} device(s) with incorrect DNS settings.")
    configuration_results = []
    verification_results = []

    for device in misconfigured_devices:
        print(f"\n{'=' * 60}\n{device['name']} ({device['address']})\n{'=' * 60}")
        try:
            target = next(item for item in devices if item["name"].lower() == device["name"].lower())
            connected_and_configured = configure_dns(target)
            if not connected_and_configured:
                print("Unable to update DNS settings.")
            configuration_results.append(connected_and_configured)
            verification_results.append(verify_dns(target))
            print(f"DEVICE SUCCESS: {device['name']} updated to DNS1 ({DNS1}) and DNS2 ({DNS2}).")
        except Exception as exc:
            print(f"Connection/configuration failed for {device['name']}: {exc}")
            configuration_results.append(False)
            verification_results.append(False)

    print("\n===== DNS verification summary =====")
    if verification_results and all(verification_results):
        print("All devices have the correct internal DNS settings and report success.")
        return 0

    failed = sum(1 for result in verification_results if not result)
    print(f"{failed} device(s) did not resolve to the expected DNS settings.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
