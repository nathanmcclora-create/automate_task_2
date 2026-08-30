"""Restart a stopped internal DNS service and verify both DNS servers."""

import subprocess
import sys
import shlex
from pathlib import Path

import paramiko


DNS_SERVERS = [
	{
		"name": "DNS1",
		"address": "10.10.10.10",
		"hostname": "ns1.d522.wgu.internal",
		"username": "ubuntu",
		"password": "ubuntu",
	},
	{
		"name": "DNS2",
		"address": "10.10.10.20",
		"hostname": "ns2.d522.wgu.internal",
		"username": "ubuntu",
		"password": "ubuntu",
	},
]

SSH_PORT = 22
SSH_TIMEOUT_SECONDS = 10
VERIFY_SCRIPT = Path(__file__).with_name("d1_connect_dns.py")

# Detect either service name, restart it only when it is not active, and
# return the resulting state. sudo -S supports the supplied Ubuntu password.
RESTART_COMMAND = """
if systemctl list-unit-files bind9.service 2>/dev/null | grep -q '^bind9.service'; then
    service=bind9
elif systemctl list-unit-files named.service 2>/dev/null | grep -q '^named.service'; then
    service=named
else
    echo 'No bind9.service or named.service unit was found.'
    exit 1
fi

state=$(systemctl is-active "$service" 2>/dev/null || true)
echo "Service: $service"
echo "Before restart: $state"
if [ "$state" != "active" ]; then
    echo "Restart services"
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' systemctl restart "$service"
    state=$(systemctl is-active "$service" 2>/dev/null || true)
fi
echo "After restart: $state"
[ "$state" = "active" ]
"""


def restart_if_down(server: dict[str, str]) -> bool:
	"""Restart the server's DNS service when down and return its final state."""
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		client.connect(
			hostname=server["address"],
			port=SSH_PORT,
			username=server["username"],
			password=server["password"],
			timeout=SSH_TIMEOUT_SECONDS,
			banner_timeout=SSH_TIMEOUT_SECONDS,
			auth_timeout=SSH_TIMEOUT_SECONDS,
		)
		command = f"export SUDO_PASSWORD={shlex.quote(server['password'])}\n{RESTART_COMMAND}"
		_, stdout, stderr = client.exec_command(command, timeout=SSH_TIMEOUT_SECONDS)
		output = stdout.read().decode("utf-8", errors="replace").strip()
		error = stderr.read().decode("utf-8", errors="replace").strip()
		print(output or "No restart output was returned.")
		if error:
			print(f"Command errors:\n{error}")
		return stdout.channel.recv_exit_status() == 0
	finally:
		client.close()


def verify_restart() -> int:
	"""Rerun d1_connect_dns.py and print its separate DNS server results."""
	if not VERIFY_SCRIPT.exists():
		print("\nVerification script not found")
		return 1
	result = subprocess.run(
		[sys.executable, str(VERIFY_SCRIPT)],
		capture_output=True,
		text=True,
		check=False,
		cwd=str(VERIFY_SCRIPT.parent),
	)
	print("\n===== DNS restart verification =====")
	print(result.stdout.strip())
	if result.stderr.strip():
		print(f"\nVerification errors:\n{result.stderr.strip()}")
	if result.returncode == 0:
		print("\nServices restored successfully")
	return result.returncode


def main() -> int:
	all_restarts_succeeded = True
	for server in DNS_SERVERS:
		print(f"\n{'=' * 60}\n{server['name']} - {server['hostname']} ({server['address']})\n{'=' * 60}")
		try:
			if not restart_if_down(server):
				all_restarts_succeeded = False
		except Exception as exc:
			all_restarts_succeeded = False
			print(f"Connection/restart failed: {exc}")

	verification_status = verify_restart()
	return 0 if all_restarts_succeeded and verification_status == 0 else 1


if __name__ == "__main__":
	raise SystemExit(main())
