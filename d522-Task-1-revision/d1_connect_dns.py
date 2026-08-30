"""Connect to the internal DNS servers and print each service status separately."""

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

# Ubuntu commonly uses bind9; the fallback also supports systems using named.
STATUS_COMMAND = (
	"hostname; "
	"if systemctl list-unit-files bind9.service 2>/dev/null | grep -q '^bind9.service'; then "
	"systemctl is-active bind9; systemctl --no-pager --full status bind9; "
	"elif systemctl list-unit-files named.service 2>/dev/null | grep -q '^named.service'; then "
	"systemctl is-active named; systemctl --no-pager --full status named; "
	"else echo 'No bind9.service or named.service unit was found.'; fi"
)


def get_dns_status(server: dict[str, str]) -> tuple[str, str]:
	"""Connect to one server and return its hostname, stdout, and stderr."""
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
		_, stdout, stderr = client.exec_command(STATUS_COMMAND, timeout=SSH_TIMEOUT_SECONDS)
		return (
			stdout.read().decode("utf-8", errors="replace").strip(),
			stderr.read().decode("utf-8", errors="replace").strip(),
		)
	finally:
		client.close()


def print_server_status(server: dict[str, str]) -> bool:
	"""Print one server's result and return whether SSH/status retrieval succeeded."""
	print(f"\n{'=' * 60}\n{server['name']} - {server['hostname']} ({server['address']})\n{'=' * 60}")
	try:
		stdout, stderr = get_dns_status(server)
		print(stdout or "No status output was returned.")
		if stderr:
			print(f"\nCommand errors:\n{stderr}")
		return bool(stdout)
	except Exception as exc:
		print(f"Connection/status check failed: {exc}")
		return False


if __name__ == "__main__":
	results = [print_server_status(server) for server in DNS_SERVERS]
	raise SystemExit(0 if all(results) else 1)
