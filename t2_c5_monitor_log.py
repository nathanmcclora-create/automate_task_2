"""Log successful DNS checks while the DNS monitor workflow is running.

Run this script in a separate terminal while t2_c4_1_monitor_dns.py is active.
"""


from __future__ import annotations

import argparse
import time
from datetime import datetime
from pathlib import Path

from t2_c4_1_monitor_dns import inspect_device, load_devices


LOG_DIR = Path(__file__).with_name("monitor_logs")
DEFAULT_INTERVAL_SECONDS = 30
MIN_INTERVAL_SECONDS = 15


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Log every successful DNS check with a delay between monitoring passes."
	)
	parser.add_argument(
		"--interval-seconds",
		type=int,
		default=DEFAULT_INTERVAL_SECONDS,
		help="Delay between monitoring passes to avoid excessive logging (default: 30).",
	)
	parser.add_argument(
		"--one-shot",
		action="store_true",
		help="Run one monitoring pass and exit.",
	)
	return parser.parse_args()


def get_log_file_path() -> Path:
	LOG_DIR.mkdir(parents=True, exist_ok=True)
	date_tag = datetime.now().strftime("%Y%m%d")
	return LOG_DIR / f"dns_success_log_{date_tag}.log"


def write_success_log(log_file: Path, timestamp: str, hostname: str, ip_address: str, dns_setting: str) -> None:
	date_value, time_value = timestamp.split(" ", 1)
	line = (
		f"Date: {date_value} | Time: {time_value} | Device Name: {hostname} | "
		f"IP Address: {ip_address} | Status: SUCCESS | DNS: {dns_setting}\n"
	)
	with log_file.open("a", encoding="utf-8") as handle:
		handle.write(line)


def format_status_line(timestamp: str, hostname: str, ip_address: str, status: str) -> str:
	date_value, time_value = timestamp.split(" ", 1)
	return f"Date: {date_value} | Time: {time_value} | Device Name: {hostname} | IP Address: {ip_address} | Status: {status}"


def run_logging_loop(interval_seconds: int, one_shot: bool) -> None:
	print("Starting DNS success logger. Press Ctrl+C to stop.")
	print("This logger mirrors DNS checks from t2_c4_1_monitor_dns.py.")
	log_file = get_log_file_path()
	print(f"Log folder ready: {LOG_DIR}")
	print(f"Writing success checks to: {log_file}")
	print(f"Monitoring delay between passes: {interval_seconds} seconds")
	if one_shot:
		print("One-shot mode enabled: script will run one pass and exit.")

	try:
		while True:
			devices = load_devices()
			for device in devices:
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				result = inspect_device(device)
				name = result["name"]
				ip_address = result["ip_address"]
				status = result["status"]

				print(format_status_line(timestamp, name, ip_address, status))
				if status == "SUCCESS":
					write_success_log(log_file, timestamp, name, ip_address, result["dns"])

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
	interval = max(MIN_INTERVAL_SECONDS, args.interval_seconds)
	run_logging_loop(interval_seconds=interval, one_shot=args.one_shot)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())