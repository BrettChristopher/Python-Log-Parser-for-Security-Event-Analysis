#!/usr/bin/env python3

import re
from collections import defaultdict
from pathlib import Path

# Pattern to match failed SSH login attempts
FAILED_LOGIN = re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)")

def parse_log(file_path):
    # Count failed attempts by IP
    failed_attempts = defaultdict(int)

    with open(file_path, "r", errors="ignore") as log:
        for line in log:
            match = FAILED_LOGIN.search(line)
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1

    return failed_attempts


def print_summary(failed):
    print("\n=== Failed Login Summary ===\n")

    if not failed:
        print("No failed login attempts found.\n")
        return

    for ip, count in failed.items():
        print(f"{ip}: {count} failed attempts")

    print()


if __name__ == "__main__":
    log_file = "/var/log/auth.log"

    if not Path(log_file).exists():
        print(f"Log file not found: {log_file}")
        exit(1)

    failed = parse_log(log_file)
    print_summary(failed)
