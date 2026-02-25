#!/usr/bin/env python3

import re
from collections import defaultdict
from pathlib import Path


# Regex patterns for common SSH/auth events
# These match failed logins, successful logins, and disconnects.

FAILED_LOGIN = re.compile(r"Failed password for (invalid user )?(\w+|\S+) from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_LOGIN = re.compile(r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)")
SSH_CONNECTION = re.compile(r"Disconnected from (\d+\.\d+\.\d+\.\d+)")


def parse_log(file_path):
    
    # Dictionaries to count events by IP address.
    # defaultdict(int) automatically starts counts at 0.

    failed_attempts = defaultdict(int)
    successful_logins = defaultdict(int)
    disconnects = defaultdict(int)

    
    # Open the log file and iterate line by line.
    # errors="ignore" prevents crashes on weird characters.

    with open(file_path, "r", errors="ignore") as log:
        for line in log:

         
            # Match failed SSH login attempts.
            # Extract the IP and increment its counter.
      
            if match := FAILED_LOGIN.search(line):
                ip = match.group(3)
                failed_attempts[ip] += 1

        
            # Match successful SSH logins.
            # Extract the IP and increment its counter.
      
            elif match := SUCCESS_LOGIN.search(line):
                ip = match.group(2)
                successful_logins[ip] += 1

            
            # Match SSH disconnect events.
            # Useful for spotting quick connect/disconnect patterns.
          
            elif match := SSH_CONNECTION.search(line):
                ip = match.group(1)
                disconnects[ip] += 1

  
    # Return all three dictionaries for reporting.
  
    return failed_attempts, successful_logins, disconnects


def print_summary(failed, success, disconnects):
  
    # Print a clean summary of all parsed events.
   
    print("\n=== Log Analysis Summary ===\n")

    # Failed login attempts
    print("Failed Login Attempts:")
    for ip, count in failed.items():
        print(f"  {ip}: {count} attempts")
    if not failed:
        print("  None detected")

    # Successful logins
    print("\nSuccessful Logins:")
    for ip, count in success.items():
        print(f"  {ip}: {count} logins")
    if not success:
        print("  None detected")

    # SSH disconnects
    print("\nSSH Disconnects:")
    for ip, count in disconnects.items():
        print(f"  {ip}: {count} disconnects")
    if not disconnects:
        print("  None detected")

    # Simple brute-force detection:
    # Any IP with 5+ failed attempts is flagged.

    print("\n=== Potential Brute Force Sources ===")
    for ip, count in failed.items():
        if count >= 5:
            print(f"  {ip}: {count} failed attempts (suspicious)")
    print()


if __name__ == "__main__":
    
    # Default log file path.
    
    log_file = "/var/log/auth.log"


    # Check if the log file exists before parsing.

    if not Path(log_file).exists():
        print(f"Log file not found: {log_file}")
        exit(1)


    # Parse the log and print the summary.
   
    failed, success, disconnects = parse_log(log_file)
    print_summary(failed, success, disconnects)
