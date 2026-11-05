#!/usr/bin/env python3
"""
log-sentinel: detect SSH brute-force attempts in Linux auth logs.

Usage:
    python log_sentinel.py sample_logs/auth.log
    python log_sentinel.py /var/log/auth.log --threshold 3 --json report.json
"""
import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict

FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})")


@dataclass
class IPReport:
    ip: str
    failed: int = 0
    users_tried: set = field(default_factory=set)
    successful_logins: list = field(default_factory=list)

    @property
    def compromised(self) -> bool:
        """Many failures followed by a success = likely cracked account."""
        return self.failed > 0 and bool(self.successful_logins)

    def to_dict(self):
        d = asdict(self)
        d["users_tried"] = sorted(self.users_tried)
        d["compromised"] = self.compromised
        return d


def parse_lines(lines):
    reports = defaultdict(lambda: None)
    for line in lines:
        for regex, kind in ((FAILED_RE, "fail"), (INVALID_USER_RE, "invalid"), (ACCEPTED_RE, "ok")):
            m = regex.search(line)
            if not m:
                continue
            ip, user = m.group("ip"), m.group("user")
            if reports[ip] is None:
                reports[ip] = IPReport(ip)
            r = reports[ip]
            if kind == "fail":
                r.failed += 1
                r.users_tried.add(user)
            elif kind == "invalid":
                r.users_tried.add(user)
            else:
                r.successful_logins.append(user)
            break
    return {ip: r for ip, r in reports.items() if r is not None}


def analyze(reports, threshold):
    suspicious = [r for r in reports.values() if r.failed >= threshold]
    return sorted(suspicious, key=lambda r: r.failed, reverse=True)


def print_report(reports, suspicious, threshold):
    total_fail = sum(r.failed for r in reports.values())
    print(f"\n=== log-sentinel report ===")
    print(f"Unique IPs seen:       {len(reports)}")
    print(f"Failed login attempts: {total_fail}")
    print(f"Flagged IPs (>= {threshold} fails): {len(suspicious)}\n")

    for r in suspicious:
        tag = "  [!!] POSSIBLE COMPROMISE" if r.compromised else ""
        print(f"{r.ip:<16} {r.failed:>4} fails  users: {', '.join(sorted(r.users_tried))}{tag}")
        if r.compromised:
            print(f"{'':<16} successful login as: {', '.join(r.successful_logins)}")

    users = Counter(u for r in reports.values() for u in r.users_tried)
    if users:
        print("\nMost targeted usernames:")
        for user, n in users.most_common(5):
            print(f"  {user:<12} {n}")

    if suspicious:
        print("\nSuggested block commands:")
        for r in suspicious:
            print(f"  sudo ufw deny from {r.ip}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Detect SSH brute-force attempts in auth logs.")
    p.add_argument("logfile")
    p.add_argument("-t", "--threshold", type=int, default=5, help="fails before flagging (default 5)")
    p.add_argument("--json", metavar="FILE", help="also write results to a JSON file")
    args = p.parse_args(argv)

    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as f:
            reports = parse_lines(f)
    except FileNotFoundError:
        print(f"error: file not found: {args.logfile}", file=sys.stderr)
        return 1
    except PermissionError:
        print("error: permission denied (try sudo for /var/log/auth.log)", file=sys.stderr)
        return 1

    suspicious = analyze(reports, args.threshold)
    print_report(reports, suspicious, args.threshold)

    if args.json:
        with open(args.json, "w") as f:
            json.dump([r.to_dict() for r in suspicious], f, indent=2)
        print(f"\nJSON report written to {args.json}")
    return 2 if suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
