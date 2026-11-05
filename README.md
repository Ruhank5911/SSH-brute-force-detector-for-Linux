# log-sentinel 🛡️

![tests](https://github.com/Ruhank5911/log-sentinel/actions/workflows/tests.yml/badge.svg)

A lightweight Python tool that scans Linux SSH auth logs and flags **brute-force attacks** — including the dangerous case where an attacker fails many times and then **gets in**.

Built as a blue-team (defensive) companion to my [password strength checker](https://github.com/Ruhank5911).

## What it detects
- IPs with repeated failed SSH logins (configurable threshold)
- Username enumeration (`invalid user admin`, `oracle`, `test`…)
- **Possible compromise**: failures followed by a successful login from the same IP
- Most targeted usernames
- Prints ready-to-use `ufw` block commands

## Usage
```bash
python log_sentinel.py sample_logs/auth.log
python log_sentinel.py /var/log/auth.log --threshold 3 --json report.json
```

Exit codes: `0` clean · `1` error · `2` suspicious activity found (handy for scripts/cron).

## Example output
```
203.0.113.45        6 fails  users: admin, oracle, root, test
198.51.100.7        5 fails  users: ubuntu  [!!] POSSIBLE COMPROMISE
                 successful login as: ubuntu
```

## Run tests
```bash
pip install pytest
pytest -v
```

## What I learned
- How SSH authentication events appear in `/var/log/auth.log`
- Parsing logs with regular expressions
- Brute-force vs credential-stuffing patterns, and why a success after failures matters
- Writing tests and CI with GitHub Actions

## Ideas for next version
- Time-window detection (e.g. 5 fails in 60 seconds)
- GeoIP lookup for flagged IPs
- Support for `journalctl` and Windows Event Logs
- Map findings to MITRE ATT&CK (T1110 – Brute Force)

> Sample log uses reserved documentation IPs (RFC 5737). Only analyse logs from systems you own or are authorised to monitor.
