# logsift

logsift reads web server, Linux authentication and AWS CloudTrail logs, finds signs of attack, and writes an incident report that answers four questions for each attacker: **what happened, when, from where, and did it work?**

It links activity across logs by source IP. A scanner that hits the website, brute-forces SSH and then uses stolen AWS keys from the same address shows up as one timeline instead of three unrelated alerts.

Python 3.10+, standard library only.

## Example

The `samples/` folder holds a small synthetic incident (all IPs come from the RFC 5737 documentation ranges):

1. `203.0.113.45` runs gobuster and sqlmap against the site, and one `UNION SELECT` gets a 200 response.
2. The same IP brute-forces SSH for the `deploy` user and gets in.
3. It reads `~/.aws/credentials` with sudo, then uses the `deploy-ci` keys: a burst of `AccessDenied` calls while it maps permissions, then `CreateAccessKey`, `StopLogging`, and opens ports 22 and 3306 to `0.0.0.0/0`.
4. Separately, `198.51.100.23` sprays SSH passwords and fails, `192.0.2.77` tries XSS and is blocked, and the root user signs in to the console without MFA.

```console
$ python -m logsift --web samples/access.log --auth samples/auth.log \
    --cloudtrail samples/cloudtrail.json --year 2026 --tz +05:30 \
    -o examples/report.md --json examples/report.json
logsift: 16 finding(s), report written to examples/report.md
```

The full output is in [`examples/report.md`](examples/report.md). An excerpt:

```text
**203.0.113.45** (auth, cloudtrail, web)

1. 2026-11-07 09:40:00 +0530 · WEB-006 Known scanner user agent · outcome: unknown
1. 2026-11-07 09:40:00 +0530 · WEB-007 Content discovery (directory brute force) · outcome: unknown
1. 2026-11-07 09:45:30 +0530 · WEB-001 SQL injection attempt · outcome: possible
1. 2026-11-07 10:10:00 +0530 · AUTH-003 Successful SSH login after repeated failures · outcome: succeeded
1. 2026-11-07 10:20:00 +0530 · CT-007 Burst of access-denied API calls · outcome: unknown
1. 2026-11-07 10:23:40 +0530 · CT-003 Logging or monitoring disabled · outcome: succeeded
1. 2026-11-07 10:24:10 +0530 · CT-005 Security group opened to the internet · outcome: succeeded
```

## Install

```console
git clone https://github.com/Naved124/logsift && cd logsift
python -m logsift --help        # run in place, or:
pip install .                   # adds a `logsift` command
```

## Usage

```text
logsift [--web FILE]... [--auth FILE]... [--cloudtrail FILE]...
        [-o report.md] [--json findings.json]
        [--year YEAR] [--tz +05:30] [--min-severity LEVEL] [--fail-on LEVEL]
        [--bruteforce-threshold N]
```

| Option | Meaning |
|---|---|
| `--web` | nginx/Apache access log, common or combined format |
| `--auth` | `/var/log/auth.log`, `/var/log/secure`, or `journalctl` output |
| `--cloudtrail` | CloudTrail log file (`{"Records": [...]}`), a JSON array, JSON Lines, or `aws cloudtrail lookup-events` output |
| `--year`, `--tz` | Classic syslog lines carry no year or timezone. `--tz` is also the timezone every time in the report is shown in |
| `--min-severity` | Leave out findings below `info`/`low`/`medium`/`high`/`critical` |
| `--fail-on` | Exit with status 2 if any finding reaches this severity, for cron jobs or CI |

Every input flag can be repeated, and `.gz` files (rotated logs, CloudTrail S3 objects) are read directly.

### Getting logs from a server

```console
# SSH and sudo events from the systemd journal, with full timestamps
journalctl -t sshd -t sudo -o short-iso --since "2 days ago" > auth.log

# CloudTrail management events from the last 90 days (no trail needed)
aws cloudtrail lookup-events --max-results 1000 > cloudtrail.json

# Delivered trail files from S3
aws s3 cp --recursive s3://my-trail-bucket/AWSLogs/111122223333/CloudTrail/ap-south-1/2026/11/07/ trail/
```

## Detections

| ID | Log | Detects | Default severity |
|---|---|---|---|
| AUTH-001 | auth | SSH brute force: 10+ failures from one IP in 10 minutes | high |
| AUTH-002 | auth | SSH password spraying: 5+ usernames from one IP in 10 minutes | high |
| AUTH-003 | auth | Successful SSH login from an IP with 3+ earlier failures | critical |
| AUTH-004 | auth | Direct root login over SSH | medium |
| AUTH-005 | auth | Failed sudo authentication | low / medium |
| WEB-001 | web | SQL injection (UNION/SELECT, boolean and time-based, error-based) | high |
| WEB-002 | web | Cross-site scripting | medium |
| WEB-003 | web | Path traversal and local file read | high |
| WEB-004 | web | OS command injection | high |
| WEB-005 | web | Probes for `.env`, `.git/`, backups and other sensitive files | medium |
| WEB-006 | web | Known scanner user agents (sqlmap, nikto, gobuster, nuclei, ...) | medium |
| WEB-007 | web | Content discovery: 50+ 404s from one IP in 5 minutes | medium |
| CT-001 | cloudtrail | Root account used | high |
| CT-002 | cloudtrail | Console login without MFA | high |
| CT-003 | cloudtrail | CloudTrail, GuardDuty, Security Hub or flow logs disabled | critical |
| CT-004 | cloudtrail | IAM changes: new users, access keys, policies, MFA removal | medium / high |
| CT-005 | cloudtrail | Security group ingress opened to `0.0.0.0/0` or `::/0` | high |
| CT-006 | cloudtrail | 3+ failed console logins from one IP (critical if one then succeeds) | medium / critical |
| CT-007 | cloudtrail | 8+ access-denied calls by one principal in 10 minutes | medium |

### How "did it work?" is decided

- **SSH:** a failure burst is marked `succeeded` if the same IP later logs in.
- **Web:** an attack payload that got a 2xx response is marked `possible` and its severity goes up one level. A 200 does not prove the injection ran (many apps return 200 with an error page), so the report puts those requests first for a person to check against response sizes and application logs.
- **CloudTrail:** the API call's own error code says whether it was allowed.

## Limitations

- Signatures are regular expressions, so they miss heavily obfuscated payloads and can flag harmless requests. They point a person at the right lines rather than give a verdict.
- Only what the logs record can be seen: POST bodies, encrypted traffic and anything behind a CDN or load balancer that hides the client IP are out of view unless the real IP is logged.
- Syslog lines without a year are all given `--year`, so a log that spans New Year needs to be split.
- Correlation is by IP address. Attackers who change IP between stages appear as separate actors.

## Tests

```console
python -m unittest discover -s tests -t .
```

## License

MIT
