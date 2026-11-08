# logsift incident report

Generated 2026-11-08 18:52:08 +0530 by logsift 0.1.0. All times are shown as UTC+0530.

## Inputs

| File | Type | Events parsed | Lines skipped |
|---|---|---|---|
| `samples/access.log` | web | 347 | 0 |
| `samples/auth.log` | auth | 41 | 1 |
| `samples/cloudtrail.json` | cloudtrail | 18 | 0 |

Time range covered: 2026-11-07 09:00:00 +0530 to 2026-11-07 12:59:17 +0530

## Summary

critical: 3 · high: 7 · medium: 5 · low: 1

**Attacks that appear to have succeeded:**

- `203.0.113.45`: SSH brute force (AUTH-001); Successful SSH login after repeated failures (AUTH-003); IAM change (CT-004); Logging or monitoring disabled (CT-003); Security group opened to the internet (CT-005)
- `198.51.100.200`: Root account used (CT-001); Console login without MFA (CT-002)

### Source IPs

| IP | Worst severity | Outcome | Logs involved | Accounts | First seen | Last seen |
|---|---|---|---|---|---|---|
| `203.0.113.45` | critical | succeeded | auth, cloudtrail, web | deploy, deploy-ci | 2026-11-07 09:40:00 +0530 | 2026-11-07 10:24:10 +0530 |
| `198.51.100.200` | high | succeeded | cloudtrail | root | 2026-11-07 09:50:00 +0530 | 2026-11-07 09:50:00 +0530 |
| `198.51.100.23` | high | no sign of success | auth | - | 2026-11-07 09:20:01 +0530 | 2026-11-07 09:22:56 +0530 |
| `192.0.2.77` | medium | no sign of success | web | - | 2026-11-07 11:05:00 +0530 | 2026-11-07 11:06:00 +0530 |

### Timelines for IPs seen in more than one log

**203.0.113.45** (auth, cloudtrail, web)

1. 2026-11-07 09:40:00 +0530 · WEB-006 Known scanner user agent · outcome: unknown
1. 2026-11-07 09:40:00 +0530 · WEB-007 Content discovery (directory brute force) · outcome: unknown
1. 2026-11-07 09:42:20 +0530 · WEB-005 Probe for sensitive files · outcome: failed
1. 2026-11-07 09:45:30 +0530 · WEB-001 SQL injection attempt · outcome: possible
1. 2026-11-07 10:02:00 +0530 · WEB-003 Path traversal / local file read attempt · outcome: failed
1. 2026-11-07 10:10:00 +0530 · AUTH-001 SSH brute force · outcome: succeeded
1. 2026-11-07 10:10:00 +0530 · AUTH-003 Successful SSH login after repeated failures · outcome: succeeded
1. 2026-11-07 10:20:00 +0530 · CT-007 Burst of access-denied API calls · outcome: unknown
1. 2026-11-07 10:23:00 +0530 · CT-004 IAM change · outcome: succeeded
1. 2026-11-07 10:23:40 +0530 · CT-003 Logging or monitoring disabled · outcome: succeeded
1. 2026-11-07 10:24:10 +0530 · CT-005 Security group opened to the internet · outcome: succeeded

## Findings

### 1. [CRITICAL] SQL injection attempt (WEB-001)

- **What:** 6 request(s) matched; response codes: 200, 500. 3 got a 2xx response, so check whether the payload was actually executed (response size, application logs).
- **When:** 2026-11-07 09:45:30 +0530 to 2026-11-07 09:46:00 +0530
- **From:** `203.0.113.45` (web log)
- **Outcome:** **possible** (got a 2xx response)
- **Events:** 6

```
203.0.113.45 - - [07/Nov/2026:09:45:30 +0530] "GET /products?id=12%20AND%201%3D1 HTTP/1.1" 200 4100 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
203.0.113.45 - - [07/Nov/2026:09:45:42 +0530] "GET /products?id=12%20AND%20SLEEP(5) HTTP/1.1" 200 4100 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
203.0.113.45 - - [07/Nov/2026:09:45:54 +0530] "GET /products?id=-1%20UNION%20ALL%20SELECT%20username,password,NULL%20FROM%20users--%20- HTTP/1.1" 200 4100 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
203.0.113.45 - - [07/Nov/2026:09:45:36 +0530] "GET /products?id=12%27%20OR%20%271%27%3D%271 HTTP/1.1" 500 210 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
203.0.113.45 - - [07/Nov/2026:09:46:00 +0530] "GET /products?id=12%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,version())) HTTP/1.1" 500 210 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
```

### 2. [CRITICAL] Successful SSH login after repeated failures (AUTH-003)

- **What:** 'deploy' logged in via password after 18 failed attempts from the same IP. Treat the account as compromised until proven otherwise.
- **When:** 2026-11-07 10:10:00 +0530 to 2026-11-07 10:11:35 +0530
- **From:** `203.0.113.45` (auth log)
- **Account:** `deploy`
- **Outcome:** **SUCCEEDED**
- **Events:** 19

```
Nov  7 10:11:20 web01 sshd[4036]: Failed password for deploy from 203.0.113.45 port 51389 ssh2
Nov  7 10:11:29 web01 sshd[4037]: Failed password for deploy from 203.0.113.45 port 34462 ssh2
Nov  7 10:11:32 web01 sshd[4038]: Failed password for deploy from 203.0.113.45 port 58084 ssh2
Nov  7 10:11:35 web01 sshd[4039]: Accepted password for deploy from 203.0.113.45 port 51544 ssh2
```

### 3. [CRITICAL] Logging or monitoring disabled (CT-003)

- **What:** StopLogging was called by 'deploy-ci'. Attackers do this to hide what they do next.
- **When:** 2026-11-07 10:23:40 +0530
- **From:** `203.0.113.45` (cloudtrail log)
- **Account:** `deploy-ci`
- **Outcome:** **SUCCEEDED**
- **Events:** 1

```
{"eventTime":"2026-11-07T04:53:40Z","eventSource":"cloudtrail.amazonaws.com","eventName":"StopLogging","sourceIPAddress":"203.0.113.45","principal":"deploy-ci"}
```

### 4. [HIGH] SSH password spraying (AUTH-002)

- **What:** 8 failed SSH logins for 8 different usernames within 10 minutes.
- **When:** 2026-11-07 09:20:01 +0530 to 2026-11-07 09:22:56 +0530
- **From:** `198.51.100.23` (auth log)
- **Outcome:** failed
- **Events:** 8

```
Nov  7 09:20:01 web01 sshd[4006]: Failed password for invalid user admin from 198.51.100.23 port 35857 ssh2
Nov  7 09:20:26 web01 sshd[4008]: Failed password for invalid user ubuntu from 198.51.100.23 port 30114 ssh2
Nov  7 09:20:51 web01 sshd[4010]: Failed password for invalid user test from 198.51.100.23 port 46039 ssh2
Nov  7 09:21:16 web01 sshd[4012]: Failed password for invalid user oracle from 198.51.100.23 port 37708 ssh2
Nov  7 09:22:56 web01 sshd[4020]: Failed password for invalid user support from 198.51.100.23 port 35884 ssh2
```

### 5. [HIGH] Root account used (CT-001)

- **What:** The root user called ConsoleLogin. Root should only be used for the few tasks that require it.
- **When:** 2026-11-07 09:50:00 +0530
- **From:** `198.51.100.200` (cloudtrail log)
- **Account:** `root`
- **Outcome:** **SUCCEEDED**
- **Events:** 1

```
{"eventTime":"2026-11-07T04:20:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","sourceIPAddress":"198.51.100.200","principal":"root"}
```

### 6. [HIGH] Console login without MFA (CT-002)

- **What:** 'root' signed in to the AWS console without MFA.
- **When:** 2026-11-07 09:50:00 +0530
- **From:** `198.51.100.200` (cloudtrail log)
- **Account:** `root`
- **Outcome:** **SUCCEEDED**
- **Events:** 1

```
{"eventTime":"2026-11-07T04:20:00Z","eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","sourceIPAddress":"198.51.100.200","principal":"root"}
```

### 7. [HIGH] Path traversal / local file read attempt (WEB-003)

- **What:** 1 request(s) matched; response codes: 400.
- **When:** 2026-11-07 10:02:00 +0530
- **From:** `203.0.113.45` (web log)
- **Outcome:** failed
- **Events:** 1

```
203.0.113.45 - - [07/Nov/2026:10:02:00 +0530] "GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 400 157 "-" "curl/8.5.0"
```

### 8. [HIGH] SSH brute force (AUTH-001)

- **What:** 18 failed SSH logins within 10 minutes, mostly for 'deploy'.
- **When:** 2026-11-07 10:10:00 +0530 to 2026-11-07 10:11:32 +0530
- **From:** `203.0.113.45` (auth log)
- **Account:** `deploy`
- **Outcome:** **SUCCEEDED**
- **Events:** 18

```
Nov  7 10:10:00 web01 sshd[4021]: Failed password for deploy from 203.0.113.45 port 56559 ssh2
Nov  7 10:10:06 web01 sshd[4022]: Failed password for deploy from 203.0.113.45 port 43118 ssh2
Nov  7 10:10:09 web01 sshd[4023]: Failed password for deploy from 203.0.113.45 port 32199 ssh2
Nov  7 10:10:13 web01 sshd[4024]: Failed password for deploy from 203.0.113.45 port 41749 ssh2
Nov  7 10:11:32 web01 sshd[4038]: Failed password for deploy from 203.0.113.45 port 58084 ssh2
```

### 9. [HIGH] IAM change (CT-004)

- **What:** 'deploy-ci' called CreateAccessKey on 'deploy-ci'.
- **When:** 2026-11-07 10:23:00 +0530
- **From:** `203.0.113.45` (cloudtrail log)
- **Account:** `deploy-ci`
- **Outcome:** **SUCCEEDED**
- **Events:** 1

```
{"eventTime":"2026-11-07T04:53:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateAccessKey","sourceIPAddress":"203.0.113.45","principal":"deploy-ci"}
```

### 10. [HIGH] Security group opened to the internet (CT-005)

- **What:** 'deploy-ci' allowed tcp/22 from 0.0.0.0/0, tcp/3306 from 0.0.0.0/0 on sg-0abc1234def567890.
- **When:** 2026-11-07 10:24:10 +0530
- **From:** `203.0.113.45` (cloudtrail log)
- **Account:** `deploy-ci`
- **Outcome:** **SUCCEEDED**
- **Events:** 1

```
{"eventTime":"2026-11-07T04:54:10Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"203.0.113.45","principal":"deploy-ci"}
```

### 11. [MEDIUM] Known scanner user agent (WEB-006)

- **What:** 80 request(s) sent by gobuster, sqlmap.
- **When:** 2026-11-07 09:40:00 +0530 to 2026-11-07 09:46:00 +0530
- **From:** `203.0.113.45` (web log)
- **Outcome:** unknown
- **Events:** 80

```
203.0.113.45 - - [07/Nov/2026:09:40:00 +0530] "GET /api80 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:40:02 +0530] "GET /config10 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:40:04 +0530] "GET /uploads5 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:40:06 +0530] "GET /server71 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:46:00 +0530] "GET /products?id=12%20AND%20EXTRACTVALUE(1,CONCAT(0x7e,version())) HTTP/1.1" 500 210 "-" "sqlmap/1.8.4#stable (https://sqlmap.org)"
```

### 12. [MEDIUM] Content discovery (directory brute force) (WEB-007)

- **What:** 72 requests returned 404 within 5 minutes.
- **When:** 2026-11-07 09:40:00 +0530 to 2026-11-07 09:42:24 +0530
- **From:** `203.0.113.45` (web log)
- **Outcome:** unknown
- **Events:** 72

```
203.0.113.45 - - [07/Nov/2026:09:40:00 +0530] "GET /api80 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:40:02 +0530] "GET /config10 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:40:04 +0530] "GET /uploads5 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:40:06 +0530] "GET /server71 HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:42:24 +0530] "GET /backup.zip HTTP/1.1" 404 153 "-" "gobuster/3.6"
```

### 13. [MEDIUM] Probe for sensitive files (WEB-005)

- **What:** 3 request(s) matched; response codes: 403, 404.
- **When:** 2026-11-07 09:42:20 +0530 to 2026-11-07 09:42:24 +0530
- **From:** `203.0.113.45` (web log)
- **Outcome:** failed
- **Events:** 3

```
203.0.113.45 - - [07/Nov/2026:09:42:20 +0530] "GET /.env HTTP/1.1" 403 162 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:42:22 +0530] "GET /.git/config HTTP/1.1" 404 153 "-" "gobuster/3.6"
203.0.113.45 - - [07/Nov/2026:09:42:24 +0530] "GET /backup.zip HTTP/1.1" 404 153 "-" "gobuster/3.6"
```

### 14. [MEDIUM] Burst of access-denied API calls (CT-007)

- **What:** 'deploy-ci' was denied 9 times across 9 API call(s). This pattern is typical of someone enumerating what stolen credentials can do.
- **When:** 2026-11-07 10:20:00 +0530 to 2026-11-07 10:22:45 +0530
- **From:** `203.0.113.45` (cloudtrail log)
- **Account:** `deploy-ci`
- **Outcome:** unknown
- **Events:** 9

```
{"eventTime":"2026-11-07T04:50:00Z","eventSource":"iam.amazonaws.com","eventName":"ListUsers","sourceIPAddress":"203.0.113.45","errorCode":"AccessDenied","principal":"deploy-ci"}
{"eventTime":"2026-11-07T04:50:15Z","eventSource":"iam.amazonaws.com","eventName":"ListRoles","sourceIPAddress":"203.0.113.45","errorCode":"AccessDenied","principal":"deploy-ci"}
{"eventTime":"2026-11-07T04:50:30Z","eventSource":"iam.amazonaws.com","eventName":"GetAccountAuthorizationDetails","sourceIPAddress":"203.0.113.45","errorCode":"AccessDenied","principal":"deploy-ci"}
{"eventTime":"2026-11-07T04:50:45Z","eventSource":"s3.amazonaws.com","eventName":"ListBuckets","sourceIPAddress":"203.0.113.45","errorCode":"AccessDenied","principal":"deploy-ci"}
{"eventTime":"2026-11-07T04:52:45Z","eventSource":"iam.amazonaws.com","eventName":"ListPolicies","sourceIPAddress":"203.0.113.45","errorCode":"AccessDenied","principal":"deploy-ci"}
```

### 15. [MEDIUM] Cross-site scripting attempt (WEB-002)

- **What:** 3 request(s) matched; response codes: 403.
- **When:** 2026-11-07 11:05:00 +0530 to 2026-11-07 11:06:00 +0530
- **From:** `192.0.2.77` (web log)
- **Outcome:** failed
- **Events:** 3

```
192.0.2.77 - - [07/Nov/2026:11:05:00 +0530] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 403 162 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
192.0.2.77 - - [07/Nov/2026:11:05:30 +0530] "GET /search?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E HTTP/1.1" 403 162 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
192.0.2.77 - - [07/Nov/2026:11:06:00 +0530] "GET /search?q=javascript:alert(1) HTTP/1.1" 403 162 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
```

### 16. [LOW] Failed sudo authentication (AUTH-005)

- **What:** 'deploy' failed sudo authentication 1 time(s).
- **When:** 2026-11-07 10:13:35 +0530
- **From:** local (auth log)
- **Account:** `deploy`
- **Outcome:** unknown
- **Events:** 1

```
Nov  7 10:13:35 web01 sudo[4040]:   deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
```

