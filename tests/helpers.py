from datetime import datetime, timedelta, timezone

IST = timezone(timedelta(hours=5, minutes=30))
BASE = datetime(2026, 11, 7, 10, 0, 0, tzinfo=IST)


def web_line(ip, request, status=200, ts=BASE, ua="Mozilla/5.0", size=512):
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{request}" {status} {size} "-" "{ua}"'


def syslog_line(msg, ts=BASE, proc="sshd", pid=1000):
    return f"{ts.strftime('%b %e %H:%M:%S')} web01 {proc}[{pid}]: {msg}"


def ct_record(name, ts=BASE, ip="203.0.113.9", identity=None, **extra):
    record = {
        "eventTime": ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": "iam.amazonaws.com",
        "eventName": name,
        "awsRegion": "ap-south-1",
        "sourceIPAddress": ip,
        "userIdentity": identity or {"type": "IAMUser", "userName": "alice",
                                     "arn": "arn:aws:iam::111122223333:user/alice"},
        "eventType": "AwsApiCall",
    }
    record.update(extra)
    return record
