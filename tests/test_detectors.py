import unittest
from datetime import timedelta

from logsift.detectors import Config, auth as auth_rules, cloudtrail as ct_rules, web as web_rules
from logsift.parsers import auth, cloudtrail, web
from tests.helpers import BASE, IST, ct_record, syslog_line, web_line

CONFIG = Config()


def auth_events(lines):
    return [auth.parse_line(line, 2026, IST) for line in lines]


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


class AuthDetectorTest(unittest.TestCase):
    def failures(self, n, ip="203.0.113.1", user="deploy", start=BASE, step=5):
        return [syslog_line(f"Failed password for {user} from {ip} port 1 ssh2", start + timedelta(seconds=i * step))
                for i in range(n)]

    def test_brute_force_without_success(self):
        findings = auth_rules.detect(auth_events(self.failures(12)), CONFIG)
        self.assertEqual(rule_ids(findings), ["AUTH-001"])
        self.assertEqual(findings[0].outcome, "failed")
        self.assertEqual(findings[0].user, "deploy")

    def test_below_threshold_is_quiet(self):
        self.assertEqual(auth_rules.detect(auth_events(self.failures(9)), CONFIG), [])

    def test_failures_spread_out_are_not_brute_force(self):
        # 12 failures, one every 2 minutes: never 10 inside a 10-minute window
        self.assertEqual(auth_rules.detect(auth_events(self.failures(12, step=120)), CONFIG), [])

    def test_success_after_failures_is_critical(self):
        lines = self.failures(12) + [syslog_line("Accepted password for deploy from 203.0.113.1 port 2 ssh2",
                                                 BASE + timedelta(minutes=2))]
        findings = auth_rules.detect(auth_events(lines), CONFIG)
        self.assertEqual(rule_ids(findings), ["AUTH-001", "AUTH-003"])
        self.assertTrue(all(f.outcome == "succeeded" for f in findings))
        critical = [f for f in findings if f.rule_id == "AUTH-003"][0]
        self.assertEqual(critical.severity, "critical")
        self.assertIn("Accepted password", critical.evidence[-1])

    def test_success_from_other_ip_is_not_linked(self):
        lines = self.failures(12) + [syslog_line("Accepted publickey for deploy from 198.51.100.9 port 2 ssh2",
                                                 BASE + timedelta(minutes=2))]
        findings = auth_rules.detect(auth_events(lines), CONFIG)
        self.assertEqual(rule_ids(findings), ["AUTH-001"])
        self.assertEqual(findings[0].outcome, "failed")

    def test_password_spraying(self):
        lines = [syslog_line(f"Failed password for invalid user {u} from 198.51.100.3 port 1 ssh2",
                             BASE + timedelta(seconds=i * 10))
                 for i, u in enumerate(["admin", "test", "oracle", "git", "ubuntu", "pi"])]
        findings = auth_rules.detect(auth_events(lines), CONFIG)
        self.assertEqual(rule_ids(findings), ["AUTH-002"])
        self.assertEqual(len(findings[0].details["usernames"]), 6)

    def test_root_login(self):
        findings = auth_rules.detect(auth_events([syslog_line("Accepted password for root from 192.0.2.5 port 1 ssh2")]),
                                     CONFIG)
        self.assertEqual(rule_ids(findings), ["AUTH-004"])

    def test_sudo_failures(self):
        line = "  bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh"
        findings = auth_rules.detect(auth_events([syslog_line(line, proc="sudo")]), CONFIG)
        self.assertEqual(rule_ids(findings), ["AUTH-005"])


class WebDetectorTest(unittest.TestCase):
    def detect(self, rows):
        events = [web.parse_line(web_line(*row)) for row in rows]
        return web_rules.detect(events, CONFIG)

    def test_sqli_blocked(self):
        findings = self.detect([("203.0.113.2", "GET /p?id=1%20UNION%20SELECT%20NULL--%20- HTTP/1.1", 403)])
        self.assertEqual(rule_ids(findings), ["WEB-001"])
        self.assertEqual((findings[0].outcome, findings[0].severity), ("failed", "high"))

    def test_sqli_with_2xx_is_escalated(self):
        findings = self.detect([
            ("203.0.113.2", "GET /p?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1", 500),
            ("203.0.113.2", "GET /p?id=-1%20union%20select%20user,pass%20from%20users HTTP/1.1", 200),
        ])
        self.assertEqual(findings[0].outcome, "possible")
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].details["successful_requests"], 1)
        self.assertIn(" 200 ", findings[0].evidence[0])

    def test_each_signature(self):
        cases = {
            "WEB-002": "GET /s?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1",
            "WEB-003": "GET /dl?f=..%2F..%2Fetc%2Fpasswd HTTP/1.1",
            "WEB-004": "GET /ping?host=1.1.1.1;cat%20/etc/hosts HTTP/1.1",
            "WEB-005": "GET /.env HTTP/1.1",
        }
        for rule, request in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, rule_ids(self.detect([("192.0.2.9", request, 404)])))

    def test_normal_traffic_is_quiet(self):
        rows = [("192.0.2.10", f"GET {path} HTTP/1.1", 200) for path in
                ["/", "/products?id=12", "/search?q=select+a+blue+shirt", "/blog/union-of-two-sets", "/static/app.js"]]
        self.assertEqual(self.detect(rows), [])

    def test_scanner_user_agent(self):
        findings = self.detect([("192.0.2.9", "GET / HTTP/1.1", 200, BASE, "Mozilla/5.00 (Nikto/2.5.0)")])
        self.assertEqual(rule_ids(findings), ["WEB-006"])
        self.assertEqual(findings[0].details["tools"], ["nikto"])

    def test_directory_brute_force(self):
        rows = [("192.0.2.9", f"GET /x{i} HTTP/1.1", 404, BASE + timedelta(seconds=i)) for i in range(60)]
        self.assertEqual(rule_ids(self.detect(rows)), ["WEB-007"])


class CloudTrailDetectorTest(unittest.TestCase):
    def detect(self, records):
        return ct_rules.detect([cloudtrail.record_to_event(r) for r in records], CONFIG)

    def test_console_login_without_mfa(self):
        findings = self.detect([ct_record("ConsoleLogin", responseElements={"ConsoleLogin": "Success"},
                                          additionalEventData={"MFAUsed": "No"})])
        self.assertEqual(rule_ids(findings), ["CT-002"])

    def test_root_usage(self):
        findings = self.detect([ct_record("DescribeInstances", identity={"type": "Root", "arn": "arn:aws:iam::1:root"})])
        self.assertEqual(rule_ids(findings), ["CT-001"])

    def test_aws_service_events_by_root_are_ignored(self):
        findings = self.detect([ct_record("SomeServiceEvent", identity={"type": "Root"}, eventType="AwsServiceEvent")])
        self.assertEqual(findings, [])

    def test_stop_logging(self):
        findings = self.detect([ct_record("StopLogging")])
        self.assertEqual((findings[0].rule_id, findings[0].severity), ("CT-003", "critical"))

    def test_iam_change_failed(self):
        findings = self.detect([ct_record("CreateAccessKey", errorCode="AccessDenied",
                                          requestParameters={"userName": "bob"})])
        self.assertEqual(rule_ids(findings), ["CT-004"])
        self.assertEqual(findings[0].outcome, "failed")
        self.assertIn("'bob'", findings[0].description)

    def test_security_group_open_to_world(self):
        perms = {"items": [
            {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}},
            {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}},
        ]}
        findings = self.detect([ct_record("AuthorizeSecurityGroupIngress",
                                          requestParameters={"groupId": "sg-1", "ipPermissions": perms})])
        self.assertEqual(rule_ids(findings), ["CT-005"])
        self.assertEqual(findings[0].details["rules"], ["tcp/22 from 0.0.0.0/0"])

    def test_private_ingress_is_quiet(self):
        perms = {"items": [{"ipProtocol": "-1", "ipRanges": {"items": [{"cidrIp": "10.0.0.0/8"}]}}]}
        self.assertEqual(self.detect([ct_record("AuthorizeSecurityGroupIngress",
                                                requestParameters={"ipPermissions": perms})]), [])

    def test_failed_console_logins_then_success(self):
        records = [ct_record("ConsoleLogin", BASE + timedelta(seconds=i), responseElements={"ConsoleLogin": "Failure"})
                   for i in range(4)]
        records.append(ct_record("ConsoleLogin", BASE + timedelta(minutes=1), responseElements={"ConsoleLogin": "Success"},
                                 additionalEventData={"MFAUsed": "Yes"}))
        findings = [f for f in self.detect(records) if f.rule_id == "CT-006"]
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].outcome, findings[0].severity), ("succeeded", "critical"))

    def test_access_denied_burst(self):
        records = [ct_record(f"List{i}", BASE + timedelta(seconds=i * 10), errorCode="AccessDenied") for i in range(9)]
        findings = self.detect(records)
        self.assertEqual(rule_ids(findings), ["CT-007"])
        self.assertEqual(findings[0].count, 9)


if __name__ == "__main__":
    unittest.main()
