import gzip
import json
import tempfile
import unittest
from datetime import timedelta, timezone
from pathlib import Path

from logsift.parsers import auth, cloudtrail, web
from tests.helpers import BASE, IST, ct_record, syslog_line, web_line


class WebParserTest(unittest.TestCase):
    def test_combined_format(self):
        line = web_line("203.0.113.5", "GET /a?q=%253Cscript%253E HTTP/1.1", 404, ua="sqlmap/1.8")
        event = web.parse_line(line)
        self.assertEqual(event.ip, "203.0.113.5")
        self.assertEqual(event.status, "404")
        self.assertEqual(event.details["method"], "GET")
        self.assertEqual(event.details["user_agent"], "sqlmap/1.8")
        self.assertEqual(event.ts, BASE)
        # double-encoded payloads are decoded twice
        self.assertEqual(event.details["decoded_target"], "/a?q=<script>")

    def test_common_format_without_agent(self):
        event = web.parse_line('192.0.2.1 - bob [07/Nov/2026:10:00:00 +0000] "GET / HTTP/1.0" 200 10')
        self.assertEqual(event.user, "bob")
        self.assertEqual(event.details["user_agent"], "")

    def test_malformed_request_kept(self):
        event = web.parse_line('192.0.2.1 - - [07/Nov/2026:10:00:00 +0000] "\\x16\\x03\\x01" 400 0 "-" "-"')
        self.assertEqual(event.details["method"], "")

    def test_garbage_is_skipped(self):
        self.assertIsNone(web.parse_line("not a log line"))

    def test_gzip_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "access.log.gz"
            with gzip.open(path, "wt") as handle:
                handle.write(web_line("192.0.2.1", "GET / HTTP/1.1") + "\nbroken\n")
            events, skipped = web.parse_file(path)
        self.assertEqual((len(events), skipped), (1, 1))


class AuthParserTest(unittest.TestCase):
    def test_failed_invalid_user(self):
        event = auth.parse_line(
            syslog_line("Failed password for invalid user admin from 198.51.100.7 port 4022 ssh2"), 2026, IST)
        self.assertEqual(event.action, "ssh_failed")
        self.assertEqual((event.user, event.ip), ("admin", "198.51.100.7"))
        self.assertTrue(event.details["invalid_user"])
        self.assertEqual(event.ts, BASE)

    def test_accepted_publickey(self):
        event = auth.parse_line(syslog_line("Accepted publickey for naved from 198.51.100.8 port 1 ssh2: ED25519 x"), 2026)
        self.assertEqual(event.action, "ssh_accepted")
        self.assertEqual(event.details["method"], "publickey")
        self.assertEqual(event.ts.tzinfo, timezone.utc)

    def test_iso_timestamp(self):
        line = "2026-11-07T10:00:00+05:30 web01 sshd[9]: Failed password for root from 192.0.2.4 port 2 ssh2"
        event = auth.parse_line(line, 1999)
        self.assertEqual(event.ts, BASE)

    def test_sudo_command_and_failure(self):
        ok = auth.parse_line(syslog_line(
            "  deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id", proc="sudo"), 2026)
        self.assertEqual(ok.action, "sudo_command")
        self.assertEqual(ok.details["command"], "/usr/bin/id")
        bad = auth.parse_line(syslog_line(
            "  deploy : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
            proc="sudo"), 2026)
        self.assertEqual(bad.action, "sudo_failed")

    def test_unrelated_lines_skipped(self):
        self.assertIsNone(auth.parse_line(syslog_line("pam_unix(cron:session): session opened", proc="CRON"), 2026))
        self.assertIsNone(auth.parse_line(syslog_line("Connection closed by 192.0.2.1 port 5 [preauth]"), 2026))


class CloudTrailParserTest(unittest.TestCase):
    def test_records_array_and_jsonl(self):
        records = [ct_record("CreateUser"), ct_record("ListUsers", errorCode="AccessDenied")]
        self.assertEqual(len(cloudtrail.load_records(json.dumps({"Records": records}))), 2)
        self.assertEqual(len(cloudtrail.load_records(json.dumps(records))), 2)
        jsonl = "\n".join(json.dumps(r) for r in records)
        self.assertEqual(len(cloudtrail.load_records(jsonl)), 2)
        lookup = {"Events": [{"EventName": r["eventName"], "CloudTrailEvent": json.dumps(r)} for r in records]}
        loaded = cloudtrail.load_records(json.dumps(lookup))
        self.assertEqual([r["eventName"] for r in loaded], ["CreateUser", "ListUsers"])

    def test_event_fields(self):
        event = cloudtrail.record_to_event(ct_record("ListUsers", errorCode="AccessDenied"))
        self.assertEqual(event.status, "AccessDenied")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.ts, BASE)

    def test_console_login_status_and_root(self):
        event = cloudtrail.record_to_event(ct_record(
            "ConsoleLogin", identity={"type": "Root", "arn": "arn:aws:iam::1:root"},
            responseElements={"ConsoleLogin": "Failure"}))
        self.assertEqual((event.user, event.status), ("root", "failure"))

    def test_assumed_role_principal(self):
        event = cloudtrail.record_to_event(ct_record("GetObject", identity={
            "type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/ci-role/run-42"}))
        self.assertEqual(event.user, "ci-role/run-42")

    def test_bad_record_skipped(self):
        self.assertIsNone(cloudtrail.record_to_event({"eventName": "X"}))


if __name__ == "__main__":
    unittest.main()
