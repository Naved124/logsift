import contextlib
import io
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from logsift.cli import main, parse_tz
from logsift.correlate import build_actors
from tests.helpers import BASE, syslog_line, web_line

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def run(argv):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(argv)
    return code, stdout.getvalue(), stderr.getvalue()


class CliTest(unittest.TestCase):
    def test_sample_scenario_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, data = Path(tmp) / "r.md", Path(tmp) / "r.json"
            code, _, _ = run(["--web", str(SAMPLES / "access.log"), "--auth", str(SAMPLES / "auth.log"),
                              "--cloudtrail", str(SAMPLES / "cloudtrail.json"), "--year", "2026", "--tz", "+05:30",
                              "-o", str(report), "--json", str(data), "--fail-on", "critical"])
            self.assertEqual(code, 2)
            text = report.read_text()
            result = json.loads(data.read_text())

        self.assertIn("Attacks that appear to have succeeded", text)
        top = result["actors"][0]
        self.assertEqual(top["ip"], "203.0.113.45")
        self.assertEqual(top["outcome"], "succeeded")
        self.assertEqual(top["sources"], ["auth", "cloudtrail", "web"])
        for rule in ("WEB-001", "WEB-007", "AUTH-003", "CT-003", "CT-005", "CT-007"):
            self.assertIn(rule, top["rule_ids"])
        sprayer = next(a for a in result["actors"] if a["ip"] == "198.51.100.23")
        self.assertEqual(sprayer["outcome"], "no sign of success")
        # every time in the report is shown in the requested timezone
        self.assertNotIn("+0000", text)

    def test_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "access.log"
            log.write_text(web_line("192.0.2.1", "GET / HTTP/1.1") + "\n")
            code, out, _ = run(["--web", str(log), "--fail-on", "low"])
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_min_severity_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "auth.log"
            log.write_text(syslog_line("  bob : 1 incorrect password attempt ; TTY=pts/1 ; PWD=/ ; USER=root ; "
                                       "COMMAND=/bin/sh", proc="sudo") + "\n")
            _, low, _ = run(["--auth", str(log), "--year", "2026"])
            _, medium, _ = run(["--auth", str(log), "--year", "2026", "--min-severity", "medium"])
        self.assertIn("AUTH-005", low)
        self.assertNotIn("AUTH-005", medium)

    def test_bruteforce_threshold_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "auth.log"
            log.write_text("\n".join(syslog_line(f"Failed password for x from 192.0.2.2 port 1 ssh2",
                                                 BASE + timedelta(seconds=i)) for i in range(5)) + "\n")
            _, default, _ = run(["--auth", str(log), "--year", "2026"])
            _, strict, _ = run(["--auth", str(log), "--year", "2026", "--bruteforce-threshold", "5"])
        self.assertNotIn("AUTH-001", default)
        self.assertIn("AUTH-001", strict)

    def test_errors(self):
        self.assertEqual(run([])[0], 1)
        code, _, err = run(["--web", "/nonexistent/access.log"])
        self.assertEqual(code, 1)
        self.assertIn("no such file", err)

    def test_parse_tz(self):
        self.assertEqual(parse_tz("+0530").utcoffset(None), timedelta(hours=5, minutes=30))
        self.assertEqual(parse_tz("-04:00").utcoffset(None), timedelta(hours=-4))
        self.assertEqual(parse_tz("UTC").utcoffset(None), timedelta(0))

    def test_actors_without_ip_are_ignored(self):
        self.assertEqual(build_actors([]), [])


if __name__ == "__main__":
    unittest.main()
