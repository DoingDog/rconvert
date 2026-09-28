import unittest
from pathlib import Path


class WorkflowScheduleTests(unittest.TestCase):
    def test_daily_midnight_uses_beijing_timezone(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("    - cron: '0 0 * * *'\n      timezone: \"Asia/Shanghai\"\n", workflow)

    def test_static_whitelist_entries_include_requested_domains(self):
        root = Path(__file__).resolve().parents[1]
        direct = (root / "static/main/Direct.list").read_text(encoding="utf-8")
        no_reject = (root / "static/main/NoReject.list").read_text(encoding="utf-8")
        self.assertIn("DOMAIN-SUFFIX,galileotelemetry.tencent.com\n", direct)
        self.assertIn("DOMAIN-SUFFIX,featureassets.org\n", no_reject)
