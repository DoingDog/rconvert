import unittest
from pathlib import Path


class WorkflowScheduleTests(unittest.TestCase):
    def test_daily_midnight_uses_beijing_timezone(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("    - cron: '0 0 * * *'\n      timezone: \"Asia/Shanghai\"\n", workflow)
