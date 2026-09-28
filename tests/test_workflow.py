import unittest
from pathlib import Path


class WorkflowScheduleTests(unittest.TestCase):
    def test_daily_midnight_uses_beijing_timezone(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("    - cron: '0 0 * * *'\n      timezone: \"Asia/Shanghai\"\n", workflow)

    def test_update_stages_only_configured_generated_files(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("from sources import load_config", workflow)
        self.assertIn("for group in load_config(Path('.')) for name in FILES", workflow)
        self.assertNotIn("for group in a1 a2 a3 cdn big-data dirt", workflow)

    def test_static_baseline_includes_new_whitelist_without_disabling_checks(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count('test "$(git ls-tree -r --name-only HEAD static | wc -l)" -eq 19'), 2)
        self.assertEqual(workflow.count('git diff HEAD --exit-code -- static'), 2)

    def test_static_whitelist_entries_include_requested_domains(self):
        root = Path(__file__).resolve().parents[1]
        direct = (root / "static/main/Direct.list").read_text(encoding="utf-8")
        no_reject = (root / "static/main/NoReject.list").read_text(encoding="utf-8")
        self.assertIn("DOMAIN-SUFFIX,galileotelemetry.tencent.com\n", direct)
        self.assertIn("DOMAIN-SUFFIX,featureassets.org\n", no_reject)
