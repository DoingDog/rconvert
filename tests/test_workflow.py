import unittest
from pathlib import Path


class WorkflowScheduleTests(unittest.TestCase):
    def test_daily_midnight_uses_beijing_timezone(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("    - cron: '0 0 * * *'\n      timezone: \"Asia/Shanghai\"\n", workflow)

    def test_push_main_builds_the_same_commit_it_tests(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("  push:\n    branches: [main]\n", workflow)
        self.assertEqual(workflow.count("      - uses: actions/checkout@v5\n        with:\n          ref: ${{ github.sha }}"), 2)
        self.assertNotIn("          ref: main", workflow)

    def test_update_calls_the_behavior_tested_publication_entry_point(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("          .venv/bin/python update.py\n", workflow)
        self.assertNotIn(".venv/bin/python generate.py", workflow)
        self.assertNotIn("git add", workflow)
        self.assertNotIn("--force", workflow)
        self.assertNotIn("rebase", workflow)

    def test_full_suite_runs_only_for_push_and_pull_request(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("  test:\n    if: github.event_name == 'push' || github.event_name == 'pull_request'\n", workflow)

    def test_update_accepts_skipped_tests_only_for_scheduled_and_manual_events(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        update = workflow.split("  update:\n", 1)[1]
        self.assertIn("      (needs.test.result == 'success' || (needs.test.result == 'skipped' &&\n"
                      "      (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'))) }}\n", update)

    def test_update_retains_needs_main_and_readonly_pr_boundaries(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        readonly, update = workflow.split("  update:\n", 1)
        self.assertIn("  pull_request:\n", readonly)
        self.assertIn("permissions:\n  contents: read\n", readonly)
        self.assertNotIn("contents: write", readonly)
        self.assertIn("    if: >-\n"
                      "      ${{ !cancelled() && github.event_name != 'pull_request' && github.ref == 'refs/heads/main' &&\n", update)
        self.assertIn("    needs: test\n", update)
        self.assertIn("    permissions:\n      contents: write\n", update)
        self.assertIn("  group: rules-${{ github.ref }}\n  cancel-in-progress: false\n", readonly)

    def test_workflow_allows_edited_and_untracked_static_inputs(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertNotIn('git ls-tree -r --name-only HEAD static | wc -l', workflow)
        self.assertNotIn('git rev-parse HEAD:static', workflow)
        self.assertNotIn('git diff HEAD --exit-code -- static', workflow)
        self.assertNotIn('git ls-files --others -- static', workflow)
