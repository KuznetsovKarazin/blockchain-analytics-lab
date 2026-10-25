"""Focused SQL contracts; real subprocess termination is exercised by the pilot."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / "durable_replay.py"
SPEC = importlib.util.spec_from_file_location("monitoring_durable_replay", PATH)
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class DurableReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        path = Path(self.tmp.name)
        self.local, self.sink = module.connect(path / "local.sqlite"), module.connect(path / "sink.sqlite")
        self.config = json.loads((PATH.parent / "durable_replay_config.json").read_text())
        module.initialize(self.local, self.sink, {"input": "fixture"}, self.config)

    def tearDown(self):
        self.local.close(); self.sink.close(); self.tmp.cleanup()

    def test_sink_repeated_attempt_is_recorded_without_second_effect(self):
        self.assertTrue(module.deliver(self.sink, "alert:1", '{"value":1}'))
        self.assertFalse(module.deliver(self.sink, "alert:1", '{"value":1}'))
        self.assertEqual(self.sink.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 1)
        self.assertEqual(self.sink.execute("SELECT inserted FROM attempts ORDER BY attempt").fetchall(), [(1,), (0,)])

    def test_conflicting_payload_does_not_overwrite_or_acknowledge(self):
        module.deliver(self.sink, "alert:1", '{"value":1}')
        with self.assertRaisesRegex(ValueError, "conflicting"):
            module.deliver(self.sink, "alert:1", '{"value":2}')
        self.assertEqual(self.sink.execute("SELECT payload FROM effects").fetchone()[0], '{"value":1}')
        self.assertEqual(self.sink.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 1)

    def test_changed_resume_identity_is_rejected_before_checkpoint_mutation(self):
        before = self.local.execute("SELECT * FROM checkpoint").fetchall()
        with self.assertRaisesRegex(ValueError, "changed"):
            module.initialize(self.local, self.sink, {"input": "different"}, self.config)
        self.assertEqual(self.local.execute("SELECT * FROM checkpoint").fetchall(), before)

    def test_sql_transaction_rollback_preserves_cursor_decision_and_outbox_together(self):
        before = self.local.execute("SELECT * FROM checkpoint").fetchall()
        self.local.execute("BEGIN IMMEDIATE")
        self.local.execute("UPDATE checkpoint SET cursor=0 WHERE id=1")
        self.local.execute("INSERT INTO decisions VALUES (0,'event:1','{}')")
        self.local.execute("INSERT INTO outbox VALUES ('alert:1',0,'{}',0)")
        self.local.execute("ROLLBACK")
        self.assertEqual(self.local.execute("SELECT * FROM checkpoint").fetchall(), before)
        self.assertEqual(self.local.execute("SELECT COUNT(*) FROM decisions").fetchone()[0], 0)
        self.assertEqual(self.local.execute("SELECT COUNT(*) FROM outbox").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
