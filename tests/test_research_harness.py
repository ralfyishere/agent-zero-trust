"""Evaluator bookkeeping failure tests; these do NOT count as Docker trials."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import subprocess
import json
from unittest.mock import Mock, patch

spec=importlib.util.spec_from_file_location('research_evaluator',Path(__file__).resolve().parents[1]/'scripts/test_research_integration.py')
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvaluatorTests(unittest.TestCase):
    def harness(self):
        h=object.__new__(module.Harness)
        h.owned=[]; h.networks=[]; h.docker=Mock()
        return h

    def test_absence_requires_successful_query(self):
        h=self.harness(); h.docker.command.side_effect=OSError('daemon unavailable')
        with self.assertRaises(OSError): h.absent('a'*64)
        h.docker.command.side_effect=None
        h.docker.command.return_value=(0,b'a'*64+b'\n',b'')
        self.assertFalse(h.absent('a'*64))
        h.docker.command.return_value=(0,b'',b'')
        self.assertTrue(h.absent('a'*64))

    def test_cleanup_continues_after_exact_target_failure(self):
        h=self.harness(); h.owned=['azt-research-first','azt-research-second']; h.networks=['azt-research-network']
        h.docker.command.side_effect=[OSError('daemon'),(0,b'',b''),(0,b'',b'')]
        self.assertFalse(h.cleanup())
        self.assertEqual(h.docker.command.call_count,3)
        self.assertEqual(h.docker.command.call_args_list[-1].args,('network','rm','azt-research-network'))

    def test_frozen_runtime_expectations(self):
        import json
        p=Path(__file__).resolve().parents[1]/'packs/AZT-RESEARCH-001/v1/expectations.json'
        e=json.loads(p.read_text())
        self.assertEqual(len(e['runtime_cases']),10)
        self.assertEqual(e['pack'],module.PACK)

    def test_public_cli_timeout_keeps_exact_cleanup_target(self):
        h=self.harness()
        with tempfile.TemporaryDirectory() as t:
            h.root=Path(t).resolve(); h.image='sha256:'+'b'*64; h.endpoint='unix:///synthetic'
            p=h.root/'public CLI run'/'runtime-control'; p.mkdir(parents=True)
            (p/'session.json').write_text(json.dumps({'container_id':'a'*64}))
            with patch.object(module.subprocess,'run',side_effect=subprocess.TimeoutExpired('synthetic',40)):
                with self.assertRaises(subprocess.TimeoutExpired): h.legitimate()
            self.assertEqual(h.owned,['a'*64])
            h.docker.command.return_value=(0,b'',b'')
            self.assertTrue(h.cleanup())
            self.assertEqual(h.docker.command.call_args.args,('rm','--force','a'*64))
