"""Evaluator bookkeeping failure tests; these do NOT count as Docker trials."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import subprocess
import json
from unittest.mock import Mock, patch, mock_open

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
        self.assertEqual(e['pack'],module.BASE_PACK)
        current=json.loads((p.parents[1]/'v2/expectations.json').read_text())
        self.assertEqual(current['pack'], module.PACK)
        self.assertEqual(current['inherits'], module.BASE_PACK)
        self.assertEqual(len(current['additional_cases']),3)

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

    def test_removed_container_can_precede_durable_lease_record(self):
        record={'schema':'azt.research-lease.v1','container_id':'a'*64,
                'reason':'controller_channel_closed','cleanup':'removed'}
        raw=(json.dumps(record)+'\n').encode()
        opened=mock_open(read_data=raw)
        path=Mock()
        # Exercise both a not-created record and a partially written frame.
        partial=mock_open(read_data=b'{')
        path.open.side_effect=[FileNotFoundError(),partial(),opened()]
        with patch.object(module.time,'monotonic',return_value=1), patch.object(module.time,'sleep'):
            self.assertEqual(module.await_lease_record(path,deadline=2),record)
        self.assertEqual(path.open.call_count,3)

    def test_missing_lease_record_does_not_extend_stop_bound_or_pass(self):
        path=Mock(); path.open.side_effect=FileNotFoundError()
        with patch.object(module.time,'monotonic',side_effect=[1,1,2]), patch.object(module.time,'sleep'):
            with self.assertRaisesRegex(AssertionError,'original stop bound'):
                module.await_lease_record(path,deadline=2)
