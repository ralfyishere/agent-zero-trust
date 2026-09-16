"""Regression measurement failures are not successful negative observations."""
import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("evaluate_precision", Path(__file__).resolve().parent.parent / "scripts/evaluate_precision.py")
evaluation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluation)


class PrecisionEvaluatorTests(unittest.TestCase):
    def test_existing_output_is_setup_error_without_path_or_traceback(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / 'synthetic-private-label.json'
            output.write_text('keep original')
            error = io.StringIO()
            with patch.object(sys, 'argv', ['evaluate_precision', '--python', sys.executable,
                                          '--output', str(output)]), contextlib.redirect_stderr(error):
                self.assertEqual(evaluation.main(), 2)
            self.assertEqual(output.read_text(), 'keep original')
            self.assertNotIn('synthetic-private-label', error.getvalue())
            self.assertNotIn('Traceback', error.getvalue())

    def test_empty_control_requires_a_real_structured_component_result(self):
        for absent in ({}, {"id": "P01"}, {"id": "P01", "findings": {}, "errors": []},
                       {"id": "P01", "findings": [], "errors": None},
                       {"id": "P02", "findings": [], "errors": []}):
            with self.subTest(absent=absent):
                self.assertFalse(evaluation.component_row_valid(absent, "P01"))
        self.assertTrue(evaluation.component_row_valid({"id": "P01", "findings": [], "errors": []}, "P01"))

    def test_invalid_observation_structure_is_not_bound_evidence(self):
        for invalid in (None, {}, ["not a finding"], [{"rule": evaluation.RULE, "sensitive_request": []}],
                        [{"rule": evaluation.RULE, "path": "README.md", "sensitive_request": {"support": {}, "references": []}}]):
            with self.subTest(invalid=invalid):
                self.assertEqual(([], False), evaluation.observations(invalid, {"README.md": "synthetic"}))

    def test_real_failed_command_retains_status_without_echoing_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="azt precision evaluator ") as temporary:
            status, raw = evaluation.invoke(Path(sys.executable), Path(temporary).resolve(),
                ["-c", "import sys;sys.stderr.write('synthetic-private-diagnostic');raise SystemExit(7)"])
        self.assertEqual(7, status["exit"])
        self.assertIsNone(status["error"])
        self.assertGreater(status["stderr_bytes"], 0)
        self.assertNotIn("synthetic-private-diagnostic", str(status))
        self.assertEqual(b"", raw)

    def test_real_output_overflow_is_a_categorical_failure(self):
        with tempfile.TemporaryDirectory(prefix="azt precision evaluator ") as temporary, \
                patch.object(evaluation, "MAX_OUTPUT", 64):
            status, raw = evaluation.invoke(Path(sys.executable), Path(temporary).resolve(),
                ["-c", "print('x' * 4096)"])
        self.assertIsNone(status["exit"])
        self.assertEqual("ValueError", status["error"])
        self.assertLessEqual(len(raw), 64)


if __name__ == "__main__":
    unittest.main()
