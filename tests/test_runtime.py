"""Prerequisite diagnostics, not containment evidence.

Run: python3 -m unittest discover -s tests -p test_runtime.py -v
"""
import json
import os
import unittest
from unittest.mock import mock_open, patch

import azt_runtime


class RuntimeDoctorTests(unittest.TestCase):
    def test_actual_host_report_is_json_and_never_claims_runtime_ready(self):
        report = azt_runtime.runtime_doctor()
        self.assertEqual(json.loads(json.dumps(report)), report)
        self.assertFalse(report["runtime_ready"])
        self.assertEqual(azt_runtime.doctor_exit_code(report), 2)
        self.assertEqual(set(report["controls"].values()), {"not_verified"})

    def test_unsupported_platform_does_not_probe_programs_or_cgroups(self):
        with patch("azt_runtime.platform.system", return_value="Darwin"), \
                patch("azt_runtime.shutil.which") as which, \
                patch("azt_runtime._read_controllers") as controllers:
            report = azt_runtime.runtime_doctor()
        self.assertEqual(report["status"], "unsupported_platform")
        which.assert_not_called()
        controllers.assert_not_called()

    def test_unknown_backend_is_non_success_and_not_reflected(self):
        report = azt_runtime.runtime_doctor("host-shell\x1b[31m")
        self.assertEqual(report["status"], "unsupported_backend")
        self.assertEqual(report["backend"], "unsupported")
        self.assertEqual(azt_runtime.doctor_exit_code(report), 2)

    def test_linux_missing_dependency(self):
        with patch("azt_runtime.platform.system", return_value="Linux"), \
                patch("azt_runtime.shutil.which", return_value=None), \
                patch("azt_runtime._read_controllers", return_value=["cpu", "memory", "pids"]):
            report = azt_runtime.runtime_doctor()
        self.assertEqual(report["status"], "missing_dependency")

    def test_missing_process_controller_fails(self):
        with patch("azt_runtime.platform.system", return_value="Linux"), \
                patch("azt_runtime.shutil.which", return_value="/usr/bin/fixture"), \
                patch("azt_runtime._read_controllers", return_value=["cpu", "memory"]):
            report = azt_runtime.runtime_doctor()
        self.assertEqual(report["status"], "missing_control")
        self.assertIn({"name": "cgroup_v2.pids", "status": "missing"}, report["checks"])

    def test_unreadable_controllers_do_not_pass(self):
        with patch("azt_runtime.platform.system", return_value="Linux"), \
                patch("azt_runtime.shutil.which", return_value="/usr/bin/fixture"), \
                patch("azt_runtime._read_controllers", return_value=None):
            report = azt_runtime.runtime_doctor()
        self.assertEqual(report["status"], "missing_control")

    def test_all_prerequisites_present_still_not_verified(self):
        with patch("azt_runtime.platform.system", return_value="Linux"), \
                patch("azt_runtime.shutil.which", return_value="/usr/bin/fixture") as which, \
                patch("azt_runtime._read_controllers", return_value=["cpu", "memory", "pids"]):
            report = azt_runtime.runtime_doctor()
        self.assertEqual(report["status"], "integration_unverified")
        self.assertEqual(azt_runtime.doctor_exit_code(report), 2)
        self.assertIsNone(report["backend_version"])
        self.assertEqual(which.call_args_list[0].kwargs, {"path": os.defpath})

    def test_kernel_read_is_bounded(self):
        with patch("builtins.open", mock_open(read_data="x" * 4097)) as mocked:
            self.assertIsNone(azt_runtime._read_controllers())
        mocked().read.assert_called_once_with(4097)

    def test_kernel_read_errors_are_explicitly_unknown(self):
        for error in (OSError("fixture"), UnicodeError("fixture")):
            with self.subTest(error=type(error).__name__), patch("builtins.open", side_effect=error):
                self.assertIsNone(azt_runtime._read_controllers())


if __name__ == "__main__":
    unittest.main()
