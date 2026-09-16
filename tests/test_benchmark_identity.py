"""Intake benchmark source labels must describe the installed module bytes."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('bench', Path(__file__).resolve().parents[1] / 'scripts/containmentbench.py')
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


class BenchmarkIdentityTests(unittest.TestCase):
    def test_all_declared_modules_checked_including_analyzer_and_reader(self):
        modules = [name for name in bench.SOURCES if '/' not in name and name.endswith('.py')]
        self.assertIn('azt_sensitive.py', modules)
        self.assertIn('azt_review.py', modules)
        sources = {name: bench.sha(b'reviewed synthetic module') for name in modules}
        sources['pyproject.toml'] = 'metadata is not a wheel module'
        with tempfile.TemporaryDirectory() as temporary:
            for changed in (None, 'azt_sensitive.py', 'azt_review.py'):
                with self.subTest(changed=changed):
                    wheel = Path(temporary) / ((changed or 'unchanged') + '.whl')
                    with zipfile.ZipFile(wheel, 'w') as archive:
                        for name in modules:
                            archive.writestr(name, b'different bytes' if name == changed else b'reviewed synthetic module')
                    if changed:
                        with self.assertRaisesRegex(ValueError, 'current source'):
                            bench.verify_wheel_sources(wheel, sources)
                    else:
                        bench.verify_wheel_sources(wheel, sources)

    def test_missing_declared_module_cannot_issue_matching_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            wheel = Path(temporary) / 'empty.whl'
            with zipfile.ZipFile(wheel, 'w'):
                pass
            with self.assertRaises(KeyError):
                bench.verify_wheel_sources(wheel, {'azt_sensitive.py': bench.sha(b'expected')})


if __name__ == '__main__':
    unittest.main()
