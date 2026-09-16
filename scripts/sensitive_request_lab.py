"""Run frozen synthetic sensitive-request cases through an installed AZT CLI.

Never execute fixture instructions. Output is create-only, outside fixture trees.
The five development cases and eight challenge cases are separate measurements.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import resource
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
PACKS = ROOT / 'examples' / 'sensitive-request'
RULE = 'request.sensitive_disclosure'
MAX_STDOUT = 8 * 1024 * 1024
MAX_STDERR = 65536


def write_new(path, text):
    with path.open('x', encoding='utf-8') as stream:
        stream.write(text)


def read_pack(path):
    raw = path.read_bytes()
    if len(raw) > 256 * 1024:
        raise ValueError('fixture manifest exceeds 256 KiB')
    spec = json.loads(raw)
    if spec['schema'] != 'azt.sensitive-request-cases.v1' or spec['rule'] != RULE:
        raise ValueError('unsupported fixture manifest')
    if not 1 <= len(spec['cases']) <= 32:
        raise ValueError('case count outside bounds')
    identifiers = set()
    for case in spec['cases']:
        name = case['id']
        if not re.fullmatch(r'[A-Za-z0-9-]{1,64}', name) or name in identifiers:
            raise ValueError('invalid or duplicate case identifier')
        identifiers.add(name)
        if not 1 <= len(case['files']) <= 8:
            raise ValueError('fixture file count outside bounds')
        for rel, text in case['files'].items():
            path = PurePosixPath(rel)
            if (path.is_absolute() or str(path) != rel or
                    any(part in ('', '.', '..') for part in rel.split('/')) or
                    '\\' in rel or ':' in rel or len(rel) > 256 or
                    not isinstance(text, str) or len(text.encode('utf-8')) > 16384):
                raise ValueError('invalid bounded fixture file')
    return spec, hashlib.sha256(raw).hexdigest()


class Capture:
    def __init__(self, cli, output, fixtures):
        self.cli, self.output, self.fixtures = cli, output, fixtures
        self.commands = []

    def normalized(self, value):
        return str(value).replace(str(self.fixtures), '<fixtures>').replace(
            str(self.output), '<output>').replace(str(self.cli), '<installed-cli>')

    def invoke(self, label, args):
        start = time.monotonic()
        error, exit_code = None, None
        environment = dict(os.environ)
        environment.pop('PYTHONPATH', None)
        environment.pop('PYTHONHOME', None)
        environment['PYTHONNOUSERSITE'] = '1'
        with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
            try:
                result = subprocess.run([str(self.cli), *map(str, args)],
                    cwd=self.output, env=environment, stdout=out, stderr=err, timeout=30)
                exit_code = result.returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                error = type(exc).__name__
            out.seek(0); err.seek(0)
            stdout, stderr = out.read(MAX_STDOUT + 1), err.read(MAX_STDERR + 1)
        if len(stdout) > MAX_STDOUT or len(stderr) > MAX_STDERR:
            error = 'captured output exceeded bounds; truncated'
        stdout = stdout[:MAX_STDOUT].decode('utf-8', errors='replace')
        stderr = stderr[:MAX_STDERR].decode('utf-8', errors='replace')
        stdout_path, stderr_path = label + '.stdout.txt', label + '.stderr.txt'
        write_new(self.output / stdout_path, stdout)
        write_new(self.output / stderr_path, stderr)
        record = {'id': label, 'argv': [self.normalized(x) for x in args],
                  'exit': exit_code, 'seconds': round(time.monotonic() - start, 6),
                  'stdout': stdout_path, 'stderr': stderr_path, 'error': error}
        self.commands.append(record)
        return record, stdout


def parsed(stdout):
    try:
        value = json.loads(stdout)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def export_record(name, path, expected_schema=None):
    failures, observed = [], {'artifact': path.name}
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_STDOUT:
        failures.append('expected bounded nonempty export absent')
    else:
        raw = path.read_bytes()
        observed.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        text = raw.decode('utf-8', errors='replace')
        if RULE not in text:
            failures.append('sensitive rule absent from export')
        if expected_schema:
            report = parsed(text)
            observed['schema'] = report.get('schema')
            if report.get('schema') != expected_schema:
                failures.append('export schema mismatch')
            if not any(f.get('rule') == RULE and f.get('sensitive_request')
                       for f in report.get('scan', {}).get('findings', [])):
                failures.append('contextual observation absent from review export')
    return {'case': name, 'observed': observed, 'failures': failures, 'passed': not failures}


def scan_case(case, root, capture, baseline=False):
    root.mkdir()
    for rel, text in case['files'].items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        write_new(path, text)
    scans, failures = {}, []
    for threshold in ('default', 'medium'):
        args = ['scan', root, '--json']
        if threshold == 'medium':
            args += ['--fail-on', 'medium']
        command, stdout = capture.invoke(case['id'] + '-' + threshold, args)
        report = parsed(stdout)
        findings = report.get('findings', [])
        sensitive = [f for f in findings if f.get('rule') == RULE]
        expectation = case['expected']
        if command['error'] or (command['exit'] not in (0, 1, 2) if baseline else
                                command['exit'] != expectation[threshold + '_exit']):
            failures.append(threshold + ': unexpected exit or command error')
        if report.get('schema_version') not in ((1, 2) if baseline else (2,)):
            failures.append(threshold + ': unsupported scan schema for measurement mode')
        if report.get('scope', {}).get('complete') is not True:
            failures.append(threshold + ': expected complete declared inspection')
        if bool(sensitive) != expectation['sensitive_disclosure']:
            failures.append(threshold + ': sensitive disclosure observation mismatch')
        if not baseline and expectation.get('source') and not any(f.get('path') == expectation['source'] for f in sensitive):
            failures.append(threshold + ': expected source attribution absent')
        if not baseline and any(f.get('severity') != 'MEDIUM' or not isinstance(f.get('sensitive_request'), dict) for f in sensitive):
            failures.append(threshold + ': missing MEDIUM contextual observation')
        if not baseline and expectation.get('unresolved_reference') and not any(
                ref.get('status') not in ('resolved', 'no-sharing-context')
                for finding in sensitive
                for ref in finding.get('sensitive_request', {}).get('references', [])):
            failures.append(threshold + ': expected unresolved reference absent')
        scans[threshold] = {'exit': command['exit'], 'report': command['stdout'],
            'schema_version': report.get('schema_version'), 'version': report.get('version'),
            'engine': report.get('engine'), 'input_digest': report.get('input_digest'),
            'decision': report.get('decision'), 'threshold': report.get('threshold'),
            'scope': report.get('scope'), 'total_findings': len(findings),
            'rules': dict(sorted(Counter(f.get('rule', '<missing>') for f in findings).items())),
            'sensitive_findings': sensitive}
    return {'case': case['id'], 'category': case['category'], 'expected': case['expected'],
            'file_sha256': {p: hashlib.sha256(t.encode('utf-8')).hexdigest() for p, t in case['files'].items()},
            'scans': scans, 'failures': failures, 'passed': not failures}


def workflows(spec, cases, capture):
    records = []
    by_name = {case['case']: case for case in cases}
    for comparison in spec.get('comparisons', []):
        before = capture.output / by_name[comparison['before']]['scans']['default']['report']
        after = capture.output / by_name[comparison['after']]['scans']['default']['report']
        args = ['changes', '--before', before, '--after', after]
        command, stdout = capture.invoke(comparison['id'], args + ['--json'])
        report, failures = parsed(stdout), []
        expected = comparison['expected']
        if command['exit'] != 0 or command['error']:
            failures.append('changes command failed')
        if report.get('schema') != 'azt.changes.v2':
            failures.append('expected changes schema v2')
        if report.get('meaningful_delta') != expected['meaningful_delta']:
            failures.append('meaningful delta mismatch')
        if report.get('comparability', {}).get('status') != expected['comparability']:
            failures.append('comparability mismatch')
        groups = report.get('findings', {})
        if expected.get('new_sensitive') and not any(f.get('rule') == RULE for f in groups.get('new', [])):
            failures.append('expected new sensitive finding absent')
        if expected.get('changed_sensitive_dependency') and not any(
                f.get('rule') == RULE and f.get('dependencies_changed') is True
                for f in groups.get('persisting', [])):
            failures.append('expected changed sensitive dependency absent')
        records.append({'case': comparison['id'], 'expected': expected,
            'observed': {'schema': report.get('schema'), 'meaningful_delta': report.get('meaningful_delta'),
                         'comparability': report.get('comparability'), 'content': report.get('content'),
                         'findings': groups}, 'failures': failures, 'passed': not failures})
        for fmt in ('text', 'html'):
            destination = capture.output / (comparison['id'] + '.' + ('txt' if fmt == 'text' else fmt))
            capture.invoke(comparison['id'] + '-' + fmt, args + ['--format', fmt, '--output', destination])
            records.append(export_record(comparison['id'] + '-' + fmt, destination))
    broad = capture.output / by_name['broad-original']['scans']['default']['report']
    for fmt in ('json', 'text', 'html'):
        destination = capture.output / ('scan-review.' + ('txt' if fmt == 'text' else fmt))
        capture.invoke('report-' + fmt, ['report', '--input', broad, '--format', fmt,
                       '--output', destination])
        records.append(export_record('report-' + fmt, destination, 'azt.review.v2' if fmt == 'json' else None))
    command, stdout = capture.invoke('explain-json', ['explain', RULE, '--json'])
    guidance = parsed(stdout)
    failures = [] if command['exit'] == 0 and guidance.get('rule') == RULE else ['rule explanation failed']
    records.append({'case': 'rule-guidance', 'observed': guidance, 'failures': failures, 'passed': not failures})
    capture.invoke('explain-text', ['explain', RULE])
    return records


def prepare_output(output):
    output = Path(output).absolute()
    if '..' in output.parts:
        raise ValueError('output path must not contain parent traversal')
    if any(part.is_symlink() for part in (output, *output.parents)):
        raise ValueError('output path must use real directories, not symlink aliases')
    if output == PACKS or PACKS in output.parents:
        raise ValueError('output must be outside source fixture trees')
    output.mkdir(mode=0o700)  # create-only, including when the destination exists
    return output


def run_lab(cli, output, pack='development-v1', include_workflows=True, baseline=False):
    started = time.monotonic()
    cli = Path(cli).resolve(strict=True)
    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise ValueError('--cli must identify an executable installed AZT CLI')
    spec, digest = read_pack(PACKS / (pack + '.json'))
    output = prepare_output(output)
    with tempfile.TemporaryDirectory(prefix='azt sensitive fixtures ') as temporary:
        fixtures = Path(temporary).resolve()
        capture = Capture(cli, output, fixtures)
        _, version_text = capture.invoke('version', ['--version'])
        cases = [scan_case(case, fixtures / (case['id'] + ' project'), capture, baseline) for case in spec['cases']]
        reviews = workflows(spec, cases, capture) if include_workflows and not baseline else []
    failed_commands = [c['id'] for c in capture.commands if c['error'] or (
        c['id'] not in {case['case'] + '-' + t for case in cases for t in ('default', 'medium')} and c['exit'] != 0)]
    failures = sum(not c['passed'] for c in cases) + sum(not c['passed'] for c in reviews)
    peak_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    result = {'schema': 'azt.sensitive-request-results.v1', 'pack': spec['pack'],
        'mode': 'baseline-observations' if baseline else 'candidate-contract',
        'manifest_sha256': digest, 'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'installed_version': version_text.strip(), 'cli_executable_sha256': hashlib.sha256(cli.read_bytes()).hexdigest(),
        'host_python': platform.python_version(), 'platform': platform.system() + ' ' + platform.release(),
        'cases': cases, 'workflows': reviews, 'commands': capture.commands,
        'case_count': len(cases), 'passed_cases': sum(c['passed'] for c in cases),
        'failed_cases': sum(not c['passed'] for c in cases),
        'failed_commands': failed_commands, 'passed': not failures and not failed_commands,
        'seconds': round(time.monotonic() - started, 6), 'runtime_trials': 0,
        'peak_rss_bytes': int(peak_rss if platform.system() == 'Darwin' else peak_rss * 1024),
        'peak_rss_scope': 'resource.getrusage(RUSAGE_CHILDREN).ru_maxrss for this runner process; child-process high-water RSS, not per-case allocation; macOS bytes and Linux KiB normalized to bytes.',
        'fixture_paths_contain_spaces': True,
        'command_path_labels': 'Command argv uses <fixtures>, <output>, and <installed-cli> labels for temporary/operator paths.',
        'subprocess_python_environment': 'PYTHONPATH and PYTHONHOME removed; PYTHONNOUSERSITE=1; working directory outside source.',
        'authorship': 'Reviewer-authored challenge then available during development; related development tests were added with those cases visible. This is not blind validation, held-out validation, or an independent third-party audit.',
        'baseline_limits': 'Baseline mode measures actual rule observations and accepts historical scan schema 1; it does not assert candidate metadata or candidate threshold exits. Expected positive misses remain failed cases.' if baseline else None,
        'limits': spec['limits']}
    write_new(output / 'results.json', json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'pack': result['pack'], 'manifest_sha256': digest,
        'mode': result['mode'],
        'installed_version': result['installed_version'], 'case_count': len(cases),
        'passed_cases': result['passed_cases'], 'failed_cases': result['failed_cases'],
        'failed_commands': failed_commands, 'passed': result['passed'], 'seconds': result['seconds']}, indent=2, sort_keys=True))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True, help='explicit executable from the installed candidate')
    parser.add_argument('--output', required=True, help='new private result directory outside fixtures')
    args = parser.parse_args()
    result = run_lab(args.cli, args.output)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
