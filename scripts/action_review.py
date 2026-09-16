"""Trusted Action orchestration; inspected snapshots supply data, never code.

Only this pinned action checkout and an explicitly selected package are built.
No target hooks, Git commands, network reference resolution or raw report output.
"""
from collections import Counter
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

# Entry uses -I. This root is the trusted Action checkout, NOT inputs.path.
ROOT = Path(__file__).resolve().parent.parent
if __name__ == '__main__':
    sys.path.insert(0, str(ROOT))
import azt_review as review

SUMMARY_LIMIT = 48 * 1024
DISPLAY_LIMIT = 12


class ActionError(ValueError):
    pass


def outside(path, root):
    return path != root and root not in path.parents


def canonical(value, base):
    if len(os.fspath(value))>4096:
        raise ActionError('input path exceeds limit')
    path = Path(value)
    if '..' in path.parts:
        raise ActionError('path traversal is unsupported')
    path = Path(os.path.abspath(base / path))
    try:
        if len(path.parts)>128 or any(p.is_symlink() for p in (path,*path.parents)) or path.resolve()!=path:
            raise ActionError('symlink or ambiguous input path')
    except (OSError, RuntimeError, ValueError):
        # Python versions differ on cyclic links. Never expose their raw path
        # in a traceback or discard an otherwise valid candidate scan.
        raise ActionError('unsafe or unresolved input path') from None
    return path


def clean_environment(work):
    return {'PATH': os.defpath, 'HOME': str(work/'home'), 'TMPDIR': str(work),
            'LANG': 'C.UTF-8', 'PYTHONNOUSERSITE': '1', 'PIP_CONFIG_FILE': os.devnull,
            'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_INPUT': '1'}


def capture(command, work, limit=review.MAX_REPORT, seconds=120):
    """Finite capture of trusted tooling. Never stream untrusted output to logs."""
    process = subprocess.Popen(command, cwd=work, env=clean_environment(work),
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    output = bytearray()
    total = 0
    deadline = time.monotonic() + seconds
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, True)
            selector.register(process.stderr, selectors.EVENT_READ, False)
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ActionError('tool timeout')
                for key, _ in selector.select(0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > limit:
                        raise ActionError('tool output limit exceeded')
                    if key.data:
                        output.extend(chunk)
        return process.wait(timeout=max(0.1, deadline-time.monotonic())), bytes(output)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        process.stdout.close()
        process.stderr.close()


def scan(command, path, threshold, work, policy=None):
    args = ['scan', '--json', '--fail-on', threshold]
    if policy:
        args += ['--policy', str(policy)]
    try:
        code, raw = capture(command + args + ['--', str(path)], work)
        report = review.adapt(review.parse(raw))['scan']
        expected = {'pass': 0, 'deny': 1, 'incomplete': 2}[report['decision']]
        if code != expected or report['threshold'] != threshold:
            raise ActionError('scan exit/report mismatch')
        return {'exit': code, 'report': report, 'error': None}
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        # Error messages can carry target material. Emit a categorical diagnosis.
        return {'exit': 2, 'report': None, 'error': 'scan execution or structured validation failed'}


def evaluate(command, head, base, threshold, work, policy=None):
    candidate = scan(command, head, threshold, work, policy)
    baseline = scan(command, base, threshold, work, policy) if base else None
    delta, comparison_error = None, None
    if baseline:
        try:
            if not baseline['report'] or not candidate['report']:
                raise ActionError('missing validated snapshot')
            delta = review.compare(baseline['report'], candidate['report'])
            if baseline['exit'] == 2 or candidate['exit'] == 2:
                comparison_error = 'requested comparison includes incomplete inspection'
            elif any(k in delta['differences'] for k in ('engine','version','policy','threshold')):
                comparison_error = 'scanner or policy changed between snapshots'
        except (ValueError, KeyError):
            comparison_error = 'requested comparison could not be validated'
    code = 2 if comparison_error else candidate['exit']
    return {'candidate': candidate, 'baseline': baseline, 'comparison': delta,
            'comparison_error': comparison_error, 'exit': code}


def label(value):
    """Display escapes, not reversible raw evidence. No Markdown/URL/@ controls."""
    result = ''.join(c if c.isascii() and (c.isalnum() or c in ' /._-')
                     else ' U+%04X ' % ord(c) for c in str(value)[:180])
    # No dots adjacent to slash? Plain labels inside code spans; punctuation
    # capable of breaking spans, autolinking or mentioning is already removed.
    return result + (' [display shortened]' if len(str(value)) > 180 else '')


def commit_label(value):
    return value if re.fullmatch('[0-9a-f]{40}', value or '') else 'unknown / not supplied'


def package_spec(version):
    if version and version!='latest' and not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+([ab][0-9]+|rc[0-9]+)?',version):
        raise ActionError('invalid version input')
    return str(ROOT) if not version else 'agent-zero-trust' if version=='latest' else 'agent-zero-trust=='+version


def summary(result, head_label='', base_label=''):
    lines = ['## AZT repository review', '',
             'Review assistance, not approval or proof of safety. No target execution.', '']
    catalog = review.catalog()
    for name, ref in [('candidate', head_label), ('baseline', base_label)]:
        side = result[name]
        if side is None:
            continue
        lines += ['### '+name.capitalize(), '',
                  'Checkout commit label (caller supplied, not authenticated): `'+commit_label(ref)+'`']
        report = side['report']
        if not report:
            lines += ['Inspection failed; no validated report. Scanner exit: '+str(side['exit']), '']
            continue
        counts = Counter(f['severity'] for f in report['findings'])
        scope = report['scope']
        lines += ['Input manifest SHA-256: `'+report['input_digest']+'`',
                  'Scanner version: `'+label(report['version'])+'`',
                  'Engine SHA-256: `'+report.get('engine',{}).get('implementation_sha256','unavailable (legacy report)')+'`',
                  'Rules SHA-256: `'+report.get('engine',{}).get('text_rules_sha256','unavailable (legacy report)')+'`',
                  'Policy digest: `'+report['policy'].get('digest','unavailable')+'`',
                  'Inspection complete within declared scope: '+str(scope['complete']).lower()+
                  '; inspected '+str(len(scope['inspected']))+'; skipped '+str(len(scope['skipped']))+
                  '; errors '+str(len(scope['errors']))+'.',
                  'Findings: HIGH '+str(counts['HIGH'])+'; MEDIUM '+str(counts['MEDIUM'])+'; INFO '+str(counts['INFO'])+'.',
                  'Threshold: '+report['threshold'].upper()+'; '+
                  ('not evaluated to completion' if side['exit']==2 else 'met/exceeded' if side['exit']==1 else 'not reached')+
                  '; scanner exit '+str(side['exit'])+'.',
                  'Reviewed exceptions: '+str(len(report['suppressed_findings']))+
                  '; target requests (not applied): '+str(len(report['target_requests']))+'.', '']
        for finding in report['findings'][:DISPLAY_LIMIT]:
            rule = finding['rule']
            guidance = catalog.get(rule)
            lines.append('- '+finding['severity']+' `'+label(rule)+'` at `'+label(finding['path'])+'`, line '+str(finding['line']))
            if guidance:
                lines.append('  '+label(guidance['meaning']))
            if rule==review.SENSITIVE_RULE and finding.get('sensitive_request'):
                observed=finding['sensitive_request']
                names={'tokens':'API keys or tokens','environment':'environment variables',
                       'shell-history':'shell history','configuration':'credential-bearing configuration',
                       'private-keys':'private keys'}
                lines.append('  Requested information: '+', '.join(names[c] for c in observed['information_classes'])+'.')
                lines.append('  These materials may contain credentials or private activity. No actual secret presence or disclosure was established.')
                lines.append('  Destination observation: '+observed['destination']['status']+'; recipient values omitted.')
        lines += ['Displayed '+str(min(DISPLAY_LIMIT,len(report['findings'])))+' of '+str(len(report['findings']))+
                  ' findings; raw excerpts, recipients, source descriptions and gap paths omitted.', '']
    delta = result['comparison']
    if delta:
        f = delta['findings']
        lines += ['### Comparison', '', 'Comparability: '+delta['comparability']['status']+'.',
                  'New '+str(len(f['new']))+'; persisting '+str(len(f['persisting']))+
                  '; no longer observed '+str(len(f['no_longer_observed']))+'; unresolved '+str(len(f['unresolved']))+'.',
                  'Persisting with changed dependencies: '+str(sum(bool(v.get('dependencies_changed')) for v in f['persisting']))+'.',
                  'Meaningful delta: '+str(delta['meaningful_delta']).lower()+'.']
        lines += ['- '+label(v) for v in delta['comparability']['reasons'][:DISPLAY_LIMIT]]
        lines += ['Displayed '+str(min(DISPLAY_LIMIT,len(delta['comparability']['reasons'])))+' of '+str(len(delta['comparability']['reasons']))+' comparability reasons.']
        lines += ['No longer observed does not mean proven fixed. Missing support can keep an observation unresolved.', '']
    elif result['baseline'] is None:
        lines += ['Single snapshot: findings are not labeled new; no baseline comparison was requested.', '']
    if result['comparison_error']:
        lines += ['Comparison failed: '+result['comparison_error']+'.', '']
    lines += ['Next: inspect the indicated local passages, run `azt explain RULE_ID`, and review the minimum needed access or disclosure. Use local JSON/text/HTML export for fuller scope details.', '',
              'Paths and labels can still be sensitive. This bounded summary is a derivative, not the original report. Hosted summaries/logs follow workflow visibility; no raw report is uploaded by this Action.', '',
              'Action exit: '+str(result['exit'])+'.', '']
    text = '\n'.join(lines)
    if len(text.encode()) > SUMMARY_LIMIT:
        raise ActionError('summary display bound exceeded')
    return text


def write_summary(path, text, forbidden):
    destination = canonical(path, Path.cwd())
    if any(not outside(destination, root) for root in forbidden):
        raise ActionError('summary is inside inspected input')
    fd = os.open(destination, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 or meta.st_uid != os.getuid():
            raise ActionError('unsafe summary output')
        with os.fdopen(fd, 'a', encoding='utf-8', closefd=False) as stream:
            stream.write(text)
    finally:
        os.close(fd)


def main():
    # Runner/workflow state is configuration, not workload metadata discovery.
    env = os.environ
    result, head, base = None, None, None
    stage = 'input validation'
    try:
        workspace = Path(env['GITHUB_WORKSPACE']).resolve()
        head = canonical(env.get('AZT_SCAN_PATH','.'), workspace)
        baseline_problem = False
        try:
            base = canonical(env['AZT_BASE_PATH'],workspace) if env.get('AZT_BASE_PATH') else None
        except ActionError:
            base, baseline_problem = None, True
        if base and (not outside(head,base) or not outside(base,head)):
            raise ActionError('snapshots must be separate, non-nested directories')
        roots = [p for p in (head,base) if p]
        temporary = canonical(env['RUNNER_TEMP'],Path.cwd())
        if any(not outside(temporary,p) or not outside(ROOT,p) or not outside(Path(sys.executable).resolve(),p) for p in roots):
            raise ActionError('tooling or temporary output overlaps inspected input')
        threshold = env.get('AZT_FAIL_ON','high')
        version = env.get('AZT_ACTION_VERSION','')
        enabled = env.get('AZT_JOB_SUMMARY','true')
        if threshold not in ('high','medium','any') or enabled not in ('true','false'):
            raise ActionError('invalid threshold or summary input')
        spec = package_spec(version)
        with tempfile.TemporaryDirectory(prefix='azt-action-',dir=temporary) as directory:
            work = Path(directory)
            (work/'home').mkdir()
            stage = 'environment preparation'
            code,_ = capture([sys.executable,'-I','-m','venv',str(work/'venv')],work,seconds=60)
            if code:
                raise ActionError('isolated Python environment preparation failed')
            python = work/'venv/bin/python'
            stage = 'scanner installation'
            code,_ = capture([str(python),'-I','-m','pip','--isolated','install','--no-cache-dir','--disable-pip-version-check','--no-input','--no-deps',spec],work,limit=1024*1024,seconds=180)
            if code:
                raise ActionError('trusted scanner installation failed')
            result = evaluate([str(python),'-I','-m','azt'],head,base,threshold,work)
            if baseline_problem:
                result.update(baseline={'exit':2,'report':None,'error':'unsupported baseline path'},
                              comparison_error='requested baseline path is unsupported',exit=2)
            stage = 'summary formatting'
            text = summary(result,env.get('AZT_HEAD_LABEL',''),env.get('AZT_BASE_LABEL',''))
            if enabled=='true':
                stage = 'summary writing'
                if not env.get('GITHUB_STEP_SUMMARY'):
                    raise ActionError('summary output unavailable; set job-summary false for local use')
                write_summary(env['GITHUB_STEP_SUMMARY'],text,roots)
                # Only this allowlisted, bounded derivative reaches hosted logs.
                # Logging the payload makes actual CI evidence inspectable without
                # an artifact upload or access to raw snapshot reports.
                print(text)
            print('AZT: candidate scan exit='+str(result['candidate']['exit'])+
                  '; comparison='+('failed' if result['comparison_error'] else 'completed' if base else 'not requested')+
                  '; summary='+('written' if enabled=='true' else 'disabled'))
            return result['exit']
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        # Do not reflect exception strings, commands, paths or installer output.
        print('AZT: '+stage+' failed; candidate scan exit='+
              (str(result['candidate']['exit']) if result else 'unavailable')+'; action exit=2',file=sys.stderr)
        return 2


if __name__=='__main__':
    raise SystemExit(main())
