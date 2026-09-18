"""Captured-source review: local bytes are observations, never authority.

No fetching, credential collection, conversation replay, target imports or target
execution. Repository capture uses intake's existing descriptor-relative reader.
"""
import copy
import hashlib
import html
import json
import os
from pathlib import Path
import re
import tempfile

import azt_intake as intake
import azt_review as review

SCHEMA = 'azt.research-review.v1'
MANIFEST_SCHEMA = 'azt.research-sources.v1'
MAX_MANIFEST = 65536
MAX_SOURCES = 16
MAX_DOCUMENTS = 128
MAX_DOCUMENT_BYTES = 65536
MAX_MESSAGE_BYTES = 6 * MAX_DOCUMENT_BYTES + 512
PAGE_BYTES = 8192
MAX_CAPTURE_BYTES = 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
SETTINGS = {'sources': MAX_SOURCES, 'documents': MAX_DOCUMENTS,
            'document_bytes': MAX_DOCUMENT_BYTES, 'captured_bytes': MAX_CAPTURE_BYTES,
            'method': 'captured-source-v2', 'repository_sources': 2}
LEGACY_SETTINGS = dict(SETTINGS, document_bytes=8192, method='captured-source-v1')
NOTICE = ('Captured local material, not authenticated original sources. No network fetch, '
          'diagnostic collection, target execution, admission or permission is issued. '
          'Raw text, origin values and claimed roles are omitted from exports; local paths may remain sensitive.')


class ResearchError(intake.IntakeError):
    pass


def require(ok, reason):
    if not ok:
        raise ResearchError(reason)


def identifier(value):
    require(isinstance(value, str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,63}', value), 'invalid source/root ID')
    return value


def absolute(path):
    require('..' not in Path(path).parts, 'traversal in operator path')
    return Path(os.path.abspath(path))


def contains(parent, child):
    return child == parent or parent in child.parents


def read_local(path, limit, operator=False):
    fd = intake.open_absolute(path)
    try:
        raw, meta = intake.read_fd(fd, limit)
        if operator:
            require(meta.st_uid == os.getuid() and not meta.st_mode & 0o022,
                    'registration must be operator-owned and not group/world writable')
        return raw
    finally:
        os.close(fd)


def registration(path, roots):
    require(isinstance(roots, dict) and 0 < len(roots) <= MAX_SOURCES, 'explicit input roots required')
    selected = {}
    for name, root in roots.items():
        identifier(name)
        root = absolute(root)
        fd = intake.open_absolute(root, directory=True)
        os.close(fd)
        require(not any(contains(root, old) or contains(old, root) for old in selected.values()),
                'input roots must not overlap')
        selected[name] = root
    path = absolute(path)
    require(not any(contains(root, path) for root in selected.values()), 'registration must be outside input roots')
    raw = read_local(path, MAX_MANIFEST, operator=True)
    value = review.parse(raw)
    review.obj(value, ['schema', 'sources'])
    require(value['schema'] == MANIFEST_SCHEMA, 'unsupported source registration schema')
    require(isinstance(value['sources'], list) and 0 < len(value['sources']) <= MAX_SOURCES, 'source count limit')
    seen, paths, repos = set(), set(), 0
    for item in value['sources']:
        review.obj(item, ['id', 'kind', 'root', 'path', 'method'], ['sha256', 'origin', 'captured_at'])
        identifier(item['id']); identifier(item['root'])
        require(item['id'] not in seen, 'duplicate source ID')
        seen.add(item['id'])
        require(item['root'] in selected, 'source root was not selected')
        require(item['kind'] in ('text', 'markdown', 'message', 'repository'), 'unsupported registered kind')
        require(item['method'] in ('operator-supplied-text', 'saved-message', 'repository-snapshot'), 'unsupported capture method')
        require(item['method'] == {'text': 'operator-supplied-text', 'markdown': 'operator-supplied-text',
                                  'message': 'saved-message', 'repository': 'repository-snapshot'}[item['kind']], 'kind/method mismatch')
        if item['path'] != '.' or item['kind'] != 'repository':
            intake.relative_path(item['path'])
            require('%' not in item['path'], 'encoded paths are unsupported')
        key = (item['root'], item['path'])
        require(key not in paths, 'duplicate source path')
        paths.add(key)
        if item.get('sha256') is not None:
            review.sha(item['sha256'])
        for field in ('origin', 'captured_at'):
            v = item.get(field)
            require(v is None or isinstance(v, str) and len(v) <= 512, 'oversized origin metadata')
        repos += item['kind'] == 'repository'
    require(repos <= SETTINGS['repository_sources'], 'repository source limit')
    # Overlapping registrations would duplicate work and create misleading identities.
    expanded = [selected[i['root']] / i['path'] for i in value['sources']]
    for i, path_i in enumerate(expanded):
        require(not any(contains(path_i, p) or contains(p, path_i) for p in expanded[i+1:]),
                'source registrations overlap')
    return value, selected, hashlib.sha256(raw).hexdigest()


class Capture:
    """Private immutable byte snapshots and validated scan records for a mission."""
    def __init__(self):
        self.documents = {}
        self.bytes = 0
        self.report = None

    def add(self, source, path, raw, sha):
        require(len(raw) <= MAX_DOCUMENT_BYTES, 'research document byte limit exceeded')
        require(len(self.documents) < MAX_DOCUMENTS and self.bytes + len(raw) <= MAX_CAPTURE_BYTES,
                'research capture aggregate limit exceeded')
        # Source prefixes are shortened only for the private protocol ID, not provenance.
        key = 's-' + hashlib.sha256((source + '\0' + path).encode()).hexdigest()[:48]
        require(key not in self.documents, 'conflicting captured source ID')
        self.documents[key] = {'id': key, 'registration': source, 'path': path,
                               'sha256': sha, 'text': raw.decode('utf-8'), 'check': None}
        self.bytes += len(raw)


def pages(text, parent_sha256):
    """Deterministic UTF-8 byte pages of frozen text, not detector windows.

    Offsets are zero-based half-open bytes; lines are one-based inclusive.
    Split only on UTF-8 codepoint boundaries. Page identity binds the parent
    digest and offsets. Scan relationships are computed on full admitted bytes
    before this presentation/channel segmentation, never separately per page.
    """
    raw = text.encode('utf-8')
    require(len(raw) <= MAX_DOCUMENT_BYTES and hashlib.sha256(raw).hexdigest() == parent_sha256,
            'invalid frozen page source')
    result, start, line = [], 0, 1
    while start < len(raw) or not result:
        end = min(start + PAGE_BYTES, len(raw))
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        part = raw[start:end]
        content = part.decode('utf-8')
        identity = {'parent_sha256': parent_sha256, 'byte_start': start, 'byte_end': end}
        result.append(dict(identity, id='p-' + intake.digest(identity), index=len(result),
                           sha256=hashlib.sha256(part).hexdigest(), text=content,
                           start_line=line, end_line=line + content.count('\n') - int(content.endswith('\n'))))
        result[-1]['end_line'] = max(line, result[-1]['end_line'])
        line += content.count('\n')
        start = end
        if start == len(raw):
            break
    return result


def inspect_sources(manifest, roots, fail_on='high'):
    import azt
    value, roots, registration_sha = registration(manifest, roots)
    require(fail_on in ('high', 'medium', 'any'), 'invalid failure threshold')
    capture = Capture()
    sources, errors = [], []
    for item in value['sources']:
        source = {'id': item['id'], 'kind': item['kind'], 'method': item['method'],
                  'root_id': item['root'], 'path': item['path'], 'status': 'omitted',
                  'byte_sha256': None, 'snapshot_sha256': None, 'review': None,
                  'origin_claim_sha256': intake.digest(item['origin']) if item.get('origin') is not None else None,
                  'capture_time_claim_sha256': intake.digest(item['captured_at']) if item.get('captured_at') is not None else None,
                  'claimed_role_sha256': None, 'reason': None}
        sources.append(source)
        path = roots[item['root']] / item['path']
        try:
            # Selecting an excluded descendant does not silently widen existing intake scope.
            require(not any(part in azt.SKIP_DIRS for part in Path(item['path']).parts), 'selected path is intake-excluded')
            if item['kind'] == 'repository':
                scan = azt.scan_report(path, fail_on=fail_on,
                                       capture=lambda p, b, h: capture.add(item['id'], p, b, h))
                source['snapshot_sha256'] = scan['input_digest']
                expected = item.get('sha256')
                require(expected is None or expected == scan['input_digest'], 'registered repository identity changed')
            else:
                suffixes = {'text': ('.txt',), 'markdown': ('.md', '.mdc'), 'message': ('.json',)}
                require(path.suffix.lower() in suffixes[item['kind']], 'unsupported source format; no conversion attempted')
                raw = read_local(path, MAX_MESSAGE_BYTES if item['kind'] == 'message' else MAX_DOCUMENT_BYTES)
                source['byte_sha256'] = hashlib.sha256(raw).hexdigest()
                require(item.get('sha256') is None or item['sha256'] == source['byte_sha256'], 'registered source bytes changed')
                if item['kind'] == 'message':
                    # Only saved capture content gets the larger string bound;
                    # report readers retain their existing strict 8192 bound.
                    message = review.parse(raw, string_limit=MAX_DOCUMENT_BYTES)
                    review.obj(message, ['schema', 'role', 'content'])
                    require(message['schema'] == 'azt.saved-message.v1', 'unsupported saved-message schema')
                    require(isinstance(message['role'], str) and len(message['role']) <= 128, 'invalid claimed role')
                    require(isinstance(message['content'], str), 'invalid saved message content')
                    source['claimed_role_sha256'] = intake.digest(message['role'])
                    raw = message['content'].encode('utf-8')
                require(len(raw) <= MAX_DOCUMENT_BYTES, 'research document byte limit exceeded')
                raw.decode('utf-8')
                # The existing engine inspects frozen bytes. Each standalone capture
                # gets its own root: unrelated sources are never a conversation.
                with tempfile.TemporaryDirectory(prefix='azt-capture-') as temp:
                    frozen = Path(temp).resolve()
                    target = frozen / 'captured.md'
                    target.write_bytes(raw)
                    scan = azt.scan_report(frozen, fail_on=fail_on,
                                           capture=lambda p, b, h: capture.add(item['id'], p, b, h))
                source['snapshot_sha256'] = scan['input_digest']
            source['review'] = review.adapt(scan)
            source['status'] = 'inspected' if scan['scope']['complete'] else 'partial'
            for doc in capture.documents.values():
                if doc['registration'] == item['id']:
                    doc['check'] = {'source': doc['id'], 'sha256': doc['sha256'],
                                    'complete': scan['scope']['complete'], 'findings': [
                                        {k: f[k] for k in ('rule', 'severity', 'line')}
                                        for f in scan['findings'] if f['path'] == doc['path']]}
        except (OSError, UnicodeError, ValueError, RuntimeError) as exc:
            reason = str(exc) if isinstance(exc, (ResearchError, review.ReviewError, intake.IntakeError)) else 'source read/encoding failed'
            source['reason'] = reason
            errors.append({'source': item['id'], 'reason': reason})
            # A failed identity check must not leave bytes available to a worker.
            for key in [k for k, d in capture.documents.items() if d['registration'] == item['id']]:
                del capture.documents[key]
    complete = all(s['status'] == 'inspected' for s in sources)
    source_identity = [{k: s[k] for k in ('id', 'kind', 'method', 'root_id', 'path', 'byte_sha256',
                                        'snapshot_sha256', 'origin_claim_sha256', 'capture_time_claim_sha256',
                                        'claimed_role_sha256', 'status')} for s in sources]
    report = {'schema': SCHEMA, 'mode': 'captured-local', 'registration_sha256': registration_sha,
              'input_sha256': intake.digest(source_identity), 'engine': review.engine_identity(azt),
              'adapter_sha256': intake.digest({'source': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'settings': SETTINGS}),
              'settings': dict(SETTINGS), 'threshold': fail_on, 'complete': complete,
              'sources': sources, 'errors': errors, 'captured_documents': len(capture.documents),
              'captured_bytes': capture.bytes, 'notice': NOTICE}
    # Producer/reader bound: fail clearly instead of emitting an unreadable report.
    require(len(intake.canonical(report)) <= MAX_OUTPUT, 'research report byte limit exceeded')
    capture.report = report
    return capture


def validate_report(value):
    review.bounded(value)
    require(len(intake.canonical(value)) <= MAX_OUTPUT, 'research report byte limit exceeded')
    value = copy.deepcopy(value)
    require(isinstance(value, dict) and value.get('schema') == SCHEMA, 'unsupported research review schema')
    review.obj(value, ['schema', 'mode', 'registration_sha256', 'input_sha256', 'engine', 'adapter_sha256',
                       'settings', 'threshold', 'complete', 'sources', 'errors', 'captured_documents', 'captured_bytes', 'notice'])
    for key in ('registration_sha256', 'input_sha256', 'adapter_sha256'):
        review.sha(value[key])
    require(value['mode'] == 'captured-local' and value['threshold'] in ('high', 'medium', 'any'), 'invalid research mode')
    require(type(value['complete']) is bool, 'invalid completeness')
    require(value['settings'] in (SETTINGS, LEGACY_SETTINGS), 'unsupported research analysis settings')
    review.obj(value['engine'], ['version', 'implementation_sha256', 'text_rules_sha256'])
    review.string(value['engine']['version'])
    review.sha(value['engine']['implementation_sha256']); review.sha(value['engine']['text_rules_sha256'])
    require(type(value['captured_documents']) is int and 0 <= value['captured_documents'] <= MAX_DOCUMENTS, 'invalid captured document count')
    require(type(value['captured_bytes']) is int and 0 <= value['captured_bytes'] <= MAX_CAPTURE_BYTES, 'invalid captured byte count')
    require(isinstance(value['errors'], list) and len(value['errors']) <= MAX_SOURCES, 'invalid errors')
    require(isinstance(value['sources'], list) and 0 < len(value['sources']) <= MAX_SOURCES, 'invalid sources')
    ids = set()
    for s in value['sources']:
        review.obj(s, ['id', 'kind', 'method', 'root_id', 'path', 'status', 'byte_sha256', 'snapshot_sha256', 'review',
                       'origin_claim_sha256', 'capture_time_claim_sha256', 'claimed_role_sha256', 'reason'])
        identifier(s['id']); identifier(s['root_id'])
        require(s['id'] not in ids, 'duplicate source ID'); ids.add(s['id'])
        require(s['status'] in ('inspected', 'partial', 'omitted'), 'invalid source status')
        require(s['kind'] in ('text', 'markdown', 'message', 'repository'), 'invalid source kind')
        require(s['method'] == {'text': 'operator-supplied-text', 'markdown': 'operator-supplied-text',
                               'message': 'saved-message', 'repository': 'repository-snapshot'}[s['kind']], 'kind/method mismatch')
        if s['path'] != '.' or s['kind'] != 'repository': intake.relative_path(s['path'])
        for k in ('byte_sha256', 'snapshot_sha256', 'origin_claim_sha256', 'capture_time_claim_sha256', 'claimed_role_sha256'):
            if s[k] is not None: review.sha(s[k])
        if s['review'] is not None:
            adapted = review.adapt(s['review'])
            require(s['snapshot_sha256'] == adapted['scan']['input_digest'], 'source/snapshot mismatch')
            require(s['status'] == ('inspected' if adapted['scan']['scope']['complete'] else 'partial'), 'source completeness mismatch')
            require(adapted['scan']['threshold'] == value['threshold'], 'threshold mismatch')
            require(adapted['scan']['engine'] == value['engine'], 'engine mismatch')
            s['review'] = adapted
        else:
            require(s['status'] == 'omitted', 'missing inspection record')
        require(s['reason'] is None or isinstance(s['reason'], str) and len(s['reason']) <= 512, 'invalid source reason')
    for error in value['errors']:
        review.obj(error, ['source', 'reason'])
        require(error['source'] in ids and isinstance(error['reason'], str) and len(error['reason']) <= 512, 'invalid source error')
    require({e['source'] for e in value['errors']} == {s['id'] for s in value['sources'] if s['status'] == 'omitted'}, 'omission/error mismatch')
    require(value['complete'] == all(s['status'] == 'inspected' for s in value['sources']), 'completeness mismatch')
    identities = [{k: s[k] for k in ('id', 'kind', 'method', 'root_id', 'path', 'byte_sha256', 'snapshot_sha256',
                                    'origin_claim_sha256', 'capture_time_claim_sha256', 'claimed_role_sha256', 'status')}
                  for s in value['sources']]
    require(intake.digest(identities) == value['input_sha256'], 'research input identity mismatch')
    value['notice'] = NOTICE
    return value


def render(value, fmt):
    value = validate_report(value)
    lines = ['AZT CAPTURED-SOURCE REVIEW', 'Inspection: ' + ('complete within declared scope' if value['complete'] else 'INCOMPLETE'),
             'Input SHA-256: ' + value['input_sha256'], NOTICE]
    for source in value['sources']:
        lines += ['', 'Source ' + source['id'] + ' (' + source['kind'] + '): ' + source['status']]
        if source['review']:
            adapted = source['review']
            scan = adapted['scan']
            lines.append(review.scan_summary(scan))
            lines.append('Snapshot SHA-256: ' + source['snapshot_sha256'])
            # Human view is a bounded maintained explanation, not a wall of
            # serialized metadata or advice copied from the captured material.
            for finding in scan['findings'][:32]:
                lines.append(finding['severity'] + ' ' + finding['rule'] + ' at ' +
                             intake.safe_label(finding['path']) + ':' + str(finding['line']))
                guidance = adapted['guidance'].get(finding['rule'])
                if guidance:
                    lines += [guidance['meaning'], 'Why review: ' + guidance['why_review'],
                              'Next step: ' + guidance['next_step']]
                if 'sensitive_request' in finding:
                    import azt_sensitive
                    lines.append(azt_sensitive.summary(finding['sensitive_request']))
            if len(scan['findings']) > 32:
                lines.append(str(len(scan['findings']) - 32) + ' further findings omitted from this display; use the complete JSON record.')
            lines.append('Visible reviewed exceptions: %d; target requests (not authority): %d.' %
                         (len(scan['suppressed_findings']), len(scan['target_requests'])))
            for gap in scan['scope']['errors'][:8]:
                lines.append('Inspection gap: ' + intake.safe_label(gap['path']) + '; ' + intake.safe_label(gap['reason']))
            if len(scan['scope']['errors']) > 8:
                lines.append(str(len(scan['scope']['errors']) - 8) + ' further gaps omitted from this display; use JSON.')
        else:
            lines.append('Reason: ' + intake.safe_label(source['reason']))
    if fmt == 'json':
        result = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n'
    elif fmt == 'text':
        result = '\n'.join(lines) + '\n'
    else:
        result = ('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
                  '<title>AZT captured-source review</title><style>body{font:16px/1.6 system-ui;margin:2em;max-width:100ch}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'
                  '<h1>Captured-source review</h1><pre>' + html.escape('\n'.join(lines)) + '</pre></html>')
    require(len(result.encode()) <= MAX_OUTPUT, 'research rendered output limit exceeded')
    return result


def reserve_directory(path):
    """Create-only operator output slot, never a workload-provided destination."""
    path = absolute(path)
    parent = intake.open_absolute(path.parent, directory=True)
    try:
        meta = os.fstat(parent)
        require(meta.st_uid == os.getuid() and not meta.st_mode & 0o022,
                'output parent must be operator-owned and not group/world writable')
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
    finally:
        os.close(parent)
    return path


def protected_run(capture, output, image, endpoint):
    """Reserve durable authority/evidence outside the worker before any launch.

    Abrupt controller death may leave only inspection.json, events.jsonl and the
    independent lease result. Missing report.json is explicitly not completion.
    No original source bytes are persisted in this slot.
    """
    from azt_research_broker import Broker
    from azt_research_runtime import run_worker
    control = reserve_directory(output)
    review.write_new(control / 'inspection.json', render(capture.report, 'json'))
    broker = Broker(capture, audit_path=control / 'events.jsonl')
    try:
        execution = run_worker(broker, image, endpoint, control_dir=control / 'runtime-control')
    finally:
        broker.close()
    value = {'schema': 'azt.research-run.v1', 'review': capture.report,
             'mission': broker.summary(), 'execution': execution, 'events': broker.events,
             'notice': 'Controller observations, not a complete syscall trace, authenticated source or live-model test.'}
    result = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n'
    require(len(result.encode()) <= MAX_OUTPUT, 'run evidence output limit exceeded')
    review.write_new(control / 'report.json', result)
    # Shared source rendering remains the canonical human review. Execution
    # status is separate; worker completion is not permission or truth.
    review.write_new(control / 'review.html', render(capture.report, 'html'))
    summary = ('AZT protected reference-worker run\n'
               'Outcome: ' + execution['status'] + '\n'
               'Review completed before authority retired: ' + str(broker.review_completed) + '\n'
               'Cleanup: ' + execution['cleanup'] + '\n'
               'Read report.json for controller stages; review.html for source findings.\n'
               'No live model, external upload or general containment claim.\n')
    review.write_new(control / 'summary.txt', summary)
    return 0 if execution['status'] == 'passed' and capture.report['complete'] else 2


def add_parser(sub):
    group = sub.add_parser('research', help='review registered local captures; optional protected reference-worker profile')
    commands = group.add_subparsers(dest='research_cmd', required=True)
    for name in ('review', 'run'):
        p = commands.add_parser(name, help='inspect frozen local captures' if name == 'review' else 'experimental native-Linux Docker reference worker')
        p.add_argument('--manifest', required=True)
        p.add_argument('--root', action='append', required=True, help='explicit ID=/absolute/input/root (repeatable)')
        p.add_argument('--fail-on', choices=['high', 'medium', 'any'], default='high')
        p.add_argument('--output', required=True, help='new private '+('directory' if name == 'run' else 'file')+' outside all input roots')
        if name == 'review':
            p.add_argument('--format', choices=['json', 'text', 'html'], default='json')
        if name == 'run':
            p.add_argument('--image', required=True, help='approved preloaded immutable Docker Official Python identity; never pulled')
            p.add_argument('--endpoint', default='unix:///var/run/docker.sock')
    export = commands.add_parser('export', help='render a saved captured-source review; never reread source files')
    export.add_argument('--input', required=True); export.add_argument('--output', required=True)
    export.add_argument('--format', choices=['json', 'text', 'html'], default='html')
    pending = commands.add_parser('case', help='export a pending, untrusted local case; no policy/rule promotion')
    pending.add_argument('--input', required=True); pending.add_argument('--output', required=True)


def command(args):
    try:
        if args.research_cmd in ('export', 'case'):
            raw = read_local(args.input, MAX_OUTPUT)
            value = validate_report(review.parse(raw))
            if args.research_cmd == 'case':
                value = {'schema': 'azt.research-case.v1', 'status': 'pending-owner-review',
                         'source_record_sha256': hashlib.sha256(raw).hexdigest(),
                         'research_input_sha256': value['input_sha256'], 'review': value,
                         'authority': 'none; submission does not modify rules, memory, permissions or model weights'}
                result = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + '\n'
            else:
                result = render(value, args.format)
            require(len(result.encode()) <= MAX_OUTPUT, 'case/export output limit exceeded')
            code = 0
        else:
            roots = {}
            for item in args.root:
                require('=' in item, 'root must be ID=/absolute/path')
                name, path = item.split('=', 1)
                require(name not in roots and Path(path).is_absolute(), 'duplicate or nonabsolute root')
                roots[name] = absolute(path)
            output = absolute(args.output)
            require(not any(contains(r, output) for r in roots.values()), 'output must be outside inspected roots')
            capture = inspect_sources(args.manifest, roots, args.fail_on)
            value = capture.report
            code = 0 if value['complete'] else 2
            if args.research_cmd == 'run':
                code = protected_run(capture, output, args.image, args.endpoint)
                print('AZT research runtime: ' + ('completed' if code == 0 else 'blocked or failed') + '; private evidence directory retained.')
                return code
            else:
                result = render(value, args.format)
        review.write_new(args.output, result)
        print('AZT research: ' + ('completed within declared scope' if code == 0 else 'incomplete or blocked') + '; private output written.')
        return code
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        import sys
        reason = str(exc) if isinstance(exc, (ResearchError, review.ReviewError)) else 'input, backend or evidence operation failed'
        print(json.dumps({'schema': 'azt.research-error.v1', 'status': 'error', 'reason': intake.safe_label(reason)}))
        print('azt research: no authority issued; operation did not complete', file=sys.stderr)
        return 2
