"""Offline saved-scan review. Untrusted observations, never admission authority."""
from collections import Counter, defaultdict
import copy
import hashlib
import html
from importlib import resources
import json
import os
from pathlib import Path
import re
import stat

import azt_intake as intake

MAX_REPORT = 8 * 1024 * 1024
MAX_OUTPUT = MAX_REPORT
MAX_ITEMS = 10000
SEVERITY = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
NOTICE = ("Informational review only. Reports are untrusted assertions; hashes and schema "
          "validation do not authenticate them. No longer observed does not mean proven fixed. "
          "No receipt, authorization, upload or target execution occurs.")


class ReviewError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ReviewError(message)


def bounded(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        require(depth <= 32 and count <= 150000, "report complexity limit exceeded")
        if isinstance(item, dict):
            require(all(isinstance(k, str) and len(k) <= 128 for k in item), "invalid object key")
            stack.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            require(len(item) <= MAX_ITEMS, "report array limit exceeded")
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            require(len(item) <= 8192 and not any(0xD800 <= ord(c) <= 0xDFFF for c in item), "invalid or oversized string")
        else:
            require(item is None or type(item) in (bool, int), "unsupported JSON scalar")
            if type(item) is int:
                require(abs(item) <= 10**19, "integer limit exceeded")


def parse(raw):
    require(len(raw) <= MAX_REPORT, "report byte limit exceeded")
    text = raw.decode("utf-8")
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            require(depth <= 32, "JSON nesting limit exceeded")
        elif char in ']}':
            depth -= 1

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def integer(token):
        require(len(token) <= 20, "integer token limit exceeded")
        return int(token)

    def unsupported(_):
        raise ReviewError("non-integer number unsupported")

    value = json.loads(text, object_pairs_hook=pairs, parse_int=integer,
                       parse_float=unsupported, parse_constant=unsupported)
    bounded(value)
    return value


def load(path):
    require('..' not in Path(path).parts, "traversal in report path")
    fd = intake.open_absolute(path)
    try:
        raw, _ = intake.read_fd(fd, MAX_REPORT)
    finally:
        os.close(fd)
    return parse(raw)


def obj(value, required, optional=()):
    require(isinstance(value, dict), "expected object")
    require(set(required) <= set(value) <= set(required) | set(optional), "unsupported or missing fields")


def string(value):
    require(isinstance(value, str) and bool(value), "expected nonempty string")


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), "invalid SHA-256")


def number(value):
    require(type(value) is int and 0 <= value <= 10**19, "expected nonnegative integer")


def path_name(value, root=False):
    require(isinstance(value, str) and len(value) <= 4096, "invalid report path")
    if root and value == '':
        return
    require(value and not value.startswith('/') and '\\' not in value and
            not re.match(r'^[A-Za-z]:', value) and
            all(part not in ('', '.', '..') for part in value.split('/')), "noncanonical report path")


def records(value):
    require(isinstance(value, list) and len(value) <= MAX_ITEMS, "expected bounded array")
    return value


def policy(value, digest_required=True):
    obj(value, ['source', 'digest'] if digest_required else ['source'], [] if digest_required else ['digest'])
    string(value['source'])
    if 'digest' in value:
        sha(value['digest'])


def catalog():
    return json.loads(resources.files('azt_resources').joinpath('guidance-v1.json').read_text(encoding='utf-8'))['rules']


def explain(rule):
    rules = catalog()
    require(rule in rules, "unknown rule ID")
    return dict(schema='azt.guidance.v1', rule=rule, **rules[rule])


def engine_identity(engine):
    modules = {}
    for module in (engine, intake):
        location = Path(module.__file__)
        modules[location.name] = hashlib.sha256(location.read_bytes()).hexdigest()
    return {'version': engine.__version__, 'implementation_sha256': intake.digest(modules),
            'text_rules_sha256': intake.digest(engine.TEXT_RULES)}


def _validate_scan(report):
    """Validate supported scan-v1, including historical reports without engine provenance.

    No rule catalog lookup can turn an unknown historical rule into a clean result.
    Embedded admission data is bounded but never consumed as authority.
    """
    bounded(report)
    fields = ['schema_version', 'version', 'decision', 'threshold', 'input_digest',
              'manifest', 'policy', 'scope', 'inventory', 'findings',
              'suppressed_findings', 'target_requests']
    obj(report, fields, ['engine', 'admission'])
    require(type(report['schema_version']) is int and report['schema_version'] == 1, "unsupported scan schema version")
    string(report['version'])
    require(report['threshold'] in ('high', 'medium', 'any'), "invalid threshold")
    policy(report['policy'])
    if 'engine' in report:
        obj(report['engine'], ['version', 'implementation_sha256', 'text_rules_sha256'])
        require(report['engine']['version'] == report['version'], "engine/version conflict")
        sha(report['engine']['implementation_sha256']); sha(report['engine']['text_rules_sha256'])
    manifest = {}
    for entry in records(report['manifest']):
        require(isinstance(entry, dict) and entry.get('kind') in ('file', 'directory', 'symlink', 'excluded'), "invalid manifest entry")
        kind = entry['kind']
        obj(entry, ['path', 'kind'] + (['sha256', 'executable'] if kind == 'file' else ['target_digest'] if kind == 'symlink' else []))
        path_name(entry['path'])
        require(entry['path'] not in manifest, "duplicate manifest path")
        if kind == 'file':
            sha(entry['sha256']); require(type(entry['executable']) is bool, "invalid executable bit")
        if kind == 'symlink':
            sha(entry['target_digest'])
        manifest[entry['path']] = entry
    sha(report['input_digest'])
    require(intake.digest(report['manifest']) == report['input_digest'], "manifest/input digest mismatch")
    scope = report['scope']
    obj(scope, ['complete', 'inspected', 'skipped', 'errors', 'limits', 'bytes_read',
                'builtin_excluded_directories', 'text_extensions'])
    require(type(scope['complete']) is bool, "invalid completeness")
    number(scope['bytes_read'])
    obj(scope['limits'], ['file_bytes', 'total_bytes', 'entries', 'depth', 'line_characters', 'findings'])
    for value in scope['limits'].values():
        number(value)
    for key in ('builtin_excluded_directories', 'text_extensions'):
        for value in records(scope[key]):
            require(isinstance(value, str), "invalid scope declaration")
    inspected = set()
    for entry in records(scope['inspected']):
        obj(entry, ['path', 'analyses']); path_name(entry['path'])
        require(entry['path'] not in inspected, "duplicate inspection path")
        inspected.add(entry['path'])
        require(manifest.get(entry['path'], {}).get('kind') == 'file', "inspection lacks file evidence")
        require(records(entry['analyses']) and all(isinstance(v, str) and v for v in entry['analyses']), "invalid analyses")
    errors = records(scope['errors'])
    for entry in errors:
        obj(entry, ['path', 'reason']); path_name(entry['path'], root=True); string(entry['reason'])
    require(scope['complete'] == (not errors), "completeness/errors conflict")
    for entry in records(scope['skipped']):
        obj(entry, ['path', 'reason'], ['policy']); path_name(entry['path']); string(entry['reason'])
        require(entry['path'] in manifest, "skip lacks manifest evidence")
        if 'policy' in entry:
            policy(entry['policy'], False)
    accounted = inspected | {e['path'] for e in scope['skipped']} | {e['path'] for e in errors}
    require(all(e['kind'] != 'file' or p in accounted for p, e in manifest.items()), "file lacks inspection/skip/error disposition")
    known_paths = set(manifest) | {entry['path'] for entry in errors}
    for entry in records(report['inventory']):
        obj(entry, ['path', 'class', 'severity', 'why']); path_name(entry['path'])
        require(entry['path'] in known_paths and entry['severity'] in SEVERITY, "inventory lacks evidence")
        string(entry['class']); string(entry['why'])
    require(len({e['path'] for e in report['inventory']}) == len(report['inventory']), "duplicate inventory path")
    for key in ('findings', 'suppressed_findings'):
        for f in records(report[key]):
            obj(f, ['rule', 'severity', 'description', 'path', 'line', 'excerpt'] + (['exception'] if key == 'suppressed_findings' else []))
            require(isinstance(f['rule'], str) and re.fullmatch(r'[a-z][a-z0-9_.]{0,100}', f['rule']), "invalid rule ID")
            require(f['severity'] in SEVERITY, "invalid severity")
            path_name(f['path']); number(f['line'])
            require(f['path'] in known_paths, "finding lacks manifest/error evidence")
            string(f['description']); require(isinstance(f['excerpt'], str), "invalid excerpt")
            if key == 'suppressed_findings':
                obj(f['exception'], ['reason', 'policy'], ['file_sha256']); string(f['exception']['reason']); policy(f['exception']['policy'])
                require(f['exception']['policy'] == report['policy'], "exception policy conflict")
                require(manifest.get(f['path'], {}).get('sha256') is not None, "exception lacks content binding")
                if 'file_sha256' in f['exception']:
                    require(f['exception']['file_sha256'] == manifest[f['path']]['sha256'], "stale exception binding")
    for entry in records(report['target_requests']):
        obj(entry, ['path', 'sha256', 'status', 'requested_lines']); path_name(entry['path']); sha(entry['sha256']); number(entry['requested_lines'])
        require(entry['status'] == 'untrusted; not applied', "target request claimed authority")
        require(manifest.get(entry['path'], {}).get('sha256') == entry['sha256'], "target request binding mismatch")
    failed = any(SEVERITY[f['severity']] <= {'high': 0, 'medium': 1, 'any': 2}[report['threshold']] for f in report['findings'])
    expected = 'incomplete' if errors else 'deny' if failed else 'pass'
    require(report['decision'] == expected, "decision contradicts findings/scope/threshold")
    return report


def validate_scan(report):
    try:
        return _validate_scan(report)
    except (KeyError, TypeError, AttributeError) as error:
        raise ReviewError('invalid scan structure') from error


def adapt(value):
    """Return review-v1, retaining source identity while omitting raw excerpts.

    Review exports may be read back; their input record hash then identifies that
    derivative, not the original serialized scan. No history is authenticated.
    """
    bounded(value)
    source_digest = intake.digest(value)
    if isinstance(value, dict) and value.get('schema') == 'azt.review.v1':
        obj(value, ['schema', 'source_report_sha256', 'scan', 'guidance', 'notice', 'redaction'])
        sha(value['source_report_sha256'])
        value = value['scan']
    scan = copy.deepcopy(validate_scan(value))
    scan.pop('admission', None)
    guidance = catalog()
    for f in scan['findings'] + scan['suppressed_findings']:
        f['excerpt'] = '[omitted in review export]'
        # Source descriptions can carry credentials even when excerpts do not.
        f['description'] = guidance.get(f['rule'], {}).get('meaning', 'Unknown rule; consult the producing engine.')
    rules = sorted({f['rule'] for f in scan['findings'] + scan['suppressed_findings']})
    return {'schema': 'azt.review.v1', 'source_report_sha256': source_digest,
            'scan': scan, 'guidance': {r: guidance.get(r) for r in rules}, 'notice': NOTICE,
            'redaction': 'Derivative: excerpts and source descriptions omitted; admission discarded. Paths, reasons and labels may still be sensitive.'}


def ordered(items):
    return sorted(items, key=lambda v: intake.canonical(v))


def multiset_delta(before, after):
    b = Counter(intake.canonical(x).decode() for x in before)
    a = Counter(intake.canonical(x).decode() for x in after)
    return {'added': [json.loads(x) for x in sorted((a-b).elements())],
            'removed': [json.loads(x) for x in sorted((b-a).elements())]}


def compare(before, after):
    b, a = adapt(before), adapt(after)
    bs, ass = b['scan'], a['scan']
    bm = {e['path']: e for e in bs['manifest']}
    am = {e['path']: e for e in ass['manifest']}
    bsrf = {e['path']: e for e in bs['inventory']}
    asrf = {e['path']: e for e in ass['inventory']}
    reduced, differences = [], {}
    for key in ('version', 'engine', 'policy', 'threshold'):
        if bs.get(key) != ass.get(key):
            differences[key] = {'before': bs.get(key), 'after': ass.get(key)}
            reduced.append(key + ' changed')
    if not bs.get('engine') or not ass.get('engine'):
        reduced.append('missing engine implementation/rules provenance in legacy report')
    if any('file_sha256' not in f['exception'] for scan in (bs, ass) for f in scan['suppressed_findings']):
        reduced.append('legacy exception approval digest missing; manifest binding is only an inference')
    scope_keys = ('limits', 'builtin_excluded_directories', 'text_extensions', 'skipped')
    for key in scope_keys:
        x, y = bs['scope'][key], ass['scope'][key]
        if (ordered(x) if isinstance(x, list) else x) != (ordered(y) if isinstance(y, list) else y):
            differences['scope.'+key] = {'before': x, 'after': y}
            reduced.append('scope.'+key+' changed')
    for side, scan in [('before', bs), ('after', ass)]:
        if not scan['scope']['complete']:
            reduced.append(side+' inspection incomplete')
    for key in ('inspected', 'errors', 'complete'):
        x, y = bs['scope'][key], ass['scope'][key]
        if (ordered(x) if isinstance(x, list) else x) != (ordered(y) if isinstance(y, list) else y):
            differences['scope.'+key] = {'before': x, 'after': y}
    bi = {e['path']: set(e['analyses']) for e in bs['scope']['inspected']}
    ai = {e['path']: set(e['analyses']) for e in ass['scope']['inspected']}
    if any(p in am and not analyses <= ai.get(p, set()) for p, analyses in bi.items()):
        reduced.append('previously inspected content has reduced analysis')
    surfaces = {'added': [], 'removed': [], 'modified': [], 'unavailable': []}
    content = {'added': [], 'removed': [], 'modified': [], 'unavailable': []}
    for p in sorted(set(bm) | set(am)):
        key = 'added' if p not in bm else 'removed' if p not in am else 'modified'
        if key == 'removed' and not ass['scope']['complete']:
            key = 'unavailable'
        if bm.get(p) != am.get(p):
            content[key].append(p)
    for p in sorted(set(bsrf) | set(asrf)):
        if p in bsrf and (p not in am or am[p].get('kind') != 'file') and not ass['scope']['complete']:
            surfaces['unavailable'].append(p)
        elif p not in bsrf:
            surfaces['added'].append(p)
        elif p not in asrf:
            surfaces['removed'].append(p)
        elif bm.get(p) != am.get(p) or bsrf[p] != asrf[p]:
            surfaces['modified'].append(p)
    findings = {'new': [], 'persisting': [], 'no_longer_observed': [], 'unresolved': []}
    grouped = []
    for scan in (bs, ass):
        groups = defaultdict(list)
        for f in scan['findings']:
            groups[(f['rule'], f['path'], f['severity'])].append(f)
        grouped.append(groups)
    # Same deterministic inputs cannot explain a changed finding count/line.
    # These are untrusted assertions, not proof that either report is authentic.
    if not reduced:
        for key in set(grouped[0]) | set(grouped[1]):
            p = key[1]
            if p in bm and bm.get(p) == am.get(p) and bi.get(p) == ai.get(p):
                old_lines = sorted(f['line'] for f in grouped[0].get(key, []))
                new_lines = sorted(f['line'] for f in grouped[1].get(key, []))
                if old_lines != new_lines:
                    reduced.append('contradictory findings on unchanged analyzed content')
                    break
    for key in sorted(set(grouped[0]) | set(grouped[1])):
        old, new = [sorted(g.get(key, []), key=lambda f: f['line']) for g in grouped]
        pairs = min(len(old), len(new))
        ambiguous = len(old) > 1 or len(new) > 1
        for i in range(pairs):
            findings['persisting'].append({'rule': key[0], 'path': key[1], 'severity': key[2],
                'before_line': old[i]['line'], 'after_line': new[i]['line'],
                'matching': 'ambiguous ordinal within rule/path/severity group' if ambiguous else 'rule/path/severity',
                'content_changed': bm.get(key[1]) != am.get(key[1]),
                'continuity': 'same occurrence not established; raw evidence unavailable'})
        findings['new'].extend(new[pairs:])
        for f in old[pairs:]:
            destination = 'unresolved' if reduced or (key[1] in am and key[1] not in ai) else 'no_longer_observed'
            findings[destination].append(f)
    # Renames are not inferred as identity. Offer bounded candidates by file hash.
    old_hashes, new_hashes = defaultdict(list), defaultdict(list)
    for p in content['removed']:
        if 'sha256' in bm[p]: old_hashes[bm[p]['sha256']].append(p)
    for p in content['added']:
        if 'sha256' in am[p]: new_hashes[am[p]['sha256']].append(p)
    renames = [{'sha256': h, 'before_paths': old_hashes[h], 'after_paths': new_hashes[h],
                'status': 'candidate only; findings remain removed/new by path'} for h in sorted(set(old_hashes) & set(new_hashes))]
    def exceptions(scan, manifest):
        return [dict(f, bound_file_sha256=manifest[f['path']]['sha256']) for f in scan['suppressed_findings']]
    exceptions_delta = multiset_delta(exceptions(bs, bm), exceptions(ass, am))
    requests = multiset_delta(bs['target_requests'], ass['target_requests'])
    meaningful = bool(any(content.values()) or any(surfaces.values()) or differences or
                      any(exceptions_delta.values()) or any(requests.values()) or
                      findings['new'] or findings['no_longer_observed'] or findings['unresolved'] or
                      any(f['before_line'] != f['after_line'] for f in findings['persisting']))
    return {'schema': 'azt.changes.v1', 'before': b, 'after': a,
            'meaningful_delta': meaningful, 'comparability': {'status': 'reduced' if reduced else 'comparable', 'reasons': sorted(set(reduced))},
            'surfaces': surfaces, 'content': content, 'findings': findings,
            'exceptions': exceptions_delta, 'target_requests': requests,
            'differences': differences, 'rename_candidates': renames,
            'matching_method': 'Exact case-sensitive relative path; findings grouped by rule/path/severity with multiplicity. No content excerpt identity, rename merge, exception inheritance or fix inference.',
            'notice': NOTICE}


def readable(value):
    """ASCII-safe, loss-visible terminal rendering: no hidden bidi/control text."""
    return json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)


def text_report(value):
    if value['schema'] == 'azt.changes.v1':
        lines = ['AZT CHANGE REVIEW', 'Meaningful delta: '+str(value['meaningful_delta']).lower(),
                 'Comparability: '+value['comparability']['status']]
        for key, entries in value['surfaces'].items():
            lines.append('Special surfaces '+key+': '+str(len(entries)))
        for key, entries in value['findings'].items():
            lines.append('Findings '+key+': '+str(len(entries)))
        for side in ('before', 'after'):
            scan = value[side]['scan']
            lines.append(side.title()+' input: '+scan['input_digest'])
            lines.append(side.title()+' inspection: '+str(len(scan['scope']['inspected']))+' files; complete='+str(scan['scope']['complete']).lower())
        for key in ('surfaces', 'content', 'findings', 'exceptions', 'target_requests'):
            for status, entries in value[key].items():
                if entries:
                    lines.append(key+' / '+status+': '+readable(entries))
        if value['differences']: lines.append('Provenance/scope differences: '+readable(value['differences']))
        if value['comparability']['reasons']: lines.append('Cautions: '+readable(value['comparability']['reasons']))
        if value['rename_candidates']: lines.append('Possible renames: '+readable(value['rename_candidates']))
        lines += ['Next step: review changed content and scope; use azt explain RULE_ID.', NOTICE]
    elif value['schema'] == 'azt.guidance.v1':
        lines = ['AZT RULE GUIDANCE: '+value['rule']]
        for key in ('meaning', 'why_review', 'context_example', 'limits', 'next_step'):
            lines.append(key.replace('_', ' ').capitalize()+': '+readable(value[key]))
    else:
        lines = ['AZT SCAN REVIEW', 'Decision: '+value['scan']['decision'], NOTICE, readable(value)]
    return '\n'.join(lines)+'\n'


def render(value, fmt):
    bounded(value)
    if fmt == 'json':
        result = readable(value)+'\n'
    elif fmt == 'text':
        result = text_report(value)
    else:
        result = ('<!doctype html><html lang="en"><meta charset="utf-8">'
                  '<meta name="viewport" content="width=device-width,initial-scale=1">'
                  '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">'
                  '<title>AZT local review</title><style>body{background:#0b1220;color:#edf5ff;font:16px/1.6 system-ui;margin:2em;max-width:100ch}h1{color:#56e0ee}pre{white-space:pre-wrap;overflow-wrap:anywhere}a{color:inherit}</style>'
                  '<h1>AZT local review</h1><p>Redacted local derivative. No authentication or approval. Paths and labels may still be sensitive.</p><pre>'+
                  html.escape(text_report(value))+'</pre></html>')
    raw = result.encode('utf-8')
    require(len(raw) <= MAX_OUTPUT, "rendered output limit exceeded")
    return result


def write_new(path, text):
    """Create-only export in an operator-owned private parent; no symlink following."""
    value = Path(path)
    require('..' not in value.parts and value.name not in ('', '.', '..'), "unsafe output path")
    parent = intake.open_absolute(value.absolute().parent, directory=True)
    fd = None
    try:
        info = os.fstat(parent)
        require(info.st_uid == os.getuid() and not info.st_mode & 0o022, "output parent must be operator-owned, not group/world writable")
        fd = os.open(value.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            fd = None
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


def add_parsers(sub):
    changes = sub.add_parser('changes', help='compare two saved scans; informational, never approval')
    changes.add_argument('--before', required=True); changes.add_argument('--after', required=True)
    report = sub.add_parser('report', help='validate and redact a saved scan into a local review')
    report.add_argument('--input', required=True)
    guidance = sub.add_parser('explain', help='offline guidance for a scanner rule')
    guidance.add_argument('rule')
    for parser in (changes, report, guidance):
        group = parser.add_mutually_exclusive_group()
        group.add_argument('--json', action='store_true')
        group.add_argument('--format', choices=['json', 'text', 'html'], default='text')
        parser.add_argument('--output', help='create a new private local file; never overwrite')


def command(args):
    try:
        if args.cmd == 'changes': value = compare(load(args.before), load(args.after))
        elif args.cmd == 'report': value = adapt(load(args.input))
        else: value = explain(args.rule)
        fmt = 'json' if args.json else args.format
        output = render(value, fmt)
        if args.output: write_new(args.output, output)
        else: print(output, end='')
        return 0
    except (ReviewError, intake.IntakeError, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        import sys
        diagnostic = str(error) if isinstance(error, ReviewError) else 'invalid input or unsafe input/output operation'
        if args.json or args.format == 'json':
            print(json.dumps({'schema': 'azt.review-error.v1', 'status': 'error',
                              'error': diagnostic, 'notice': 'No approval issued.'}))
        print('azt: review failed: '+diagnostic, file=sys.stderr)
        return 2
