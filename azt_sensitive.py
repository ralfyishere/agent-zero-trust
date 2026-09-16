"""Bounded English request observations over intake-owned text snapshots.

No filesystem or network operations. Subjects of requests are never retrieved.
This is selected wording analysis, not intent classification or secret detection.
"""
import re
from pathlib import PurePosixPath

RULE = "request.sensitive_disclosure"
SETTINGS = {"method": "sensitive-request-v1", "block_characters": 4096,
            "block_lines": 16, "references_per_request": 2,
            "reference_characters": 256, "requests": 1000,
            "retained_characters": 32000000, "correlations": 2000}
LIMITATIONS = ["bounded-english-context", "wording-not-intent",
               "no-secret-content-inspected", "destination-not-verified"]
CLASSES = {
    "environment": r"\b(?:environment\s+(?:variables?|details|dumps?)|env(?:ironment)?\s+dump|printenv)\b",
    "shell-history": r"\b(?:(?:shell|bash|zsh|command|terminal)\s+histor(?:y|ies))\b|\.bash_history\b|\.zsh_history\b",
    "configuration": r"\b(?:(?:local|credential(?:-bearing)?|cloud|authentication)\s+config(?:uration)?(?:\s+(?:files?|folder|directory))?)\b|(?<!\w)\.env\b|\.aws/credentials\b|\.npmrc\b|\.netrc\b",
    "tokens": r"\b(?:(?:access|api|authentication|auth|session|secret)\s+(?:tokens?|keys?)|tokens?)\b",
    "private-keys": r"\bprivate\s+(?:ssh\s+)?keys?\b|\bid_(?:rsa|ed25519)\b",
}
PATTERNS = {key: re.compile(value, re.I) for key, value in CLASSES.items()}
SHARE = re.compile(r"\b(?:send|share|upload|submit|attach|paste|email|forward|post|transmit|provide)\b", re.I)
COLLECT = re.compile(r"\b(?:gather|collect|copy|capture|bundle|include|export|dump)\b", re.I)
NEGATE = re.compile(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|not\s+to)\b", re.I)
NEGATED_ACTION = re.compile(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|not\s+to)\s+(?:ever\s+)?$", re.I)
LOCAL_SHARE = re.compile(r'\b(?:share|provide)\s+(?:(?:it|them|the bundle|these diagnostics)\s+)?locally\b', re.I)
LOCAL = re.compile(r"\b(?:locally|local-only|on\s+your\s+(?:own\s+)?machine|do\s+not\s+share)\b", re.I)
BROAD = re.compile(r"\b(?:full|all|entire|complete|unredacted|raw)\b", re.I)
LIMITED = re.compile(r"\b(?:only|minimum|limited|redacted|sanitized)\b", re.I)
LINK = re.compile(r"\[([^\]\n]{1,128})\]\(([^)\n]{1,1024})\)")
# Bare references require the immediately preceding relationship phrase. A
# requested .env or credential path is never itself treated as a reference.
BARE = re.compile(r"\b(?:address\s+(?:listed\s+)?in|instructions\s+in|steps\s+in|see|refer\s+to|follow)\s+`?([^\s`<>]{1,1024})", re.I)
RELATION = re.compile(r"\b(?:address|contact|recipient|destination|sharing|upload|send|share|instructions|steps|follow|see|diagnostics)\b", re.I)
ADDRESS = re.compile(r"https?://[^\s<>\"']{1,1024}|\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,24}\b", re.I)


def blocks(text):
    """Paragraphs, up to 16 lines / 4096 chars. No cross-paragraph inference.

    Long paragraphs split into non-overlapping windows; relations straddling
    those windows are unsupported, not silently given unlimited context.
    """
    chunk, size, start = [], 0, 1
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or len(chunk) >= SETTINGS["block_lines"] or size + len(line) + 1 > SETTINGS["block_characters"]:
            if chunk:
                yield start, line_no - 1, "\n".join(chunk)
            chunk, size = [], 0
        if line.strip():
            if not chunk:
                start = line_no
            chunk.append(line)
            size += len(line) + 1
    if chunk:
        yield start, start + len(chunk) - 1, "\n".join(chunk)


def positive(text):
    """Drop locally prohibited clauses, not all quotations/fences/docs."""
    out = []
    normalized = re.sub(r"[\t\r\n ]+", " ", text)
    for clause in re.split(r"(?<=[.!?;])\s+|\bbut\b", normalized, flags=re.I):
        actions = sorted(list(SHARE.finditer(clause)) + list(COLLECT.finditer(clause)), key=lambda m: m.start())
        # A noun such as environment 'dump' must not undo a prohibition on send.
        if actions and NEGATED_ACTION.search(clause[max(0, actions[0].start()-80):actions[0].start()]):
            continue
        if re.search(r"\b(?:warning|unsafe|dangerous)\b", clause, re.I) and re.search(r"\b(?:do not follow|never follow|do not execute|not an instruction)\b", clause, re.I):
            continue
        out.append(clause)
    return "; ".join(out)


def references(text, source):
    candidates = []
    for match in LINK.finditer(text):
        if RELATION.search(text[max(0, match.start()-100):match.end()]):
            candidates.append(match.group(2))
    candidates += [m.group(1).rstrip(".,;") for m in BARE.finditer(text)
                   if not m.group(1).startswith('[')]
    result = []
    for value in dict.fromkeys(candidates):
        status, path = "unsafe", None
        if (len(value) <= SETTINGS["reference_characters"] and
                re.fullmatch(r"[A-Za-z0-9_.\-/]+", value) and
                not value.startswith('/') and
                all(p not in ('', '.', '..') for p in value.split('/')) and
                PurePosixPath(value).suffix.lower() in ('.md', '.txt', '.mdc')):
            path = str(PurePosixPath(source).parent / value)
            status = "cycle" if path == source else "missing"
        result.append({"path": path, "status": status, "sha256": None})
        if len(result) == SETTINGS["references_per_request"]:
            break
    if len(candidates) > SETTINGS["references_per_request"]:
        result = [{"path": None, "status": "limit", "sha256": None}]
    return result


def addresses(text):
    matches = list(ADDRESS.finditer(text))[:9]
    kinds = {"url" if m.group().lower().startswith(('http:', 'https:')) else "email" for m in matches}
    return {"status": "ambiguous" if len(matches) > 1 else "explicit" if matches else "not-stated",
            "kind": next(iter(kinds)) if len(kinds) == 1 else "unknown", "count": min(len(matches), 8)}


def request_classes(text, refs):
    """Require a local action/subject relation, or explicit bundle anaphora.

    A separate local read followed by a version-only sharing request is not
    evidence that the configuration was requested for sharing.
    """
    clauses = re.split(r'(?<=[.!?;])\s+|\bbut\b|\band\s+(?=(?:send|share|upload|submit|attach|paste|email|forward|post|transmit|provide)\b)', text, flags=re.I)
    disclosed, collected = set(), set()
    onward_bundle = False
    for clause in clauses:
        classes = {key for key, pattern in PATTERNS.items() if pattern.search(clause)}
        if SHARE.search(clause) and not LOCAL_SHARE.search(clause):
            disclosed.update(classes)
            if re.search(r'\b(?:them|it|both|these|bundle|diagnostics|details|results|material|values)\b', clause, re.I):
                onward_bundle = True
        if COLLECT.search(clause):
            collected.update(classes)
    # Bullet semicolons can separate subjects from their include directive.
    # Only explicit include/bundle scaffolding enables this bounded list case.
    if re.search(r'\b(?:bundle|diagnostics)\b[^.]{0,80}\binclude\s*:', text, re.I):
        collected.update(key for key, pattern in PATTERNS.items() if pattern.search(text))
    return sorted(disclosed | (collected if onward_bundle or refs else set()))


def onward_request(text):
    return any(SHARE.search(clause) and not LOCAL_SHARE.search(clause) and
               re.search(r'\b(?:them|it|both|bundle|diagnostics|details|results|material|values)\b', clause, re.I)
               for clause in re.split(r'(?<=[.!?;])\s+', text))


def analyze(snapshots, dispositions):
    """snapshots: {path: {text, sha256}} supplied only by safe intake.

    Returns findings and bounded operational analysis errors. Index each document
    once; each request does at most two O(1) lookups. No recursive resolution.
    """
    index, requests, errors, retained = {}, [], [], 0
    line_counts, capped_paths = {}, set()
    for path, source in sorted(snapshots.items()):
        retained += len(source['text'])
        if retained > SETTINGS['retained_characters']:
            errors.append({'path': path, 'reason': 'sensitive request retained-text limit exceeded'})
            break
        contexts = []
        line_counts[path] = max(1, len(source['text'].splitlines()))
        for start, end, raw in blocks(source['text']):
            text = positive(raw)
            share, collect = bool(SHARE.search(text)), bool(COLLECT.search(text))
            refs = references(text, path)
            classes = request_classes(text, refs)
            dest = addresses(text)
            support = {'path': path, 'sha256': source['sha256'], 'start_line': start,
                       'end_line': end, 'role': 'sharing-context'}
            # Contact references can establish an address without a second
            # imperative. Multiple contexts remain ambiguous, never guessed.
            onward = bool(onward_request(text))
            if dest['count'] or onward:
                if len(contexts) < 3:
                    contexts.append((support, dest, onward, bool(refs)))
            if not classes or not (share or (collect and refs)):
                continue
            if not share and not re.search(r'\b(?:sharing|share|send|upload|address|contact|recipient|destination)\b', text, re.I):
                continue
            if not share and LOCAL.search(text) and not refs:
                continue
            if len(requests) >= SETTINGS['requests']:
                error = {'path': path, 'reason': 'sensitive request count limit exceeded'}
                if path not in capped_paths:
                    errors.append(error)
                    capped_paths.add(path)
                # Continue indexing this document's bounded contact summary.
                # Truncating it here could turn multiple recipients into one.
                continue
            support['role'] = 'request'
            requests.append((path, support.copy(), classes, share, collect, refs, dest,
                             'broad' if BROAD.search(text) else 'limited' if LIMITED.search(text) else 'unspecified'))
        index[path] = contexts
    findings, correlations = [], 0
    for path, primary, classes, share, collect, refs, destination, breadth in requests:
        support = [primary]
        for ref in refs:
            correlations += 1
            if correlations > SETTINGS['correlations']:
                ref.update(status='limit', sha256=None)
                errors.append({'path': path, 'reason': 'sensitive correlation work limit exceeded'})
                continue
            target = ref['path']
            if ref['status'] == 'cycle':
                ref['sha256'] = primary['sha256']
                continue
            if ref['status'] in ('unsafe', 'limit'):
                continue
            if target not in index:
                ref['status'] = dispositions.get(target, 'missing')
                continue
            contexts = index[target]
            if len(contexts) > 1:
                ref.update(status='ambiguous', sha256=snapshots[target]['sha256'])
                support.append({'path': target, 'sha256': ref['sha256'], 'start_line': 1,
                                'end_line': line_counts[target], 'role': 'sharing-context'})
                continue
            if not contexts:
                # An inspected source with no qualifying context is evidence too.
                ref.update(status='no-sharing-context', sha256=snapshots[target]['sha256'])
                support.append({'path': target, 'sha256': ref['sha256'], 'start_line': 1,
                                'end_line': line_counts[target], 'role': 'sharing-context'})
                continue
            location, found, onward, further = contexts[0]
            if further:
                ref['status'] = 'cycle'  # One hop only; never traverse another reference.
                ref['sha256'] = location['sha256']
                support.append(dict(location, role='sharing-context'))
                continue
            ref.update(status='resolved', sha256=location['sha256'])
            support.append(dict(location, role='sharing-context'))
            share = share or onward
            if found['count']:
                if destination['count']:
                    destination = {'status': 'ambiguous', 'kind': 'unknown', 'count': min(8, destination['count']+found['count'])}
                else:
                    destination = dict(found)
        if refs:
            if len(refs) > 1 or any(r['status'] == 'ambiguous' for r in refs):
                destination = {'status': 'ambiguous', 'kind': 'local-reference', 'count': destination['count']}
            elif any(r['status'] != 'resolved' for r in refs):
                destination = {'status': 'unresolved', 'kind': 'local-reference', 'count': destination['count']}
            elif not destination['count']:
                destination = {'status': 'reference-only', 'kind': 'local-reference', 'count': 0}
        findings.append({'rule': RULE, 'severity': 'MEDIUM',
            'description': 'Review before sharing potentially sensitive diagnostic or authentication information',
            'path': path, 'line': primary['start_line'], 'excerpt': '',
            'sensitive_request': {'schema': 'azt.sensitive-request.v1',
                'action': 'collect-and-share' if collect and share else 'share' if share else 'collect',
                'information_classes': classes, 'breadth': breadth, 'destination': destination,
                'support': support, 'references': refs, 'limitations': list(LIMITATIONS)}})
    return findings, errors


def summary(observation):
    """Only bounded maintained labels; never return source commands/recipients."""
    names = {'environment': 'environment variables', 'shell-history': 'shell history',
             'configuration': 'configuration', 'tokens': 'tokens', 'private-keys': 'private keys'}
    classes = ', '.join(names[key] for key in observation['information_classes'])
    verb = 'collect' if observation['action'] == 'collect' else 'share'
    destination = observation['destination']['status']
    return ('This request asks you to '+verb+' '+classes+'.\n'
            'These materials may contain credentials or private activity; their contents were not collected.\n'
            'Destination observation: '+destination+' (not verified; recipient details omitted).\n'
            'Next step: verify the request independently, provide only necessary diagnostics, and inspect the exact contents before sharing.\n'
            'No upload or target execution was performed by this inspection.')
