"""Bounded English request observations over intake-owned text snapshots.

No filesystem or network operations. Subjects of requests are never retrieved.
This is selected wording analysis, not intent classification or secret detection.
"""
import re
from pathlib import PurePosixPath

RULE = "request.sensitive_disclosure"
SETTINGS = {"method": "sensitive-request-v1.2", "block_characters": 4096,
            "block_lines": 16, "references_per_request": 2,
            "reference_characters": 256, "requests": 1000,
            "retained_characters": 32000000, "correlations": 2000}
LIMITATIONS = ["bounded-english-context", "wording-not-intent",
               "no-secret-content-inspected", "destination-not-verified"]
CLASSES = {
    "environment": r"\b(?:environment\s+(?:variables?|details|dumps?)|env(?:ironment)?\s+dump|printenv)\b",
    "shell-history": r"\b(?:(?:shell|bash|zsh|command|terminal)\s+histor(?:y|ies))\b|\.bash_history\b|\.zsh_history\b",
    "configuration": r"\b(?:(?:local|credential(?:-bearing)?|cloud|authentication)\s+config(?:uration)?(?:\s+(?:files?|folder|directory))?)\b|(?<!\w)\.env\b|\.aws/credentials\b|\.npmrc\b|\.netrc\b",
    "tokens": r"\b(?:(?:access|api|authentication|auth|session|secret|bearer)(?:\s+|-)(?:tokens?|keys?)|tokens?)\b",
    "private-keys": r"\bprivate\s+(?:ssh\s+)?keys?\b|\bid_(?:rsa|ed25519)\b",
}
PATTERNS = {key: re.compile(value, re.I) for key, value in CLASSES.items()}
SHARE = re.compile(r"\b(?:send|share|upload|submit|attach|paste|email|forward|post|transmit|provide)\b", re.I)
COLLECT = re.compile(r"\b(?:gather|collect|copy|capture|bundle|include|export|dump)\b", re.I)
NEGATE = re.compile(r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|avoid|not\s+to)\b", re.I)
NEGATED_ACTION = re.compile(r"\b(?:do\s+not|don't|never|must\s+not|mustn't|should\s+not|shouldn't|avoid|not\s+to)\s+(?:ever\s+)?$", re.I)
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
# Only these adjacent bare-token noun phrases are recognized as measurements or
# parser material. A credential-qualified match (API/access/auth token) is never
# removed, and another bare token elsewhere in the clause is checked separately.
TOKEN_MEASURE_AFTER = re.compile(r"\s+(?:counts?|budgets?|usage|totals?|limits?)\b", re.I)
TOKEN_MEASURE_BEFORE = re.compile(r"\b(?:count|the\s+number|budget|total|limit)\s+(?:of|for)\s+(?:model\s+)?$", re.I)
TOKEN_SYNTAX_BEFORE = re.compile(r"\b(?:parser|lexical|syntax)\s+$", re.I)
# A selected explicit credential role defeats an otherwise noncredential noun
# label. Merely discussing an authenticated API request does not establish that
# the requested token count is itself an authentication value.
TOKEN_AUTH_ROLE = re.compile(
    r"^\s+(?:(?:counts?|budgets?|usage|totals?|limits?)\s+)?"
    r"(?:(?:(?:(?:that|which)\s+(?:is|are)\s+)?(?:used|required|needed)\s+)?"
    r"(?:to\s+(?:authenticate|authorize|log\s+in|sign\s+in)|for\s+(?:authentication|authorization))"
    r"|(?:that|which)\s+(?:authenticates?|authorizes?|grants?\s+access))\b", re.I)
TOKEN_CREDENTIAL_VALUE = re.compile(
    r"\b(?:including|and|plus|along\s+with)\s+(?:(?:the|your|its|their|a)\s+)?"
    r"(?:(?:complete|full|actual|raw)\s+)?(?:credential|authentication|access|secret)\s+"
    r"(?:values?|contents?)\b", re.I)


def information_classes(text):
    """Classify selected subjects, retaining ambiguity for unqualified tokens.

    Bare-token measurements use at most 64 adjacent characters on either side;
    this is not an exemption for a paragraph discussing model costs. In
    particular, 'token count and API key' still names authentication material.
    Explicit credential values or a directly stated authentication role take
    precedence over a parser/measurement label. 'A number of tokens' can request
    several values and is not the definite quantity phrase 'the number of'.
    """
    found = {key for key, pattern in PATTERNS.items()
             if key != 'tokens' and pattern.search(text)}
    for match in PATTERNS['tokens'].finditer(text):
        bare = match.group().lower() in ('token', 'tokens')
        before = text[max(0, match.start()-64):match.start()]
        after = text[match.end():match.end()+64]
        credential_role = TOKEN_AUTH_ROLE.search(after) or TOKEN_CREDENTIAL_VALUE.search(after)
        if bare and not credential_role and (TOKEN_MEASURE_AFTER.match(after) or
                     TOKEN_MEASURE_BEFORE.search(before) or
                     TOKEN_SYNTAX_BEFORE.search(before)):
            continue
        found.add('tokens')
        break
    return found


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
    """Keep affirmative action/object spans inside a bounded paragraph.

    Sentence/semicolon and explicit contrast boundaries reset a prohibition.
    Coordinated actions otherwise inherit it. Each action ends at the next
    action, so a positive version request cannot inherit a prohibited object's
    words. Original block ranges, not this analysis-only view, locate evidence.
    This is selected imperative grammar, not general English interpretation.
    """
    out = []
    text = text.replace('\u2019', "'")
    text = re.sub(r'\n[ \t]*[-*+][ \t]+(?=(?:(?:do not|never|don\x27t)\s+)?(?:send|share|upload|submit|attach|paste|email|forward|post|transmit|provide|gather|collect|copy|capture|bundle|include|export|dump)\b)', '; ', text, flags=re.I)
    normalized = re.sub(r"[\t\r\n ]+", " ", text)
    # Split on grammar, never on a word inside an explicit reference/address.
    boundary_view = list(normalized)
    for match in list(LINK.finditer(normalized)) + list(ADDRESS.finditer(normalized)):
        boundary_view[match.start():match.end()] = ' ' * (match.end()-match.start())
    for match in BARE.finditer(normalized):
        boundary_view[match.start(1):match.end(1)] = ' ' * len(match.group(1))
    cuts = list(re.finditer(r"(?<=[.!?;])\s+|\b(?:but|however|instead|yet)\b\s*,?", ''.join(boundary_view), re.I))
    starts = [0] + [m.end() for m in cuts]
    ends = [m.start() for m in cuts] + [len(normalized)]
    for start, end in zip(starts, ends):
        clause = normalized[start:end]
        if re.search(r"\b(?:warning|unsafe|dangerous)\b", clause, re.I) and re.search(r"\b(?:do not follow|never follow|do not execute|not an instruction)\b", clause, re.I):
            continue
        # Reference labels/addresses may contain action words. They are data,
        # not new imperatives that may cut a supported Markdown link in half.
        action_view = list(clause)
        for match in list(LINK.finditer(clause)) + list(ADDRESS.finditer(clause)):
            action_view[match.start():match.end()] = ' ' * (match.end()-match.start())
        for match in BARE.finditer(clause):
            action_view[match.start(1):match.end(1)] = ' ' * len(match.group(1))
        action_view = ''.join(action_view)
        actions = sorted(list(SHARE.finditer(action_view)) + list(COLLECT.finditer(action_view)), key=lambda m: m.start())
        # 'environment dump' / 'diagnostics bundle' are subjects, not imperatives.
        actions = [m for m in actions if not (m.group().lower() in ('dump', 'bundle', 'copy') and
                   re.search(r'\b(?:environment|env|diagnostics|the|a|this|one)\s+$', clause[:m.start()], re.I))]
        if not actions:
            # Retain action-free contact/reference/list context for one-hop use,
            # but not explicitly excluded noun lists.
            out.append(re.split(r'\b(?:never|excluding|except)\b', clause, maxsplit=1, flags=re.I)[0])
            continue
        prohibited, pending = False, ''
        for index, action in enumerate(actions):
            prefix = clause[actions[index-1].end() if index else 0:action.start()]
            explicit = NEGATED_ACTION.search(prefix[-80:])
            prohibited = bool(explicit) or prohibited
            end = actions[index+1].start() if index+1<len(actions) else len(clause)
            span = clause[action.start():end]
            # A following negated action belongs to the next span; a direct
            # excluded noun phrase also cannot become this action's subject.
            span = re.split(r"\b(?:do\s+not|don't|mustn't|shouldn't|must\s+not|should\s+not|never|excluding|except)\b", span, maxsplit=1, flags=re.I)[0]
            if not prohibited:
                if not index:
                    # Preserve only explicit reference/address evidence before
                    # the action, not unrelated preceding sensitive nouns.
                    locations = [(m.start(),m.end(),m.group()) for m in LINK.finditer(prefix)]
                    locations += [(m.start(),m.end(),m.group()) for m in BARE.finditer(prefix) if not m.group(1).startswith('[')]
                    locations += [(m.start(),m.end(),m.group()) for m in ADDRESS.finditer(prefix)
                                  if not any(a<=m.start()<b for a,b,_ in locations)]
                    if locations:
                        span = ' '.join(v for _,_,v in sorted(locations))+' '+span
                if action.group().lower() == 'include' and re.search(r'\b(?:bundle|diagnostics)\b', prefix, re.I):
                    span = prefix + span
                bare = bool(re.fullmatch(r'(?:'+SHARE.pattern+'|'+COLLECT.pattern+r')\s+(?:and|or)(?:\s+then)?\s*', span, re.I))
                if bare:
                    pending += span+' '
                else:
                    out.append(pending+span)
                    pending = ''
            else:
                pending = ''
    return '; '.join(out)


def references(text, source):
    candidates = []
    for match in LINK.finditer(text):
        # The link label itself must identify the contact/sharing context.
        # A nearby sensitive request cannot turn an unrelated style link into it.
        if RELATION.search(match.group(1)):
            candidates.append(match.group(2))
    candidates += [m.group(1).rstrip(".,;") for m in BARE.finditer(text)
                   if not m.group(1).startswith('[')]
    # The limit applies to distinct exact reference strings. Repeating one
    # supported link does not require another lookup or imply more recipients.
    unique = list(dict.fromkeys(candidates))
    result = []
    for value in unique:
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
    if len(unique) > SETTINGS["references_per_request"]:
        result = [{"path": None, "status": "limit", "sha256": None}]
    return result


def addresses(text):
    # Exact deduplication only within this bounded block: URL path/query/case and
    # email case are not normalized into an invented recipient equivalence.
    distinct = set()
    for match in ADDRESS.finditer(text):
        distinct.add(match.group())
        if len(distinct) == 9:
            break
    kinds = {"url" if value.lower().startswith(('http:', 'https:')) else "email" for value in distinct}
    return {"status": "ambiguous" if len(distinct) > 1 else "explicit" if distinct else "not-stated",
            "kind": next(iter(kinds)) if len(kinds) == 1 else "unknown", "count": min(len(distinct), 8)}


def request_classes(text, refs):
    """Require a local action/subject relation, or explicit bundle anaphora.

    A separate local read followed by a version-only sharing request is not
    evidence that the configuration was requested for sharing.
    """
    clauses = re.split(r'(?<=[.!?;])\s+|\bbut\b|\band\s+(?=(?:send|share|upload|submit|attach|paste|email|forward|post|transmit|provide)\b)', text, flags=re.I)
    disclosed, collected = set(), set()
    onward_bundle = False
    for clause in clauses:
        subject_view = ADDRESS.sub(' ', clause)
        classes = information_classes(subject_view)
        if SHARE.search(clause) and not local_share(clause):
            disclosed.update(classes)
            if re.search(r'\b(?:them|it|both|these|the\s+(?:(?:complete|full|entire)\s+)?(?:diagnostics\s+)?(?:bundle|diagnostics|details|results|material|values))\b', clause, re.I):
                onward_bundle = True
        if COLLECT.search(clause):
            collected.update(classes)
    # Bullet semicolons can separate subjects from their include directive.
    # Only explicit include/bundle scaffolding enables this bounded list case.
    if re.search(r'\b(?:bundle|diagnostics)\b[^.]{0,80}\binclude\s*:', text, re.I):
        collected.update(information_classes(ADDRESS.sub(' ', text)))
    return sorted(disclosed | (collected if onward_bundle or refs else set()))


def local_share(clause):
    return bool(LOCAL_SHARE.search(clause) or
                (re.match(r'\s*(?:share|provide)\b', clause, re.I) and
                 re.search(r'\blocally\s*[.!?,:]*\s*$', clause, re.I) and
                 not re.search(r'\b(?:with|to|after|before|while|once)\b', clause, re.I)))


def onward_request(text):
    return any(SHARE.search(clause) and not local_share(clause) and
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
                    contexts.append((support, dest, onward, refs))
            if not classes or not (share or (collect and refs)):
                continue
            if not share and not re.search(r'\b(?:sharing|share|send|upload|address|contact|recipient|destination)\b', text, re.I):
                continue
            if not share and LOCAL.search(text) and not refs:
                continue
            # Addresses elsewhere in a paragraph are not automatically the
            # destination of this request. Referenced contact blocks retain
            # their separate context summary above.
            request_destination = addresses(' '.join(c for c in re.split(r'(?<=[.!?;])\s+', text)
                                                     if SHARE.search(c)))
            if len(requests) >= SETTINGS['requests']:
                error = {'path': path, 'reason': 'sensitive request count limit exceeded'}
                if path not in capped_paths:
                    errors.append(error)
                    capped_paths.add(path)
                # Continue indexing this document's bounded contact summary.
                # Truncating it here could turn multiple recipients into one.
                continue
            support['role'] = 'request'
            requests.append((path, support.copy(), classes, share, collect, refs, request_destination,
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
                # Inspect only the already-indexed edge, never the next target.
                # A second hop is not itself a cycle. Only a known edge to the
                # primary request or this supporting source establishes one.
                known_cycle = any(r['path'] in (path, target) for r in further)
                ref['status'] = 'cycle' if known_cycle else 'additional-hop-not-followed'
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
            'These materials may contain credentials or private activity.\n'
            'AZT inspected project material within the declared scope; it did not gather diagnostics or transmit anything in response to this request.\n'
            'Destination observation: '+destination+' (not verified; recipient details omitted).\n'
            'Next step: verify the request independently, provide only necessary diagnostics, and inspect the exact contents before sharing.\n'
            'No upload or target execution was performed by this inspection.')
