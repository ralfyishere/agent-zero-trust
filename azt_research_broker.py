"""One mission, one launch-owned channel; no caller-selectable identity or handlers.

Only the external runtime calls handle. Unit calls exercise policy, not isolation.
This broker cannot run commands, fetch URLs, install packages or issue admission.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import time

import azt_intake as intake
import azt_review as review
from azt_research import ResearchError, require, identifier

PROTOCOL = 'azt.research-channel.v1'
MAX_CALLS = 512
MAX_RESPONSE = 65536
MAX_TOTAL_RESPONSE = 8 * 1024 * 1024
MAX_OBSERVATIONS = 128
LEASE_SECONDS = 20
POLICY = {'schema': 'azt.research-policy.v1', 'operations': ['read', 'check', 'observe', 'review'],
          'requests': MAX_CALLS, 'response_bytes': MAX_RESPONSE, 'total_response_bytes': MAX_TOTAL_RESPONSE,
          'observations': MAX_OBSERVATIONS, 'lease_seconds': LEASE_SECONDS,
          'delegation': False, 'network': False, 'arbitrary_paths': False}


class Broker:
    def __init__(self, capture, audit_path, clock=time.monotonic):
        self._documents = copy.deepcopy(capture.documents)
        self._report = copy.deepcopy(capture.report)
        self.mission_id = 'm-' + secrets.token_hex(16)
        self.run_id = 'r-' + secrets.token_hex(16)
        self.clock = clock
        self.deadline = clock() + LEASE_SECONDS
        self.state = 'active'
        self.completed = False
        self.review_completed = False
        self.calls = self.response_bytes = 0
        self.events, self.observations = [], []
        self._seen, self._checked, self._read = {}, set(), set()
        self._audit = None
        self.policy_sha256 = intake.digest(POLICY)
        self.controller_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        p = Path(audit_path)
        require('..' not in p.parts, 'unsafe audit path')
        parent = intake.open_absolute(p.absolute().parent, directory=True)
        try:
            meta = os.fstat(parent)
            require(meta.st_uid == os.getuid() and not meta.st_mode & 0o077, 'audit parent must be private and operator-owned')
            self._audit = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            self._record('lifecycle', 'started', 'mission_frozen')
        except BaseException:
            self.close()
            raise

    def source_descriptors(self):
        return [{'id': d['id'], 'sha256': d['sha256']} for d in self._documents.values()]

    def _record(self, operation, decision, reason, source=None, request_sha256=None):
        event = {'sequence': len(self.events), 'mission': self.mission_id, 'run': self.run_id,
                 'policy_sha256': self.policy_sha256, 'input_sha256': self._report['input_sha256'],
                 'elapsed_ms': max(0, int((self.clock() - (self.deadline - LEASE_SECONDS)) * 1000)),
                 'operation': operation, 'decision': decision, 'reason': reason,
                 'source': source, 'request_sha256': request_sha256,
                 'scope': 'controller broker observation; not proof of worker intent or direct OS actions'}
        raw = intake.canonical(event) + b'\n'
        try:
            require(self._audit is not None and os.write(self._audit, raw) == len(raw), 'audit write failed')
            os.fsync(self._audit)
        except (OSError, ResearchError):
            self.state = 'evidence_failed'
            self.completed = False
            raise ResearchError('required evidence storage failed; mission revoked')
        self.events.append(event)

    def revoke(self):
        if self.state == 'active':
            self.state = 'revoked'
            self.completed = False
            self._record('lifecycle', 'revoked', 'operator_or_controller_stop')

    def close(self):
        if self._audit is not None:
            os.close(self._audit)
            self._audit = None

    def summary(self):
        return {'mission': self.mission_id, 'run': self.run_id, 'policy_sha256': self.policy_sha256,
                'controller_sha256': self.controller_sha256,
                'input_sha256': self._report['input_sha256'], 'state': self.state,
                'completed': self.completed, 'calls': self.calls, 'response_bytes': self.response_bytes,
                'review_completed_before_revocation': self.review_completed,
                'checked_sources': len(self._checked), 'read_sources': len(self._read),
                'documents': [{k:d[k] for k in ('id','registration','path','sha256')} for d in self._documents.values()],
                'observations': copy.deepcopy(self.observations), 'limits': dict(POLICY),
                'worker_identity': 'single controller-created channel; no asserted roles accepted',
                'record_authentication': 'none; protected placement in this run, not a signed or complete syscall log'}

    def handle(self, request):
        self.calls += 1
        # Floods cannot grow the ledger forever. Runtime terminates on this error.
        if self.calls > MAX_CALLS:
            self.state = 'exhausted'; self.completed = False
            raise ResearchError('mission request budget exhausted')
        req_id, operation, source = None, 'invalid', None
        fingerprint = None
        try:
            require(isinstance(request, dict), 'invalid_request')
            require(len(intake.canonical(request)) <= MAX_RESPONSE, 'request_too_large')
            review.bounded(request)
            req_id = identifier(request.get('id'))
            require(self.state == 'active', 'mission_not_active')
            if self.clock() >= self.deadline:
                self.state = 'expired'; self.completed = False
                raise ResearchError('lease_expired')
            require(request.get('mission') == self.mission_id and request.get('run') == self.run_id,
                    'mission_or_run_mismatch')
            op = request.get('operation')
            require(op in POLICY['operations'], 'operation_not_permitted')
            operation = op
            fields = {'id', 'mission', 'run', 'operation'}
            if op in ('read', 'check'): fields |= {'source', 'sha256'}
            if op == 'observe': fields.add('observation')
            require(set(request) == fields, 'unexpected_authority_or_argument_fields')
            fingerprint = intake.digest(request)
            if req_id in self._seen:
                old_fingerprint, response = self._seen[req_id]
                require(old_fingerprint == fingerprint, 'conflicting_request_id')
                self._record(operation, 'replayed', 'identical_request_not_reexecuted', request_sha256=fingerprint)
                return self._response_budget(copy.deepcopy(response))
            result = {}
            if op in ('read', 'check'):
                source = request['source']
                require(isinstance(source, str) and source in self._documents, 'unknown_source')
                d = self._documents[source]
                require(request['sha256'] == d['sha256'], 'source_identity_mismatch')
                require(hashlib.sha256(d['text'].encode()).hexdigest() == d['sha256'], 'frozen_source_identity_mismatch')
                if op == 'read':
                    result = {'text': d['text'], 'source': source, 'sha256': d['sha256']}
                else:
                    require(d['check'] is not None, 'inspection_not_available')
                    result = copy.deepcopy(d['check'])
                    result['total_findings'] = len(result['findings'])
                    result['findings'] = result['findings'][:8]
                    result['omitted_display_entries'] = result['total_findings'] - len(result['findings'])
            elif op == 'observe':
                observation = request['observation']
                review.obj(observation, ['source', 'sha256', 'line', 'rule'])
                source = observation['source']
                require(isinstance(source, str) and source in self._checked, 'observation_requires_checked_source')
                d = self._documents[source]
                require(observation['sha256'] == d['sha256'] and type(observation['line']) is int and
                        any(observation['line'] == f['line'] and observation['rule'] == f['rule'] for f in d['check']['findings']),
                        'observation_not_supported_by_checked_evidence')
                require(len(self.observations) < MAX_OBSERVATIONS, 'observation_budget_exhausted')
                result = {'accepted_as': 'source-linked observation proposal, not truth or authority'}
            else:
                require(self._read == set(self._documents) and self._checked == set(self._documents), 'review_sources_not_completed')
                require(self._report['complete'], 'inspection_incomplete')
                result = {'completed': True, 'source_count': len(self._documents), 'observation_count': len(self.observations)}
            response = {'id': req_id, 'decision': 'allowed', 'reason': 'within_frozen_mission', 'result': result}
            self._response_budget(response)
            # Audit must succeed BEFORE returning data/committing execution state.
            self._record(operation, 'executed', 'within_frozen_mission', source, fingerprint)
            if op == 'read': self._read.add(source)
            elif op == 'check': self._checked.add(source)
            elif op == 'observe': self.observations.append(copy.deepcopy(request['observation']))
            else:
                self.completed = True
                self.review_completed = True
            self._seen[req_id] = (fingerprint, copy.deepcopy(response))
            return response
        except (ResearchError, review.ReviewError) as exc:
            if self.state == 'evidence_failed':
                raise
            # Reasons contain maintained labels only; never rejected paths, URLs,
            # recipients, text, roles or arbitrary caller-supplied operation names.
            reason = str(exc)
            if reason not in {'invalid_request', 'request_too_large', 'mission_not_active', 'lease_expired',
                              'mission_or_run_mismatch', 'operation_not_permitted', 'unexpected_authority_or_argument_fields',
                              'conflicting_request_id', 'unknown_source', 'source_identity_mismatch', 'frozen_source_identity_mismatch',
                              'inspection_not_available', 'observation_requires_checked_source',
                              'observation_not_supported_by_checked_evidence', 'observation_budget_exhausted',
                              'review_sources_not_completed', 'inspection_incomplete'}:
                reason = 'invalid_request_structure'
            self._record(operation, 'broker-rejected', reason, request_sha256=fingerprint)
            response = {'id': req_id, 'decision': 'denied', 'reason': reason, 'result': {}}
            if req_id is not None and fingerprint is not None and req_id not in self._seen:
                self._seen[req_id] = (fingerprint, copy.deepcopy(response))
            return self._response_budget(response)

    def _response_budget(self, response):
        size = len(intake.canonical(response)) + 1
        if size > MAX_RESPONSE or self.response_bytes + size > MAX_TOTAL_RESPONSE:
            self.state = 'exhausted'; self.completed = False
            raise ResearchError('mission response budget exhausted')
        self.response_bytes += size
        return response
