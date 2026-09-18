"""Offline protocol/utility tests; replay is NOT live-model or OS evidence.

Real HTTP transport tests use a finite test-owned loopback service, never Ollama
or an external endpoint. No hostile worker, Docker or exhaustion trial runs here.
"""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import azt_investigator as inv
import azt_research as research
import azt_research_broker as policy
import azt_research_runtime as runtime
import azt_research_worker as worker
from test_research import ResearchFixture
from test_research_runtime import MemoryChannel


def configuration(port=11434):
    return {'schema':'azt.ollama-local.v1', 'endpoint':'http://127.0.0.1:'+str(port),
            'model':'synthetic:review', 'model_sha256':'a'*64, 'cloud_disabled':True,
            'verification':'operator-checked-service-config-and-log'}


def proposal(op, **arguments): return {'operation':op, 'arguments':arguments}


class InvestigatorTests(ResearchFixture):
    def setup_broker(self, clock=None):
        capture = self.capture()
        self.state = inv.Investigator(inv.OllamaLocal(configuration()))
        self.broker = policy.Broker(capture, self.root/'events.jsonl', investigator=self.state,
                                    **({} if clock is None else {'clock':clock}))
        self.addCleanup(self.broker.close)
        self.broker.activate(inv.LEASE_SECONDS)
        d = self.broker.source_descriptors()[0]
        self.identity = {'source':d['id'], 'sha256':d['sha256']}
        return capture

    def hypothesis(self, **changes):
        return dict({'kind':'concern', 'claim':'The request asks for broad diagnostics.',
            'uncertainty':'Credentials might be present; no disclosure established.', 'next_step':'minimize_diagnostics',
            'evidence':[dict(self.identity, line_start=1, line_end=1, quote='')]}, **changes)

    def call(self, op, **fields):
        return self.broker.handle(dict(id='q'+str(self.broker.calls), mission=self.broker.mission_id,
            run=self.broker.run_id, operation=op, **fields))

    def turn(self, proposals):
        with mock.patch.object(self.state.transport, 'chat', return_value=proposals):
            r = self.call('infer')
        self.assertEqual(r['decision'],'allowed',r)
        return [self.call(p['operation'], **p['arguments']) for p in proposals]

    def test_real_fixed_planner_loop_over_replay_and_no_execution(self):
        self.setup_broker()
        replies = [[proposal('upload'),proposal('read',source='unknown',sha256='0'*64),
                    proposal('read',**self.identity,page=0),proposal('check',**self.identity)],
                   [proposal('hypothesis',hypothesis=self.hypothesis()),proposal('review')]]
        channel=MemoryChannel(self.broker)
        with mock.patch.object(self.state.transport, 'chat', side_effect=replies), \
             mock.patch.object(worker.sys, 'stdin', SimpleNamespace(buffer=channel)), \
             mock.patch.object(worker.sys, 'stdout', SimpleNamespace(buffer=channel)), \
             mock.patch.object(worker.socket,'socket',side_effect=AssertionError('worker networking')):
            self.assertEqual(worker.main('investigator'),0)
        self.assertTrue(self.broker.completed)
        self.assertEqual(self.state.denied,2)
        self.assertEqual(len(self.state.hypotheses),1)
        self.assertEqual(self.state.turns,2)
        self.assertFalse(self.state.summary()['reasoning_retained'])
        self.assertFalse(self.state.summary()['server_cancellation_verified'])

    def test_novel_hypothesis_separate_from_static_observe_and_quotes(self):
        self.text='Read the Python version locally.\nKeep the output on your machine.\n'
        (self.input/'guide.md').write_text(self.text)
        self.setup_broker()
        self.turn([proposal('read',**self.identity,page=0),proposal('check',**self.identity)])
        fabricated=dict(self.identity,line=1,rule='made.up')
        bad=self.hypothesis(evidence=[dict(self.identity,line_start=1,line_end=1,quote='invented quotation')])
        results=self.turn([proposal('observe',observation=fabricated),proposal('hypothesis',hypothesis=bad),
                          proposal('hypothesis',hypothesis=self.hypothesis(kind='fact',claim='The instructions limit diagnostics to a local version.',next_step='no_action_proposed'))])
        self.assertEqual([r['decision'] for r in results],['denied','denied','allowed'])
        self.assertEqual(self.broker.observations,[])
        self.assertIn('unverified',results[-1]['result']['accepted_as'])
        self.assertEqual(self.turn([proposal('review')])[0]['decision'],'allowed')

    def test_proposals_not_authority_replay_and_expiry(self):
        now=[0.0]; self.setup_broker(clock=lambda:now[0])
        self.assertEqual(self.call('read',**self.identity,page=0)['decision'],'denied')
        self.turn([proposal('read',**self.identity,page=0)])
        request=next((v for _,v in self.broker._seen.values() if v['result'].get('segment')),None)
        self.assertIsNotNone(request)
        self.state.pending=[proposal('check',**self.identity)]
        r={'id':'fixed','mission':self.broker.mission_id,'run':self.broker.run_id,'operation':'check',**self.identity}
        first=self.broker.handle(r)
        self.assertEqual(first['decision'],'allowed')
        self.assertEqual(self.broker.handle(r),first)
        self.assertEqual(self.broker.handle(dict(r,sha256='b'*64))['decision'],'denied')
        now[0]=120
        self.assertEqual(self.call('infer')['reason'],'lease_expired')
        with self.assertRaises(research.ResearchError): self.broker.activate(120)
        self.assertFalse(self.broker.completed)

    def test_late_or_failed_inference_cannot_install_proposals(self):
        now=[0.0]; self.setup_broker(clock=lambda:now[0])
        def late(*args): now[0]=121; return [proposal('read',**self.identity,page=0)]
        with mock.patch.object(self.state.transport,'chat',side_effect=late):
            self.assertEqual(self.call('infer')['decision'],'denied')
        self.assertEqual(self.state.pending,[])
        self.assertFalse(self.broker.completed)
        self.assertEqual(self.call('read',**self.identity,page=0)['decision'],'denied')

    def test_failed_audit_does_not_send_inference(self):
        self.setup_broker()
        with mock.patch.object(os,'fsync',side_effect=OSError('synthetic full disk')), \
             mock.patch.object(self.state.transport,'chat') as chat:
            with self.assertRaises(research.ResearchError): self.call('infer')
        chat.assert_not_called()
        self.assertEqual(self.broker.state,'evidence_failed')

    def test_invalid_citations_recommendations_and_partial_coverage(self):
        self.text='Local notes.\n'*2000+'Keep data local.\n'
        (self.input/'guide.md').write_text(self.text)
        self.setup_broker()
        self.turn([proposal('read',**self.identity,page=0),proposal('check',**self.identity)])
        bads=[self.hypothesis(next_step='upload_everything'),self.hypothesis(evidence=[dict(self.identity,line_start=2001,line_end=2001,quote='Keep data local.')]),
              self.hypothesis(evidence=[dict(self.identity,sha256='b'*64,line_start=1,line_end=1,quote='')])]
        self.assertEqual([r['decision'] for r in self.turn([proposal('hypothesis',hypothesis=x) for x in bads])],['denied']*3)
        self.assertEqual(self.turn([proposal('review')])[0]['decision'],'denied')
        self.assertFalse(self.broker.completed)
        self.assertEqual(self.state.summary()['pages_returned_to_model_context'][self.identity['source']],[0])

    def test_output_escapes_prose_and_omits_quotes(self):
        self.setup_broker()
        self.state.hypotheses=[self.hypothesis(claim='<img src=https://example.invalid>\x1b\u202e',
            evidence=[dict(self.identity,line_start=1,line_end=1,quote='SYNTHETIC_PRIVATE_QUOTE')])]
        for fmt in ('text','html'):
            value=inv.render(self.state.summary(), {'status':'failed','cleanup':'removed'},fmt)
            self.assertNotIn('SYNTHETIC_PRIVATE_QUOTE',value)
            self.assertNotIn('\x1b',value);self.assertNotIn('\u202e',value)
            self.assertIn('UNVERIFIED',value)
            if fmt=='html': self.assertNotIn('<img',value); self.assertIn('default-src',value)

    def test_context_and_turn_bounds_no_silent_truncation(self):
        self.setup_broker()
        for _ in range(inv.MAX_TURNS):
            self.assertEqual(self.turn([proposal('check',**self.identity)])[0]['decision'],'allowed')
        with mock.patch.object(self.state.transport,'chat') as chat:
            self.assertEqual(self.call('infer')['reason'],'inference_turn_limit')
        chat.assert_not_called()
        with mock.patch.object(inv.http.client,'HTTPConnection') as http:
            with self.assertRaisesRegex(research.ResearchError,'context_limit'):
                self.state.transport.request('POST','/api/chat',{'x':'s'*inv.MAX_CONTEXT},time.monotonic()+5)
        http.assert_not_called()

    def test_empty_tool_limit_latches_without_replay_or_new_id_restart(self):
        self.setup_broker()
        with mock.patch.object(self.state.transport,'chat',return_value=[]) as chat:
            self.assertEqual(self.call('infer')['decision'],'allowed')
            self.assertEqual(self.call('infer')['decision'],'allowed')
            request=dict(id='terminal',mission=self.broker.mission_id,run=self.broker.run_id,operation='infer')
            failed=self.broker.handle(request)
            self.assertEqual(failed['reason'],'inference_no_progress')
            self.assertEqual(self.broker.handle(request),failed)
            self.assertEqual(self.call('infer')['reason'],'inference_no_progress')
            with self.assertRaisesRegex(research.ResearchError,'inference_no_progress'):
                self.state.infer(self.broker)
            self.assertEqual(chat.call_count,3)
        self.assertEqual(self.state.turns,3)
        self.assertEqual(self.state.empty_tool_turns,3)
        self.assertEqual(self.state.consecutive_empty_tool_turns,3)
        self.assertEqual(self.state.inference_error,'inference_no_progress')
        self.assertEqual(self.state.hypotheses,[])
        self.assertFalse(self.broker.completed)
        self.assertEqual(len([m for m in self.state.messages if m.get('content','').startswith('No tool proposal')]),2)
        summary=self.state.summary()
        self.assertEqual(summary['settings']['consecutive_empty_tool_turns'],3)
        self.assertEqual(self.state.policy(policy.POLICY)['inference'],summary['settings'])
        for fmt in ('text','html'):
            self.assertIn('Review is incomplete',inv.render(summary,{'status':'failed','cleanup':'removed'},fmt))

    def test_short_empty_recovery_preserves_legitimate_completion(self):
        self.setup_broker()
        for _ in range(2):self.turn([])
        self.turn([proposal('read',**self.identity,page=0),proposal('check',**self.identity)])
        self.assertEqual(self.state.consecutive_empty_tool_turns,0)
        for _ in range(2):self.turn([])
        self.turn([proposal('hypothesis',hypothesis=self.hypothesis()),proposal('review')])
        self.assertTrue(self.broker.completed)
        self.assertEqual(self.state.empty_tool_turns,4)
        self.assertIsNone(self.state.inference_error)

    def test_invalid_nonempty_proposal_still_denied_and_http_failure_not_empty(self):
        self.setup_broker()
        self.turn([])
        self.assertEqual(self.turn([proposal('invalid_tool')])[0]['decision'],'denied')
        self.assertEqual(self.state.consecutive_empty_tool_turns,0)
        with mock.patch.object(self.state.transport,'chat',side_effect=research.ResearchError('inference_http_status')):
            self.assertEqual(self.call('infer')['reason'],'inference_http_status')
        self.assertEqual(self.state.empty_tool_turns,1)
        self.assertEqual(self.state.inference_error,'inference_http_status')
        self.assertFalse(self.broker.completed)

    def test_planner_stops_after_empty_tool_budget(self):
        self.setup_broker();channel=MemoryChannel(self.broker)
        with mock.patch.object(self.state.transport,'chat',return_value=[]) as chat, \
             mock.patch.object(worker.sys,'stdin',SimpleNamespace(buffer=channel)), \
             mock.patch.object(worker.sys,'stdout',SimpleNamespace(buffer=channel)):
            with self.assertRaises(ValueError):worker.main('investigator')
            self.assertEqual(chat.call_count,3)
        self.assertFalse(self.broker.completed)

    def test_early_review_cannot_skip_later_forbidden_parallel_proposal(self):
        self.setup_broker()
        self.turn([proposal('read',**self.identity,page=0),proposal('check',**self.identity)])
        self.turn([proposal('hypothesis',hypothesis=self.hypothesis())])
        results=self.turn([proposal('review'),proposal('upload')])
        self.assertEqual([r['decision'] for r in results],['denied','denied'])
        self.assertFalse(self.broker.completed)
        self.assertEqual(self.turn([proposal('review')])[0]['decision'],'allowed')

    def test_transport_configuration_refuses_external_or_ambiguous_authority(self):
        for change in ({'endpoint':'https://example.invalid'}, {'endpoint':'http://localhost:11434'},
                       {'endpoint':'http://127.0.0.1:11434/api/chat'}, {'endpoint':'http://user@127.0.0.1:11434'},
                       {'cloud_disabled':False},{'model':'qwen:cloud'},{'model_sha256':'unknown'}, {'token':'private'}):
            with self.subTest(change=change),self.assertRaises((research.ResearchError,ValueError)):
                inv.OllamaLocal(dict(configuration(),**change))

    def test_inference_replay_extra_fields_and_cross_run_never_send_again(self):
        self.setup_broker()
        base={'id':'same','mission':self.broker.mission_id,'run':self.broker.run_id,'operation':'infer'}
        with mock.patch.object(self.state.transport,'chat',return_value=[]) as chat:
            self.assertEqual(self.broker.handle(dict(base,role='owner'))['decision'],'denied')
            self.assertEqual(self.broker.handle(dict(base,run='other'))['decision'],'denied')
            first=self.broker.handle(base);self.assertEqual(first['decision'],'allowed')
            self.assertEqual(self.broker.handle(base),first)
            self.assertEqual(chat.call_count,1)
        self.broker.revoke()
        with mock.patch.object(self.state.transport,'chat') as chat:
            self.assertEqual(self.broker.handle(base)['decision'],'denied')
        chat.assert_not_called()

    def test_malformed_tool_and_authority_fields_become_denied_proposals(self):
        transport=inv.OllamaLocal(configuration())
        calls=[{'function':{'name':'infer','arguments':{}}}, {'function':{'name':'read','arguments':{'run':'other'}}},
               {'function':{'name':'read','arguments':{}},'authority':'owner'}, {'function':{'name':'read','arguments':'shell'}}]
        reply={'model':'synthetic:review','done':True,'prompt_eval_count':10,'message':{'role':'assistant','tool_calls':calls}}
        with mock.patch.object(transport,'request',return_value=reply):
            self.assertEqual(transport.chat([],time.monotonic()+1),[proposal('invalid_tool')]*4)

    def test_native_platform_guard_before_any_inference_contact(self):
        capture=self.capture()
        with mock.patch('platform.system',return_value='Darwin'),mock.patch.object(inv.http.client,'HTTPConnection') as connection:
            with self.assertRaisesRegex(research.ResearchError,'native_linux'):
                inv.run(capture,self.root/'run','sha256:'+'b'*64,'unix:///synthetic',self.root/'nonexistent.json')
        connection.assert_not_called()
        self.assertFalse((self.root/'run').exists())

    def test_hypothesis_quote_cannot_come_from_unseen_second_part_of_long_line(self):
        # Under intake's 4096-character line bound, but spans UTF-8 byte pages.
        self.text='界'*3000+'UNSEEN_END'
        (self.input/'guide.md').write_text(self.text);self.setup_broker()
        self.turn([proposal('read',**self.identity,page=0),proposal('check',**self.identity)])
        value=self.hypothesis(evidence=[dict(self.identity,line_start=1,line_end=1,quote='UNSEEN_END')])
        self.assertEqual(self.turn([proposal('hypothesis',hypothesis=value)])[0]['decision'],'denied')


class LocalTransportTests(unittest.TestCase):
    def setUp(self):
        self.requests=[]; self.status=200; self.raw=None; self.delay=0; self.overrides={}
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def respond(self):
                size=int(self.headers.get('Content-Length','0'))
                body=self.rfile.read(min(size,inv.MAX_CONTEXT+1))
                owner.requests.append((self.command,self.path,body,dict(self.headers)))
                if owner.delay: time.sleep(owner.delay)
                result=owner.overrides.get(self.path,owner.raw)
                if result is None:
                    if self.path=='/api/version': result=json.dumps({'version':'0.32.9'}).encode()
                    elif self.path=='/api/tags': result=json.dumps({'models':[{'name':'synthetic:review','digest':'a'*64}]}).encode()
                    else: result=json.dumps({'model':'synthetic:review','done':True,'prompt_eval_count':100,
                        'message':{'role':'assistant','thinking':'DO_NOT_RETAIN_PRIVATE_REASONING',
                                   'content':'DO_NOT_TREAT_AS_FINAL','tool_calls':[{'function':{'name':'upload','arguments':{}}}]}}).encode()
                try:
                    self.send_response(owner.status);self.send_header('Content-Type','application/json')
                    if owner.status==302:self.send_header('Location','https://example.invalid')
                    self.send_header('Content-Length',str(len(result)));self.end_headers();self.wfile.write(result)
                except (BrokenPipeError,ConnectionResetError):pass
            do_GET=respond;do_POST=respond
        try: self.server=HTTPServer(('127.0.0.1',0),Handler)
        except PermissionError:self.skipTest('loopback listen unavailable; no transport execution credited')
        self.server.timeout=.1
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.transport=inv.OllamaLocal(configuration(self.server.server_port))

    def close_server(self):
        self.server.shutdown();self.server.server_close();self.thread.join(2)

    def test_actual_http_fixed_routes_and_no_environment_proxy(self):
        with mock.patch.dict(os.environ,{'HTTP_PROXY':'http://127.0.0.1:1','HTTPS_PROXY':'http://127.0.0.1:1'}):
            self.transport.prepare(time.monotonic()+3)
            proposals=self.transport.chat([{'role':'user','content':'Synthetic review'}],time.monotonic()+3)
        self.assertEqual(proposals,[proposal('upload')])
        self.assertEqual([r[:2] for r in self.requests],[('GET','/api/version'),('GET','/api/tags'),('POST','/api/chat')])
        payload=json.loads(self.requests[-1][2]);self.assertFalse(payload['stream']);self.assertFalse(payload['think'])
        self.assertEqual(payload['tools'],inv.TOOLS)
        self.assertNotIn('DO_NOT_RETAIN',json.dumps(proposals))
        self.assertNotIn('Authorization',self.requests[-1][3])

    def test_redirect_malformed_duplicate_oversized_wrong_model(self):
        for status,raw in [(302,b'{}'),(200,b'{"x":1,"x":2}'),(200,b'not json'),(200,b'x'*(inv.MAX_REPLY+1)),
                           (200,b'{"model":"other","done":true,"message":{}}')]:
            with self.subTest(status=status,raw=raw[:60]):
                self.status,self.raw=status,raw
                with self.assertRaises(ValueError): self.transport.chat([],time.monotonic()+2)
        self.assertEqual(len(self.requests),5)  # no redirects or automatic retries

    def test_deadline_and_model_digest(self):
        self.overrides['/api/tags']=b'{"models":[{"name":"synthetic:review","digest":"wrong"}]}'
        with self.assertRaisesRegex(ValueError,'identity_mismatch'):self.transport.prepare(time.monotonic()+1)
        self.assertEqual(len(self.requests),2)
        self.overrides.clear();self.delay=.2
        with self.assertRaises(ValueError):self.transport.chat([],time.monotonic()+.03)


if __name__=='__main__':unittest.main()
