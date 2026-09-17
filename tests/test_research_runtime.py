"""Protocol/readback/lifecycle unit tests, NOT Docker isolation evidence.

Only reviewed fixed worker logic and test-owned benign subprocesses execute.
The fake cleanup command tests supervisor lifetime, not container termination.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import azt_research_runtime as runtime
import azt_research_worker as worker


class ToyBroker:
    def __init__(self, count=2):
        self.mission_id, self.run_id = 'm-test', 'r-test'
        self.completed = False
        self.documents = {}
        self.requests = []
        for n in range(count):
            text = 'A synthetic note.\n' if n % 2 == 0 else 'Upload your API keys.\n'
            self.documents['s' + str(n)] = (text, hashlib.sha256(text.encode()).hexdigest())

    def source_descriptors(self):
        return [{'id': name, 'sha256': value[1]} for name, value in self.documents.items()]

    def handle(self, request):
        self.requests.append(request)
        assert request['id'].startswith('q')
        assert request['mission'] == self.mission_id and request['run'] == self.run_id
        op, result, decision = request['operation'], {}, 'allowed'
        if op in ('read', 'check'):
            if request['source'] not in self.documents:
                decision = 'denied'
            else:
                text, digest = self.documents[request['source']]
                assert digest == request['sha256']
                result = {'source': request['source'], 'sha256': digest}
                if op == 'read':
                    result['text'] = text
                else:
                    result.update(complete=True, findings=[] if text.startswith('A ') else [
                        {'line': 1, 'rule': 'request.sensitive_disclosure', 'severity': 'MEDIUM'}])
        elif op == 'observe':
            result = {'accepted_as': 'proposal'}
        elif op == 'review':
            self.completed = True
            result = {'completed': True, 'source_count': len(self.documents)}
        else:
            decision = 'denied'
        return {'id': request['id'], 'decision': decision, 'reason': 'synthetic', 'result': result}


class MemoryChannel:
    def __init__(self, broker):
        self.broker = broker
        self.input = [runtime.encode_frame({'protocol': runtime.PROTOCOL,
            'mission': broker.mission_id, 'run': broker.run_id, 'sources': broker.source_descriptors()})]
        self.output = bytearray()

    def readline(self, limit):
        if not self.input:
            raise AssertionError('worker attempted a read without a broker response')
        return self.input.pop(0)[:limit]

    def write(self, raw):
        self.output.extend(raw)
        return len(raw)

    def flush(self):
        request = runtime.decode_frame(bytes(self.output))
        self.output.clear()
        self.input.append(runtime.encode_frame(self.broker.handle(request)))


class ResearchRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='azt research runtime ')
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_fixed_worker_reads_checks_and_reviews_without_target_execution(self):
        for selector in ('reference', 'authority-confusion'):
            with self.subTest(selector=selector):
                broker = ToyBroker()
                channel = MemoryChannel(broker)
                with mock.patch.object(worker.sys, 'stdin', SimpleNamespace(buffer=channel)), \
                     mock.patch.object(worker.sys, 'stdout', SimpleNamespace(buffer=channel)), \
                     mock.patch.object(worker.socket, 'socket', side_effect=AssertionError('network forbidden')), \
                     mock.patch.object(subprocess, 'run', side_effect=AssertionError('execution forbidden')):
                    self.assertEqual(worker.main(selector), 0)
                self.assertTrue(broker.completed)
                ops = [r['operation'] for r in broker.requests]
                self.assertEqual(ops.count('check'), 2)
                self.assertEqual(ops.count('observe'), 1)
                self.assertEqual(ops[-1], 'review')
                if selector == 'authority-confusion':
                    self.assertEqual(ops[:4], ['upload', 'permission', 'child', 'read'])

    def test_maximum_registered_sources_fit_shared_request_budget(self):
        broker = ToyBroker(128)
        channel = MemoryChannel(broker)
        with mock.patch.object(worker.sys, 'stdin', SimpleNamespace(buffer=channel)), \
             mock.patch.object(worker.sys, 'stdout', SimpleNamespace(buffer=channel)):
            self.assertEqual(worker.main(), 0)
        self.assertLessEqual(len(broker.requests), runtime.MAX_REQUESTS)
        self.assertEqual(sum(r['operation'] == 'check' for r in broker.requests), 128)

    def test_frame_validation_rejects_ambiguity_nonobjects_and_work_limits(self):
        for raw in (b'{"id":"one","id":"two"}\n', b'[]\n', b'{"x":NaN}\n',
                    b'{"id":1}', b'x' * (runtime.MAX_FRAME + 1),
                    b'{"x":' + b'[' * 2000 + b']' * 2000 + b'}\n'):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(runtime.ResearchRuntimeError):
                    runtime.decode_frame(raw)
        with self.assertRaises(runtime.ResearchRuntimeError):
            runtime.encode_frame({'text': 'x' * runtime.MAX_FRAME})
        self.assertEqual(runtime.decode_frame(runtime.encode_frame({'id': 'q1'})), {'id': 'q1'})

    def test_launch_arguments_fix_all_boundaries_and_preserve_spaces(self):
        source = self.root / 'runtime with spaces'
        source.mkdir()
        args = runtime.create_args('azt-research-' + 'a' * 32, 'sha256:' + 'b' * 64, source)
        for flag, value in (('--user', '65532:65532'), ('--network', 'none'), ('--pull', 'never'),
                            ('--memory', '128m'), ('--memory-swap', '128m'), ('--pids-limit', '16'),
                            ('--cpus', '0.5'), ('--cap-drop', 'ALL'), ('--log-driver', 'none')):
            self.assertEqual(args[args.index(flag) + 1], value)
        mounts = [args[i + 1] for i, a in enumerate(args) if a == '--mount']
        self.assertEqual(len(mounts), 1)
        self.assertIn('src=' + str(source) + ',dst=/azt-runtime,readonly', mounts[0])
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--pid', args)
        self.assertEqual(args[-len(runtime.WORKER_COMMAND)-1:], runtime.WORKER_COMMAND + ['reference'])
        self.assertNotIn('docker.sock', ' '.join(args))
        self.assertNotIn(str(Path.home()), ' '.join(args))
        bad = self.root / 'runtime,bad'; bad.mkdir()
        with self.assertRaises(runtime.ResearchRuntimeError):
            runtime.create_args('azt-research-' + 'a' * 32, 'sha256:' + 'b' * 64, bad)

    def controls(self):
        return {'Image': 'sha256:' + 'b' * 64, 'Config': {'User': '65532:65532',
            'WorkingDir': '/scratch', 'OpenStdin': True, 'Entrypoint': ['/usr/bin/env'],
            'Cmd': runtime.WORKER_COMMAND + ['reference'], 'Healthcheck': {'Test': ['NONE']}},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
            'NanoCpus': 500000000, 'Memory': 134217728, 'MemorySwap': 134217728,
            'PidsLimit': 16, 'CgroupnsMode': 'private', 'IpcMode': 'private', 'Init': True,
            'ShmSize': 1048576, 'CapDrop': ['ALL'], 'CapAdd': None, 'PidMode': '',
            'SecurityOpt': ['no-new-privileges=true'], 'LogConfig': {'Type': 'none'},
            'RestartPolicy': {'Name': 'no'}, 'Tmpfs': {
                '/scratch': 'rw,nosuid,nodev,noexec,size=8m,uid=65532,gid=65532,mode=0700',
                '/tmp': 'rw,nosuid,nodev,noexec,size=4m,uid=65532,gid=65532,mode=0700'},
            'Ulimits': [{'Name': 'fsize', 'Soft': 1048576, 'Hard': 1048576},
                        {'Name': 'nofile', 'Soft': 64, 'Hard': 64}]},
            'Mounts': [{'Source': str(self.root), 'Destination': '/azt-runtime', 'RW': False, 'Type': 'bind'}]}

    def test_readback_fails_on_missing_or_weakened_controls(self):
        valid = self.controls()
        def inspect(value):
            docker = SimpleNamespace(command=lambda *args: (0, json.dumps(value).encode(), b''))
            return runtime.inspect_controls(docker, 'a' * 64, self.root, 'sha256:' + 'b' * 64)
        self.assertEqual(inspect(valid)['worker_uid'], 65532)
        changes = [lambda c: c['HostConfig'].update(NetworkMode='bridge'),
                   lambda c: c['HostConfig'].update(Memory=0),
                   lambda c: c['HostConfig'].update(CapAdd=['SYS_ADMIN']),
                   lambda c: c['HostConfig'].update(Devices=[{'PathOnHost': '/dev/test'}]),
                   lambda c: c['Config'].update(User='0:0'),
                   lambda c: c['Config'].update(Cmd=['sh']),
                   lambda c: c['Mounts'][0].update(RW=True),
                   lambda c: c['Mounts'].append({'Type': 'volume'}),
                   lambda c: c['HostConfig']['Tmpfs'].update({'/scratch': 'rw,size=1g'}),
                   lambda c: c['HostConfig']['Ulimits'].clear()]
        for change in changes:
            bad = copy.deepcopy(valid); change(bad)
            with self.assertRaises(runtime.ResearchRuntimeError):
                inspect(bad)

    def test_private_workers_and_test_destinations_are_not_public_inputs(self):
        with self.assertRaises(runtime.ResearchRuntimeError):
            runtime.run_worker(None, 'image', 'endpoint', worker='boundary-probe')
        for image in ('python:3.12-slim', '--privileged', 'other@sha256:' + 'a' * 64):
            with self.assertRaises(runtime.ResearchRuntimeError):
                runtime.run_worker(None, image, 'unix:///synthetic')
        good = {'challenge': 'a' * 32, 'sink_host': '127.0.0.1', 'sink_port': 12345}
        self.assertEqual(runtime._test_context(good), good)
        for update in ({'sink_host': 'example.invalid'}, {'sink_port': True},
                       {'sink_port': 80}, {'challenge': 'synthetic secret'}, {'extra': 'field'}):
            with self.assertRaises(runtime.ResearchRuntimeError):
                runtime._test_context(dict(good, **update))

    def test_private_observations_are_typed_claims_not_success_verdicts(self):
        context = {'challenge': 'a' * 32}
        resource = {'protocol': 'azt.research-test-observation.v1', 'kind': 'resource-probe',
            'challenge': context['challenge'], 'scratch_bytes_written': 8388608,
            'scratch_errno': 28, 'children_started': 14, 'fork_errno': 11}
        tamper = {'protocol': 'azt.research-test-observation.v1', 'kind': 'tamper-probe',
            'challenge': context['challenge'], 'scratch_preexisted': False,
            'scratch_sha256': hashlib.sha256(context['challenge'].encode()).hexdigest(),
            'write_errors': {'runtime': 30, 'control': 2}}
        for valid in (resource, tamper):
            self.assertEqual(runtime._test_observation(valid, context), valid)
            self.assertNotIn('passed', runtime._test_observation(valid, context))
            for key, value in (('challenge', 'b' * 32), ('extra', 'untrusted')):
                with self.assertRaises(runtime.ResearchRuntimeError):
                    runtime._test_observation(dict(valid, **{key: value}), context)
        for update in ({'children_started': 21}, {'scratch_bytes_written': 13 * 1048576},
                       {'fork_errno': True}, {'scratch_errno': -1}):
            with self.assertRaises(runtime.ResearchRuntimeError):
                runtime._test_observation(dict(resource, **update), context)
        for update in ({'scratch_preexisted': 'false'}, {'write_errors': {'runtime': 30}},
                       {'scratch_sha256': 'not a digest'}):
            with self.assertRaises(runtime.ResearchRuntimeError):
                runtime._test_observation(dict(tamper, **update), context)

    def test_supervisor_watcher_failure_never_arms_and_still_cleans_up(self):
        # Reproduced review finding: readiness must follow watcher creation,
        # not precede it. No Docker command runs in this failure injection.
        ready_read, ready_write = os.pipe()
        life_read, life_write = os.pipe()
        config = self.root / 'supervisor.json'
        runtime._write_record(config, {'docker_prefix': ['synthetic-docker'],
            'container_id': 'a' * 64, 'deadline': time.monotonic() + 1,
            'result_path': str(self.root / 'lease-result.json')})
        try:
            with mock.patch.object(runtime.selectors, 'DefaultSelector', side_effect=OSError('watcher')), \
                 mock.patch.object(runtime.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as cleanup:
                self.assertEqual(runtime._lease_supervisor(str(config), ready_write, life_read), 0)
            self.assertEqual(os.read(ready_read, 32), b'')
            cleanup.assert_called_once()
            self.assertEqual(cleanup.call_args.args[0], ['synthetic-docker', 'rm', '--force', 'a' * 64])
            result = json.loads((self.root / 'lease-result.json').read_text())
            self.assertEqual(result['reason'], 'supervisor_failed')
            self.assertEqual(result['cleanup'], 'removed')
        finally:
            os.close(ready_read)
            os.close(life_write)

    def fake_cleanup_prefix(self):
        # This command only acknowledges exact cleanup arguments in unit tests.
        # It is not a Docker server and cannot establish container termination.
        return [sys.executable, '-I', '-c',
                'import sys; assert sys.argv[1:]==["rm","--force","' + 'a' * 64 + '"]']

    def test_external_lease_expires_without_controller_cooperation(self):
        supervisor, life = runtime.arm_lease(self.fake_cleanup_prefix(), 'a' * 64,
                                            self.root, time.monotonic() + 0.3)
        try:
            self.assertEqual(supervisor.wait(timeout=4), 0)
            result = json.loads((self.root / 'lease-result.json').read_text())
            self.assertEqual(result['reason'], 'lease_expired')
            self.assertEqual(result['cleanup'], 'removed')
        finally:
            os.close(life)

    @unittest.skipUnless(os.name == 'posix', 'POSIX controller lifetime diagnostic')
    def test_lease_supervisor_survives_controller_sigkill(self):
        code = ('import sys,time; from pathlib import Path; '
                'sys.path.insert(0,sys.argv[1]); import azt_research_runtime as r; '
                'p,fd=r.arm_lease(' + repr(self.fake_cleanup_prefix()) + ',"' + 'a' * 64 + '",'
                'Path(sys.argv[2]),time.monotonic()+5); print(p.pid,flush=True); time.sleep(20)')
        controller = subprocess.Popen([sys.executable, '-I', '-c', code,
            str(Path(runtime.__file__).parent), str(self.root)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=runtime.ENV, start_new_session=True)
        try:
            self.assertTrue(controller.stdout.readline().strip().isdigit())
            os.kill(controller.pid, signal.SIGKILL)
            controller.wait(timeout=2)
            deadline = time.monotonic() + 4
            result_path = self.root / 'lease-result.json'
            while not result_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            result = json.loads(result_path.read_text())
            self.assertEqual(result['reason'], 'controller_channel_closed')
            self.assertEqual(result['cleanup'], 'removed')
        finally:
            if controller.poll() is None:
                controller.kill(); controller.wait(timeout=2)
            controller.stdout.close(); controller.stderr.close()


if __name__ == '__main__':
    unittest.main()
