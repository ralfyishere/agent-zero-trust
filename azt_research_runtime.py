"""Experimental native-Linux Docker boundary for a fixed research worker.

The daemon/kernel and external lease supervisor are trusted. A pre-armed host
supervisor outlives controller SIGKILL; it is not protected against host, daemon,
or supervisor compromise/failure. No image downloads or weaker fallback exist.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

PROTOCOL = 'azt.research-channel.v2'
MAX_FRAME = 65536
MAX_CHANNEL = 8 * 1024 * 1024
MAX_REQUESTS = 640
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LC_ALL': 'C'}
TEST_WORKERS = ('authority-confusion', 'boundary-probe', 'resource-probe', 'tamper-probe',
                'descendants', 'flood', 'stall')
WORKER_COMMAND = ['-i', 'PATH=/usr/local/bin:/usr/bin:/bin', 'HOME=/scratch',
                  'TMPDIR=/scratch', 'LC_ALL=C', '/usr/local/bin/python3', '-I', '-u',
                  '/azt-runtime/worker.py']


class ResearchRuntimeError(ValueError):
    pass


def encode_frame(value):
    raw = (json.dumps(value, separators=(',', ':'), ensure_ascii=True, allow_nan=False) + '\n').encode('ascii')
    if len(raw) > MAX_FRAME:
        raise ResearchRuntimeError('channel_frame_limit')
    return raw


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ResearchRuntimeError('duplicate_channel_key')
        value[key] = item
    return value


def decode_frame(raw):
    if len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
        raise ResearchRuntimeError('channel_frame_limit')
    try:
        value = json.loads(raw, object_pairs_hook=_object,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ResearchRuntimeError('invalid_channel_json') from exc
    if not isinstance(value, dict):
        raise ResearchRuntimeError('channel_requires_object')
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > 8 or nodes > 2048:
            raise ResearchRuntimeError('channel_structure_limit')
        if isinstance(item, dict):
            pending.extend((v, depth + 1) for v in item.values())
        elif isinstance(item, list):
            pending.extend((v, depth + 1) for v in item)
    return value


def create_args(name, image_id, runtime_dir, worker='reference'):
    if worker not in ('reference', 'investigator') and worker not in TEST_WORKERS:
        raise ResearchRuntimeError('unknown_bundled_worker')
    if not re.fullmatch(r'azt-research-[0-9a-f]{32}', name):
        raise ResearchRuntimeError('invalid_container_name')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ResearchRuntimeError('immutable_image_required')
    source = str(Path(runtime_dir).resolve(strict=True))
    if any(c in source for c in ',\n\r\x00'):
        raise ResearchRuntimeError('unsupported_mount_path')
    return ['create', '--name', name, '--label', 'org.azt.profile='+('investigator-v1' if worker == 'investigator' else 'research-v1'),
        '--pull', 'never', '--interactive', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
        '--cgroupns', 'private', '--ipc', 'private', '--init', '--user', '65532:65532',
        '--restart', 'no', '--no-healthcheck', '--cpus', '0.5', '--memory', '128m',
        '--memory-swap', '128m', '--pids-limit', '16', '--ulimit', 'fsize=1048576:1048576',
        '--ulimit', 'nofile=64:64', '--shm-size', '1m', '--log-driver', 'none',
        '--stop-timeout', '1', '--workdir', '/scratch',
        '--tmpfs', '/scratch:rw,nosuid,nodev,noexec,size=8m,uid=65532,gid=65532,mode=0700',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=4m,uid=65532,gid=65532,mode=0700',
        '--mount', 'type=bind,src=%s,dst=/azt-runtime,readonly,bind-propagation=rprivate' % source,
        '--entrypoint', '/usr/bin/env', image_id] + WORKER_COMMAND + [worker]


def inspect_controls(docker, container, runtime_dir, image_id, worker='reference'):
    _, raw, _ = docker.command('inspect', container, '--format', '{{json .}}')
    cfg = json.loads(raw)
    h, c = cfg['HostConfig'], cfg['Config']
    required = {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
        'NanoCpus': 500000000, 'Memory': 134217728, 'MemorySwap': 134217728,
        'PidsLimit': 16, 'CgroupnsMode': 'private', 'IpcMode': 'private',
        'Init': True, 'ShmSize': 1048576}
    if any(h.get(k) != v for k, v in required.items()):
        raise ResearchRuntimeError('required_control_not_accepted')
    if (cfg.get('Image') != image_id or c.get('User') != '65532:65532' or
            c.get('WorkingDir') != '/scratch' or c.get('OpenStdin') is not True or
            c.get('Entrypoint') != ['/usr/bin/env'] or
            c.get('Cmd') != WORKER_COMMAND + [worker] or
            c.get('Healthcheck', {}).get('Test') != ['NONE']):
        raise ResearchRuntimeError('worker_launch_control_mismatch')
    if (h.get('CapDrop') != ['ALL'] or h.get('CapAdd') or
            h.get('PidMode') not in ('', None) or
            h.get('Devices') or h.get('DeviceRequests') or h.get('PortBindings') or
            'no-new-privileges=true' not in h.get('SecurityOpt', []) or
            h.get('LogConfig', {}).get('Type') != 'none' or
            h.get('RestartPolicy', {}).get('Name') != 'no'):
        raise ResearchRuntimeError('namespace_or_privilege_control_mismatch')
    mounts = cfg['Mounts']
    actual = {(m['Source'], m['Destination'], m['RW']) for m in mounts if m['Type'] == 'bind'}
    if (actual != {(str(runtime_dir), '/azt-runtime', False)} or
            any(m['Type'] not in ('bind', 'tmpfs') for m in mounts)):
        raise ResearchRuntimeError('host_mount_scope_mismatch')
    tmpfs = h.get('Tmpfs', {})
    if set(tmpfs) != {'/scratch', '/tmp'}:
        raise ResearchRuntimeError('storage_scope_mismatch')
    for path, size in (('/scratch', '8m'), ('/tmp', '4m')):
        if not {'rw', 'nosuid', 'nodev', 'noexec', 'size=' + size,
                'uid=65532', 'gid=65532', 'mode=0700'} <= set(tmpfs[path].split(',')):
            raise ResearchRuntimeError('storage_limit_mismatch')
    limits = {u['Name']: (u['Soft'], u['Hard']) for u in h.get('Ulimits', [])}
    if limits.get('fsize') != (1048576, 1048576) or limits.get('nofile') != (64, 64):
        raise ResearchRuntimeError('file_limit_mismatch')
    return {'configuration_readback': required, 'worker_uid': 65532,
        'worker_gid': 65532, 'capabilities': 'all dropped', 'host_mounts': 'bundled read-only worker only',
        'environment': 'cleared by fixed env -i entrypoint',
        'storage_bytes': {'scratch': 8388608, 'tmp': 4194304, 'shm': 1048576},
        'observation_scope': 'Docker configuration readback, not exercised denial evidence'}


def _write_record(path, value):
    raw = encode_frame(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)


def _lease_supervisor(config_path, ready_fd, life_fd):
    """Separate-session host process; never mounted or addressable by worker."""
    with open(config_path, 'rb') as stream:
        config = decode_frame(stream.read(MAX_FRAME + 1))
    prefix, container = config['docker_prefix'], config['container_id']
    if not re.fullmatch(r'[0-9a-f]{64}', container):
        return 2
    # No project imports: this entry point is stdlib-only even from source. Arm
    # only after the lifetime watcher exists. Ordinary watcher errors must still
    # reach cleanup; supervisor SIGKILL/host failure remain outside the claim.
    reason = 'supervisor_failed'
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(life_fd, selectors.EVENT_READ)
            os.write(ready_fd, b'armed\n')
            os.close(ready_fd)
            ready_fd = None
            reason = 'lease_expired'
            while time.monotonic() < config['deadline']:
                if selector.select(min(0.1, max(0, config['deadline'] - time.monotonic()))):
                    if not os.read(life_fd, 1):
                        reason = 'controller_channel_closed'
                        break
    except (OSError, ValueError):
        reason = 'supervisor_failed'
    finally:
        if ready_fd is not None:
            os.close(ready_fd)
        os.close(life_fd)
    cleanup = 'failed'
    try:
        # Output is discarded: a failed daemon must not fill the evidence store.
        result = subprocess.run(prefix + ['rm', '--force', container], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, env=ENV, close_fds=True)
        if result.returncode == 0:
            cleanup = 'removed'
    except (OSError, subprocess.SubprocessError):
        pass
    _write_record(config['result_path'], {'schema': 'azt.research-lease.v1',
        'container_id': container, 'reason': reason, 'cleanup': cleanup})
    return 0 if cleanup == 'removed' else 2


def arm_lease(docker_prefix, container, control, deadline):
    """Arm before Docker start; absence of acknowledgment prohibits launch."""
    ready_read, ready_write = os.pipe()
    life_read, life_write = os.pipe()
    config = control / 'lease-config.json'
    _write_record(config, {'docker_prefix': docker_prefix, 'container_id': container,
                          'deadline': deadline, 'result_path': str(control / 'lease-result.json')})
    try:
        process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()),
            '--lease-supervisor', str(config), str(ready_write), str(life_read)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=ENV, close_fds=True, pass_fds=(ready_write, life_read), start_new_session=True)
    except BaseException:
        os.close(ready_read)
        os.close(life_write)
        raise
    finally:
        os.close(ready_write)
        os.close(life_read)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(ready_read, selectors.EVENT_READ)
            if not selector.select(3) or os.read(ready_read, 32) != b'armed\n':
                raise ResearchRuntimeError('lease_supervisor_not_armed')
        return process, life_write
    except BaseException:
        os.close(life_write)
        raise
    finally:
        os.close(ready_read)


def _test_context(value, network=True):
    expected = {'challenge', 'sink_host', 'sink_port'} if network else {'challenge'}
    if not isinstance(value, dict) or set(value) != expected:
        raise ResearchRuntimeError('invalid_test_context')
    if not isinstance(value['challenge'], str) or not re.fullmatch(r'[0-9a-f]{32,64}', value['challenge']):
        raise ResearchRuntimeError('invalid_test_challenge')
    if network:
        try:
            ipaddress.IPv4Address(value['sink_host'])
        except (ValueError, TypeError) as exc:
            raise ResearchRuntimeError('invalid_test_destination') from exc
        if type(value['sink_port']) is not int or not 1024 <= value['sink_port'] <= 65535:
            raise ResearchRuntimeError('invalid_test_port')
    return dict(value)


def _test_observation(value, context):
    if value.get('kind') == 'resource-probe':
        keys = {'protocol', 'kind', 'challenge', 'scratch_bytes_written', 'scratch_errno',
                'children_started', 'fork_errno'}
        if (set(value) != keys or value['challenge'] != context['challenge'] or
                any(type(value[k]) is not int or value[k] < 0 for k in
                    ('scratch_bytes_written', 'scratch_errno', 'children_started', 'fork_errno')) or
                value['scratch_bytes_written'] > 12 * 1048576 or value['children_started'] > 20):
            raise ResearchRuntimeError('invalid_resource_observation')
        return value
    if value.get('kind') == 'tamper-probe':
        keys = {'protocol', 'kind', 'challenge', 'scratch_preexisted', 'scratch_sha256', 'write_errors'}
        if (set(value) != keys or value['challenge'] != context['challenge'] or
                type(value['scratch_preexisted']) is not bool or
                not re.fullmatch(r'[0-9a-f]{64}', str(value['scratch_sha256'])) or
                not isinstance(value['write_errors'], dict) or
                set(value['write_errors']) != {'runtime', 'control'} or
                any(type(v) is not int or v < 0 for v in value['write_errors'].values())):
            raise ResearchRuntimeError('invalid_tamper_observation')
        return value
    keys = {'protocol', 'challenge', 'canary_response', 'network_connected',
            'accessible_protected_paths', 'uid', 'gid'}
    if (set(value) != keys or value['challenge'] != context['challenge'] or
            type(value['network_connected']) is not bool or
            type(value['uid']) is not int or type(value['gid']) is not int or
            value['canary_response'] is not None and
            not re.fullmatch(r'[0-9a-f]{64}', str(value['canary_response'])) or
            not isinstance(value['accessible_protected_paths'], list) or
            len(value['accessible_protected_paths']) > 3 or
            any(p not in ('/var/run/docker.sock', '/control/policy.json', '/root/.ssh/id_rsa')
                for p in value['accessible_protected_paths'])):
        raise ResearchRuntimeError('invalid_test_observation')
    return value


def exchange(process, broker, initial, deadline, report, test_context=None):
    """Bounded duplex NDJSON. No target data is executed or printed to logs."""
    pending, received = bytearray(encode_frame(initial)), bytearray()
    totals, requests = 0, 0
    with selectors.DefaultSelector() as selector:
        for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        os.set_blocking(process.stdin.fileno(), False)
        selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise ResearchRuntimeError('execution_deadline')
            for event, _ in selector.select(min(0.1, deadline - time.monotonic())):
                stream, kind = event.fileobj, event.data
                if kind == 'stdin':
                    count = os.write(stream.fileno(), pending[:4096])
                    totals += count
                    del pending[:count]
                    if not pending:
                        selector.unregister(stream)
                else:
                    raw = os.read(stream.fileno(), 4096)
                    if not raw:
                        selector.unregister(stream)
                        if kind == 'stdout' and received:
                            raise ResearchRuntimeError('truncated_channel_frame')
                        continue
                    totals += len(raw)
                    if kind == 'stderr':
                        report['stderr_bytes'] += len(raw)
                    else:
                        received.extend(raw)
                        while b'\n' in received:
                            end = received.index(b'\n') + 1
                            value = decode_frame(bytes(received[:end]))
                            del received[:end]
                            if value.get('protocol') == 'azt.research-test-observation.v1':
                                if test_context is None or report['test_observations']:
                                    raise ResearchRuntimeError('unexpected_test_observation')
                                report['test_observations'].append(_test_observation(value, test_context))
                                continue
                            requests += 1
                            report['requests_observed'] = requests
                            if requests > MAX_REQUESTS:
                                raise ResearchRuntimeError('channel_request_limit')
                            reply = broker.handle(value)
                            pending.extend(encode_frame(reply))
                            if len(pending) > 2 * MAX_FRAME:
                                raise ResearchRuntimeError('channel_backpressure_limit')
                            try:
                                selector.get_key(process.stdin)
                            except KeyError:
                                selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
                        if len(received) >= MAX_FRAME:
                            raise ResearchRuntimeError('channel_frame_limit')
                report['channel_bytes'] = totals
                if totals > MAX_CHANNEL:
                    raise ResearchRuntimeError('channel_total_limit')
    report['channel_bytes'] = totals
    process.wait(timeout=max(0.01, deadline - time.monotonic()))
    if process.returncode != 0:
        raise ResearchRuntimeError('attach_failed')


def run_worker(broker, image, endpoint, worker='reference', lease_seconds=20, control_dir=None):
    if worker != 'reference':
        raise ResearchRuntimeError('only_reference_worker_is_public')
    return _run(broker, image, endpoint, worker, lease_seconds, control_dir, None)


def run_investigator(broker, image, endpoint, control_dir=None):
    from azt_investigator import LEASE_SECONDS
    if broker.investigator is None:
        raise ResearchRuntimeError('investigator_profile_required')
    return _run(broker, image, endpoint, 'investigator', LEASE_SECONDS, control_dir, None)


def _run_test_worker(broker, image, endpoint, worker, test_context=None, lease_seconds=20, control_dir=None):
    if worker not in TEST_WORKERS:
        raise ResearchRuntimeError('unknown_bundled_test_worker')
    probes = ('boundary-probe', 'resource-probe', 'tamper-probe')
    context = _test_context(test_context, network=worker == 'boundary-probe') if worker in probes else None
    if worker not in probes and test_context is not None:
        raise ResearchRuntimeError('unexpected_test_context')
    return _run(broker, image, endpoint, worker, lease_seconds, control_dir, context)


def _run(broker, image, endpoint, worker, lease_seconds, control_dir, test_context):
    from azt_docker import Docker, IntakeError
    from azt_research import ResearchError
    # Reuse the existing backend without changing FS-001 behavior. Every setup
    # command consumes one cumulative preparation deadline; cleanup does not.
    class PreparedDocker(Docker):
        preparing = True

        def command(self, *args, timeout=10, **kwargs):
            if self.preparing:
                timeout = min(timeout, broker.preparation_remaining())
            result = super().command(*args, timeout=timeout, **kwargs)
            if self.preparing:
                broker.preparation_remaining()
            return result
    maximum = 120 if worker == 'investigator' and broker.investigator is not None else 30
    if type(lease_seconds) is not int or not 2 <= lease_seconds <= maximum:
        raise ResearchRuntimeError('lease_outside_selected_profile')
    if not isinstance(image, str) or not re.fullmatch(
            r'(?:sha256:[0-9a-f]{64}|(?:docker.io/library/)?python@sha256:[0-9a-f]{64})', image):
        raise ResearchRuntimeError('preloaded_immutable_official_python_image_required')
    default_control = control_dir is None
    control = (Path(tempfile.mkdtemp(prefix='azt-research-control-')).resolve()
               if default_control else Path(control_dir).absolute())
    if not default_control:
        if '..' in control.parts or any(p.is_symlink() for p in (control, *control.parents)):
            raise ResearchRuntimeError('unsafe_control_directory')
        control.mkdir(mode=0o700)
    runtime = control / 'runtime'
    runtime.mkdir(mode=0o755)
    bundled = Path(__file__).with_name('azt_research_worker.py').read_bytes()
    (runtime / 'worker.py').write_bytes(bundled)
    (runtime / 'worker.py').chmod(0o444)
    report = {'schema': 'azt.research-runtime.v1', 'status': 'blocked',
        'mission': broker.mission_id, 'run': broker.run_id,
        'worker': worker, 'worker_sha256': hashlib.sha256(bundled).hexdigest(),
        'container_id': None, 'stages': {'controls_read_back': False, 'lease_armed': False,
        'broker_activated': False, 'container_started': False, 'channel_completed': False, 'review_completed': False},
        'requests_observed': 0, 'channel_bytes': 0, 'stderr_bytes': 0,
        'test_observations': [], 'cleanup': 'not_created', 'lease_seconds': lease_seconds,
        'limitations': ['Docker/kernel, host supervisor and operator are trusted.',
            'Controller SIGKILL is distinct from supervisor, daemon or host failure.',
            'Readback is not exercised denial evidence; worker claims require external verification.',
            'No general agent, live model, or arbitrary repository program runs.']}
    if worker == 'investigator':
        report['profile'] = 'azt.investigator-local.v1'
        report['limitations'][-1] = 'Fixed optional planner; inference-service behavior trusted separately, cancellation unverified.'
    docker, container, supervisor, life, attached, name = None, None, None, None, None, None
    stage = 'preflight'
    try:
        broker.preparation_remaining()
        docker = PreparedDocker(endpoint, control)
        backend = docker.preflight(image)
        report['backend'] = backend
        if backend['status'] != 'available':
            report['error_stage'] = stage
            report['error'] = backend['reason']
            return report
        image_id = backend['image_id']
        _, raw, _ = docker.command('image', 'inspect', image_id, '--format', '{{json .}}')
        metadata = json.loads(raw)
        official = any(re.fullmatch(r'(?:docker.io/library/)?python@sha256:[0-9a-f]{64}', d)
                       for d in metadata.get('RepoDigests', []))
        if not official or metadata.get('Architecture') != 'amd64':
            raise ResearchRuntimeError('official_python_linux_amd64_image_required')
        name = 'azt-research-' + uuid.uuid4().hex
        stage = 'create'
        _, raw, _ = docker.command(*create_args(name, image_id, runtime, worker))
        observed_id = raw.decode('ascii').strip()
        if not re.fullmatch(r'[0-9a-f]{64}', observed_id):
            raise ResearchRuntimeError('invalid_daemon_container_id')
        container = observed_id
        report['container_id'] = container
        report['status'] = 'failed'
        stage = 'control_readback'
        report['controls'] = inspect_controls(docker, container, runtime, image_id, worker)
        report['stages']['controls_read_back'] = True
        stage = 'arm_lease'
        broker.preparation_remaining()
        deadline = time.monotonic() + lease_seconds
        supervisor, life = arm_lease(docker.prefix, container, control, deadline)
        report['stages']['lease_armed'] = True
        stage = 'activate'
        broker.activate(lease_seconds, deadline=deadline)
        docker.preparing = False
        report['stages']['broker_activated'] = True
        _write_record(control / 'session.json', {'container_id': container,
            'supervisor_pid': supervisor.pid, 'lease_seconds': lease_seconds,
            'mission': broker.mission_id, 'run': broker.run_id})
        stage = 'start'
        docker.command('start', container)
        report['stages']['container_started'] = True
        initial = {'protocol': PROTOCOL, 'mission': broker.mission_id,
                   'run': broker.run_id, 'sources': broker.source_descriptors()}
        if test_context is not None:
            initial['test_context'] = test_context
        stage = 'channel'
        attached = subprocess.Popen(docker.prefix + ['attach', '--sig-proxy=false', container],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=ENV, close_fds=True, start_new_session=True)
        exchange(attached, broker, initial, deadline, report, test_context)
        report['stages']['channel_completed'] = True
        stage = 'outcome'
        _, raw, _ = docker.command('inspect', container, '--format', '{{json .State}}')
        state = json.loads(raw)
        report['worker_exit_code'] = state.get('ExitCode')
        if state.get('Running') is not False or state.get('ExitCode') != 0 or not broker.completed:
            raise ResearchRuntimeError('worker_or_review_incomplete')
        report['stages']['review_completed'] = True
        report['status'] = 'passed'
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError, IntakeError) as exc:
        report['status'] = 'blocked' if stage == 'preflight' else 'failed'
        report['error_stage'] = stage
        controlled = {'preparation_deadline', 'mission_not_preparing', 'invalid_active_deadline', 'invalid_active_lease'}
        report['error'] = (str(exc) if isinstance(exc, ResearchRuntimeError) or
                           isinstance(exc, ResearchError) and str(exc) in controlled else 'operation_failed')
    finally:
        if docker is not None:
            docker.preparing = False
        try:
            broker.revoke()
        except Exception:
            report['status'] = 'failed'
            report['authority_cleanup'] = 'failed'
        if attached is not None:
            try:
                if attached.poll() is None:
                    os.killpg(attached.pid, signal.SIGKILL)
                    attached.wait(timeout=3)
            except (OSError, subprocess.SubprocessError):
                report['status'] = 'failed'
                report['attach_cleanup'] = 'failed'
            for stream in (attached.stdin, attached.stdout, attached.stderr):
                try:
                    stream.close()
                except OSError:
                    report['status'] = 'failed'
                    report['attach_cleanup'] = 'failed'
        if life is not None:
            try:
                os.close(life)
            except OSError:
                # A closed/failed lifeline never cancels the supervisor's
                # independently armed deadline or skips its result check.
                report['status'] = 'failed'
                report['lifeline_cleanup'] = 'failed'
        if supervisor is not None:
            try:
                supervisor.wait(timeout=8)
                with (control / 'lease-result.json').open('rb') as stream:
                    report['lease'] = decode_frame(stream.read(MAX_FRAME + 1))
                report['cleanup'] = report['lease']['cleanup']
                if report['lease']['reason'] == 'supervisor_failed':
                    report['status'] = 'failed'
            except (OSError, ValueError, subprocess.SubprocessError):
                report['cleanup'] = 'unknown'
        elif name is not None and docker is not None:
            try:
                # This cryptographically random controller-owned name also
                # covers create timing out after Docker created the container.
                docker.command('rm', '--force', container or name, timeout=5)
                report['cleanup'] = 'removed'
            except (OSError, ValueError, subprocess.SubprocessError, IntakeError):
                report['cleanup'] = 'failed'
        if container is not None and report['cleanup'] != 'removed':
            report['status'] = 'failed'
        if default_control and (container is None or report['cleanup'] == 'removed'):
            shutil.rmtree(control)
    return report


if __name__ == '__main__':
    if len(sys.argv) == 5 and sys.argv[1] == '--lease-supervisor':
        raise SystemExit(_lease_supervisor(sys.argv[2], int(sys.argv[3]), int(sys.argv[4])))
    raise SystemExit(2)
