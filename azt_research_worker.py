"""Fixed deterministic worker for the experimental protected research profile.

Runs only inside the selected Docker profile. Source text is data: this worker
never evaluates it, imports it, or follows its instructions. Private diagnostic
selectors are bundled reviewed tests, not a repository-selected plugin system.
"""
import hashlib
import json
import os
import socket
import sys
import time

PROTOCOL = 'azt.research-channel.v1'
MAX_FRAME = 65536
TEST_WORKERS = ('authority-confusion', 'boundary-probe', 'resource-probe', 'tamper-probe',
                'descendants', 'flood', 'stall')


def receive():
    raw = sys.stdin.buffer.readline(MAX_FRAME + 1)
    if not raw or len(raw) > MAX_FRAME or not raw.endswith(b'\n'):
        raise ValueError('invalid bounded channel frame')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('channel requires objects')
    return value


def send(value):
    raw = (json.dumps(value, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    if len(raw) > MAX_FRAME:
        raise ValueError('outgoing frame exceeds bound')
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def boundary_probe(context):
    """Trusted synthetic instrumentation; controller/harness must verify claims."""
    response, accessible = None, []
    try:
        with open('/protected/canary', 'rb') as stream:
            raw = stream.read(1025)
        if len(raw) <= 1024:
            response = hashlib.sha256(context['challenge'].encode('ascii') + raw).hexdigest()
    except OSError:
        pass
    for path in ('/var/run/docker.sock', '/control/policy.json', '/root/.ssh/id_rsa'):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
            accessible.append(path)
        except OSError:
            pass
    connected = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect((context['sink_host'], context['sink_port']))
            client.sendall(context['challenge'].encode('ascii'))
            connected = True
    except OSError:
        pass
    send({'protocol': 'azt.research-test-observation.v1',
          'challenge': context['challenge'], 'canary_response': response,
          'network_connected': connected, 'accessible_protected_paths': accessible,
          'uid': os.getuid(), 'gid': os.getgid()})


def resource_probe(context):
    """Finite test only: <=12 MiB attempted and <=20 children; no memory bomb."""
    written, storage_error, fork_error, children = 0, 0, 0, []
    block = b'S' * 1048576
    try:
        for index in range(12):
            with open('/scratch/resource-%d' % index, 'xb', buffering=0) as stream:
                remaining = block
                while remaining:
                    count = stream.write(remaining)
                    written += count
                    remaining = remaining[count:]
    except OSError as exc:
        storage_error = exc.errno or 0
    try:
        for _ in range(20):
            child = os.fork()
            if child == 0:
                time.sleep(30)
                os._exit(0)
            children.append(child)
    except OSError as exc:
        fork_error = exc.errno or 0
    finally:
        for child in children:
            try:
                os.kill(child, 9)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)
    send({'protocol': 'azt.research-test-observation.v1', 'kind': 'resource-probe',
          'challenge': context['challenge'], 'scratch_bytes_written': written,
          'scratch_errno': storage_error, 'children_started': len(children), 'fork_errno': fork_error})


def tamper_probe(context):
    errors = {}
    for label, path in (('runtime', '/azt-runtime/worker.py'), ('control', '/control/policy.json')):
        errors[label] = 0
        try:
            with open(path, 'ab') as stream:
                stream.write(b'SYNTHETIC TEST MUTATION\n')
        except OSError as exc:
            errors[label] = exc.errno or 0
    target = '/scratch/session-state'
    existed = os.path.exists(target)
    content = context['challenge'].encode('ascii')
    with open(target, 'xb') as stream:
        stream.write(content)
    send({'protocol': 'azt.research-test-observation.v1', 'kind': 'tamper-probe',
          'challenge': context['challenge'], 'scratch_preexisted': existed,
          'scratch_sha256': hashlib.sha256(content).hexdigest(), 'write_errors': errors})


def main(worker='reference'):
    if worker != 'reference' and worker not in TEST_WORKERS:
        raise ValueError('unknown bundled worker')
    initial = receive()
    if initial.get('protocol') != PROTOCOL:
        raise ValueError('unsupported channel')
    counter = 0

    def request(operation, **fields):
        nonlocal counter
        counter += 1
        message = {'id': 'q' + str(counter), 'mission': initial['mission'],
                   'run': initial['run'], 'operation': operation, **fields}
        send(message)
        response = receive()
        if response.get('id') != message['id'] or response.get('decision') not in ('allowed', 'denied'):
            raise ValueError('invalid broker response')
        return response

    if worker == 'authority-confusion':
        # The broker must reject these even for a benign source. No network or
        # privilege operation is implemented by this worker request protocol.
        for operation in ('upload', 'permission', 'child'):
            if request(operation)['decision'] != 'denied':
                raise ValueError('forbidden operation unexpectedly granted')
        if request('read', source='unknown-source', sha256='0' * 64)['decision'] != 'denied':
            raise ValueError('unregistered source unexpectedly granted')
    elif worker == 'boundary-probe':
        boundary_probe(initial['test_context'])
    elif worker == 'resource-probe':
        resource_probe(initial['test_context'])
    elif worker == 'tamper-probe':
        tamper_probe(initial['test_context'])
    elif worker == 'flood':
        while True:
            os.write(sys.stdout.fileno(), b'x' * 4096)
    elif worker in ('descendants', 'stall'):
        if worker == 'descendants':
            for _ in range(2):
                if os.fork() == 0:
                    while True:
                        time.sleep(1)
        while True:
            time.sleep(1)

    for source in initial['sources']:
        identity = {'source': source['id'], 'sha256': source['sha256']}
        read = request('read', **identity)
        if read['decision'] != 'allowed':
            raise ValueError('source read was denied')
        value = read['result']
        if (value.get('source') != source['id'] or value.get('sha256') != source['sha256'] or
                hashlib.sha256(value['text'].encode('utf-8')).hexdigest() != source['sha256']):
            raise ValueError('source identity mismatch')
        checked = request('check', **identity)
        if checked['decision'] != 'allowed' or checked['result'].get('complete') is not True:
            raise ValueError('source inspection incomplete')
        checked = checked['result']
        if checked.get('source') != source['id'] or checked.get('sha256') != source['sha256']:
            raise ValueError('check identity mismatch')
        # One source-linked observation proposal per source is sufficient here;
        # the trusted static review retains all findings and any display limits.
        for finding in checked['findings'][:1]:
            observation = dict(identity, line=finding['line'], rule=finding['rule'])
            if request('observe', observation=observation)['decision'] != 'allowed':
                raise ValueError('observation rejected')
    response = request('review')
    if response['decision'] != 'allowed' or response['result'].get('completed') is not True:
        raise ValueError('review incomplete')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main(sys.argv[1] if len(sys.argv) == 2 else 'reference'))
    except (OSError, ValueError, TypeError, KeyError):
        # Never echo source material, broker responses, or traceback paths.
        print('research worker protocol failed', file=sys.stderr)
        raise SystemExit(2)
