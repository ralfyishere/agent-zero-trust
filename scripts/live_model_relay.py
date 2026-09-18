"""Fixed test-only relay inside a container; no target-selected routes or code.

The inference namespace has only loopback. Host access is through Docker stdin,
not a published model port. This helper never imports the inspected application.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sys
import time

MODEL = 'qwen3:0.6b'
MODEL_DIGEST = '7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435'
LIMIT = 65536
ERROR_SCHEMA = 'azt.test-relay-error.v1'
ERROR_REASONS = frozenset(('timeout', 'http_status', 'encoding', 'reply_bound',
                           'invalid_json', 'transport', 'unknown'))


class RelayError(ValueError):
    """Only maintained categories cross the test relay's error channel."""
    def __init__(self, reason):
        self.reason = reason if reason in ERROR_REASONS else 'unknown'
        super().__init__(self.reason)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate_key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    queue = [(value, 0)]; count = 0
    while queue:
        item, depth = queue.pop(); count += 1
        require(depth <= 16 and count <= 4096, 'json_complexity')
        if isinstance(item, dict):queue.extend((x,depth+1) for x in item.values())
        elif isinstance(item, list):queue.extend((x,depth+1) for x in item)
    return value


def request(method, path, payload, timeout=9):
    require((method, path) in (('GET', '/api/version'), ('GET', '/api/tags'),
                              ('POST', '/api/chat'), ('POST', '/api/pull')), 'fixed_route')
    raw = None if payload is None else json.dumps(payload, ensure_ascii=True).encode()
    require(raw is None or len(raw) <= 16384, 'request_bound')
    connection = http.client.HTTPConnection('127.0.0.1', 11434, timeout=timeout)
    try:
        connection.request(method, path, raw, {'Content-Type': 'application/json'})
        response = connection.getresponse()
        if response.status != 200 or response.getheader('Location'):
            raise RelayError('http_status')
        if response.getheader('Content-Encoding', 'identity') != 'identity':
            raise RelayError('encoding')
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT: raise RelayError('reply_bound')
        try:
            value = parse(raw)
            require(isinstance(value, dict), 'object_required')
        except (ValueError, RecursionError):
            raise RelayError('invalid_json') from None
        # Hidden reasoning is not part of test evidence or returned to AZT.
        if isinstance(value.get('message'), dict):
            value['message'].pop('thinking', None)
        return value
    except TimeoutError:
        raise RelayError('timeout') from None
    except (OSError, http.client.HTTPException):
        raise RelayError('transport') from None
    finally:
        connection.close()


def store_identity():
    root = Path('/models')
    path = root / 'manifests/registry.ollama.ai/library/qwen3/0.6b'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= LIMIT, 'manifest_file')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == MODEL_DIGEST, 'model_manifest_changed')
    manifest = json.loads(raw)
    entries = [manifest['config']] + manifest['layers']
    require(len(entries) <= 8 and sum(x['size'] for x in entries) <= 600_000_000, 'model_size')
    for entry in entries:
        require(re.fullmatch('sha256:[0-9a-f]{64}', entry['digest']), 'model_digest')
        blob = root / 'blobs' / entry['digest'].replace(':', '-')
        info = blob.lstat()
        require(not blob.is_symlink() and blob.is_file() and info.st_nlink == 1 and info.st_size == entry['size'], 'model_blob')
        digest = hashlib.sha256()
        with blob.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        require(digest.hexdigest() == entry['digest'][7:], 'model_blob_hash')
    return {'model': MODEL, 'manifest_sha256': MODEL_DIGEST,
            'bytes': sum(x['size'] for x in entries), 'all_blob_hashes_verified': True}


def probe(address, nonce):
    require(re.fullmatch(r'[0-9.]{7,15}', address) and re.fullmatch('[0-9a-f]{32}', nonce), 'probe_data')
    result = {'interfaces': [name for _, name in socket.if_nameindex()], 'connected': False, 'challenge_verified': False}
    try:
        with socket.create_connection((address, 18080), timeout=2) as channel:
            result['connected'] = True
            channel.sendall(nonce.encode())
            result['challenge_verified'] = channel.recv(64) == hashlib.sha256(nonce.encode()).hexdigest().encode()
    except OSError:
        pass
    return result


def sink():
    end = time.monotonic() + 60
    with socket.socket() as listener:
        listener.bind(('0.0.0.0', 18080)); listener.listen(2); listener.settimeout(1)
        while time.monotonic() < end:
            try:
                channel, _ = listener.accept()
            except socket.timeout:
                continue
            with channel:
                channel.settimeout(2)
                value = channel.recv(64)
                if re.fullmatch(b'[0-9a-f]{32}', value):
                    channel.sendall(hashlib.sha256(value).hexdigest().encode())


def main():
    if sys.argv[1:] == ['--sink']:
        sink(); return
    raw = sys.stdin.buffer.read(32769)
    require(len(raw) <= 32768, 'frame_bound')
    value = parse(raw)
    mode = value['mode']
    if mode == 'pull':
        result = request('POST', '/api/pull', {'model': MODEL, 'stream': False}, 235)
        require(result.get('status') == 'success', 'download_failed')
    elif mode == 'store':
        result = store_identity()
    elif mode == 'probe':
        result = probe(value['address'], value['nonce'])
    elif mode == 'request':
        method, path, payload = value['method'], value['path'], value['payload']
        require((method, path) in (('GET', '/api/version'), ('GET', '/api/tags'), ('POST', '/api/chat')), 'review_route')
        result = request(method, path, payload)
    elif mode == 'preload':
        result = request('POST', '/api/chat', {'model': MODEL, 'messages': [], 'stream': False,
            'think': False, 'options': {'num_ctx': 32768, 'num_predict': 1}, 'keep_alive': '5m'}, 45)
        result = {'done': result.get('done'), 'model': result.get('model'), 'empty_preload': True}
    else:
        raise ValueError('unsupported_mode')
    raw = json.dumps(result, ensure_ascii=True).encode()
    require(len(raw) <= LIMIT, 'export_bound')
    sys.stdout.buffer.write(raw + b'\n')


def entrypoint():
    try:
        main()
        return 0
    except Exception as exc:
        # No traceback, service body, exception message, headers or arguments.
        # A nonzero process exit AND this bounded stderr envelope are required
        # by the host. Service JSON on successful stdout cannot forge a failure.
        reason = exc.reason if type(exc) is RelayError else 'unknown'
        sys.stderr.write(json.dumps({'schema': ERROR_SCHEMA, 'reason': reason})+'\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(entrypoint())
