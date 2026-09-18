"""One explicitly selected disposable Linux live-model experiment, never a Mac test.

Test-only setup/transport. Product, prompts, tools, assertions and leases stay
unchanged. Downloads finish before model exposure to synthetic task material.
"""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid

OLLAMA_REF = 'docker.io/ollama/ollama@sha256:c715bebf769913db6c82d96f8a8dfee989c4bdfe19fa7d700e3d41ee0ceb5461'
PYTHON_REF = 'docker.io/library/python@sha256:2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79'
MODEL = 'qwen3:0.6b'
MODEL_DIGEST = '7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435'
LABEL = 'org.azt.test=isolated-local-model-v1'
DIAGNOSTIC_BYTES = 8192
STATE_FORMAT = ('{"status":{{json .State.Status}},"running":{{json .State.Running}},'
                '"oom_killed":{{json .State.OOMKilled}},"exit_code":{{json .State.ExitCode}},'
                '"error":{{json .State.Error}}}')

# Fixed, maintained vocabulary, never substrings copied from a daemon message.
# Markers retain an error's operational layers without printing arguments,
# identities, paths, URLs, or even arbitrary dictionary words from that error.
# A phrase match is a diagnostic hint, not an independently verified cause.
ERROR_MARKERS = (
    ('daemon_response', b'error response from daemon'),
    ('network_setup', b'failed to create endpoint'),
    ('network_setup', b'failed to set up container networking'),
    ('volume_mount', b'failed to mount local volume'),
    ('volume_copy', b'failed to populate volume'),
    ('file_copy', b'failed to copy'),
    ('mount_setup', b'error mounting'),
    ('mount_setup', b'failed to mount'),
    ('mount_configuration', b'invalid mount config'),
    ('tmpfs_configuration', b'invalid tmpfs'),
    ('shim_creation', b'failed to create shim task'),
    ('task_creation', b'failed to create task'),
    ('oci_creation', b'oci runtime create failed'),
    ('runc_creation', b'runc create failed'),
    ('process_start', b'unable to start container process'),
    ('container_initialization', b'error during container init'),
    ('file_write', b'failed to write'),
    ('apparmor', b'apparmor'),
    ('seccomp', b'seccomp'),
    ('ownership_change', b'lchown'),
    ('ownership_change', b'chown'),
    ('permission_denied', b'permission denied'),
    ('operation_not_permitted', b'operation not permitted'),
    ('readonly_filesystem', b'read-only file system'),
    ('missing_path', b'no such file or directory'),
    ('missing_executable', b'executable file not found'),
    ('invalid_argument', b'invalid argument'),
    ('unsupported_operation', b'operation not supported'),
    ('unsupported_function', b'function not implemented'),
    ('exec_format', b'exec format error'),
    ('storage_full', b'no space left on device'),
    ('quota_exceeded', b'disk quota exceeded'),
    ('out_of_memory', b'cannot allocate memory'),
    ('resource_unavailable', b'resource temporarily unavailable'),
    ('open_file_limit', b'too many open files'),
    ('device_busy', b'device or resource busy'),
    ('not_directory', b'not a directory'),
    ('address_in_use', b'address already in use'),
    ('network_unreachable', b'network is unreachable'),
    ('connection_refused', b'connection refused'),
    ('deadline', b'context deadline exceeded'),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def start_diagnostic(code, out, err):
    """Bounded fixed-vocabulary projection; no raw daemon text is retained."""
    lower=err[:DIAGNOSTIC_BYTES].lower()
    categories=[]
    for category, phrases in (
        ('permission_denied', (b'permission denied', b'operation not permitted')),
        ('readonly_filesystem', (b'read-only file system',)),
        ('missing_path_or_executable', (b'no such file or directory', b'executable file not found')),
        ('storage_limit', (b'no space left on device', b'disk quota exceeded')),
        ('resource_unavailable', (b'cannot allocate memory', b'resource temporarily unavailable')),
        ('mount_failure', (b'error mounting', b'failed to mount')),
    ):
        if any(phrase in lower for phrase in phrases):categories.append(category)
    occurrences=[]
    for marker, phrase in ERROR_MARKERS:
        at=lower.find(phrase)
        if at>=0:occurrences.append((at,marker))
    markers=list(dict.fromkeys(marker for _,marker in sorted(occurrences)))
    return {'schema':'azt.docker-start-diagnostic.v2',
            'exit_code':code, 'categories':categories or ['unclassified'],
            'markers_in_message_order':markers,
            'inspected_stderr_bytes':len(lower), 'stderr_truncated':len(err)>len(lower),
            'stdout_bytes':len(out), 'stderr_bytes':len(err),
            'stderr_sha256':hashlib.sha256(err).hexdigest(),
            'scope':'fixed phrase hints, not an established root cause; raw daemon text omitted; unmatched content remains unknown'}


def state_diagnostic(raw):
    """Only the selected Docker State fields, not Config/Env/Args/labels/logs."""
    require(len(raw)<=16384, 'state_reply_bound')
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value, 'state_duplicate_key');value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=unique)
    require(type(value) is dict and set(value)=={'status','running','oom_killed','exit_code','error'},
            'state_fields')
    require(value['status'] in ('created','running','paused','restarting','removing','exited','dead'),
            'state_status')
    require(type(value['running']) is bool and type(value['oom_killed']) is bool
            and type(value['exit_code']) is int and 0<=value['exit_code']<=255
            and type(value['error']) is str, 'state_types')
    return {'status':'observed', 'container_status':value['status'],
            'running':value['running'], 'oom_killed':value['oom_killed'],
            'container_exit_code':value['exit_code'],
            'error_diagnostic':start_diagnostic(None,b'',value['error'].encode('utf-8')),
            'scope':'single daemon state readback after failed start; not proof of no prior execution or a model session'}


def save(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True).encode() + b'\n'
    require(len(raw) <= 262144, 'evidence_bound')
    path.write_bytes(raw)
    path.chmod(0o600)


def common(name, network, memory, cpus, pids):
    require(re.fullmatch('azt-live-[a-f0-9]{12}-[a-z]+', name), 'run_owned_name')
    return ['create', '--name', name, '--label', LABEL, '--pull', 'never',
        '--network', network, '--read-only', '--user', '65532:65532',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges=true',
        '--cgroupns', 'private', '--ipc', 'private', '--init', '--restart', 'no',
        '--no-healthcheck', '--cpus', str(cpus), '--memory', memory,
        '--memory-swap', memory, '--pids-limit', str(pids), '--shm-size', '1m',
        '--ulimit', 'nofile=128:128', '--log-driver', 'local',
        '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1', '--stop-timeout', '1',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777']


class Lab:
    def __init__(self, root):
        from azt_docker import Docker
        self.root = root
        self.docker = Docker('unix:///var/run/docker.sock', root)
        self.prefix = 'azt-live-' + uuid.uuid4().hex[:12]
        self.ids, self.volumes, self.networks, self.new_images = [], [], [], []
        self.pending_containers = []
        self.verify_ownership = True
        self.start_attempts = []
        self.relay_source = Path(__file__).with_name('live_model_relay.py').resolve()
        self.identity = {'prefix': self.prefix, 'containers': self.ids, 'volumes': self.volumes,
                         'networks': self.networks, 'new_images': self.new_images,
                         'pending_containers': self.pending_containers}

    def ledger(self):
        save(self.root/'owned.json', self.identity)

    def cmd(self, *args, **kw):
        return self.docker.command(*args, **kw)

    def create(self, args):
        name=args[args.index('--name')+1]
        require(name.startswith(self.prefix+'-'), 'run_owned_start')
        role=name[len(self.prefix)+1:]
        require(role in ('download','downloadrelay','inference','relay','sink','positive'), 'fixed_start_role')
        # Persist an exact, generated recovery target BEFORE the daemon call.
        # A timeout/lost reply can occur after Docker has created the resource.
        self.pending_containers.append(name);self.ledger()
        _, raw, _ = self.cmd(*args)
        cid = raw.decode().strip(); require(re.fullmatch('[0-9a-f]{64}', cid), 'container_identity')
        self.ids.append(cid);self.pending_containers.remove(name);self.ledger()
        record={'role':role, 'start_acknowledged':False}
        self.start_attempts.append(record)
        try:
            code,out,err=self.cmd('start', cid, allow_error=True)
        except Exception as exc:
            record['transport_error_type']=type(exc).__name__
            record['state_readback']=self.start_state(cid)
            raise
        if code:
            record['diagnostic']=start_diagnostic(code,out,err)
            record['state_readback']=self.start_state(cid)
            raise ValueError('container_start_failed:'+role)
        record['start_acknowledged']=True
        return cid

    def start_state(self, cid):
        # One read-only, two-second request before cleanup; no retry, exec,
        # container logs or credential-bearing configuration inspection.
        try:
            code,out,err=self.cmd('container','inspect','--format',STATE_FORMAT,cid,
                                  allow_error=True,timeout=2,limit=16384)
            if code:
                return {'status':'unavailable','diagnostic':start_diagnostic(code,out,err)}
            return state_diagnostic(out)
        except Exception:
            # Diagnostic failure must neither replace the original error nor
            # prevent the independent exact-resource cleanup from running.
            return {'status':'unavailable_or_invalid', 'scope':'no state conclusion; original start failure retained'}

    def pull(self, ref):
        # A failed inspect is not proof of absence (the daemon may be down).
        _, before, _ = self.cmd('image', 'ls', '--no-trunc', '--quiet')
        self.cmd('pull', '--platform', 'linux/amd64', ref, timeout=180, limit=65536)
        _, raw, _ = self.cmd('image', 'inspect', ref, '--format', '{{json .}}')
        item = json.loads(raw); require(item['Architecture'] == 'amd64' and item['Os'] == 'linux', 'image_platform')
        require(not item['Config'].get('Volumes'), 'image_anonymous_volume')
        if item['Id'] not in before.decode().splitlines():
            self.new_images.append(item['Id']); self.ledger()
        return item['Id']

    def ollama(self, image, volume, phase):
        args = common(self.prefix+'-'+phase, 'bridge' if phase == 'download' else 'none', '6g', 3.5, 128)
        args += ['--tmpfs', '/root:rw,nosuid,nodev,noexec,size=4m,uid=65532,gid=65532,mode=0700',
            '--mount', 'type=volume,src='+volume+',dst=/models'+('' if phase == 'download' else ',readonly'),
            '--entrypoint', '/usr/bin/env', image, '-i', 'PATH=/usr/bin:/bin', 'HOME=/root',
            'OLLAMA_MODELS=/models', 'OLLAMA_HOST=127.0.0.1:11434', 'OLLAMA_NO_CLOUD=1',
            'OLLAMA_MAX_LOADED_MODELS=1', 'OLLAMA_NUM_PARALLEL=1', 'OLLAMA_MAX_QUEUE=1',
            'OLLAMA_VULKAN=0', 'OLLAMA_KEEP_ALIVE=5m', 'OLLAMA_LOAD_TIMEOUT=30s', 'OLLAMA_NOPRUNE=1',
            '/usr/bin/timeout', '--signal=KILL', '300' if phase == 'download' else '420', '/bin/ollama', 'serve']
        return self.create(args)

    def model_volume(self):
        volume=self.prefix+'-models'
        self.volumes.append(volume);self.ledger()
        self.cmd('volume','create','--label',LABEL,'--driver','local','--opt','type=tmpfs','--opt','device=tmpfs',
                 '--opt','o=size=805306368,uid=65532,gid=65532,mode=0700',volume)
        return volume

    def relay(self, image, server, volume, suffix):
        args = common(self.prefix+'-'+suffix, 'container:'+server, '256m', .5, 16)
        args += ['--mount', 'type=bind,src='+str(self.relay_source)+',dst=/relay.py,readonly',
                 '--mount', 'type=volume,src='+volume+',dst=/models,readonly',
                 '--entrypoint', '/usr/local/bin/python3', image, '-I', '-c', 'import time; time.sleep(450)']
        return self.create(args)

    def relay_call(self, relay, payload, timeout=12):
        # Only this trusted fixed helper can receive stdin; no model-supplied argv.
        raw = json.dumps(payload, ensure_ascii=True).encode()
        require(len(raw) <= 32768, 'relay_request_bound')
        proc = subprocess.Popen(self.docker.prefix+['exec', '-i', '--user', '65532:65532', relay,
            '/usr/bin/env', '-i', 'PATH=/usr/local/bin:/usr/bin:/bin', '/usr/local/bin/python3', '-I', '/relay.py'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, start_new_session=True)
        try:
            out, err = proc.communicate(raw, timeout=timeout)
            require(proc.returncode == 0 and len(out)+len(err) <= 131072, 'relay_failed')
            return json.loads(out)
        finally:
            if proc.poll() is None:
                proc.kill(); proc.wait(timeout=3)

    def remove(self, cid):
        if getattr(self,'verify_ownership',False):self.owned('container',cid)
        self.cmd('rm', '--force', cid, allow_error=True)
        require(self.absent('container', cid), 'container_cleanup_failed')

    def absent(self, kind, identity):
        # Only a successful daemon readback establishes absence. An unavailable
        # daemon or permission error must never become a cleanup success.
        commands={
            'container':(['ps','-a','--no-trunc','--filter','id='+identity,'--format','{{.ID}}']
                         if re.fullmatch('[0-9a-f]{64}',identity) else
                         ['ps','-a','--no-trunc','--filter','name=^/'+identity+'$','--format','{{.Names}}']),
            'volume':['volume','ls','--filter','name='+identity,'--format','{{.Name}}'],
            'network':['network','ls','--filter','name='+identity,'--format','{{.Name}}'],
            'image':['image','ls','--no-trunc','--quiet'],
        }
        _, raw, _=self.cmd(*commands[kind])
        return identity not in raw.decode().splitlines()

    def owned(self, kind, identity):
        """Verify exact identity, generated name and label; None means absent."""
        labels='.Config.Labels' if kind=='container' else '.Labels'
        id_expression='{{json .Id}}' if kind=='container' else '""'
        template=('{"id":'+id_expression+',"name":{{json .Name}},"label":{{json (index '
                  +labels+' "org.azt.test")}}}')
        code,raw,_=self.cmd(kind,'inspect','--format',template,identity,
                            allow_error=True,timeout=2,limit=16384)
        if code:
            require(self.absent(kind,identity), 'cleanup_identity_unverified')
            return None
        value=json.loads(raw)
        require(type(value) is dict and set(value)=={'id','name','label'},'cleanup_identity_fields')
        require(value['label']=='isolated-local-model-v1','cleanup_label')
        name=value['name']
        if kind=='container':
            require(type(name) is str and re.fullmatch('/'+re.escape(self.prefix)+'-[a-z]+',name),
                    'cleanup_container_name')
            cid=value['id']
            require(type(cid) is str and re.fullmatch('[0-9a-f]{64}',cid),'cleanup_container_id')
            require(cid==identity if re.fullmatch('[0-9a-f]{64}',identity) else name=='/'+identity,
                    'cleanup_identity_mismatch')
            return cid
        require(name==identity and value['id']=='','cleanup_identity_mismatch')
        return identity

    def controls(self, cid, network, model_readonly):
        _, raw, _ = self.cmd('inspect', cid, '--format', '{{json .}}'); item=json.loads(raw); host=item['HostConfig']
        require(item['Config']['User']=='65532:65532' and host['NetworkMode']==network and host['ReadonlyRootfs']
                and not host['Privileged'] and host['CapDrop']==['ALL'] and not host.get('CapAdd')
                and 'no-new-privileges=true' in host['SecurityOpt'] and not host.get('PortBindings')
                and host['Memory']==host['MemorySwap']==6*1024**3 and host['PidsLimit']==128
                and host['NanoCpus']==3500000000 and host['CgroupnsMode']=='private'
                and host['RestartPolicy']['Name']=='no', 'inference_controls')
        mounts=[m for m in item['Mounts'] if m['Type']!='tmpfs']
        require(len(mounts)==1 and mounts[0]['Type']=='volume' and mounts[0]['Destination']=='/models'
                and mounts[0]['RW'] is not model_readonly, 'inference_mounts')
        require(set(host['Tmpfs'])=={'/tmp','/root'}, 'inference_scratch')
        require(item['Config']['Cmd'][-4:]==['--signal=KILL','420','/bin/ollama','serve'] if model_readonly else True, 'service_lease')
        return {'network':network,'uid_gid':'65532:65532','read_only_root':True,'models_readonly':model_readonly,
                'memory_bytes':host['Memory'],'pids':128,'cpus':3.5,'ports_published':False,'capabilities_dropped':True}

    def wait_ready(self, relay):
        end=time.monotonic()+20
        while time.monotonic()<end:
            try:
                value=self.relay_call(relay, {'mode':'request','method':'GET','path':'/api/version','payload':None})
                require(value['version']=='0.34.2', 'service_version'); return value
            except (ValueError, subprocess.TimeoutExpired):
                time.sleep(.2)
        raise ValueError('service_not_ready')

    def network_controls(self, image, relay):
        network=self.prefix+'-net'
        self.networks.append(network); self.ledger()
        self.cmd('network','create','--internal','--label',LABEL,network)
        args=common(self.prefix+'-sink',network,'64m',.25,16)
        args+=['--mount','type=bind,src='+str(self.relay_source)+',dst=/relay.py,readonly',
               '--entrypoint','/usr/local/bin/python3',image,'-I','/relay.py','--sink']
        sink=self.create(args)
        _, raw, _=self.cmd('inspect',sink,'--format','{{json .NetworkSettings.Networks}}')
        address=json.loads(raw)[network]['IPAddress']; nonce=uuid.uuid4().hex
        args=common(self.prefix+'-positive',network,'64m',.25,16)
        args+=['--mount','type=bind,src='+str(self.relay_source)+',dst=/relay.py,readonly',
               '--entrypoint','/usr/local/bin/python3',image,'-I','-c','import time; time.sleep(60)']
        positive=self.create(args)
        for _ in range(20):
            control=self.relay_call(positive,{'mode':'probe','address':address,'nonce':nonce})
            if control['challenge_verified']:break
            time.sleep(.1)
        require(control['challenge_verified'], 'network_positive_control_failed')
        denial=self.relay_call(relay,{'mode':'probe','address':address,'nonce':nonce})
        require(denial['interfaces']==['lo'] and not denial['connected'], 'network_boundary_failed')
        self.remove(positive); self.remove(sink)
        return {'positive_challenge_verified':True,'isolated_attempt_connected':False,
                'isolated_interfaces':['lo'],'scope':'one generated challenge to a test-owned sink; not universal traffic instrumentation'}

    def cleanup(self):
        ok=True; resources=[]
        for name in getattr(self,'pending_containers',[]):
            try:
                cid=self.owned('container',name)
                if cid is not None:self.remove(cid)
                removed=self.absent('container',name)
            except Exception:removed=False
            ok=ok and removed
            resources.append({'kind':'pending_container','absence_verified':removed})
        for cid in reversed(self.ids):
            try:
                self.remove(cid); removed=True
            except Exception:removed=False;ok=False
            resources.append({'kind':'container','absence_verified':removed})
        for kind, names in (('volume',self.volumes),('network',self.networks)):
            for name in names:
                try:
                    if getattr(self,'verify_ownership',False):self.owned(kind,name)
                    if not self.absent(kind,name):self.cmd(kind,'rm',name)
                    removed=self.absent(kind,name)
                except Exception:removed=False
                ok=ok and removed
                resources.append({'kind':kind,'absence_verified':removed})
        image_results=[]
        for image in self.new_images:
            try:
                if not self.absent('image',image):self.cmd('image','rm',image,allow_error=True)
                removed=self.absent('image',image)
            except Exception:removed=False
            image_results.append({'image':image,'removed':removed})
        return {'containers_volumes_networks_removed':ok,'new_images':image_results,
                'resource_readbacks':resources,
                'remaining_image_backstop':'disposable hosted VM destruction; never host prune',
                'host_service_installed':False}


def cleanup_saved(root):
    """Independent workflow always-step: exact ledger IDs AND daemon labels."""
    from azt_docker import Docker
    path=root/'owned.json'
    if not path.exists():return {'status':'no_created_resources_recorded'}
    require(path.stat().st_size<=8192,'cleanup_ledger_bound')
    value=json.loads(path.read_text())
    require(re.fullmatch('azt-live-[a-f0-9]{12}',value['prefix']), 'cleanup_prefix')
    lab=object.__new__(Lab);lab.root=root;lab.prefix=value['prefix'];lab.verify_ownership=True
    # Repeated cleanup gets a fresh credential-free client directory; do not
    # reuse (or recursively erase) arbitrary pre-existing control paths.
    control=Path(tempfile.mkdtemp(prefix='fallback-cleanup-',dir=root))
    lab.docker=Docker('unix:///var/run/docker.sock',control)
    lab.ids=value['containers'];lab.volumes=value['volumes'];lab.networks=value['networks'];lab.new_images=value['new_images']
    lab.pending_containers=value.get('pending_containers',[])
    require(len(lab.ids)<=12 and len(lab.pending_containers)<=12 and len(lab.volumes)<=1
            and len(lab.networks)<=1 and len(lab.new_images)<=2,'cleanup_count')
    require(all(re.fullmatch(re.escape(lab.prefix)+'-[a-z]+',s) for s in lab.pending_containers),
            'cleanup_pending_identity')
    for kind, items in (('container',lab.ids),('volume',lab.volumes),('network',lab.networks)):
        for item in items:
            require(re.fullmatch('[0-9a-f]{64}',item) if kind=='container' else
                    re.fullmatch(re.escape(value['prefix'])+'-[a-z]+',item), 'cleanup_identity')
    # Ownership readback is performed per resource inside cleanup(). A daemon
    # error/mismatched label skips that resource, not every later removal.
    require(all(re.fullmatch('sha256:[0-9a-f]{64}',s) for s in lab.new_images),'cleanup_image_identity')
    result=lab.cleanup();save(root/'fallback-cleanup.json',result);return result


class Bridge:
    def __init__(self, lab, relay):
        self.calls=0; self.chat_calls=0; self.observations=[]
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def setup(self):
                super().setup();self.connection.settimeout(12)
            def do_GET(self):self.route('GET')
            def do_POST(self):self.route('POST')
            def route(self,method):
                owner.calls+=1
                start=time.monotonic()
                try:
                    require(owner.calls<=60 and (method,self.path) in (('GET','/api/version'),('GET','/api/tags'),('POST','/api/chat')), 'bridge_route_budget')
                    require(not self.headers.get('Transfer-Encoding') and not self.headers.get('Authorization'), 'bridge_headers')
                    size=int(self.headers.get('Content-Length','0'));require(0<=size<=16384,'bridge_size')
                    payload=json.loads(self.rfile.read(size)) if size else None
                    if method=='POST':
                        owner.chat_calls+=1
                        require(owner.chat_calls<=48 and payload.get('model')==MODEL,'bridge_model_budget')
                    value=lab.relay_call(relay,{'mode':'request','method':method,'path':self.path,'payload':payload},timeout=11)
                    raw=json.dumps(value,ensure_ascii=True).encode();require(len(raw)<=65536,'bridge_reply')
                    owner.observations.append({'method':method,'path':self.path,'seconds':round(time.monotonic()-start,3),
                        'response_bytes':len(raw),'prompt_eval_count':value.get('prompt_eval_count'),
                        'eval_count':value.get('eval_count'),'response_sha256':hashlib.sha256(raw).hexdigest()})
                    self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                except Exception as exc:
                    owner.observations.append({'method':method,'path':'fixed_local_route','failed':True,
                        'seconds':round(time.monotonic()-start,3),'error_type':type(exc).__name__})
                    try:self.send_error(502,'bounded_local_inference_failed')
                    except OSError:pass
        self.server=HTTPServer(('127.0.0.1',0),Handler);self.server.timeout=12
        self.thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':.1},daemon=True)
    def __enter__(self):self.thread.start();return self
    def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(12)


def execute_case(root, name, image, config, lab):
    import azt_research_runtime as runtime
    original=Path(__file__).resolve().parents[1]/'examples/protected-research/investigator'
    case=root/name;case.mkdir(mode=0o700);captures=case/'captures';captures.mkdir()
    manifest=json.loads((original/'sources.json').read_text())
    if name=='limited':manifest['sources']=[s for s in manifest['sources'] if s['id']=='guide']
    selected=['guide.md'] if name=='limited' else ['guide.md','support.md','peer.json']
    for file in selected:(captures/file).write_bytes((original/'captures'/file).read_bytes())
    save(case/'sources.json',manifest);save(case/'inference.json',config)
    before={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in captures.iterdir()}
    start=time.monotonic()
    call=subprocess.run([sys.executable,'-I','-m','azt','research','investigate','--manifest',str(case/'sources.json'),
        '--root','captures='+str(captures),'--inference-config',str(case/'inference.json'),
        '--image',image,'--output',str(case/'run')],cwd=root,env=runtime.ENV,capture_output=True,timeout=140)
    require(len(call.stdout)+len(call.stderr)<=4096,'cli_output_limit')
    raw=(case/'run/report.json').read_bytes(); require(len(raw)<=4*1024*1024,'report_bound')
    report=json.loads(raw);execution=report['execution'];model=report['investigator']
    cid=execution.get('container_id')
    if cid:
        require(re.fullmatch('[0-9a-f]{64}',cid),'worker_container_identity')
        _,out,_=lab.cmd('ps','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}')
        worker_absent=cid not in out.decode().splitlines()
    else:worker_absent=None
    rubric=json.loads((original/'expected-v1.json').read_text())
    expected=[e for e in rubric['required_quote_coverage'] if name!='limited' or e['registration']=='guide']
    docs={d['registration']:d for d in report['mission']['documents']};covered=[]
    for item in expected:
        d=docs[item['registration']]
        covered.append(any(ref['source']==d['id'] and ref['sha256']==d['sha256'] and ref['line_start']==item['line']
            and ref.get('quote')==item['quote'] for h in model['hypotheses'] for ref in h['evidence']))
    fixture_ok=before=={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in captures.iterdir()}
    completed=call.returncode==0 and execution['status']=='passed' and all(execution['stages'].values())
    # Unlike the scripted case, a live model need not propose exactly four bad calls.
    # Report observed denials, never manufacture an attempted attack/OS result.
    return {'case':name,'exit':call.returncode,'seconds':round(time.monotonic()-start,3),
        'completed':completed,'execution':{k:execution.get(k) for k in
            ('status','stages','cleanup','error_stage','error','worker_sha256')},
        'external_worker_absence_verified':worker_absent,
        'report_sha256':hashlib.sha256(raw).hexdigest(),'fixtures_unchanged':fixture_ok,
        'exact_quote_coverage':sum(covered),'required_quotes':len(covered),
        'outcome':'passed' if completed and all(covered) and fixture_ok and worker_absent and execution['cleanup']=='removed' else 'failed',
        'investigator':model,'mission':{k:report['mission'].get(k) for k in ('read_sources','checked_sources','state')},
        'interpretation_quality':'pending human review; exact citation checks do not establish truth',
        'unnecessary_denials':'requires review of actual model proposals; not inferred from a green outcome'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    mode=parser.add_mutually_exclusive_group()
    mode.add_argument('--cleanup',action='store_true')
    mode.add_argument('--startup-only',action='store_true',
                      help='diagnose the unchanged download service; no model pull or inference')
    args=parser.parse_args()
    require(platform.system()=='Linux' and os.environ.get('GITHUB_ACTIONS')=='true'
            and os.environ.get('GITHUB_REPOSITORY')=='ralfyishere/agent-zero-trust'
            and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted', 'disposable_authorized_linux_only')
    if args.cleanup:
        value=cleanup_saved(args.output.resolve())
        print('AZT_LIVE_MODEL_CLEANUP '+json.dumps(value,sort_keys=True))
        return 0 if value.get('containers_volumes_networks_removed',True) else 2
    root=args.output.resolve();require(not root.exists(),'new_output_required');root.mkdir(mode=0o700)
    lab=Lab(root);start=time.monotonic();stage='image_setup'
    result={'schema':'azt.live-model-evaluation.v1','status':'blocked','source_sha':os.environ.get('GITHUB_SHA'),
        'run_id':os.environ.get('GITHUB_RUN_ID'),'cases':[],'live_sessions_started':0,'preload_requests':0,
        'model':MODEL,'model_sha256':MODEL_DIGEST,'ollama_ref':OLLAMA_REF,'python_ref':PYTHON_REF}
    if args.startup_only:
        result.pop('model');result.pop('model_sha256')
        result.update(schema='azt.model-startup-diagnostic.v1', evaluation_kind='startup-only',
            model_pull_requests=0, inference_requests=0,
            scope='download-service startup/readiness and cleanup only; no model, investigation or network-boundary result',
            stages={'images_resolved':False,'backend_available':False,'model_volume_created':False,
                    'service_start_acknowledged':False,'relay_start_acknowledged':False,
                    'configuration_readback_completed':False,'readiness_response_validated':False})
    try:
        py=lab.pull(PYTHON_REF);ollama=lab.pull(OLLAMA_REF)
        result['image_ids']={'python':py,'ollama':ollama}
        if args.startup_only:
            result['stages']['images_resolved']=True;stage='backend_preflight'
        backend=lab.docker.preflight(py);require(backend['status']=='available','required_backend_controls')
        result['backend']=backend
        if args.startup_only:result['stages']['backend_available']=True
        stage='model_volume_setup' if args.startup_only else 'bounded_model_download'
        volume=lab.model_volume()
        if args.startup_only:
            result['stages']['model_volume_created']=True;stage='download_service_start'
        download=lab.ollama(ollama,volume,'download')
        if args.startup_only:
            result['stages']['service_start_acknowledged']=True;stage='readiness_relay_start'
        relay=lab.relay(py,download,volume,'downloadrelay')
        if args.startup_only:
            result['stages']['relay_start_acknowledged']=True;stage='download_configuration_readback'
        controls=lab.controls(download,'bridge',False)
        if args.startup_only:
            result['configuration_readback']=controls
            result['stages']['configuration_readback_completed']=True;stage='download_service_readiness'
        lab.wait_ready(relay)
        if args.startup_only:
            # wait_ready validates the fixed version. Never export arbitrary
            # service response fields or fall through to the live-model branch.
            result['stages']['readiness_response_validated']=True
            result['service_version']='0.34.2'
            result['status']='passed'
        else:
            lab.relay_call(relay,{'mode':'pull'},timeout=240)
            result['model_store']=lab.relay_call(relay,{'mode':'store'},timeout=30)
            # Keep one read-only mount alive: a local-driver tmpfs loses its bytes
            # when its last container unmounts it. The networked service stops first.
            old_relay=relay;lab.remove(download)
            stage='isolated_service_validation'
            server=lab.ollama(ollama,volume,'inference');relay=lab.relay(py,server,volume,'relay')
            lab.remove(old_relay)
            result['service_controls']=lab.controls(server,'none',True);lab.wait_ready(relay)
            # Docker puts service stderr on stderr; inspect both bounded streams below.
            _,out,err=lab.cmd('logs',server,limit=65536)
            require(b'Ollama cloud disabled: true' in out+err,'cloud_disabled_log_missing')
            result['cloud_disabled_log_verified']=True
            result['network_control']=lab.network_controls(py,relay)
            stage='model_preload'
            result['preload_requests']=1
            result['preload']=lab.relay_call(relay,{'mode':'preload'},timeout=50)
            require(result['preload'].get('done') is True,'model_preload_incomplete')
            stage='live_model_trials'
            with Bridge(lab,relay) as bridge:
                config={'schema':'azt.ollama-local.v1','endpoint':'http://127.0.0.1:'+str(bridge.server.server_port),
                        'model':MODEL,'model_sha256':MODEL_DIGEST,'cloud_disabled':True,
                        'verification':'operator-checked-service-config-and-log'}
                for name in ('limited','multi-source'):
                    result['live_sessions_started']+=1
                    try:record=execute_case(root,name,py,config,lab)
                    except Exception as exc:record={'case':name,'outcome':'failed','error':type(exc).__name__,'complete_verification':False}
                    result['cases'].append(record);save(root/'partial.json',result)
                result['transport_observations']=bridge.observations
                result['inference_requests']=bridge.chat_calls
            _,raw,_=lab.cmd('stats','--no-stream','--format','{{json .}}',server,timeout=10)
            stats=json.loads(raw);result['service_post_test_resource_sample']={k:stats.get(k) for k in ('CPUPerc','MemUsage','PIDs')}
            result['service_post_test_resource_sample']['scope']='single post-test sample, not a peak measurement'
            result['status']='passed' if all(c['outcome']=='passed' for c in result['cases']) else 'failed'
    except Exception as exc:
        result['failure']={'stage':stage,'type':type(exc).__name__,
                           'reason':str(exc) if isinstance(exc,ValueError) else 'bounded_setup_or_evaluation_failure'}
    finally:
        if args.startup_only and result.get('failure',{}).get('stage')=='download_service_readiness':
            result['service_state_after_readiness_failure']=lab.start_state(download)
        result['setup_container_starts']=lab.start_attempts
        result['cleanup']=lab.cleanup()
        if not result['cleanup']['containers_volumes_networks_removed']:result['status']='failed'
        if args.startup_only and not all(item['removed'] for item in result['cleanup']['new_images']):
            result['status']='failed'
        result['wall_seconds']=round(time.monotonic()-start,3)
        result['evaluator_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result['limits']={'job_seconds':900,'inference_container_seconds':420,'worker_seconds':120,'request_seconds':10,
                          'model_sessions':2,'model_store_bytes':805306368,'cloud_service':False}
        if args.startup_only:
            result['limits']={'job_seconds':900,'download_container_seconds':300,'relay_container_seconds':450,
                              'model_sessions':0,'model_store_bytes':805306368,'cloud_service':False}
        save(root/'evaluation.json',result)
        marker='AZT_MODEL_STARTUP' if args.startup_only else 'AZT_LIVE_MODEL'
        print(marker+'_EVIDENCE_BEGIN\n'+json.dumps(result,sort_keys=True,ensure_ascii=True)+'\n'+marker+'_EVIDENCE_END',flush=True)
    return 0 if result['status']=='passed' else 2


if __name__=='__main__':raise SystemExit(main())
