"""Offline setup/relay regressions. No Docker or model execution here."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name, file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/'scripts'/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


lab=module('live_model_lab','test_live_model.py')
relay=module('live_model_relay','live_model_relay.py')


class LiveModelSetupTests(unittest.TestCase):
    def test_cleanup_daemon_errors_are_not_absence_and_do_not_abort(self):
        obj=object.__new__(lab.Lab)
        obj.ids=['a'*64];obj.volumes=['azt-live-'+'b'*12+'-models']
        obj.networks=['azt-live-'+'b'*12+'-net'];obj.new_images=['sha256:'+'c'*64]
        def unavailable(*args,**kwargs):raise RuntimeError('daemon unavailable')
        obj.cmd=unavailable
        value=obj.cleanup()
        self.assertFalse(value['containers_volumes_networks_removed'])
        self.assertEqual(len(value['resource_readbacks']),3)
        self.assertTrue(all(not r['absence_verified'] for r in value['resource_readbacks']))
        self.assertFalse(value['new_images'][0]['removed'])

    def test_exact_cleanup_readback_and_repetition(self):
        obj=object.__new__(lab.Lab);prefix='azt-live-'+'a'*12
        obj.ids=['b'*64];obj.volumes=[prefix+'-models'];obj.networks=[prefix+'-net']
        obj.new_images=['sha256:'+'c'*64]
        present={'container':set(obj.ids),'volume':set(obj.volumes),
                 'network':set(obj.networks),'image':set(obj.new_images)|{'sha256:'+'d'*64}}
        calls=[]
        def command(*args,**kwargs):
            calls.append(args)
            if args[0]=='rm':present['container'].discard(args[-1])
            elif len(args)>1 and args[1]=='rm':present[args[0]].discard(args[-1])
            else:
                kind='container' if args[0]=='ps' else args[0]
                return 0,'\n'.join(sorted(present[kind])).encode(),b''
            return 0,b'',b''
        obj.cmd=command
        for _ in range(2):
            value=obj.cleanup()
            self.assertTrue(value['containers_volumes_networks_removed'])
            self.assertTrue(value['new_images'][0]['removed'])
            self.assertTrue(all(r['absence_verified'] for r in value['resource_readbacks']))
        self.assertEqual(present['image'],{'sha256:'+'d'*64})
        self.assertFalse(any('prune' in call for call in calls))

    def test_successful_remove_return_does_not_substitute_for_absence(self):
        obj=object.__new__(lab.Lab);obj.ids=['a'*64]
        obj.volumes=[];obj.networks=[];obj.new_images=[]
        obj.cmd=lambda *args,**kw:(0,('a'*64).encode() if args[0]=='ps' else b'',b'')
        self.assertFalse(obj.cleanup()['containers_volumes_networks_removed'])

    def test_fallback_cleanup_can_be_repeated_without_reusing_client_directory(self):
        clients=[]
        class Docker:
            def __init__(self,endpoint,control):clients.append(control)
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)
            lab.save(path/'owned.json',{'prefix':'azt-live-'+'a'*12,'containers':[],
                'volumes':[],'networks':[],'new_images':[]})
            with patch('azt_docker.Docker',Docker):
                for _ in range(2):self.assertTrue(lab.cleanup_saved(path)['containers_volumes_networks_removed'])
            self.assertEqual(len(set(clients)),2)
            self.assertTrue(all(p.parent==path for p in clients))

    def test_fallback_lookup_failure_requires_successful_absence_readback(self):
        calls=[]
        class Docker:
            def __init__(self,*args):pass
            def command(self,*args,**kwargs):
                calls.append(args)
                if 'inspect' in args:return 1,b'',b'permission denied'
                raise RuntimeError('daemon unavailable')
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)
            lab.save(path/'owned.json',{'prefix':'azt-live-'+'a'*12,'containers':[],
                'volumes':['azt-live-'+'a'*12+'-models'],'networks':[],'new_images':[]})
            with patch('azt_docker.Docker',Docker),self.assertRaises(RuntimeError):lab.cleanup_saved(path)
        self.assertFalse(any('rm' in call for call in calls))

    def test_preexisting_image_identity_not_added_to_cleanup_ledger(self):
        obj=object.__new__(lab.Lab);obj.new_images=[];obj.ledger=lambda:None
        image='sha256:'+'a'*64
        def command(*args,**kw):
            if args[:2]==('image','ls'):return 0,image.encode(),b''
            if args[0]=='pull':return 0,b'',b''
            return 0,json.dumps({'Id':image,'Architecture':'amd64','Os':'linux','Config':{}}).encode(),b''
        obj.cmd=command
        self.assertEqual(obj.pull(lab.OLLAMA_REF),image)
        self.assertEqual(obj.new_images,[])

    def test_start_transport_failure_keeps_cleanup_target_and_unknown_progress(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.ids=[];obj.start_attempts=[];obj.ledger=lambda:None
        def command(*args,**kw):
            if args[0]=='create':return 0,('b'*64).encode(),b''
            raise RuntimeError('private daemon details')
        obj.cmd=command
        with self.assertRaises(RuntimeError):obj.create(['create','--name',obj.prefix+'-downloadrelay'])
        self.assertEqual(obj.ids,['b'*64])
        self.assertEqual(obj.start_attempts,[{'role':'downloadrelay','start_acknowledged':False,
                                            'transport_error_type':'RuntimeError'}])

    def test_workflow_keeps_cleanup_and_failure_export_independent(self):
        # Wiring check only, not a simulation of the GitHub Actions engine.
        text=(Path(__file__).resolve().parents[1]/'.github/workflows/research.yml').read_text()
        cleanup=text.split('      - name: Exact-resource cleanup, even after failure\n',1)[1]
        cleanup,export=cleanup.split('      - name: Export sanitized evidence and preserve experiment failure\n',1)
        for block in (cleanup,export):self.assertIn('        if: always()\n',block)
        self.assertIn('--cleanup --output',cleanup)
        self.assertNotIn('research_ci_evidence.py',cleanup)
        self.assertIn('research_ci_evidence.py',export)
        self.assertNotIn('continue-on-error',text)
        self.assertNotIn('|| true',text)

    def test_start_failure_preserves_owned_cleanup_target_and_safe_diagnostic(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.ids=[];obj.start_attempts=[];obj.ledger=lambda:None
        cid='b'*64;calls=[]
        def command(*args,**kwargs):
            calls.append((args,kwargs))
            if args[0]=='create':return 0,cid.encode(),b''
            return 1,b'',b'error mounting /private/SENSITIVE: permission denied\n@recipient'
        obj.cmd=command
        with self.assertRaisesRegex(ValueError,'container_start_failed:download'):
            obj.create(['create','--name',obj.prefix+'-download'])
        self.assertEqual(obj.ids,[cid])
        self.assertEqual(calls[-1],(('start',cid),{'allow_error':True}))
        record=obj.start_attempts[0]
        self.assertFalse(record['start_acknowledged'])
        self.assertEqual(record['diagnostic']['categories'],['permission_denied','mount_failure'])
        serialized=json.dumps(record)
        for value in ('SENSITIVE','recipient','/private',cid):self.assertNotIn(value,serialized)

    def test_successful_start_and_unknown_failure_are_not_conflated(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.ids=[];obj.start_attempts=[];obj.ledger=lambda:None
        obj.cmd=lambda *args,**kw:(0,('b'*64).encode() if args[0]=='create' else b'',b'')
        self.assertEqual(obj.create(['create','--name',obj.prefix+'-relay']),'b'*64)
        self.assertEqual(obj.start_attempts,[{'role':'relay','start_acknowledged':True}])
        self.assertEqual(lab.start_diagnostic(1,b'',b'unknown PRIVATE message')['categories'],['unclassified'])

    def test_fixed_controls_and_no_host_namespace(self):
        args=lab.common('azt-live-'+'a'*12+'-inference','none','6g',3.5,128)
        for flag,value in (('--user','65532:65532'),('--network','none'),('--cap-drop','ALL'),
                           ('--security-opt','no-new-privileges=true'),('--memory-swap','6g'),('--pids-limit','128')):
            self.assertEqual(args[args.index(flag)+1],value)
        self.assertIn('--read-only',args);self.assertNotIn('--privileged',args)
        self.assertNotIn('--publish',args);self.assertNotIn('--pid',args)

    def test_unsafe_names_rejected(self):
        for name in ('main','--privileged','azt-live-'+'a'*12+'-x;echo bad','azt-live-'+'a'*12+'-../'):
            with self.assertRaises(ValueError):lab.common(name,'none','6g',3.5,128)

    def test_service_uses_only_bounded_container_state(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12;obj.create=lambda args:args
        args=obj.ollama('sha256:'+'b'*64,'test-model-volume','inference')
        self.assertEqual(args[args.index('--network')+1],'none')
        self.assertIn('type=volume,src=test-model-volume,dst=/models,readonly',args)
        self.assertIn('OLLAMA_NO_CLOUD=1',args);self.assertIn('420',args)
        self.assertNotIn('type=bind',','.join(args));self.assertNotIn('/var/run/docker.sock',','.join(args))
        self.assertEqual(args[-2:],['/bin/ollama','serve'])

    def test_relay_refuses_arbitrary_route_without_connection(self):
        with patch.object(relay.http.client,'HTTPConnection') as connect:
            for method,path in (('POST','/api/delete'),('GET','https://example.invalid/'),('GET','/api/tags?secret=x')):
                with self.assertRaises(ValueError):relay.request(method,path,None)
            connect.assert_not_called()

    def test_relay_bounds_response_and_drops_reasoning(self):
        class Response:
            status=200
            def getheader(self,key,default=None):return default
            def read(self,n):return json.dumps({'message':{'thinking':'PRIVATE_INTERNAL_TRACE','content':'bounded'}}).encode()
        class Connection:
            def __init__(self,*a,**kw):pass
            def request(self,*a,**kw):pass
            def getresponse(self):return Response()
            def close(self):pass
        with patch.object(relay.http.client,'HTTPConnection',Connection):
            value=relay.request('GET','/api/version',None)
            self.assertEqual(value,{'message':{'content':'bounded'}})
        with patch.object(Response,'read',lambda self,n:b'a'*(relay.LIMIT+1)):
            with patch.object(relay.http.client,'HTTPConnection',Connection):
                with self.assertRaisesRegex(ValueError,'reply_bound'):relay.request('GET','/api/version',None)
        with patch.object(Response,'status',302):
            with patch.object(relay.http.client,'HTTPConnection',Connection):
                with self.assertRaisesRegex(ValueError,'service_status'):relay.request('GET','/api/version',None)

    def test_probes_are_fixed_synthetic_data_not_urls(self):
        with patch.object(relay.socket,'create_connection') as connect:
            for address in ('example.invalid','127.0.0.1;touch X','::1'):
                with self.assertRaises(ValueError):relay.probe(address,'a'*32)
            connect.assert_not_called()

    def test_relay_cannot_normalize_malformed_duplicate_records(self):
        with self.assertRaisesRegex(ValueError,'duplicate_key'):relay.parse('{"done":false,"done":true}')
        with self.assertRaisesRegex(ValueError,'json_complexity'):relay.parse('['*20+'0'+']'*20)
        with self.assertRaisesRegex(ValueError,'json_complexity'):relay.parse(json.dumps([0]*5000))
        self.assertEqual(relay.parse('{"done":true}'),{'done':True})

    def test_missing_ledger_cleanup_is_noop(self):
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(lab.cleanup_saved(Path(root)),{'status':'no_created_resources_recorded'})

    def test_mac_guard_precedes_docker_and_model_calls(self):
        with patch.object(lab.platform,'system',return_value='Darwin'),patch.object(lab,'Lab') as launch:
            with patch.object(lab.sys,'argv',['test','--output','/unused']):
                with self.assertRaisesRegex(ValueError,'disposable_authorized_linux_only'):lab.main()
            launch.assert_not_called()


if __name__=='__main__':unittest.main()
