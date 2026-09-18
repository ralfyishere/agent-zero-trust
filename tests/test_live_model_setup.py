"""Offline setup/relay regressions. No Docker or model execution here."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


def module(name, file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/'scripts'/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


lab=module('live_model_lab','test_live_model.py')
relay=module('live_model_relay','live_model_relay.py')


class LiveModelSetupTests(unittest.TestCase):
    def startup(self, fail=None, cleanup_ok=True, readiness=None, backend='available', images_ok=True):
        """Exercise orchestration with a fake backend; never runtime evidence."""
        obj=Mock(spec=lab.Lab)
        obj.docker=Mock();obj.docker.preflight.return_value={'status':backend}
        obj.pull.side_effect=['sha256:'+'a'*64,'sha256:'+'b'*64]
        obj.model_volume.return_value='test-volume'
        obj.ollama.return_value='test-service';obj.relay.return_value='test-relay'
        obj.controls.return_value={'network':'bridge','uid_gid':'65532:65532'}
        obj.start_attempts=[]
        obj.cleanup.return_value={'containers_volumes_networks_removed':cleanup_ok,
                                  'new_images':[{'image':'sha256:'+'a'*64,'removed':images_ok}]}
        obj.start_state.return_value={'status':'observed','container_status':'exited'}
        obj.relay_call.return_value={'version':'0.34.2','private':'DO_NOT_EXPORT'}
        if fail:getattr(obj,fail).side_effect=ValueError('synthetic_setup_failure')
        with tempfile.TemporaryDirectory(prefix='azt startup with spaces ') as directory:
            output=Path(directory)/'private evidence'
            argv=['test','--startup-only','--output',str(output)]
            env={'GITHUB_ACTIONS':'true','GITHUB_REPOSITORY':'ralfyishere/agent-zero-trust',
                 'RUNNER_ENVIRONMENT':'github-hosted','GITHUB_SHA':'c'*40,'GITHUB_RUN_ID':'synthetic'}
            original_readiness=lab.Lab.wait_ready
            # Actual readiness logic over a mocked transport, not an OS test.
            obj.wait_ready.side_effect=readiness or (lambda relay:original_readiness(obj,relay))
            with patch.object(lab.platform,'system',return_value='Linux'), \
                 patch.dict(lab.os.environ,env,clear=True),patch.object(lab.sys,'argv',argv), \
                 patch.object(lab,'Lab',return_value=obj), \
                 patch.object(lab,'Bridge') as bridge,patch.object(lab,'execute_case') as task, \
                 patch.object(lab.sys,'stdout',new_callable=io.StringIO) as stdout:
                code=lab.main()
                printed=stdout.getvalue()
            value=json.loads((output/'evaluation.json').read_text())
        bridge.assert_not_called();task.assert_not_called()
        obj.cleanup.assert_called_once_with();obj.network_controls.assert_not_called()
        obj.cmd.assert_not_called()  # no service logs, stats or other commands
        for call in obj.relay_call.call_args_list:
            self.assertEqual(call.args,('test-relay',{'mode':'request','method':'GET',
                                                     'path':'/api/version','payload':None}))
        self.assertEqual(value['cases'],[])
        for counter in ('model_pull_requests','preload_requests','inference_requests','live_sessions_started'):
            self.assertEqual(value[counter],0)
        return code,value,obj,printed

    def test_startup_only_completes_diagnostic_not_a_live_model_trial(self):
        code,value,obj,printed=self.startup()
        self.assertEqual(code,0);self.assertEqual(value['status'],'passed')
        self.assertEqual(value['schema'],'azt.model-startup-diagnostic.v1')
        self.assertEqual(value['evaluation_kind'],'startup-only')
        self.assertTrue(all(value['stages'].values()))
        self.assertEqual(value['service_version'],'0.34.2')
        self.assertNotIn('DO_NOT_EXPORT',printed)
        self.assertIn('AZT_MODEL_STARTUP_EVIDENCE_BEGIN',printed)
        self.assertNotIn('AZT_LIVE_MODEL_EVIDENCE_BEGIN',printed)
        for absent in ('model','model_sha256','model_store','network_control','cloud_disabled_log_verified'):
            self.assertNotIn(absent,value)
        obj.pull.assert_any_call(lab.PYTHON_REF);obj.pull.assert_any_call(lab.OLLAMA_REF)
        self.assertEqual(obj.pull.call_count,2)
        obj.ollama.assert_called_once_with('sha256:'+'b'*64,'test-volume','download')
        obj.relay.assert_called_once_with('sha256:'+'a'*64,'test-service','test-volume','downloadrelay')
        obj.controls.assert_called_once_with('test-service','bridge',False)
        obj.relay_call.assert_called_once()
        obj.start_state.assert_not_called()

    def test_startup_only_setup_failures_preserve_progress_and_cleanup(self):
        for method,stage,completed in (
            ('pull','image_setup',0),('model_volume','model_volume_setup',2),
            ('ollama','download_service_start',3),('relay','readiness_relay_start',4),
            ('controls','download_configuration_readback',5)):
            with self.subTest(method=method):
                code,value,obj,_=self.startup(fail=method)
                self.assertEqual(code,2);self.assertEqual(value['status'],'blocked')
                self.assertEqual(value['failure']['stage'],stage)
                self.assertEqual(sum(value['stages'].values()),completed)
                obj.wait_ready.assert_not_called();obj.relay_call.assert_not_called()
                obj.start_state.assert_not_called()

    def test_startup_only_unready_service_is_not_a_start_failure(self):
        code,value,obj,_=self.startup(readiness=ValueError('service_not_ready'))
        self.assertEqual(code,2);self.assertEqual(value['failure']['stage'],'download_service_readiness')
        self.assertTrue(value['stages']['service_start_acknowledged'])
        self.assertFalse(value['stages']['readiness_response_validated'])
        self.assertEqual(value['service_state_after_readiness_failure']['container_status'],'exited')
        obj.start_state.assert_called_once_with('test-service')

    def test_startup_only_backend_block_never_creates_a_service(self):
        code,value,obj,_=self.startup(backend='unavailable')
        self.assertEqual(code,2);self.assertEqual(value['status'],'blocked')
        self.assertEqual(value['failure']['stage'],'backend_preflight')
        self.assertEqual(sum(value['stages'].values()),1)
        obj.model_volume.assert_not_called();obj.ollama.assert_not_called()

    def test_startup_only_retained_new_image_is_not_complete_cleanup(self):
        code,value,_,_=self.startup(images_ok=False)
        self.assertEqual(code,2);self.assertEqual(value['status'],'failed')
        self.assertTrue(value['stages']['readiness_response_validated'])
        self.assertFalse(value['cleanup']['new_images'][0]['removed'])

    def test_existing_export_retains_diagnostic_scope_and_non_success(self):
        exporter=module('startup_evidence_exporter','research_ci_evidence.py')
        for cleanup_ok in (True,False):
            _,value,_,_=self.startup(cleanup_ok=cleanup_ok)
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);lab.save(root/'evaluation.json',value)
                with patch.object(lab.sys,'argv',['export','--evidence',str(root/'evaluation.json'),
                                                 '--dist',str(root/'dist')]), \
                     patch.object(lab.sys,'stdout',new_callable=io.StringIO) as stdout:
                    code=exporter.main()
                record=json.loads(stdout.getvalue().splitlines()[1])
            self.assertEqual(code,0 if cleanup_ok else 2)
            self.assertEqual(record['evaluation'],value)
            self.assertEqual(record['evaluation']['schema'],'azt.model-startup-diagnostic.v1')

    def test_startup_only_cleanup_failure_cannot_return_success(self):
        code,value,_,_=self.startup(cleanup_ok=False)
        self.assertEqual(code,2);self.assertEqual(value['status'],'failed')
        self.assertTrue(value['stages']['readiness_response_validated'])
        self.assertFalse(value['cleanup']['containers_volumes_networks_removed'])

    def test_readiness_wrong_version_never_validates(self):
        obj=object.__new__(lab.Lab)
        with patch.object(obj,'relay_call',return_value={'version':'unreviewed'}) as request, \
             patch.object(lab.time,'monotonic',side_effect=[0,1,21]),patch.object(lab.time,'sleep'):
            with self.assertRaisesRegex(ValueError,'service_not_ready'):obj.wait_ready('relay')
        request.assert_called_once_with('relay',{'mode':'request','method':'GET',
                                                'path':'/api/version','payload':None})

    def test_startup_and_cleanup_modes_cannot_be_combined(self):
        with patch.object(lab.sys,'argv',['test','--startup-only','--cleanup','--output','/unused']), \
             patch.object(lab.sys,'stderr',new_callable=io.StringIO),patch.object(lab,'Lab') as launch:
            with self.assertRaises(SystemExit) as error:lab.main()
        self.assertEqual(error.exception.code,2);launch.assert_not_called()

    def test_startup_only_mac_guard_precedes_every_backend_operation(self):
        with patch.object(lab.platform,'system',return_value='Darwin'),patch.object(lab,'Lab') as launch, \
             patch.object(lab.sys,'argv',['test','--startup-only','--output','/unused']):
            with self.assertRaisesRegex(ValueError,'disposable_authorized_linux_only'):lab.main()
        launch.assert_not_called()

    def test_ordered_markers_preserve_layers_but_never_raw_daemon_text(self):
        error=(b'Error response from daemon: failed to create shim task: OCI runtime create failed: '
               b'runc create failed: unable to start container process: error during container init: '
               b'error mounting /private/SYNTHETIC_SECRET: invalid argument\n'
               b'::error::https://user:SECRET@example.invalid/?token=PRIVATE\x1b[31m')
        value=lab.start_diagnostic(1,b'PRIVATE_STDOUT',error)
        self.assertEqual(value['markers_in_message_order'],[
            'daemon_response','shim_creation','oci_creation','runc_creation',
            'process_start','container_initialization','mount_setup','invalid_argument'])
        self.assertEqual(value['schema'],'azt.docker-start-diagnostic.v2')
        self.assertEqual(value['stderr_bytes'],len(error))
        self.assertEqual(value['stdout_bytes'],14)
        for secret in ('PRIVATE','SECRET','example.invalid','::error::','/private','user:', '\\u001b'):
            self.assertNotIn(secret,json.dumps(value))

    def test_markers_distinguish_os_failures_without_inventing_a_cause(self):
        for error,marker in ((b'invalid argument','invalid_argument'),
                             (b'operation not supported','unsupported_operation'),
                             (b'exec format error','exec_format'),
                             (b'too many open files','open_file_limit')):
            with self.subTest(marker=marker):
                value=lab.start_diagnostic(1,b'',error)
                self.assertEqual(value['markers_in_message_order'],[marker])
                self.assertIn('not an established root cause',value['scope'])
        unknown=lab.start_diagnostic(1,b'',b'\xff\xfePRIVATE\xe2\x80\xae')
        self.assertEqual(unknown['categories'],['unclassified'])
        self.assertEqual(unknown['markers_in_message_order'],[])

    def test_diagnostic_truncation_is_explicit_and_output_is_bounded(self):
        raw=b'z'*lab.DIAGNOSTIC_BYTES+b' invalid argument'
        value=lab.start_diagnostic(1,b'',raw)
        self.assertTrue(value['stderr_truncated'])
        self.assertEqual(value['inspected_stderr_bytes'],lab.DIAGNOSTIC_BYTES)
        self.assertEqual(value['markers_in_message_order'],[])
        self.assertEqual(value['stderr_sha256'],lab.hashlib.sha256(raw).hexdigest())
        repeated=lab.start_diagnostic(1,b'',b'permission denied '*3000)
        self.assertEqual(repeated['markers_in_message_order'],['permission_denied'])
        self.assertLess(len(json.dumps(repeated)),2048)

    def test_state_projection_keeps_returned_data_separate_from_verified_execution(self):
        raw=json.dumps({'status':'created','running':False,'oom_killed':False,'exit_code':128,
                        'error':'failed to mount local volume /private/SECRET: invalid argument'}).encode()
        result=lab.state_diagnostic(raw)
        self.assertEqual(result['container_status'],'created')
        self.assertFalse(result['running'])
        self.assertEqual(result['container_exit_code'],128)
        self.assertIn('invalid_argument',result['error_diagnostic']['markers_in_message_order'])
        self.assertIn('not proof of no prior execution',result['scope'])
        self.assertNotIn('SECRET',json.dumps(result))

    def test_invalid_state_cannot_smuggle_fields_or_types_into_evidence(self):
        original={'status':'created','running':False,'oom_killed':False,'exit_code':0,'error':''}
        for update in ({'status':'PRIVATE_LABEL'},{'running':'false'},{'exit_code':True},
                       {'exit_code':999999},{'error':[]},{'Env':['SECRET']},{'oom_killed':None}):
            with self.subTest(update=update),self.assertRaises(ValueError):
                lab.state_diagnostic(json.dumps(dict(original,**update)).encode())
        for raw in (b'{',b'[]',b'{"status":"created","status":"exited"}',b'x'*16385):
            with self.subTest(raw=raw[:40]),self.assertRaises(ValueError):lab.state_diagnostic(raw)

    def test_state_readback_has_one_bounded_fixed_request_and_does_not_execute(self):
        obj=object.__new__(lab.Lab);cid='b'*64
        raw=json.dumps({'status':'running','running':True,'oom_killed':False,'exit_code':0,'error':''}).encode()
        with patch.object(obj,'cmd',return_value=(0,raw,b'')) as command:
            result=obj.start_state(cid)
        command.assert_called_once_with('container','inspect','--format',lab.STATE_FORMAT,cid,
                                        allow_error=True,timeout=2,limit=16384)
        self.assertTrue(result['running'])  # A failed acknowledgement is not proof of no execution.
        for forbidden in ('Config','Env','Args','Health','LogPath'):self.assertNotIn(forbidden,lab.STATE_FORMAT)

    def test_lost_create_reply_has_a_persisted_name_and_can_be_cleaned(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.ids=[];obj.pending_containers=[];obj.start_attempts=[]
        obj.volumes=[];obj.networks=[];obj.new_images=[];persisted=[];calls=[]
        obj.ledger=lambda:persisted.append(list(obj.pending_containers))
        name=obj.prefix+'-download';cid='b'*64;present=set()
        def command(*args,**kwargs):
            calls.append(args)
            if args[0]=='create':
                self.assertEqual(persisted,[[name]])
                present.add(cid)
                raise TimeoutError('reply lost AFTER daemon creates container')
            if args[:2]==('container','inspect'):
                return 0,json.dumps({'id':cid,'name':'/'+name,'label':'isolated-local-model-v1'}).encode(),b''
            if args[0]=='rm':present.discard(args[-1])
            if args[0]=='ps':return 0,b'' if not present else name.encode(),b''
            return 0,b'',b''
        obj.cmd=command
        with self.assertRaises(TimeoutError):obj.create(['create','--name',name])
        self.assertEqual(obj.ids,[])
        self.assertEqual(obj.pending_containers,[name])
        result=obj.cleanup()
        self.assertTrue(result['containers_volumes_networks_removed'])
        self.assertEqual(result['resource_readbacks'],[{'kind':'pending_container','absence_verified':True}])
        self.assertIn(('rm','--force',cid),calls)
        self.assertTrue(any('name=^/'+name+'$' in call for call in calls))
        self.assertEqual(present,set())

    def test_create_ledger_failure_prevents_mutation(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12;obj.pending_containers=[]
        with patch.object(obj,'ledger',side_effect=OSError('storage full')), \
             patch.object(obj,'cmd') as command:
            with self.assertRaises(OSError):obj.create(['create','--name',obj.prefix+'-download'])
            command.assert_not_called()

    def test_volume_and_network_are_recorded_before_lost_create_reply(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.volumes=[];obj.networks=[];records=[]
        obj.ledger=lambda:records.append((list(obj.volumes),list(obj.networks)))
        def command(*args,**kwargs):
            self.assertTrue(records)
            if args[0]=='volume':self.assertEqual(records[-1][0],[obj.prefix+'-models'])
            if args[0]=='network':self.assertEqual(records[-1][1],[obj.prefix+'-net'])
            raise TimeoutError('reply lost')
        obj.cmd=command
        with self.assertRaises(TimeoutError):obj.model_volume()
        with self.assertRaises(TimeoutError):obj.network_controls('unused','unused')
        self.assertEqual(obj.volumes,[obj.prefix+'-models'])
        self.assertEqual(obj.networks,[obj.prefix+'-net'])

    def test_fallback_unverifiable_resource_does_not_prevent_other_cleanup(self):
        prefix='azt-live-'+'a'*12;calls=[];present={'network':True}
        class Docker:
            def __init__(self,*args):pass
            def command(self,*args,**kwargs):
                calls.append(args)
                if args[0]=='volume':raise RuntimeError('volume subsystem unavailable')
                if args[:2]==('network','inspect'):
                    return 0,json.dumps({'id':'','name':prefix+'-net','label':'isolated-local-model-v1'}).encode(),b''
                if args[:2]==('network','rm'):present['network']=False
                if args[:2]==('network','ls'):
                    return 0,(prefix+'-net').encode() if present['network'] else b'',b''
                return 0,b'',b''
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)
            lab.save(path/'owned.json',{'prefix':prefix,'containers':[],
                'volumes':[prefix+'-models'],'networks':[prefix+'-net'],'new_images':[]})
            with patch('azt_docker.Docker',Docker):result=lab.cleanup_saved(path)
            self.assertEqual(json.loads((path/'fallback-cleanup.json').read_text()),result)
        self.assertFalse(result['containers_volumes_networks_removed'])
        self.assertEqual(result['resource_readbacks'],[
            {'kind':'volume','absence_verified':False},{'kind':'network','absence_verified':True}])
        self.assertIn(('network','rm',prefix+'-net'),calls)
        self.assertFalse(present['network'])

    def test_pending_cleanup_rejects_wrong_label_identity_and_missing_readback(self):
        prefix='azt-live-'+'a'*12;name=prefix+'-download';cid='b'*64
        good={'id':cid,'name':'/'+name,'label':'isolated-local-model-v1'}
        for update in ({'name':'/unrelated'},{'label':'unrelated'},{'id':'bad'}):
            obj=object.__new__(lab.Lab);obj.prefix=prefix;obj.pending_containers=[name]
            obj.ids=[];obj.volumes=[];obj.networks=[];obj.new_images=[]
            with patch.object(obj,'cmd',return_value=(0,json.dumps(dict(good,**update)).encode(),b'')) as command:
                result=obj.cleanup()
            self.assertFalse(result['containers_volumes_networks_removed'])
            self.assertFalse(any('rm' in c.args for c in command.call_args_list))

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
            with patch('azt_docker.Docker',Docker):
                result=lab.cleanup_saved(path)
                self.assertFalse(result['containers_volumes_networks_removed'])
                self.assertEqual(result['resource_readbacks'],[{'kind':'volume','absence_verified':False}])
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
        obj.ids=[];obj.pending_containers=[];obj.start_attempts=[];obj.ledger=lambda:None
        def command(*args,**kw):
            if args[0]=='create':return 0,('b'*64).encode(),b''
            raise RuntimeError('private daemon details')
        obj.cmd=command
        with self.assertRaises(RuntimeError):obj.create(['create','--name',obj.prefix+'-downloadrelay'])
        self.assertEqual(obj.ids,['b'*64])
        self.assertEqual(obj.start_attempts,[{'role':'downloadrelay','start_acknowledged':False,
                                            'transport_error_type':'RuntimeError',
                                            'state_readback':{'status':'unavailable_or_invalid',
                                                'scope':'no state conclusion; original start failure retained'}}])

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
        self.assertIn('test_live_model.py" --startup-only --output',text)
        self.assertIn('github.run_attempt == 1',text)
        self.assertIn('inputs.source_sha == github.sha',text)
        self.assertNotIn('pull_request:',text)
        self.assertNotIn('push:',text)

    def test_start_failure_preserves_owned_cleanup_target_and_safe_diagnostic(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.ids=[];obj.pending_containers=[];obj.start_attempts=[];obj.ledger=lambda:None
        cid='b'*64;calls=[]
        def command(*args,**kwargs):
            calls.append((args,kwargs))
            if args[0]=='create':return 0,cid.encode(),b''
            return 1,b'',b'error mounting /private/SENSITIVE: permission denied\n@recipient'
        obj.cmd=command
        with self.assertRaisesRegex(ValueError,'container_start_failed:download'):
            obj.create(['create','--name',obj.prefix+'-download'])
        self.assertEqual(obj.ids,[cid])
        self.assertEqual(calls[1],(('start',cid),{'allow_error':True}))
        self.assertEqual(calls[-1],(('container','inspect','--format',lab.STATE_FORMAT,cid),
                                    {'allow_error':True,'timeout':2,'limit':16384}))
        record=obj.start_attempts[0]
        self.assertFalse(record['start_acknowledged'])
        self.assertEqual(record['diagnostic']['categories'],['permission_denied','mount_failure'])
        serialized=json.dumps(record)
        for value in ('SENSITIVE','recipient','/private',cid):self.assertNotIn(value,serialized)

    def test_successful_start_and_unknown_failure_are_not_conflated(self):
        obj=object.__new__(lab.Lab);obj.prefix='azt-live-'+'a'*12
        obj.ids=[];obj.pending_containers=[];obj.start_attempts=[];obj.ledger=lambda:None
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
