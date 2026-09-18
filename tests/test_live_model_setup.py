"""Offline setup/relay regressions. No Docker or model execution here."""
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch


def module(name, file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/'scripts'/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


lab=module('live_model_lab','test_live_model.py')
relay=module('live_model_relay','live_model_relay.py')


class LiveModelSetupTests(unittest.TestCase):
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
