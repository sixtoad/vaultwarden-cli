import importlib.util,pathlib,sys,time,json
from types import SimpleNamespace
runner_path=pathlib.Path(__file__).resolve().parents[1]/'secret-storage-acceptance.py'
spec=importlib.util.spec_from_file_location('unlock_test_runner',runner_path);runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
root=runner.check(pathlib.Path(sys.argv[1])); original=runner.http.client.HTTPSConnection
class DelayedConnection(original):
 def request(self,method,url,*args,**kwargs):
  self.test_method=method;self.test_path=url;self.test_started=time.monotonic()
  return super().request(method,url,*args,**kwargs)
 def getresponse(self):
  response=super().getresponse(); flag=root/'delay-next-token'
  if self.test_method=='POST' and self.test_path=='/identity/connect/token' and flag.exists():
   delay=float(flag.read_text());assert 0<delay<=8;flag.unlink()
   before=time.monotonic();runner.save(root/'unlock-delay-observed.json',{'token_response_status':response.status,'upstream_elapsed_seconds':before-self.test_started,'delay_seconds':delay,'phase':'delaying'})
   time.sleep(delay)
   runner.save(root/'unlock-delay-observed.json',{'token_response_status':response.status,'upstream_elapsed_seconds':before-self.test_started,'delay_seconds':delay,'elapsed_seconds':time.monotonic()-self.test_started,'phase':'released'})
  return response
runner.http=SimpleNamespace(client=SimpleNamespace(HTTPSConnection=DelayedConnection),server=runner.http.server)
runner.proxy(root)
