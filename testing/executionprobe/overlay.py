"""Test-only payload worker tracing. Never modifies candidate/control source."""
from pathlib import Path
import argparse, json, hashlib
E = None
def build(root,label):
 out=E/('overlay-'+label);out.mkdir(exist_ok=True);repl={};audit=[]
 def put(name,s):
  f=out/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(s,newline='\n');repl[str(root/name)]=str(f)
  audit.append(dict(path=name,source_sha256=hashlib.sha256((root/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest(),overlay_sha256=hashlib.sha256(s.encode()).hexdigest()))
 def get(n):return(root/n).read_text()
 def replace(s,a,b):assert a in s,a;return s.replace(a,b)
 n='common/task/task.go';s=get(n)
 s=replace(s,'\t\tgo func(f func() error) {','\t\te1End := E1Work("task")\n\t\tgo func(f func() error) {\n defer e1End()')
 s+='''\n// E1Work is injected only by this test overlay, never shipped.
var E1TraceHook func(string) func()
func e1Noop() {}
func E1Work(kind string) func() {if E1TraceHook!=nil{return E1TraceHook(kind)};return e1Noop}
''';put(n,s)
 n='app/proxyman/inbound/worker.go';s=get(n)
 s=replace(s,'go w.callback(conn)','e1End := task.E1Work("inbound")\n go func(){defer e1End();w.callback(conn)}()');put(n,s)
 n='app/dispatcher/default.go';s=get(n)
 s=replace(s,'"context"','"context"\n"github.com/xtls/xray-core/common/task"')
 s=replace(s,'\t\tgo d.routedDispatch(ctx, outbound, destination)','\t\te1End := task.E1Work("dispatch")\n go func(){defer e1End();d.routedDispatch(ctx,outbound,destination)}()')
 s=replace(s,'\t\tgo func() {\n\t\t\tcReader :=','\t\te1End := task.E1Work("dispatch")\n\t\tgo func() {\n defer e1End()\n\t\t\tcReader :=')
 signature='func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination net.Destination, outbound *transport.Link) error {'
 s=replace(s,signature,signature+'\n defer task.E1Work("dispatch")()');put(n,s)
 n='transport/internet/tcp/hub.go';s=get(n)
 s=replace(s,'"context"','"context"\n"github.com/xtls/xray-core/common/task"')
 s=replace(s,'\t\tgo func() {\n\t\t\tif v.tlsConfig','\t\te1End := task.E1Work("setup")\n\t\tgo func() {\n defer e1End()\n\t\t\tif v.tlsConfig');put(n,s)
 n='common/signal/timer.go';s=get(n)
 s=replace(s,'type ActivityTimer struct {','type ActivityTimer struct {\n e1TimerEnd func()')
 s=replace(s,'\tt.once.Do(func() {','\tt.once.Do(func() {\n if t.e1TimerEnd!=nil {defer t.e1TimerEnd()}')
 s=replace(s,'timer := &ActivityTimer{','timer := &ActivityTimer{\n e1TimerEnd: task.E1Work("timer"),');put(n,s)
 n='app/dispatcher/stream.go'
 if(root/n).exists():
  s=get(n);s=replace(s,'"context"','"context"\n"github.com/xtls/xray-core/common/task"')
  sig='func (d *DefaultDispatcher) DispatchStream(ctx context.Context, destination net.Destination, source exchange.Stream) error {'
  s=replace(s,sig,sig+'\n defer task.E1Work("dispatch")()');put(n,s)
 # Candidate data-plane workers are already joined by DispatchStream; no extra
 # hook is needed to wait for them. This also avoids overstating a task-count comparison.
 (E/(label+'-overlay.json')).write_text(json.dumps({'Replace':repl},indent=2))
 (E/(label+'-overlay-manifest.json')).write_text(json.dumps(audit,indent=2))

if __name__ == "__main__":
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument("root",type=Path)
 parser.add_argument("output",type=Path)
 parser.add_argument("--label",choices=("candidate","control"),default="candidate")
 args=parser.parse_args()
 E=args.output.resolve();E.mkdir(parents=True,exist_ok=True)
 build(args.root.resolve(),args.label)
 print(E/(args.label+"-overlay.json"))
