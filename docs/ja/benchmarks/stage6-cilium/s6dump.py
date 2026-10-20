#!/usr/bin/env python3
# s6dump.py <node> <dev>: dump dpp_vx_flows reachable from the before-hook of <dev>'s from_container prog.
# Prints one JSON object: {"maps":[ids], "raw_example":hex, "entries":[[saddr,daddr,sport,dport,vni,count],...]}
import json,subprocess,sys,struct,ipaddress
node,dev=sys.argv[1],sys.argv[2]
def bt(a,ns=None):
    c=(["nsenter","-t",ns,"-n"] if ns else [])+["bpftool","-j"]+a
    o=subprocess.run(c,capture_output=True,text=True).stdout
    return json.loads(o) if o.strip() else []
pid=subprocess.run(["docker","inspect","-f","{{.State.Pid}}",node],capture_output=True,text=True).stdout.strip()
tgt=None
for e in bt(["net","show"],pid):
    for a in e.get("tc",[]):
        if a.get("devname")==dev and "from_container" in a.get("name",""): tgt=a["prog_id"]
progs={p["id"]:p for p in bt(["prog","show"])}
mids=set()
for l in bt(["link","show"]):
    if l.get("type")=="tracing" and l.get("target_obj_id")==tgt and progs.get(l["prog_id"],{}).get("name")=="before":
        for m in progs[l["prog_id"]].get("map_ids",[]):
            if bt(["map","show","id",str(m)]).get("name")=="dpp_vx_flows": mids.add(m)
ents=[];raw=None
for m in sorted(mids):
    for e in bt(["map","dump","id",str(m)]):
        k=e["key"]; v=e["value"]
        if isinstance(k,list): kb=bytes(int(b,16) for b in k)
        else: raise SystemExit("unexpected formatted key: "+json.dumps(e))
        if isinstance(v,list): v=int.from_bytes(bytes(int(b,16) for b in v),"little")
        raw=raw or kb.hex()
        s,d,sp,dp,vni=struct.unpack("<IIHHI",kb)  # native (LE) numeric values, per BTF layout
        ents.append([str(ipaddress.IPv4Address(s)),str(ipaddress.IPv4Address(d)),sp,dp,vni,int(v)])
print(json.dumps({"target_prog":tgt,"maps":sorted(mids),"raw_example":raw,"entries":sorted(ents,key=lambda x:(x[4],x[2]))}))
