import lldb
def rd(proc,a,n):
    if a<0x1000: return None
    e=lldb.SBError(); d=proc.ReadMemory(a,n,e); return bytes(d) if e.Success() else None
def main():
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    t=dbg.CreateTarget("./real_bin"); log=open("hashes.txt","w")
    for addr in (0x100002634,0x100002640,0x100002644):
        bp=t.BreakpointCreateByAddress(addr)
    li=t.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=t.Launch(li,err)
    seen=set(); n=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0)
        if th.GetStopReason()==lldb.eStopReasonBreakpoint:
            x8=fr.FindRegister("x8").GetValueAsUnsigned()
            x10=fr.FindRegister("x10").GetValueAsUnsigned()
            comp=rd(proc,x8,16); exp=rd(proc,x10,16)
            for tag,val in (("computed",comp),("expected",exp)):
                if val and val not in seen:
                    seen.add(val); log.write("%s %s\n"%(tag,val.hex()))
            n+=1
            if n>2000: break
        proc.Continue()
    log.close()
main()
