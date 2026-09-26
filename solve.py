import lldb
def rdstr(proc, addr, n):
    if not addr or n<=0 or n>128: return None
    err=lldb.SBError(); data=proc.ReadMemory(addr, n, err)
    if not err.Success(): return None
    return data
def printable(b):
    return b is not None and all(32<=c<127 for c in b)
def main():
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    target=dbg.CreateTarget("./real_bin")
    log=open("cmp.txt","a")
    for name in ("memcmp","bcmp","memcmp$VARIANT$mvx","_platform_memcmp"):
        target.BreakpointCreateByName(name)
    li=target.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=target.Launch(li, err)
    seen=set(); n=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0)
        if th.GetStopReason()==lldb.eStopReasonBreakpoint:
            x0=fr.FindRegister("x0").GetValueAsUnsigned()
            x1=fr.FindRegister("x1").GetValueAsUnsigned()
            x2=fr.FindRegister("x2").GetValueAsUnsigned()
            if 2<=x2<=64:
                a=rdstr(proc,x0,x2); b=rdstr(proc,x1,x2)
                if printable(a) or printable(b):
                    key=(bytes(a) if a else b'', bytes(b) if b else b'')
                    if key not in seen:
                        seen.add(key)
                        log.write("memcmp len=%d\n  A=%r\n  B=%r\n"%(x2, bytes(a) if a else None, bytes(b) if b else None))
            n+=1
            if n>4000: break
        proc.Continue()
    log.close()
main()
