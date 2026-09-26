import lldb
def rd(proc,a,n):
    if a<0x1000: return None
    e=lldb.SBError(); d=proc.ReadMemory(a,n,e); return bytes(d) if e.Success() else None
def main():
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    t=dbg.CreateTarget("./real_bin"); log=open("hashes.txt","w")
    # PIE-safe: resolve file addresses to load addresses
    for fa in (0x100002604, 0x100002640):
        sb=t.ResolveFileAddress(fa)
        bp=t.BreakpointCreateBySBAddress(sb)
        log.write("bp set for %#x -> %s\n"%(fa, sb))
    li=t.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=t.Launch(li,err)
    seen=set(); n=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0)
        if th.GetStopReason()==lldb.eStopReasonBreakpoint:
            pc=fr.GetPC()
            fa=pc - t.GetModuleAtIndex(0).GetObjectFileHeaderAddress().GetLoadAddress(t) + 0x100000000
            x0=fr.FindRegister("x0").GetValueAsUnsigned()
            x8=fr.FindRegister("x8").GetValueAsUnsigned()
            x10=fr.FindRegister("x10").GetValueAsUnsigned()
            if (fa & 0xffff)==0x2604:
                v=rd(proc,x0,16)
                if v and v not in seen: seen.add(v); log.write("computed %s\n"%v.hex())
            else:
                c=rd(proc,x8,16); ex=rd(proc,x10,16)
                if c and c not in seen: seen.add(c); log.write("cmp_computed %s\n"%c.hex())
                if ex and ex not in seen: seen.add(ex); log.write("expected %s\n"%ex.hex())
            n+=1
            if n>3000: break
        proc.Continue()
    log.close()
main()
