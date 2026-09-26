import lldb
ALPHA=b"Zq7Wp3Kx9Rt2Yv8Nb5Jc"
def marker(L): 
    s=(ALPHA*3)[:L]; return s
def dis1(t,a):
    e=lldb.SBError(); d=t.ReadMemory(lldb.SBAddress(a,t),16,e)
    if not e.Success(): return "?"
    ins=t.GetInstructions(lldb.SBAddress(a,t),d)
    return "%s %s"%(ins.GetInstructionAtIndex(0).GetMnemonic(t),ins.GetInstructionAtIndex(0).GetOperands(t)) if ins.GetSize() else "?"
def search_heap(proc, needle):
    ml=proc.GetMemoryRegions(); reg=lldb.SBMemoryRegionInfo()
    for i in range(ml.GetSize()):
        if not ml.GetMemoryRegionAtIndex(i,reg): continue
        b=reg.GetRegionBase(); e=reg.GetRegionEnd()
        if b<0x600000000000 or b>=0x800000000000: continue
        if e-b>(32<<20): continue
        err=lldb.SBError(); d=proc.ReadMemory(b,e-b,err)
        if not err.Success(): continue
        j=d.find(needle)
        if j>=0: return b+j
    return None
def rd(proc,a,n):
    if a<0x1000: return None
    e=lldb.SBError(); d=proc.ReadMemory(a,n,e); return bytes(d) if e.Success() else None
def main():
    L=int(open("LEN.txt").read().strip()); MK=marker(L)
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    t=dbg.CreateTarget("./real_bin"); log=open("cmp.txt","a")
    t.BreakpointCreateByName("read")
    li=t.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=t.Launch(li,err)
    stage=0; gc=None; hits=0; appreads=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0); reason=th.GetStopReason()
        if reason==lldb.eStopReasonBreakpoint and stage==0:
            if fr.FindRegister("x0").GetValueAsUnsigned()==0:
                for _ in range(120):
                    for _ in range(6): th.StepInstruction(False)
                    gc=search_heap(proc, MK)
                    if gc: break
                if gc:
                    werr=lldb.SBError(); t.WatchAddress(gc,1,True,False,werr)
                    log.write("L=%d GC@%#x watch=%s\n"%(L,gc,werr.Success())); stage=2
                    proc.Continue(); continue
                else:
                    log.write("L=%d no GC copy found\n"%L); break
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint and stage==2:
            hits+=1; pc=fr.GetPC()
            if pc<0x180000000:
                appreads+=1
                log.write("  L=%d APP pc=%#x %s\n"%(L,pc,dis1(t,pc)))
                for r in range(29):
                    v=fr.FindRegister("x%d"%r).GetValueAsUnsigned()
                    s=rd(proc,v,L+2)
                    if s and all(32<=c<127 for c in s[:2]) and s[:L]!=MK:
                        log.write("     x%d->%r\n"%(r,s))
            if hits>=50: break
            proc.Continue(); continue
        else:
            proc.Continue()
    if stage==2 and appreads==0: log.write("L=%d watched, NO app read\n"%L)
    log.close()
main()
