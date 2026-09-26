import lldb
MARK=b"MK7pQ2wZx9Rt"
def regions_search(proc, needle):
    res=[]
    ml=proc.GetMemoryRegions()
    reg=lldb.SBMemoryRegionInfo()
    for i in range(ml.GetSize()):
        if not ml.GetMemoryRegionAtIndex(i, reg): continue
        if not reg.IsReadable(): continue
        base=reg.GetRegionBase(); end=reg.GetRegionEnd()
        if end-base > (64<<20): continue
        err=lldb.SBError(); data=proc.ReadMemory(base, end-base, err)
        if not err.Success(): continue
        start=0
        while True:
            j=data.find(needle, start)
            if j<0: break
            res.append(base+j); start=j+1
    return res
def dis1(target, addr):
    err=lldb.SBError(); data=target.ReadMemory(lldb.SBAddress(addr,target),16,err)
    if not err.Success(): return "?"
    insts=target.GetInstructions(lldb.SBAddress(addr,target), data)
    if insts.GetSize()==0: return "?"
    ins=insts.GetInstructionAtIndex(0)
    return "%s %s"%(ins.GetMnemonic(target), ins.GetOperands(target))
def main():
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    target=dbg.CreateTarget("./real_bin")
    log=open("cmp.txt","w")
    bp=target.BreakpointCreateByName("read")
    li=target.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=target.Launch(li, err)
    stage=0; watched=None; hits=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0); reason=th.GetStopReason()
        if reason==lldb.eStopReasonBreakpoint and stage==0:
            if fr.FindRegister("x0").GetValueAsUnsigned()==0:
                th.StepOut()
                for _ in range(400): th.StepInstruction(False)
                locs=regions_search(proc, MARK)
                log.write("MARK locations: %s\n"%[hex(x) for x in locs])
                gc=[a for a in locs if a>=0x600000000000] or locs
                if gc:
                    watched=gc[-1]
                    werr=lldb.SBError()
                    target.WatchAddress(watched,1,True,False,werr)
                    log.write("watch GC copy @ %#x err=%s\n"%(watched,werr))
                stage=1
                proc.Continue(); continue
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint:
            hits+=1
            pc=fr.GetPC()
            xs=" ".join("x%d=%#x"%(r,fr.FindRegister("x%d"%r).GetValueAsUnsigned()) for r in (0,1,2,3,8,9,10,19,20,21,22,23,24))
            log.write("---- read of GC copy hit %d pc=%#x  %s\n     %s\n"%(hits,pc,dis1(target,pc),xs))
            for r in (0,1,2,3,19,20,21,22,23,24):
                v=fr.FindRegister("x%d"%r).GetValueAsUnsigned()
                if v>0x100000000:
                    e=lldb.SBError(); dd=proc.ReadMemory(v,20,e)
                    if e.Success() and dd and all(32<=c<127 for c in dd[:6]):
                        log.write("       x%d->%r\n"%(r,bytes(dd)))
            if hits>=40: break
            proc.Continue(); continue
        else:
            proc.Continue()
    log.close()
main()
