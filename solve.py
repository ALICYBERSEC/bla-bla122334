import lldb,sys
def dis1(target,addr):
    e=lldb.SBError(); d=target.ReadMemory(lldb.SBAddress(addr,target),16,e)
    if not e.Success(): return "?"
    ins=target.GetInstructions(lldb.SBAddress(addr,target),d)
    if ins.GetSize()==0: return "?"
    i=ins.GetInstructionAtIndex(0); return "%s %s"%(i.GetMnemonic(target),i.GetOperands(target))
def rd(proc,a,n=24):
    if a<0x1000: return None
    e=lldb.SBError(); d=proc.ReadMemory(a,n,e)
    return bytes(d) if e.Success() else None
def main():
    L=int(open("LEN.txt").read().strip())
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    target=dbg.CreateTarget("./real_bin")
    log=open("cmp.txt","a")
    target.BreakpointCreateByName("read")
    li=target.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=target.Launch(li,err)
    stage=0; gc=None; hits=0; appreads=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0); reason=th.GetStopReason()
        if reason==lldb.eStopReasonBreakpoint and stage==0:
            if fr.FindRegister("x0").GetValueAsUnsigned()==0:
                th.StepOut()
                werr=lldb.SBError()
                buf=fr.FindRegister("x1").GetValueAsUnsigned()
                target.WatchAddress(buf,1,True,False,werr)
                stage=1; proc.Continue(); continue
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint and stage==1:
            pc=fr.GetPC(); ins=dis1(target,pc)
            if ins.startswith("str"):
                for r in (3,21,1,2,0):
                    v=fr.FindRegister("x%d"%r).GetValueAsUnsigned()
                    if 0x600000000000<=v<0x800000000000:
                        gc=v; break
                if gc:
                    for wp in target.watchpoint_iter(): target.DeleteWatchpoint(wp.GetID())
                    werr=lldb.SBError(); target.WatchAddress(gc,1,True,False,werr)
                    log.write("L=%d watch GC @ %#x (%s)\n"%(L,gc,werr.Success()))
                    stage=2
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint and stage==2:
            hits+=1; pc=fr.GetPC(); ins=dis1(target,pc)
            app = pc < 0x180000000
            if app:
                appreads+=1
                xs=" ".join("x%d=%#x"%(r,fr.FindRegister("x%d"%r).GetValueAsUnsigned()) for r in range(25))
                log.write("  L=%d APPREAD pc=%#x %s\n     %s\n"%(L,pc,ins,xs))
                for r in range(25):
                    v=fr.FindRegister("x%d"%r).GetValueAsUnsigned()
                    s=rd(proc,v,L+4)
                    if s and all(32<=c<127 for c in s[:min(3,len(s))]):
                        log.write("       x%d -> %r\n"%(r,bytes(s)))
            if hits>=60: break
            proc.Continue(); continue
        else:
            proc.Continue()
    if stage==2 and appreads==0: log.write("L=%d: GC watched but NO app read (length gate?)\n"%L)
    if stage<2: log.write("L=%d: never found GC copy\n"%L)
    log.close()
main()
