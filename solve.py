import lldb
ALPHA=b"Zq7Wp3Kx9Rt2Yv8Nb5JcAa1Bb2Cc3Dd4Ee5"
def marker(L): return (ALPHA*3)[:L]
def dis1(t,a):
    e=lldb.SBError(); d=t.ReadMemory(lldb.SBAddress(a,t),16,e)
    if not e.Success(): return "?"
    ins=t.GetInstructions(lldb.SBAddress(a,t),d)
    return "%s %s"%(ins.GetInstructionAtIndex(0).GetMnemonic(t),ins.GetInstructionAtIndex(0).GetOperands(t)) if ins.GetSize() else "?"
def rd(proc,a,n):
    if a<0x1000: return None
    e=lldb.SBError(); d=proc.ReadMemory(a,n,e); return bytes(d) if e.Success() else None
def main():
    L=int(open("LEN.txt").read().strip()); MK=marker(L); PRE=MK[:4]
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    t=dbg.CreateTarget("./real_bin"); log=open("cmp.txt","a")
    t.BreakpointCreateByName("read")
    li=t.GetLaunchInfo(); li.AddOpenFileAction(0,"input.txt",True,False)
    err=lldb.SBError(); proc=t.Launch(li,err)
    stage=0; hits=0; rawhits=0; gc=None
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread(); fr=th.GetFrameAtIndex(0); reason=th.GetStopReason()
        if reason==lldb.eStopReasonBreakpoint and stage==0:
            if fr.FindRegister("x0").GetValueAsUnsigned()==0:
                buf=fr.FindRegister("x1").GetValueAsUnsigned()
                th.StepOut()
                werr=lldb.SBError(); t.WatchAddress(buf,1,True,False,werr); stage=1
                proc.Continue(); continue
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint and stage==1:
            rawhits+=1
            for r in range(29):
                v=fr.FindRegister("x%d"%r).GetValueAsUnsigned()
                if 0x100000000000<=v<0x800000000000:
                    s=rd(proc,v,L+1)
                    if s and s[:4]==PRE: gc=v; break
            if gc:
                for wp in t.watchpoint_iter(): t.DeleteWatchpoint(wp.GetID())
                werr=lldb.SBError(); t.WatchAddress(gc,1,True,False,werr); stage=2
            if rawhits>200 and stage==1:
                log.write("L=%d no GC\n"%L); break
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint and stage==2:
            hits+=1; pc=fr.GetPC()
            exp=[]
            for r in range(29):
                v=fr.FindRegister("x%d"%r).GetValueAsUnsigned()
                s=rd(proc,v,L+2)
                if s and all(32<=c<127 for c in s[:2]) and s[:L]!=MK and not s.startswith(b"Zq7"):
                    exp.append("x%d->%r"%(r,s))
            if exp:
                log.write("  L=%d hit%d pc=%#x %s\n     %s\n"%(L,hits,pc,dis1(t,pc)," ".join(exp)))
            if hits>=60: break
            proc.Continue(); continue
        else:
            proc.Continue()
    if stage==2 and hits==0: log.write("L=%d GC watched, ZERO reads (len gate)\n"%L)
    log.close()
main()
