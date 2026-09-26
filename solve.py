import lldb, sys

def dis(target, addr, n=4):
    out=[]
    err=lldb.SBError()
    data=target.ReadMemory(lldb.SBAddress(addr, target), 4*n, err)
    if not err.Success(): return out
    saddr=lldb.SBAddress(addr, target)
    insts=target.GetInstructions(saddr, data)
    for i in range(min(n, insts.GetSize())):
        ins=insts.GetInstructionAtIndex(i)
        out.append("%#x: %s %s"%(ins.GetAddress().GetLoadAddress(target), ins.GetMnemonic(target), ins.GetOperands(target)))
    return out

def main():
    dbg=lldb.SBDebugger.Create(); dbg.SetAsync(False)
    target=dbg.CreateTarget("./real_bin")
    log=open("wlog.txt","w")
    li=target.GetLaunchInfo()
    li.AddOpenFileAction(0, "input.txt", True, False)   # stdin <- input.txt
    li.AddOpenFileAction(1, "prog_out.txt", False, True)
    bp=target.BreakpointCreateByName("read")
    err=lldb.SBError()
    proc=target.Launch(li, err)
    if not proc.IsValid():
        log.write("launch fail: %s\n"%err); log.close(); return
    wp_set=False; hits=0
    while proc.GetState()==lldb.eStateStopped:
        th=proc.GetSelectedThread()
        reason=th.GetStopReason()
        frame=th.GetFrameAtIndex(0)
        if reason==lldb.eStopReasonBreakpoint and not wp_set:
            # read(fd,buf,count): x0=fd x1=buf x2=count. Only fd0.
            fd=frame.FindRegister("x0").GetValueAsUnsigned()
            buf=frame.FindRegister("x1").GetValueAsUnsigned()
            if fd==0 and buf:
                # let read complete: finish out to caller, then set watchpoint on buf[0]
                th.StepOut()
                werr=lldb.SBError()
                wp=target.WatchAddress(buf, 1, True, False, werr)  # read watchpoint
                log.write("set watchpoint @ %#x err=%s\n"%(buf,werr))
                wp_set=True
                proc.Continue(); continue
            proc.Continue(); continue
        elif reason==lldb.eStopReasonWatchpoint:
            hits+=1
            pc=frame.GetPC()
            regs={}
            gpr=frame.GetRegisters().GetValueAtIndex(0)
            line="---- WP hit %d pc=%#x ----\n"%(hits,pc)
            log.write(line)
            for ins in dis(target, pc, 5): log.write("  "+ins+"\n")
            vals=[]
            for r in range(31):
                v=frame.FindRegister("x%d"%r)
                vals.append("x%d=%#x"%(r, v.GetValueAsUnsigned()))
            log.write("  "+" ".join(vals)+"\n")
            if hits>=120:
                log.write("(stop after 120 hits)\n"); break
            proc.Continue(); continue
        else:
            proc.Continue()
    log.write("final state %s exit_out:\n"%proc.GetState())
    log.close()

main()
