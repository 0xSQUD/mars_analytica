import sys

tab1=[Dword(0xE4DC00+i) for i in range(0,0x253C,4)]
tab2=[Dword(0xE50140+i) for i in range(0,0x253C,4)]
tab3=[Dword(0xE52680+i) for i in range(0,0x2B5C,4)]
tab4=[Dword(0xE551E0+i) for i in range(0,0x2B5C,4)]
tab5=[Qword(0xE57D40+i) for i in range(0,0x56B8,8)]

idc.MakeName(0x4009d7,"pop_val")
idc.MakeName(0x400aae,"push_val")

f_putchar=["pop_val","putchar","fflush"]
f_puts=["puts","fflush"]
comparison={"jle":"cle","jge":"cge","jnz":"cmp"}
operations={"xor":"xor","sub":"sub","imul":"mul","lea":"add"}

def dispatcher(num):
    global tab1,tab2,tab3,tab4,tab5
    eax = tab4[tab3[tab2[tab1[(num*1962)%len(tab1)]*1445%len(tab2)]*601%len(tab3)]*469%len(tab4)]
    edx = tab5[tab2[tab1[(num*1962)%len(tab1)]*1445%len(tab2)]]
    return eax+edx
    
def getImm(num):
    global tab1,tab2,tab5
    imm=tab5[tab2[tab1[(num*1962)%len(tab1)]*1445%len(tab2)]+1]
    return imm

def unknown_handler(handler,calls):
    print "unknown handler:" + hex(handler)
    for c in calls:
        sys.stdout.write(c + " ")
    exit(-1)
    
PC=0x0
handler=dispatcher(PC)
while 1:
    sys.stdout.write(hex(PC) +":\t"+hex(handler) +":\t")
    if handler == 0x402335:
        sys.stdout.write("push 0x%08x\n" % getImm(PC))
    elif handler == 0x401b8f:
        sys.stdout.write("store[0x%08x]\n" % getImm(PC))
    elif handler == 0x4018cd:
        sys.stdout.write("nop\n")
    elif handler == 0x401f62:
        sys.stdout.write("load[0x%08x]\n" % getImm(PC))
    elif handler == 0x401502:
        sys.stdout.write("jcc 0x%08x\n" % getImm(PC))
    elif handler == 0x402ab2:
        sys.stdout.write("swap\n")
    elif handler == 0x40114a:
        sys.stdout.write("jmp 0x%08x\n" % getImm(PC))
    elif handler == 0x46c11e:
        sys.stdout.write("sete\n")
    elif handler == 0x4030a4:
        sys.stdout.write("getchar[0x%08x]\n" % getImm(PC))
    elif handler == 0x40346D:
        sys.stdout.write("break")
        break
    else:
        if not idaapi.get_func(handler):
            idc.MakeFunction(handler)
        calls=[x for x in idautils.FuncItems(handler) if idaapi.is_call_insn(x)]
        targets=list(map(lambda x: GetOpnd(x,0),calls))
        if all(t in targets for t in f_putchar):
            sys.stdout.write("putchar\n")
        elif len(targets) == 1 and targets[0] == "push_val":
            sys.stdout.write("pushz\n")
        elif len(targets) == 2 and all(f in targets for f in f_puts):
            sys.stdout.write("puts\n")
        elif len(targets) == 3 and targets.count("pop_val") == 2:
            operation=None
            for caller in calls:
                if GetOpnd(caller,0) == "pop_val" and caller+17 in calls:
                    mnem = GetMnem(caller+22)
                    if mnem in operations.keys():
                        operation=operations[mnem]
                    elif GetMnem(caller+30) == "cdq" and GetMnem(caller+31) == "idiv":
                        operation="div"
            sys.stdout.write(operation + "\n") if operation is not None else unknown_handler(PC,targets)
        elif len(targets) == 4:
            operation=None
            for caller in calls:
                if GetOpnd(caller,0) == "pop_val":
                    caller=caller+5
                    if GetMnem(caller) == "cmp" and "eax" in GetOpnd(caller,1) and "ebx" in GetOpnd(caller,0):
                        if GetMnem(caller+2) in comparison.keys():
                            operation=comparison[GetMnem(caller+2)]
                    elif GetMnem(caller) == "cmp" and "eax" in GetOpnd(caller,0) and "1" in GetOpnd(caller,1) and GetMnem(caller+3) == "jnz":
                        operation="and"
            sys.stdout.write(operation + "\n") if operation is not None else unknown_handler(PC,targets)
        elif len(targets) == 6:
            sys.stdout.write("or\n")
        else:
            unknown_handler(PC,targets)
    PC+=1
    handler=dispatcher(PC)