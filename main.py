import sys
from typing import Optional
import time

import capstone
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RDI, \
    UC_X86_REG_RSI, UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11, \
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15, UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, \
    UC_X86_REG_XMM3, UC_X86_REG_RIP, UC_X86_REG_EFLAGS

from exc import Exited
from imports import api_list
from machine import Machine
from loader import load_pe64, load_pe32, load_pe64_u

from utils import read_int32, read_int64, read_uint64

def rflags_to_str(rflags):
    # These are the flag names and their corresponding bit positions
    flag_names = {
        0: 'CF',
        2: 'PF',
        4: 'AF',
        6: 'ZF',
        7: 'SF',
        8: 'TF',
        9: 'IF',
        10: 'DF',
        11: 'OF',
        14: 'NT',
        16: 'RF',
        17: 'VM',
        18: 'AC',
        19: 'VIF',
        20: 'VIP',
        21: 'ID',
    }

    flags = []
    for bit, name in flag_names.items():
        if rflags & (1 << bit):
            flags.append(name)
    return ' '.join(flags)

def dump(u: Uc):
    rax = u.reg_read(UC_X86_REG_RAX)
    rbx = u.reg_read(UC_X86_REG_RBX)
    rcx = u.reg_read(UC_X86_REG_RCX)
    rdx = u.reg_read(UC_X86_REG_RDX)
    rdi = u.reg_read(UC_X86_REG_RDI)
    rsi = u.reg_read(UC_X86_REG_RSI)
    rbp = u.reg_read(UC_X86_REG_RBP)
    rsp = u.reg_read(UC_X86_REG_RSP)
    r8 = u.reg_read(UC_X86_REG_R8)
    r9 = u.reg_read(UC_X86_REG_R9)
    r10 = u.reg_read(UC_X86_REG_R10)
    r11 = u.reg_read(UC_X86_REG_R11)
    r12 = u.reg_read(UC_X86_REG_R12)
    r13 = u.reg_read(UC_X86_REG_R13)
    r14 = u.reg_read(UC_X86_REG_R14)
    r15 = u.reg_read(UC_X86_REG_R15)
    xmm0 = u.reg_read(UC_X86_REG_XMM0)
    xmm1 = u.reg_read(UC_X86_REG_XMM1)
    xmm2 = u.reg_read(UC_X86_REG_XMM2)
    xmm3 = u.reg_read(UC_X86_REG_XMM3)
    rip = u.reg_read(UC_X86_REG_RIP)
    rflags = u.reg_read(UC_X86_REG_EFLAGS)
    print("rax: {:#018x}  rbx: {:#018x}  rcx: {:#018x}  rdx: {:#018x}".format(rax, rbx, rcx, rdx))
    print("rdi: {:#018x}  rsi: {:#018x}  rbp: {:#018x}  rsp: {:#018x}".format(rdi, rsi, rbp, rsp))
    print("r8 : {:#018x}  r9 : {:#018x}  r10: {:#018x}  r11: {:#018x}".format(r8, r9, r10, r11))
    print("r12: {:#018x}  r13: {:#018x}  r14: {:#018x}  r15: {:#018x}".format(r12, r13, r14, r15))
    print("xmm0: {:#034x}          xmm1: {:#034x}".format(xmm0, xmm1))
    print("xmm2: {:#034x}          xmm3: {:#034x}".format(xmm2, xmm3))
    print("rip: {:#018x}  rflags: {:s}".format(rip, rflags_to_str(rflags)))

def main():
    # noinspection PyArgumentEqualDefault
    u = Uc(UC_ARCH_X86, UC_MODE_64)
    load_pe64_u(u, sys.argv[1])
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    debug_start: Optional[int] = None
    machine = Machine(debug_start=debug_start, trace_start=None)
    load_pe64(machine, sys.argv[1])
    # load_pe32(machine, "/Users/MrX/Downloads/chuniApp_c+_origin.exe")
    # load_pe64(machine, "/Users/MrX/Downloads/amdaemon.exe")
    # load_pe64(machine, "/Users/MrX/Downloads/alls/SEGA/System/installed/0001_StandardCommon_040/System/sgimagemount.exe")
    # load_pe64(machine, "/Volumes/SanDiskX400/ong_rp/package/amdaemon_dump_SCY.exe", ["-c", "a"])
    # load_pe64(machine, "/Volumes/SanDiskX400/aca/0001_StandardCommon_064/System/sgimagemount_dump_scy.exe")
    # load_pe64(machine, "/tmp/a.exe")

    inst_count = 0
    timer = time.perf_counter_ns()

    def hook_all(uc, address, size, _):
        nonlocal inst_count, timer
        if inst_count != 0 and inst_count % 100000 == 0:
            now = time.perf_counter_ns()
            print(f"{inst_count} ({(now - timer) / 100000} ns per inst)")
            timer = now
        debug = False
        if debug_start is not None and inst_count >= debug_start:
            debug = True
            dump(uc)

        data = uc.mem_read(address, 20)

        if debug:
            try:
                inst = next(md.disasm(data, address))
                print("%d\t%#x  %s %s" % (inst_count, inst.address, inst.mnemonic, inst.op_str))
            except:
                if data[0] == 0x06:
                    s = "%#x  import handler %s"
                    i = u.__getattribute__("imports")[read_int32(data[1:5])]
                elif data[0] == 0x07:
                    s = "%#x  dynamic import handler %s"
                    i = u.__getattribute__("dynamic_imports")[read_int32(data[1:5])]
                else:
                    raise NotImplementedError
                print(s % (address, i))

        if data[0] in (0x06, 0x07):
            if data[0] == 0x06:
                i = u.__getattribute__("imports")[read_int32(data[1:5])]
            else:
                i = u.__getattribute__("dynamic_imports")[read_int32(data[1:5])]
            found = False
            for func in api_list:
                if i == func.__name__:
                    func(u)
                    found = True
                    break
            if not found:
                print(i, file=sys.stderr)
                raise NotImplementedError
            rsp = u.reg_read(UC_X86_REG_RSP)
            u.reg_write(UC_X86_REG_RIP, read_uint64(u.mem_read(rsp, 8)))
            rsp += 8
            u.reg_write(UC_X86_REG_RSP, rsp)

        inst_count += 1


    u.hook_add(UC_HOOK_CODE, hook_all)
    u.hook_add(UC_HOOK_CODE, machine.hook_code)
    u.emu_start(u.reg_read(UC_X86_REG_RIP), 0)
    print(f"{u.reg_read(UC_X86_REG_RIP):#x}")


    # try:
    #     while True:
    #         machine.step()
    #         if (machine.debug and machine.inst_count > machine.debug_start) or machine.step_into:
    #             machine.cpu.dump()
    #             pass
    #         else:
    #             if machine.inst_count % 100000 == 0:
    #                 print(machine.inst_count)
    # except Exited as e:
    #     print("Process finished with exit code %s" % e.status)

if __name__ == '__main__':
    main()
