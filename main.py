import sys

import capstone

from exc import Exited
from imports import api_list
from machine import Machine
from loader import load_pe64, load_pe32, load_pe64_u

from unicorn import *
from unicorn.x86_const import *

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

    machine = Machine(debug_start=0, trace_start=None)
    load_pe64(machine, sys.argv[1])
    # load_pe32(machine, "/Users/MrX/Downloads/chuniApp_c+_origin.exe")
    # load_pe64(machine, "/Users/MrX/Downloads/amdaemon.exe")
    # load_pe64(machine, "/Users/MrX/Downloads/alls/SEGA/System/installed/0001_StandardCommon_040/System/sgimagemount.exe")
    # load_pe64(machine, "/Volumes/SanDiskX400/ong_rp/package/amdaemon_dump_SCY.exe", ["-c", "a"])
    # load_pe64(machine, "/Volumes/SanDiskX400/aca/0001_StandardCommon_064/System/sgimagemount_dump_scy.exe")
    # load_pe64(machine, "/tmp/a.exe")

    inst_count = 0

    def hook_all(uc, address, size, _):
        dump(uc)
        nonlocal inst_count
        data = uc.mem_read(address, 20)
        try:
            inst = next(md.disasm(data, address))
            print("%d\t%#x  %s %s" % (inst_count, inst.address, inst.mnemonic, inst.op_str))
        except:
            if data[0] == 0x06:
                s = "%#x  import handler %s"
                i = u.__getattribute__("imports")[read_int32(data[1:5])]
                import_name = u.__getattribute__("imports")[read_int32(data[1:5])]
                found = False
                for func in api_list:
                    if import_name == func.__name__:
                        func(u)
                        found = True
                        break
                if not found:
                    print(import_name, file=sys.stderr)
                    raise NotImplementedError
                rsp = u.reg_read(UC_X86_REG_RSP)
                u.reg_write(UC_X86_REG_RIP, read_uint64(u.mem_read(rsp, 8)))
                rsp += 8
                u.reg_write(UC_X86_REG_RSP, rsp)
            elif data[0] == 0x07:
                s = "%#x  dynamic import handler %s"
                i = u.__getattribute__("dynamic_imports")[read_int32(data[1:5])]
                raise NotImplementedError
            else:
                raise NotImplementedError
            print(s % (address, i))
        inst_count += 1


    try:
        u.hook_add(UC_HOOK_CODE, hook_all)
        u.emu_start(u.reg_read(UC_X86_REG_RIP), 0)
        print(f"{u.reg_read(UC_X86_REG_RIP):#x}")
    except Exited as e:
        print("Process finished with exit code %s" % e.status)


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
