import sys
import math

from cpu import CPU
from datatype import Int64, Int32, Int16, Int8
from memory import Memory
from utils import read_int32, pack_int64, read_int64, read_int16, read_int8, pack_int32, read_uint32, pack_int8, \
    read_uint16, pack_int16, read_uint64, read_uint8, pack_uint8, read_int128, pack_int128, pack_uint32, pack_uint16, \
    read_float, pack_float, read_double, pack_double, pack_uint64
import capstone
from imports import api_list
from typing import List

parity = list(bin(x).count("1") % 2 == 0 for x in range(256))

scalar_float_mask = 0xffff_ffff_ffff_ffff_ffff_ffff_0000_0000
scalar_double_mask = 0xffff_ffff_ffff_ffff_0000_0000_0000_0000

bp = [
    0x190013a3d
]

inst_bp = [
    # 106815
]

class TrapException(Exception):
    pass

class ExceptionReturn(Exception):
    pass

class Machine:

    def __init__(self, cpu: CPU = CPU(), memory: Memory = Memory(), mode: int = 64, debug_start = None, trace_start: int = None):
        self.cpu = cpu
        self.memory = memory
        self.mode = mode
        if mode == 64:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif mode == 32:
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        else:
            raise NotImplementedError
        self.os = 1
        self.debug = debug_start is not None
        self.debug_start = debug_start
        self.trace = False
        self.trace_start = trace_start
        if self.trace_start is not None:
            self.trace_file = open("/tmp/trace.txt", "w")
        else:
            self.trace_file = None
        self.imports: List[str] = []
        self.inst_count = 0
        self.api_list = api_list
        self.dynamic_imports: List[str] = []
        self.trap_count = 0
        self.base = None
        self.exception_va = None
        self.exception_size = None
        self.exception = False
        self.step_into = False

    def step(self):
        data = self.memory.read(self.cpu.state.rip, 16)
        self.decode(data)
        self.inst_count += 1

    def decode(self, data: bytes):
        rex_w = False
        rex_b = False
        rex_r = False
        rex_x = False
        rex_h = False
        rep = False
        repnz = False
        gs = False
        op_size_override = False
        addr_size_override = False
        prec_size_override = False
        s_dp = False
        s_sp = False
        mode = self.mode

        def translate_plus_r_x(r: int, rex = "r"):
            if rex == "r":
                ext = rex_r
            elif rex == "b":
                ext = rex_b
            elif rex == "x":
                ext = rex_x
            else:
                raise ValueError
            if r == 0:
                if not ext:
                    return state.xmm0
                else:
                    raise NotImplementedError
            elif r == 1:
                if not ext:
                    return state.xmm1
                else:
                    raise NotImplementedError
            elif r == 2:
                if not ext:
                    return state.xmm2
                else:
                    raise NotImplementedError
            elif r == 3:
                if not ext:
                    raise NotImplementedError
                else:
                    raise NotImplementedError
            elif r == 4:
                if not ext:
                    raise NotImplementedError
                else:
                    raise NotImplementedError
            elif r == 5:
                if not ext:
                    raise NotImplementedError
                else:
                    raise NotImplementedError
            elif r == 6:
                if not ext:
                    raise NotImplementedError
                else:
                    raise NotImplementedError
            elif r == 7:
                if not ext:
                    raise NotImplementedError
                else:
                    raise NotImplementedError
            else:
                raise ValueError

        def translate_plus_r(r: int, rex = "r"):
            if rex == "r":
                ext = rex_r
            elif rex == "b":
                ext = rex_b
            elif rex == "x":
                ext = rex_x
            else:
                raise ValueError
            if r == 0:
                if not ext:
                    return state.rax
                else:
                    return state.r8
            elif r == 1:
                if not ext:
                    return state.rcx
                else:
                    return state.r9
            elif r == 2:
                if not ext:
                    return state.rdx
                else:
                    return state.r10
            elif r == 3:
                if not ext:
                    return state.rbx
                else:
                    return state.r11
            elif r == 4:
                if not ext:
                    return state.rsp
                else:
                    return state.r12
            elif r == 5:
                if not ext:
                    return state.rbp
                else:
                    return state.r13
            elif r == 6:
                if not ext:
                    return state.rsi
                else:
                    return state.r14
            elif r == 7:
                if not ext:
                    return state.rdi
                else:
                    return state.r15
            else:
                raise ValueError

        def translate_plus_r_e(r: int, rex = "r"):
            if rex == "r":
                ext = rex_r
            elif rex == "b":
                ext = rex_b
            elif rex == "x":
                ext = rex_x
            else:
                raise ValueError
            if r == 0:
                if not ext:
                    return state.eax
                else:
                    return state.r8d
            elif r == 1:
                if not ext:
                    return state.ecx
                else:
                    return state.r9d
            elif r == 2:
                if not ext:
                    return state.edx
                else:
                    return state.r10d
            elif r == 3:
                if not ext:
                    return state.ebx
                else:
                    return state.r11d
            elif r == 4:
                if not ext:
                    return state.esp
                else:
                    return state.r12d
            elif r == 5:
                if not ext:
                    return state.ebp
                else:
                    return state.r13d
            elif r == 6:
                if not ext:
                    return state.esi
                else:
                    return state.r14d
            elif r == 7:
                if not ext:
                    return state.edi
                else:
                    return state.r15d
            else:
                raise ValueError

        def translate_plus_r_w(r: int, rex = "r"):
            if rex == "r":
                ext = rex_r
            elif rex == "b":
                ext = rex_b
            elif rex == "x":
                ext = rex_x
            else:
                raise ValueError
            if r == 0:
                if not ext:
                    return state.ax
                else:
                    return state.r8w
            elif r == 1:
                if not ext:
                    return state.cx
                else:
                    return state.r9w
            elif r == 2:
                if not ext:
                    return state.dx
                else:
                    return state.r10w
            elif r == 3:
                if not ext:
                    return state.bx
                else:
                    return state.r11w
            elif r == 4:
                if not ext:
                    raise NotImplementedError
                else:
                    return state.r12w
            elif r == 5:
                if not ext:
                    return state.bp
                else:
                    return state.r13w
            elif r == 6:
                if not ext:
                    return state.si
                else:
                    return state.r14w
            elif r == 7:
                if not ext:
                    return state.di
                else:
                    return state.r15w
            else:
                raise ValueError

        def translate_plus_r_b(r: int, rex = "r"):
            ext_any = rex_w or rex_r or rex_b or rex_x or rex_h
            if rex == "r":
                ext = rex_r
            elif rex == "b":
                ext = rex_b
            elif rex == "x":
                ext = rex_x
            else:
                raise ValueError
            if r == 0:
                if not ext:
                    return state.al
                else:
                    return state.r8b
            elif r == 1:
                if not ext:
                    return state.cl
                else:
                    return state.r9b
            elif r == 2:
                if not ext:
                    return state.dl
                else:
                    return state.r10b
            elif r == 3:
                if not ext:
                    return state.bl
                else:
                    return state.r11b
            elif r == 4:
                if not ext:
                    if ext_any:
                        raise NotImplementedError
                    else:
                        raise NotImplementedError
                else:
                    return state.r12b
            elif r == 5:
                if not ext:
                    if ext_any:
                        return state.bpl
                    else:
                        return state.ch
                else:
                    return state.r13b
            elif r == 6:
                if not ext:
                    if ext_any:
                        return state.sil
                    else:
                        return state.dh
                else:
                    return state.r14b
            elif r == 7:
                if not ext:
                    if ext_any:
                        return state.dil
                    else:
                        return state.bh
                else:
                    return state.r15b
            else:
                raise ValueError

        def op_sib(sib: int):
            nonlocal self
            ss, index, base = (sib & 0b11000000) >> 6, (sib & 0b00111000) >> 3, sib & 0b00000111
            scale = int(2 ** ss)
            if index == 0b100 and not rex_x:
                index_src = Int64(0)
            else:
                if mode == 64 or not addr_size_override:
                    index_src = translate_plus_r(index, "x")
                else:
                    index_src = translate_plus_r_e(index, "x")
            if base == 0b101:
                nonlocal data, op_len
                sib_pos = 2
                if data[0] == 0x0f:
                    sib_pos += 1
                if mod == 0b00:
                    base_src = Int32(read_int32(data[sib_pos + 1:sib_pos + 5]), None)
                    data = data[:sib_pos + 1] + data[sib_pos + 5:]
                    op_len += 4
                elif mod == 0b01:
                    if addr_size_override:
                        raise NotImplementedError
                    else:
                        if not rex_b:
                            base_src = state.rbp
                        else:
                            base_src = state.r13
                else:
                    raise NotImplementedError
            else:
                if addr_size_override:
                    base_src = translate_plus_r_e(base, "b")
                else:
                    base_src = translate_plus_r(base, "b")
            return signed(base_src.value) + signed(index_src.value) * scale

        def sign_extend(v, src_len, tgt_len):
            sign_bit = 1 << (src_len - 1)
            return ((v & (sign_bit - 1)) - (v & sign_bit)) & (2 ** tgt_len - 1)

        def zero_extend(v, src_len):
            return v & (2 ** src_len - 1)

        def signed(number):
            bitLength = 32 if addr_size_override else 64
            mask = (2 ** bitLength) - 1
            if number & (1 << (bitLength - 1)):
                return number | ~mask
            else:
                return number & mask

        state = self.cpu.state
        memory = self.memory

        if self.trace_start is not None and self.inst_count >= self.trace_start and not self.trace:
            self.trace = True

        if self.debug or self.trace or self.step_into:
            try:
                if self.trace :
                    # inst = next(self.md.disasm(data, state.rip.value))
                    if state.rip.value > 0x400000 and data[0] not in [0x06, 0x07]:
                        self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                if self.debug or self.step_into:
                    if not self.step_into and self.inst_count < self.debug_start:
                        pass
                        # print("%#x" % state.rip.value)
                    else:
                        # if not self.trace:
                        inst = next(self.md.disasm(data, state.rip.value))
                        print("%d\t%#x  %s %s" % (self.inst_count, inst.address, inst.mnemonic, inst.op_str))
            except:
                if data[0] == 0x06:
                    s = "%#x  import handler %s"
                    i = self.imports[read_int32(data[1:5])]
                elif data[0] == 0x07:
                    s = "%#x  dynamic import handler %s"
                    i = self.dynamic_imports[read_int32(data[1:5])]
                else:
                    raise NotImplementedError
                print(s % (state.rip.value, i))

        op_len = 0

        # bp
        if self.step_into:
            breakpoint()

        if state.rip.value in bp:
            self.cpu.dump()
            # if state.rcx.value == 0x2bc3:
            self.step_into = True
            breakpoint()

        if self.inst_count in inst_bp:
            self.cpu.dump()
            self.step_into = True
            breakpoint()

        # prefix

        if data[0] == 0x65:
            gs = True
            data = data[1:]
            op_len += 1

        while data[0] == 0x66:
            if data[0] == 0x66:
                op_size_override = True
                prec_size_override = True
                data = data[1:]
                op_len += 1

        if data[0] == 0x67:
            addr_size_override = True
            data = data[1:]
            op_len += 1

        if data[0] == 0xf0:
            data = data[1:]
            op_len += 1

        if data[0] == 0xf2:
            rep = True
            repnz = True
            s_dp = True
            data = data[1:]
            op_len += 1

        if data[0] == 0xf3:
            rep = True
            s_sp = True
            data = data[1:]
            op_len += 1

        if data[0] == 0x40:
            rex_h = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x41:
            rex_b = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x42:
            rex_x = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x43:
            rex_b = True
            rex_x = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x44:
            rex_r = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x45:
            rex_r = True
            rex_b = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x46:
            rex_r = True
            rex_x = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x47:
            rex_r = True
            rex_x = True
            rex_b = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x48:
            rex_w = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x49:
            rex_w = True
            rex_b = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x4a:
            rex_w = True
            rex_x = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x4b:
            rex_w = True
            rex_x = True
            rex_b = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x4c:
            rex_w = True
            rex_r = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x4d:
            rex_w = True
            rex_r = True
            rex_b = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x4e:
            rex_w = True
            rex_r = True
            rex_x = True
            data = data[1:]
            op_len += 1
        elif data[0] == 0x4f:
            rex_w = True
            rex_r = True
            rex_x = True
            rex_b = True
            data = data[1:]
            op_len += 1

        # opcode
        o = (data[1] & 0b00111000) >> 3
        rm = data[1] & 0b00000111
        mod = (data[1] & 0b11000000) >> 6

        try:
            # trap processing
            if self.trap_count > 0:
                self.trap_count -= 1
            elif state.rflags.TF:
                if self.trap_count == 0:
                    self.trap_count = 1

            if self.trap_count == 0 and state.rflags.TF:
                state.rflags.TF = False
                raise TrapException("Trap flag trigger")

            if data[0] == 0x06:
                # custom import takeover
                op_len = 0
                import_name = self.imports[read_int32(data[1:5])]
                found = False
                for func in api_list:
                    if import_name == func.__name__:
                        func(self)
                        found = True
                        break
                if not found:
                    print(import_name, file=sys.stderr)
                    raise NotImplementedError
                state.rip.value = read_int64(memory.read(state.rsp, 8))
                state.rsp += 8

            elif data[0] == 0x07:
                # custom import takeover
                op_len = 0
                import_name = self.dynamic_imports[read_int32(data[1:5])]
                found = False
                for func in api_list:
                    if import_name == func.__name__:
                        func(self)
                        found = True
                        break
                if not found:
                    print("import %s not found" % import_name, file=sys.stderr)
                    raise NotImplementedError
                state.rip.value = read_int64(memory.read(state.rsp, 8))
                state.rsp += 8

            elif data[0] == 0x01:
                # add r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op2 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    if rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b").value
                        if rex_w:
                            value = read_int64(memory.read(op1, 8))
                            pack = pack_int64
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_int32(memory.read(op1, 4))
                            pack = pack_uint32
                        state.rflags.OF = value + op2.value > op2.max_signed
                        state.rflags.CF = value + op2.value > op2.max
                        value = value + op2.value
                        memory.write(op1, pack(value & op2.max))
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                        state.rflags.SF = value & (1 << msb)
                elif mod == 0b01:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b").value
                        op1 += read_int8(data[2:3])
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_int32(memory.read(op1, 4))
                            pack = pack_int32
                        state.rflags.OF = value + op2.value > op2.max_signed
                        state.rflags.CF = value + op2.value > op2.max
                        value = value + op2.value
                        memory.write(op1, pack(value))
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                        state.rflags.SF = value & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b").value
                        op1 += read_int32(data[2:6])
                        if rex_w:
                            value = read_int64(memory.read(op1, 8))
                            pack = pack_int64
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_int32(memory.read(op1, 4))
                            pack = pack_uint32
                        state.rflags.OF = value + op2.value > op2.max_signed
                        state.rflags.CF = value + op2.value > op2.max
                        value = value + op2.value
                        memory.write(op1, pack(value & op2.max))
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                        state.rflags.SF = value & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(rm, "b")
                    state.rflags.OF = op1.value + op2.value > op2.max_signed
                    state.rflags.CF = op1.value + op2.value > op2.max
                    op1.value = op1.value + op2.value
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x02:
                # add r8, r/m8
                op1 = translate_plus_r_b(o)
                if mod == 0b11:
                    op_len += 2
                    op2 = translate_plus_r_b(rm, "b")
                    state.rflags.OF = op1.value + op2.value > op2.max_signed
                    state.rflags.CF = op1.value + op2.value > op2.max
                    op1.value = op1.value + op2.value
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << 7)
                else:
                    raise NotImplementedError

            elif data[0] == 0x03:
                # add r16/32/64. r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    op1 = translate_plus_r_w(o)
                else:
                    op1 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op2 = op_sib(data[2])
                    elif rm == 0b101:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = state.rip + read_int32(data[2:6]) + op_len
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                        msb = 63
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = read_int32(memory.read(op2, 4))
                        msb = 31
                    state.rflags.OF = op1.value + op2 > op1.max_signed
                    state.rflags.CF = op1.value + op2 > op1.max
                    op1.value += op2
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                        msb = 63
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = read_int32(memory.read(op2, 4))
                        msb = 31
                    state.rflags.OF = op1.value + op2 > op1.max_signed
                    state.rflags.CF = op1.value + op2 > op1.max
                    op1.value += op2
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2]) + read_int32(data[3:7])
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = read_int32(memory.read(op2, 4))
                            msb = 31
                        state.rflags.OF = op1.value + op2 > op1.max_signed
                        state.rflags.CF = op1.value + op2 > op1.max
                        op1.value += op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                    else:
                        raise NotImplementedError
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                        msb = 63
                    elif op_size_override:
                        op2 = translate_plus_r_w(rm, "b")
                        msb = 15
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                        msb = 31
                    state.rflags.OF = op1.value + op2.value > op1.max_signed
                    state.rflags.CF = op1.value + op2.value > op1.max
                    op1.value += op2.value
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x04:
                # add AL, imm8
                op_len += 2
                op1 = state.al
                op2 = read_int8(data[1:2])
                state.rflags.OF = op1.value + op2 > op1.max_signed
                state.rflags.CF = op1.value + op2 > op1.max
                op1.value += op2
                state.rflags.ZF = op1.value == 0
                state.rflags.AF = False
                state.rflags.PF = parity[op1.value & 0xff]
                state.rflags.SF = op1.value & (1 << 7)

            elif data[0] == 0x05:
                # add rAX, imm16/32
                if rex_w:
                    op_len += 5
                    op1 = state.rax
                    op2 = sign_extend(read_uint32(data[1:5]), 32, 64)
                    msb = 63
                elif op_size_override:
                    op_len += 3
                    op1 = state.ax
                    op2 = read_uint16(data[1:3])
                    msb = 15
                else:
                    op_len += 5
                    op1 = state.eax
                    op2 = read_uint32(data[1:5])
                    msb = 31
                state.rflags.OF = op1.value + op2 > op1.max_signed
                state.rflags.CF = op1.value + op2 > op1.max
                op1.value += op2
                state.rflags.ZF = op1.value == 0
                state.rflags.AF = False
                state.rflags.PF = parity[op1.value & 0xff]
                state.rflags.SF = op1.value & (1 << msb)

            elif data[0] == 0x08:
                # or r/m8, r8
                op2 = translate_plus_r_b(o)
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                    value = read_int8(memory.read(op1, 1))
                    value = value | op2.value
                    memory.write(op1, pack_int8(value))
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = value & (1 << 7)
                    state.rflags.ZF = value == 0
                    state.rflags.PF = parity[value & 0xff]
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op1 = op_sib(data[2]) + read_int8(data[3:4])
                        value = read_int8(memory.read(op1, 1))
                        value = value | op2.value
                        memory.write(op1, pack_uint8(value))
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = value & (1 << 7)
                        state.rflags.ZF = value == 0
                        state.rflags.PF = parity[value & 0xff]
                    else:
                        raise NotImplementedError
                elif mod == 0b11:
                    op_len += 2
                    op1 = translate_plus_r_b(rm, "b")
                    op1.value = op1.value | op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << 7)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x09:
                # or r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    op2 = translate_plus_r_w(o)
                    msb = 15
                else:
                    op2 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op1 = op_sib(data[2])
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                    if rex_w:
                        raise NotImplementedError
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        value = read_int32(memory.read(op1, 4))
                        pack = pack_int32
                    value = value | op2.value
                    memory.write(op1, pack(value))
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        op1 = translate_plus_r_w(rm, "b")
                    else:
                        op1 = translate_plus_r_e(rm, "b")
                    op1.value = op1.value | op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x0b:
                # or r16/32/64, r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    op1 = translate_plus_r_w(o)
                    msb = 15
                else:
                    op1 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        op2 = translate_plus_r_w(rm, "b")
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                    op1.value = op1.value | op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x0f:
                o = (data[2] & 0b00111000) >> 3
                rm = data[2] & 0b00000111
                mod = (data[2] & 0b11000000) >> 6
                if data[1] == 0x0d:
                    if o == 1:
                        if mod == 0b01:
                            if rm == 0b100:
                                raise NotImplementedError
                            else:
                                op_len += 4
                        else:
                            raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x10:
                    if s_sp:
                        # movss xmm, xmm/m32
                        op1 = translate_plus_r_x(o)
                        if mod == 0b00:
                            if rm == 0b100:
                                raise NotImplementedError
                            elif rm == 0b101:
                                op_len += 7
                                op2 = state.rip.value + read_int32(data[3:7]) + op_len
                            else:
                                raise NotImplementedError
                            op1.value = read_int32(memory.read(op2, 4))
                        else:
                            raise NotImplementedError
                    elif s_dp:
                        # movsd xmm, xmm/m64
                        op1 = translate_plus_r_x(o)
                        if mod == 0b00:
                            if rm == 0b100:
                                raise NotImplementedError
                            elif rm == 0b101:
                                op_len += 7
                                op2 = state.rip.value + read_int32(data[3:7]) + op_len
                            else:
                                raise NotImplementedError
                            op1.value = read_int64(memory.read(op2, 8))
                        else:
                            raise NotImplementedError
                    elif prec_size_override:
                        raise NotImplementedError
                    else:
                        # movups xmm, xmm/m128
                        op1 = translate_plus_r_x(o)
                        if mod == 0b00:
                            if rm == 0b100:
                                raise NotImplementedError
                            elif rm == 0b101:
                                op_len += 7
                                op2 = state.rip.value + read_int32(data[3:7]) + op_len
                            else:
                                op_len += 3
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op2 = translate_plus_r(rm, "b")
                            op1.value = read_int128(memory.read(op2, 16))
                        elif mod == 0b01:
                            if rm == 0b100:
                                raise NotImplementedError
                            else:
                                op_len += 4
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op2 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                            op1.value = read_int128(memory.read(op2, 16))
                        else:
                            raise NotImplementedError
                elif data[1] == 0x11:
                    if s_sp:
                        raise NotImplementedError
                    elif s_dp:
                        raise NotImplementedError
                    elif prec_size_override:
                        raise NotImplementedError
                    else:
                        # movups xmm/128, xmm
                        op2 = translate_plus_r_x(o)
                        if mod == 0b00:
                            if rm == 0b100:
                                raise NotImplementedError
                            elif rm == 0b101:
                                op_len += 7
                                op1 = state.rip.value + read_int32(data[3:7]) + op_len
                            else:
                                op_len += 3
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op1 = translate_plus_r(rm, "b")
                            memory.write(op1, pack_int128(op2))
                        elif mod == 0b01:
                            if rm == 0b100:
                                raise NotImplementedError
                            else:
                                op_len += 4
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op1 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                            memory.write(op1, pack_int128(op2))
                        else:
                            raise NotImplementedError
                elif data[1] == 0x1f:
                    if o == 0:
                        # nop r/m16/32
                        if mod == 0b00:
                            if rm == 0b100:
                                raise NotImplementedError
                            elif rm == 0b101:
                                raise NotImplementedError
                            else:
                                op_len += 3
                        elif mod == 0b01:
                            if rm == 0b100:
                                op_len += 5
                                op_sib(data[3])
                            else:
                                op_len += 4
                        elif mod == 0b10:
                            if rm == 0b100:
                                op_len += 8
                                op_sib(data[3])
                            else:
                                op_len += 7
                        else:
                            raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x28:
                    # movaps/movapd xmm, xmm/m128
                    op1 = translate_plus_r_x(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b")
                        op1.value = read_int128(memory.read(op2, 16))
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = op_sib(data[3]) + read_int8(data[4:5])
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                        op1.value = read_int128(memory.read(op2, 16))
                    else:
                        raise NotImplementedError
                elif data[1] == 0x29:
                    # movaps/movapd xmm/128, xmm
                    op2 = translate_plus_r_x(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                        memory.write(op1, pack_int128(op2.value))
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                        memory.write(op1, pack_int128(op2.value))
                    else:
                        raise NotImplementedError
                elif data[1] == 0x2a:
                    if s_sp:
                        # cvtsi2ss xmm, r/m32/64
                        op1 = translate_plus_r_x(o)
                        if mod == 0b11:
                            if rex_w:
                                op_len += 3
                                op2 = translate_plus_r(rm, "b")
                                op1.value = (op1.value & 0xffffffffffff0000) | read_int32(pack_float(float(op2.value)))
                            else:
                                raise NotImplementedError
                        else:
                            raise NotImplementedError
                    elif s_dp:
                        raise NotImplementedError
                    elif prec_size_override:
                        raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x2c:
                    if s_sp:
                        raise NotImplementedError
                    elif s_dp:
                        # cvttsd2si r32/64, xmm/m64
                        if rex_w:
                            op1 = translate_plus_r(o)
                        else:
                            raise NotImplementedError
                        if mod == 0b11:
                            op_len += 3
                            op2 = translate_plus_r_x(rm, "b")
                            value = read_double(pack_int128(op2)[:8])
                            op1.value = int(value)
                        else:
                            raise NotImplementedError
                    elif prec_size_override:
                        raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x2f:
                    if prec_size_override:
                        # comisd xmm, xmm/m64
                        op1 = translate_plus_r_x(o)
                        if mod == 0b11:
                            op_len += 3
                            op2 = translate_plus_r_x(rm, "b")
                            value1 = read_double(pack_int128(op1)[:8])
                            value2 = read_double(pack_int128(op2)[:8])
                            if math.isnan(value1) or math.isnan(value2):
                                state.rflags.ZF = True
                                state.rflags.PF = True
                                state.rflags.CF = True
                            elif value1 == value2:
                                state.rflags.ZF = True
                                state.rflags.PF = False
                                state.rflags.CF = False
                            elif value1 > value2:
                                state.rflags.ZF = False
                                state.rflags.PF = False
                                state.rflags.CF = False
                            elif value1 < value2:
                                state.rflags.ZF = False
                                state.rflags.PF = False
                                state.rflags.CF = True
                            else:
                                raise ValueError
                            state.rflags.OF = False
                            state.rflags.AF = False
                            state.rflags.SF = False
                        else:
                            raise NotImplementedError
                    else:
                        # comiss xmm, xmm/m32
                        op1 = translate_plus_r_x(o)
                        if mod == 0b01:
                            if rm == 0b100:
                                raise NotImplementedError
                            else:
                                op_len += 4
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op2 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                                value1 = read_float(pack_int128(op1)[:4])
                                value2 = read_float(memory.read(op2, 4))
                        elif mod == 0b11:
                            op_len += 3
                            op2 = translate_plus_r_x(rm, "b")
                            value1 = read_float(pack_int128(op1)[:4])
                            value2 = read_float(pack_int128(op2)[:4])
                        else:
                            raise NotImplementedError
                        if math.isnan(value1) or math.isnan(value2):
                            state.rflags.ZF = True
                            state.rflags.PF = True
                            state.rflags.CF = True
                        elif value1 == value2:
                            state.rflags.ZF = True
                            state.rflags.PF = False
                            state.rflags.CF = False
                        elif value1 > value2:
                            state.rflags.ZF = False
                            state.rflags.PF = False
                            state.rflags.CF = False
                        elif value1 < value2:
                            state.rflags.ZF = False
                            state.rflags.PF = False
                            state.rflags.CF = True
                        else:
                            raise ValueError
                        state.rflags.OF = False
                        state.rflags.AF = False
                        state.rflags.SF = False
                elif data[1] == 0x40:
                    # cmovo r16/32/64, r/m16/32/64
                    cond = state.rflags.OF
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        op1 = translate_plus_r_w(o)
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if cond:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            op2 = translate_plus_r_w(rm, "b")
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if cond:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x42:
                    # cmovc r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + read_int32(data[3:7]) + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2, 8))
                            else:
                                raise NotImplementedError
                        else:
                            raise NotImplementedError
                        if state.rflags.CF:
                            op1.value = op2
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if state.rflags.CF:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x43:
                    # cmovnc r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + read_int32(data[3:7]) + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2, 8))
                            else:
                                raise NotImplementedError
                        else:
                            raise NotImplementedError
                        if not state.rflags.CF:
                            op1.value = op2
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = op_sib(data[3]) + read_int8(data[4:5])
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                        else:
                            raise NotImplementedError
                        if not state.rflags.CF:
                            op1.value = op2
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if not state.rflags.CF:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x44:
                    # cmovz r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + read_int32(data[3:7]) + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2, 8))
                            else:
                                raise NotImplementedError
                        else:
                            raise NotImplementedError
                        if state.rflags.ZF:
                            op1.value = op2
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if state.rflags.ZF:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x45:
                    # cmovnz r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if not state.rflags.ZF:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if not state.rflags.ZF:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x47:
                    # cmova r16/32/64, r/m16/32/64
                    cond = not state.rflags.CF and not state.rflags.ZF
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if cond:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = read_int32(memory.read(op2, 4))
                            if cond:
                                op1.value = op2
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if cond:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x48:
                    # cmovs r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        op1 = translate_plus_r_w(o)
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if state.rflags.SF:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            op2 = translate_plus_r_w(rm, "b")
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if state.rflags.SF:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x4c:
                    # cmovl r16/32/64, r/m16/32/64
                    cond = state.rflags.SF != state.rflags.OF
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        op1 = translate_plus_r_w(o)
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if cond:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            op2 = translate_plus_r_w(rm, "b")
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if cond:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x4e:
                    # cmovle r16/32/64, r/m16/32/64
                    cond = state.rflags.ZF or state.rflags.SF != state.rflags.OF
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        op1 = translate_plus_r_w(o)
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if cond:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            op2 = translate_plus_r_w(rm, "b")
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if cond:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x4f:
                    # cmovg r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2.value + read_int32(data[3:7]), 8))
                            else:
                                raise NotImplementedError
                            if not state.rflags.ZF and state.rflags.SF == state.rflags.OF:
                                op1.value = op2
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                        if not state.rflags.ZF and state.rflags.SF == state.rflags.OF:
                            op1.value = op2.value
                    else:
                        raise NotImplementedError
                elif data[1] == 0x57:
                    if prec_size_override:
                        raise NotImplementedError
                    else:
                        # xorps xmm, xmm/m128
                        op1 = translate_plus_r_x(o)
                        if mod == 0b11:
                            op_len += 3
                            op2 = translate_plus_r_x(rm, "b")
                            op1.value = op1.value ^ op2.value
                        else:
                            raise NotImplementedError
                elif data[1] == 0x59:
                    if s_sp:
                        raise NotImplementedError
                    elif s_dp:
                        # mulsd xmm, xmm/m64
                        op1 = translate_plus_r_x(o)
                        if mod == 0b11:
                            op_len += 3
                            op2 = translate_plus_r_x(rm, "b")
                            value1 = read_double(pack_int128(op1)[:8])
                            value2 = read_double(pack_int128(op2)[:8])
                            value = value1 * value2
                            op1.value = (op1.value & scalar_double_mask) | read_int64(pack_double(value))
                        else:
                            raise NotImplementedError
                    elif prec_size_override:
                        raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x5e:
                    if s_sp:
                        # divss xmm. xmm/m32
                        op1 = translate_plus_r_x(o)
                        if mod == 0b11:
                            op_len += 3
                            op2 = translate_plus_r_x(rm, "b")
                            value1 = read_double(pack_int128(op1)[:8])
                            value2 = read_double(pack_int128(op2)[:8])
                            value = value1 / value2
                            op1.value = (op1.value & scalar_float_mask) | read_int32(pack_float(value))
                        else:
                            raise NotImplementedError
                    elif s_dp:
                        raise NotImplementedError
                    elif prec_size_override:
                        raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x7f:
                    if s_sp or prec_size_override:
                        op2 = translate_plus_r_x(o)
                        # movdqu/movdqa xmm/m128, xmm
                        if mod == 0b00:
                            if rm == 0b100:
                                raise NotImplementedError
                            elif rm == 0b101:
                                raise NotImplementedError
                            else:
                                op_len += 3
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op1 = translate_plus_r(rm, "b")
                                memory.write(op1, pack_int128(op2))
                        elif mod == 0b01:
                            if rm == 0b100:
                                op_len += 5
                                op1 = op_sib(data[3]) + read_int8(data[4:5])
                            else:
                                op_len += 4
                                if addr_size_override:
                                    raise NotImplementedError
                                else:
                                    op1 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                            memory.write(op1, pack_int128(op2))
                        else:
                            raise NotImplementedError
                    else:
                        raise NotImplementedError
                elif data[1] == 0x82:
                    # jc rel16/32
                    op_len += 6
                    if state.rflags.CF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x83:
                    # jnc rel16/32
                    op_len += 6
                    if not state.rflags.CF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x84:
                    # jz rel16/32
                    op_len += 6
                    if state.rflags.ZF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x85:
                    # jnz rel16/32
                    op_len += 6
                    if not state.rflags.ZF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x86:
                    # jbe rel16/32
                    op_len += 6
                    if state.rflags.CF or state.rflags.ZF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x87:
                    # ja rel16/32
                    op_len += 6
                    if not state.rflags.CF and not state.rflags.ZF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x88:
                    # js rel16/32
                    op_len += 6
                    if state.rflags.SF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x8c:
                    # jl rel16/32
                    op_len += 6
                    if state.rflags.SF != state.rflags.OF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x8d:
                    # jge rel16/32
                    op_len += 6
                    if state.rflags.SF == state.rflags.OF:
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x8e:
                    # jle rel16/32
                    op_len += 6
                    if state.rflags.ZF or (state.rflags.SF != state.rflags.OF):
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x8f:
                    # jg rel16/32
                    op_len += 6
                    if not state.rflags.ZF and (state.rflags.SF == state.rflags.OF):
                        state.rip += read_int32(data[2:6])
                elif data[1] == 0x92:
                    # setc r/m8
                    op_len += 3
                    if state.rflags.CF:
                        op2 = 1
                    else:
                        op2 = 0
                    if mod == 0b11:
                        op1 = translate_plus_r_b(rm, "b")
                        op1.value = op2
                    else:
                        raise NotImplementedError
                elif data[1] == 0x93:
                    # setnc r/m8
                    op_len += 3
                    if not state.rflags.CF:
                        op2 = 1
                    else:
                        op2 = 0
                    if mod == 0b11:
                        op1 = translate_plus_r_b(rm, "b")
                        op1.value = op2
                    else:
                        raise NotImplementedError
                elif data[1] == 0x94:
                    # setz r/m8
                    op_len += 3
                    if state.rflags.ZF:
                        op2 = 1
                    else:
                        op2 = 0
                    if mod == 0b11:
                        op1 = translate_plus_r_b(rm, "b")
                        op1.value = op2
                    else:
                        raise NotImplementedError
                elif data[1] == 0x95:
                    # setnz r/m8
                    op_len += 3
                    if not state.rflags.ZF:
                        op2 = 1
                    else:
                        op2 = 0
                    if mod == 0b11:
                        op1 = translate_plus_r_b(rm, "b")
                        op1.value = op2
                    else:
                        raise NotImplementedError
                elif data[1] == 0x97:
                    # seta r/m8
                    op_len += 3
                    if not state.rflags.ZF and not state.rflags.CF:
                        op2 = 1
                    else:
                        op2 = 0
                    if mod == 0b11:
                        op1 = translate_plus_r_b(rm, "b")
                        op1.value = op2
                    else:
                        raise NotImplementedError
                elif data[1] == 0xa2:
                    # cpuid
                    op_len += 2
                    if state.eax.value == 0:
                        state.rax.value = 0
                        state.rbx.value = 0x72614820
                        state.rdx.value = 0x20616b75
                        state.rcx.value = 0x20555043
                    elif state.rax.value == 1:
                        state.rax.value = 0b0000_0000_0000_0000_0011_0100_0001_0000
                        state.rbx.value = 0x00000000
                        state.rcx.value = 0b0000_0000_0000_0000_0000_0000_0000_0000
                        state.rdx.value = 0b0000_0000_0000_0000_0000_0000_0000_0000
                    elif state.rax.value == 7:
                        state.rax.value = 0
                        state.rbx.value = 0b0000_0000_0000_0000_0000_0000_0000_0000
                        state.rcx.value = 0b0000_0000_0000_0000_0000_0000_0000_0000
                        state.rdx.value = 0b0000_0000_0000_0000_0000_0000_0000_0000
                    else:
                        print(state.eax.value)
                        raise NotImplementedError
                elif data[1] == 0xa3:
                    # bt r/m16/32/64, r16/32/64
                    op_len += 3
                    if rex_w:
                        raise NotImplementedError
                    elif op_size_override:
                        op1 = translate_plus_r_w(rm, "b")
                        op2 = translate_plus_r_w(o).value % 16
                        state.rflags.CF = op1 & (1 << op2) != 0
                    else:
                        op1 = translate_plus_r_e(rm, "b")
                        op2 = translate_plus_r_w(o).value % 32
                        state.rflags.CF = op1 & (1 << op2) != 0
                elif data[1] == 0xaf:
                    # imul r16/32/64, r/m16/32/64
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op2 = translate_plus_r(rm, "b")
                            size = 64
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b")
                            size = 32
                        tmp = op1.value * op2.value
                        if sign_extend(tmp, size, size) != tmp:
                            state.rflags.CF = True
                            state.rflags.OF = True
                        else:
                            state.rflags.CF = False
                            state.rflags.OF = False
                        op1.value = tmp
                    else:
                        raise NotImplementedError
                elif data[1] == 0xb1:
                    # cmpxchg r/m16/32/64, r16/32/64
                    if rex_w:
                        op2 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op1 = op_sib(data[3])
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip + read_int32(data[3:7]) + op_len
                        else:
                            op_len += 3
                            if addr_size_override:
                                op1 = translate_plus_r_e(rm, "b")
                            else:
                                op1 = translate_plus_r(rm, "b")
                        if rex_w:
                            value = read_int64(memory.read(op1, 8))
                            if state.rax == value:
                                state.rflags.ZF = True
                                memory.write(op1, pack_int64(op2))
                            else:
                                state.rflags.ZF = False
                                state.rax = value
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            raise NotImplementedError
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                op1 = translate_plus_r_e(rm, "b")
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 += read_int8(data[3:4])
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                        if rex_w:
                            if state.rax == value:
                                state.rflags.ZF = True
                                memory.write(op1, pack_int64(op2))
                            else:
                                state.rflags.ZF = False
                                state.rax = value
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            if state.eax == value:
                                state.rflags.ZF = True
                                memory.write(op1, pack_int32(op2))
                            else:
                                state.rflags.ZF = False
                                state.eax = value
                    else:
                        raise NotImplementedError
                elif data[1] == 0xb6:
                    # movzx r16/32/64, r/m8
                    if rex_w:
                        op1 = translate_plus_r(o)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op2 = op_sib(data[3])
                            op2 = read_int8(memory.read(op2, 1))
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip.value + read_int32(data[3:7]) + op_len
                            op2 = read_int8(memory.read(op2, 1))
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b")
                            op2 = read_int8(memory.read(op2, 1))
                            if rex_w:
                                op2 = zero_extend(op2, 8)
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = op_sib(data[3])
                            op2 = read_int8(memory.read(op2 + read_int8(data[4:5]), 1))
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b")
                            op2 = read_int8(memory.read(op2 + read_int8(data[3:4]), 1))
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                    elif mod == 0b10:
                        if rm == 0b100:
                            op_len += 8
                            op2 = op_sib(data[3])
                            op2 = read_int8(memory.read(op2 + read_int32(data[4:8]), 1))
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                        else:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b")
                            op2 = read_int8(memory.read(op2 + read_int32(data[3:7]), 1))
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op2 = zero_extend(op2, 8)
                            op1.value = op2
                    elif mod == 0b11:
                        op_len += 3
                        op2 = translate_plus_r_b(rm, "b")
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = zero_extend(op2.value, 8)
                        op1.value = op2
                elif data[1] == 0xb7:
                    # movzx r32/64, r/m16
                    if rex_w:
                        op1 = translate_plus_r(o)
                    else:
                        op1 = translate_plus_r_e(o)
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op2 = zero_extend(read_int16(memory.read(op_sib(data[3]), 2)), 16)
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = state.rip + read_int32(data[3:7]) + op_len
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b")
                        op2 = zero_extend(read_int16(memory.read(op2, 2)), 16)
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = zero_extend(read_int16(memory.read(op_sib(data[3]) + read_int8(data[4:5]), 2)), 16)
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                r2 = translate_plus_r(rm, "b")
                            op2 = zero_extend(read_int16(memory.read(r2.value + read_int8(data[3:4]), 2)), 16)
                    elif mod == 0b10:
                        if rm == 0b100:
                            op_len += 8
                            op2 = zero_extend(read_int16(memory.read(op_sib(data[3]) + read_int32(data[4:8]), 2)), 16)
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        op2 = translate_plus_r_w(rm, "b")
                        op2 = zero_extend(op2.value, 16)
                    else:
                        raise NotImplementedError
                    op1.value = op2
                elif data[1] == 0xba:
                    # bt r/m16/32/64, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 8
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip + read_int32(data[3:7]) + op_len
                            op2 = read_int8(data[7:8])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = op2 % 32
                                state.rflags.CF = op1 & (1 << op2) != 0
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op2 = read_int8(data[3:4])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = op2 % 32
                                state.rflags.CF = op1 & (1 << op2) != 0
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 5
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                            op2 = read_int8(data[4:5])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = op2 % 32
                                state.rflags.CF = op1 & (1 << op2) != 0
                    elif mod == 0b11:
                        op_len += 4
                        op2 = read_int8(data[3:4])
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = op2 % 16
                            state.rflags.CF = op1 & (1 << op2) != 0
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = op2 % 32
                            state.rflags.CF = op1 & (1 << op2) != 0
                    else:
                        raise NotImplementedError
                elif data[1] == 0xbe:
                    # movsx r16/32/64, r/m8
                    if mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = op_sib(data[3]) + read_int8(data[4:5])
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op2 = translate_plus_r(rm, "b") + read_int8(data[3:4])
                        op2 = read_int8(memory.read(op2, 1))
                    elif mod == 0b11:
                        op_len += 3
                        op2 = translate_plus_r_b(rm, "b").value
                    else:
                        raise NotImplementedError
                    if rex_w:
                        op1 = translate_plus_r(o)
                        op1.value = sign_extend(op2, 8, 64)
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(o)
                        op1.value = sign_extend(op2, 8, 32)
                elif data[1] == 0xc1:
                    # xadd r/m16/32/64, r16/32/64
                    if rex_w:
                        op2 = translate_plus_r(o)
                        msb = 63
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = translate_plus_r_e(o)
                        msb = 31
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        if rm == 0b101:
                            op_len += 7
                            op1 = state.rip.value + read_int32(data[3:7]) + op_len
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b").value
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_int32(memory.read(op1, 4))
                            pack = pack_uint32
                        src = value
                        state.rflags.OF = value + op2.value > op2.max_signed
                        state.rflags.CF = value + op2.value > op2.max
                        value = value + op2.value
                        op2.value = src
                        memory.write(op1, pack(value & op2.max))
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                        state.rflags.SF = value & (1 << msb)
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b").value
                            op1 += read_int8(data[3:4])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                pack = pack_uint32
                            src = value
                            state.rflags.OF = value + op2.value > op2.max_signed
                            state.rflags.CF = value + op2.value > op2.max
                            value = value + op2.value
                            memory.write(op1, pack(value & op2.max))
                            op2.value = src
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                            state.rflags.SF = value & (1 << msb)
                    elif mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b").value
                            op1 += read_int32(data[2:6])
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                                pack = pack_int64
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                pack = pack_int32
                            src = value
                            state.rflags.OF = value + op2.value > op2.max_signed
                            state.rflags.CF = value + op2.value > op2.max
                            value = value + op2.value
                            memory.write(op1, pack(value))
                            op2.value = src
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                            state.rflags.SF = value & (1 << msb)
                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                        state.rflags.OF = op1.value + op2.value > op2.max_signed
                        state.rflags.CF = op1.value + op2.value > op2.max
                        src = op1.value
                        op1.value = op1.value + op2.value
                        op2.value = src
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0x1b:
                # sbb r/m16/32/64, r16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op1 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = read_int32(memory.read(op2, 4))
                        op2 = op2 + state.rflags.CF
                        state.rflags.OF = op1.value - op2 < op1.min_signed
                        state.rflags.CF = op1 < op2
                        op1.value = op1.value - op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = op2.value + read_int32(data[2:6])
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                        else:
                            raise NotImplementedError
                        op2 = op2 + state.rflags.CF
                        state.rflags.OF = op1.value - op2 < op1.min_signed
                        state.rflags.CF = op1 < op2
                        op1.value = op1.value - op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                    op2 = op2 + state.rflags.CF
                    state.rflags.OF = op1.value - op2.value < op1.min_signed
                    state.rflags.CF = op1 < op2
                    op1.value = op1.value - op2.value
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x21:
                # and r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op2 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op1 = op_sib(data[2])
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                    if rex_w:
                        value = read_int64(memory.read(op1, 8))
                        msb = 63
                        pack = pack_int64
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        value = read_int32(memory.read(op1, 4))
                        msb = 31
                        pack = pack_int32
                    value = value & op2.value
                    memory.write(op1, pack(value))
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = value & (1 << msb)
                    state.rflags.ZF = value == 0
                    state.rflags.PF = parity[value & 0xff]
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op1 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                    if rex_w:
                        value = read_int64(memory.read(op1, 8))
                        msb = 63
                        pack = pack_int64
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        value = read_int32(memory.read(op1, 4))
                        msb = 31
                        pack = pack_int32
                    value = value & op2.value
                    memory.write(op1, pack(value))
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = value & (1 << msb)
                    state.rflags.ZF = value == 0
                    state.rflags.PF = parity[value & 0xff]
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, "b")
                        msb = 63
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(rm, "b")
                        msb = 31
                    op1.value = op1.value & op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x23:
                # and r16/32/64, r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op1 = translate_plus_r_e(o)
                if mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        raise NotImplementedError
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                        msb = 63
                    else:
                        raise NotImplementedError
                    op1.value = op1.value & op2
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, rex="b")
                        msb = 63
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = translate_plus_r_e(rm, rex="b")
                        msb = 31
                    op1.value = op1.value & op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x24:
                # and AL, imm8
                op_len += 2
                op1 = state.al
                op2 = data[1]
                op1.value = op1.value & op2
                state.rflags.OF = False
                state.rflags.CF = False
                state.rflags.SF = op1.value & (1 << 7)
                state.rflags.ZF = op1.value == 0
                state.rflags.PF = parity[op1.value & 0xff]

            elif data[0] == 0x25:
                # and rAX, imm16/32
                if rex_w:
                    raise NotImplementedError
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op_len += 5
                    op1 = state.eax
                    op2 = read_uint32(data[1:5])
                op1.value = op1.value & op2
                state.rflags.OF = False
                state.rflags.CF = False
                state.rflags.SF = op1.value & (1 << 7)
                state.rflags.ZF = op1.value == 0
                state.rflags.PF = parity[op1.value & 0xff]

            elif data[0] == 0x29:
                # sub r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op2 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            value = read_int32(memory.read(op1, 4))
                            msb = 31
                            pack = pack_int32
                        state.rflags.OF = value - op2.value < op1.min_signed
                        state.rflags.CF = value < op2.value
                        value = value - op2.value
                        memory.write(op1, pack(value))
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                        state.rflags.SF = value & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, "b")
                        state.rflags.OF = op1.value - op2.value < op1.min_signed
                        state.rflags.CF = op1 < op2
                        op1.value = op1.value - op2.value
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << 63)
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0x2a:
                # sub r8, r/m8
                op1 = translate_plus_r_b(o)
                if mod == 0b11:
                    op_len += 2
                    op2 = translate_plus_r_b(rm, "b")
                    state.rflags.OF = op1.value - op2.value < op1.min_signed
                    state.rflags.CF = op1 < op2
                    op1.value = op1.value - op2.value
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << 7)
                else:
                    raise NotImplementedError

            elif data[0] == 0x2c:
                # sub al, imm8
                op1 = state.al
                op_len += 2
                op2 = read_int8(data[1:2])
                state.rflags.OF = op1.value - op2 < op1.min_signed
                state.rflags.CF = op1 < op2
                op1.value = op1.value - op2
                state.rflags.ZF = op1.value == 0
                state.rflags.AF = False
                state.rflags.PF = parity[op1.value & 0xff]
                state.rflags.SF = op1.value & (1 << 7)

            elif data[0] == 0x2d:
                # sub rAX, imm16/32
                if rex_w:
                    op_len += 5
                    op1 = state.rax
                    op2 = read_int32(data[1:5])
                    state.rflags.OF = op1.value - op2 < op1.min_signed
                    state.rflags.CF = op1 < op2
                    op1.value = op1.value - sign_extend(op2, 32, 64)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << 63)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op_len += 5
                    op1 = state.rax
                    op2 = read_int32(data[1:5])
                    state.rflags.OF = op1.value - op2 < op1.min_signed
                    state.rflags.CF = op1 < op2
                    op1.value = op1.value - op2
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << 31)

            elif data[0] == 0x2b:
                # sub r16/32/64, r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    op1 = translate_plus_r_w(o)
                    msb = 15
                else:
                    op1 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = read_int32(memory.read(op2, 4))
                        state.rflags.OF = op1.value - op2 < op1.min_signed
                        state.rflags.CF = op1 < op2
                        op1.value = op1.value - op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])

                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = op2.value + read_int8(data[2:3])
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = read_int32(memory.read(op2, 4))
                    state.rflags.OF = op1.value - op2 < op1.min_signed
                    state.rflags.CF = op1 < op2
                    op1.value = op1.value - op2
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = op2.value + read_int32(data[2:6])
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                        else:
                            raise NotImplementedError
                        state.rflags.OF = op1.value - op2 < op1.min_signed
                        state.rflags.CF = op1 < op2
                        op1.value = op1.value - op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        op2 = translate_plus_r_w(rm, "b")
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                    state.rflags.OF = op1.value - op2.value < op1.min_signed
                    state.rflags.CF = op1 < op2
                    op1.value = op1.value - op2.value
                    state.rflags.ZF = op1.value == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[op1.value & 0xff]
                    state.rflags.SF = op1.value & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x31:
                # xor r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op2 = translate_plus_r_e(o)
                if mod == 0b01:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                        op1 = op1.value + read_int8(data[2:3])
                        if rex_w:
                            tmp = read_uint64(memory.read(op1, 8))
                            pack = pack_int64
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            tmp = read_uint32(memory.read(op1, 4))
                            pack = pack_int32
                            msb = 31
                        value = tmp ^ op2.value
                        memory.write(op1, pack(value))
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.PF = parity[value & 0xff]
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, rex="b")
                        msb = 63
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = translate_plus_r_e(rm, "b")
                        msb = 31
                    op1.value = op1.value ^ op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x32:
                # xor r8, r/m8
                op1 = translate_plus_r_b(o)
                if mod == 0b11:
                    op_len += 2
                    op2 = translate_plus_r_b(rm, "b")
                    op1.value = op1.value ^ op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << 7)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                else:
                    raise NotImplementedError

            elif data[0] == 0x33:
                # xor r16/32/64, r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    op1 = translate_plus_r_w(o)
                    msb = 15
                else:
                    op1 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = state.rip.value
                        if rex_w:
                            op2 = read_int64(memory.read(op2 + read_int32(data[2:6]) + op_len, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = read_int32(memory.read(op2, 4))
                    op1.value = op1.value ^ op2
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]
                elif mod == 0b01:
                    if rm == 0b100:
                        # sib
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                        if rex_w:
                            op1.value = op1.value ^ read_int64(memory.read(op2, 8))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = op1.value ^ read_int32(memory.read(op2, 4))
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                        if rex_w:
                            op2 = read_int64(memory.read(op2, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = read_int32(memory.read(op2, 4))
                        op1.value = op1.value ^ op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2]) + read_int32(data[3:7])
                        if rex_w:
                            op1.value = op1.value ^ read_int64(memory.read(op2, 8))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = op1.value ^ read_int32(memory.read(op2, 4))
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        op_len += 6
                        if addr_size_override:
                            op2 = translate_plus_r_e(rm, "b")
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = op2 + read_int32(data[2:6])
                        if rex_w:
                            op1.value = op1.value ^ read_int64(memory.read(op2, 8))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = op1.value ^ read_int32(memory.read(op2, 4))
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        op2 = translate_plus_r_w(rm, "b")
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                    op1.value = op1.value ^ op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.SF = op1.value & (1 << msb)
                    state.rflags.ZF = op1.value == 0
                    state.rflags.PF = parity[op1.value & 0xff]

            elif data[0] == 0x34:
                # xor al, imm8
                op_len += 2
                op1 = state.al
                op2 = read_int8(data[1:2])
                op1.value = op1.value ^ op2
                state.rflags.OF = False
                state.rflags.CF = False
                state.rflags.SF = op1.value & (1 << 7)
                state.rflags.ZF = op1.value == 0
                state.rflags.PF = parity[op1.value & 0xff]

            elif data[0] == 0x38:
                # cmp r/m8, r8
                op2 = translate_plus_r_b(o).value
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op1 = op_sib(data[2])
                    elif rm == 0b101:
                        op_len += 6
                        op1 = state.rip.value + read_int32(data[2:6]) + op_len
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                    op1 = read_int8(memory.read(op1, 1))
                    tmp = op1 - op2
                    state.rflags.OF = op1 - op2 < Int8.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2
                    state.rflags.SF = tmp & (1 << 7)
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op1 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                    op1 = read_int8(memory.read(op1, 1))
                    tmp = op1 - op2
                    state.rflags.OF = op1 - op2 < Int8.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2
                    state.rflags.SF = tmp & (1 << 7)
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op1 = op_sib(data[2]) + read_int32(data[3:7])
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                    op1 = read_int8(memory.read(op1, 1))
                    tmp = op1 - op2
                    state.rflags.OF = op1 - op2 < Int8.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2
                    state.rflags.SF = tmp & (1 << 7)
                else:
                    raise NotImplementedError

            elif data[0] == 0x39:
                # cmp r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                elif op_size_override:
                    op2 = translate_plus_r_w(o)
                else:
                    op2 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op1 = op_sib(data[2])
                    elif rm == 0b101:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = state.rip.value + read_int32(data[2:6]) + op_len
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                    if rex_w:
                        op1 = read_int64(memory.read(op1, 8))
                        msb = 63
                    elif op_size_override:
                        op1 = read_int16(memory.read(op1, 2))
                        msb = 15
                    else:
                        op1 = read_int32(memory.read(op1, 4))
                        msb = 31
                    tmp = op1 - op2.value
                    state.rflags.OF = op1 - op2.value < op2.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2.value
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            op1 = read_int16(memory.read(op_sib(data[2]) + read_int8(data[3:4]), 2))
                            msb = 15
                        else:
                            op1 = read_int32(memory.read(op_sib(data[2]) + read_int8(data[3:4]), 4))
                            msb = 31
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                        if rex_w:
                            op1 = read_uint64(memory.read(op1, 8))
                            msb = 63
                        elif op_size_override:
                            op1 = read_uint16(memory.read(op1, 2))
                            msb = 15
                        else:
                            op1 = read_uint32(memory.read(op1, 4))
                            msb = 31
                    tmp = op1 - op2.value
                    state.rflags.OF = op1 - op2.value < op2.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2.value
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op1 = op_sib(data[2]) + read_int32(data[3:7])
                        if rex_w:
                            op1 = read_int64(memory.read(op1, 8))
                            msb = 63
                        elif op_size_override:
                            op1 = read_int16(memory.read(op1, 2))
                            msb = 15
                        else:
                            op1 = read_int32(memory.read(op1, 4))
                            msb = 31
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                        if rex_w:
                            op1 = read_int64(memory.read(op1, 8))
                            msb = 63
                        elif op_size_override:
                            op1 = read_int16(memory.read(op1, 2))
                            msb = 15
                        else:
                            op1 = read_int32(memory.read(op1, 4))
                            msb = 31
                    tmp = op1 - op2.value
                    state.rflags.OF = op1 - op2.value < op2.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2.value
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, rex="b")
                        msb = 63
                    else:
                        raise NotImplementedError
                    tmp = op1.value - op2.value
                    state.rflags.OF = op1.value - op2.value < op1.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2
                    state.rflags.SF = tmp & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x3a:
                # cmp r8, r/m8
                op1 = translate_plus_r_b(o).value
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int8(memory.read(op1, 1))
                    tmp = op1 - op2
                elif mod == 0b01:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                        op2 = read_int8(memory.read(op1, 1))
                    tmp = op1 - op2
                elif mod == 0b11:
                    op_len += 2
                    op2 = translate_plus_r_b(rm, "b").value
                    tmp = op1 - op2
                else:
                    raise NotImplementedError
                state.rflags.OF = op1 - op2 < Int8.min_signed
                state.rflags.ZF = tmp == 0
                state.rflags.AF = False
                state.rflags.PF = parity[tmp & 0xff]
                state.rflags.CF = op1 < op2
                state.rflags.SF = tmp & (1 << 7)

            elif data[0] == 0x3b:
                # cmp r16/32/64 r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                    msb = 63
                elif op_size_override:
                    op1 = translate_plus_r_w(o)
                    msb = 15
                else:
                    op1 = translate_plus_r_e(o)
                    msb = 31
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        op_len += 6
                        op2 = state.rip.value + op_len + read_int32(data[2:6])
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = read_int32(memory.read(op2, 4))
                    tmp = op1 - op2
                    state.rflags.OF = op1.value - op2 < op1.min_signed
                    state.rflags.CF = op1 < op2
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op2 = read_int32(memory.read(op2, 4))
                    tmp = op1 - op2
                    state.rflags.OF = op1.value - op2 < op1.min_signed
                    state.rflags.CF = op1 < op2
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2]) + read_int32(data[3:7])
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                    if rex_w:
                        op2 = read_int64(memory.read(op2, 8))
                    else:
                        raise NotImplementedError
                    tmp = op1 - op2
                    state.rflags.OF = op1.value - op2 < op1.min_signed
                    state.rflags.CF = op1 < op2
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        op2 = translate_plus_r_w(rm, "b")
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                    tmp = op1 - op2
                    state.rflags.OF = op1.value - op2.value < op1.min_signed
                    state.rflags.CF = op1 < op2
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x3c:
                # cmp al, imm8
                op_len += 2
                op1 = state.al
                op2 = read_int8(data[1:2])
                tmp = op1 - op2
                state.rflags.OF = op1.value - op2 < op1.min_signed
                state.rflags.ZF = tmp == 0
                state.rflags.AF = False
                state.rflags.PF = parity[tmp & 0xff]
                state.rflags.CF = op1 < op2
                state.rflags.SF = tmp & (1 << 63)

            elif data[0] == 0x3d:
                # cmp rAX, imm16/32
                if rex_w:
                    op_len += 5
                    op1 = state.rax
                    op2 = read_int32(data[1:5])
                elif op_size_override:
                    op_len += 3
                    op1 = state.ax
                    op2 = read_int16(data[1:3])
                else:
                    op_len += 5
                    op1 = state.eax
                    op2 = read_int32(data[1:5])
                tmp = op1 - op2
                state.rflags.OF = op1.value - op2 < op1.__class__.min_signed
                state.rflags.ZF = tmp == 0
                state.rflags.AF = False
                state.rflags.PF = parity[tmp & 0xff]
                state.rflags.CF = op1 < op2
                state.rflags.SF = tmp & (1 << 63)

            elif data[0] == 0x63:
                # movsxd r32/64, r/m32
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op2 = op_sib(data[2])
                        op2 = read_int32(memory.read(op2, 4))
                    elif rm == 0b101:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = state.rip + op_len + read_int32(data[2:6])
                        op2 = read_int32(memory.read(op2, 4))
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int32(memory.read(op2, 4))
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = read_int32(memory.read(op_sib(data[2]) + read_int8(data[3:4]), 4))
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int32(memory.read(op2 + read_int8(data[2:3]), 4))
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2])
                        op2 = read_int32(memory.read(op2 + read_int32(data[3:7]), 4))
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int32(memory.read(op2 + read_int32(data[2:6]), 4))
                elif mod == 0b11:
                    op_len += 2
                    op2 = translate_plus_r_e(rm, "b").value
                else:
                    raise NotImplementedError
                if rex_w:
                    op1 = translate_plus_r(o)
                    op1.value = sign_extend(op2, 32, 64)
                else:
                    raise NotImplementedError

            elif data[0] == 0x66:
                # nop pattern
                pass

            elif data[0] == 0x69:
                # imul r16/32/64, r/m16/32/64, imm16/32
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op1 = translate_plus_r_e(o)
                if mod == 0b11:
                    if rex_w:
                        op_len += 6
                        op2 = translate_plus_r(rm, "b")
                        op3 = read_int32(data[2:6])
                        size = 64
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op_len += 6
                        op2 = translate_plus_r_e(rm, "b")
                        op3 = read_int32(data[2:6])
                        size = 32
                    tmp = op2.value * op3
                    if sign_extend(tmp, size, size) != tmp:
                        state.rflags.CF = True
                        state.rflags.OF = True
                    else:
                        state.rflags.CF = False
                        state.rflags.OF = False
                    op1.value = tmp
                else:
                    raise NotImplementedError

            elif data[0] == 0x6a:
                # push imm8
                op_len += 2
                state.rsp -= 8
                memory.write(state.rsp, pack_int64(sign_extend(read_int8(data[1:2]), 8, 64)))

            elif data[0] == 0x6b:
                # imul r16/32/64, r/m16/32/64, imm8
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op1 = translate_plus_r_e(o)
                if mod == 0b11:
                    if rex_w:
                        op_len += 3
                        op2 = translate_plus_r(rm, "b")
                        size = 64
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op_len += 3
                        op2 = translate_plus_r_e(rm, "b")
                        size = 32
                    op3 = sign_extend(read_int8(data[2:3]), 8, 32)
                    tmp = op2.value * op3
                    if sign_extend(tmp, size, size) != tmp:
                        state.rflags.CF = True
                        state.rflags.OF = True
                    else:
                        state.rflags.CF = False
                        state.rflags.OF = False
                    op1.value = tmp
                else:
                    raise NotImplementedError

            elif data[0] == 0x72:
                # jc rel8
                op_len += 2
                if state.rflags.CF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x73:
                # jnc rel8
                op_len += 2
                if not state.rflags.CF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x74:
                # jz rel8
                op_len += 2
                if state.rflags.ZF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x75:
                # jnz rel8
                op_len += 2
                if not state.rflags.ZF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x76:
                # jbe rel8
                op_len += 2
                if state.rflags.CF or state.rflags.ZF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x77:
                # ja rel8
                op_len += 2
                if not state.rflags.CF and not state.rflags.ZF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x78:
                # js rel8
                op_len += 2
                if state.rflags.SF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x79:
                # jns rel8
                op_len += 2
                if not state.rflags.SF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x7b:
                # jnp rel8
                op_len += 2
                if not state.rflags.PF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x7c:
                # jl rel8
                op_len += 2
                if state.rflags.SF != state.rflags.OF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x7d:
                # jge rel8
                op_len += 2
                if state.rflags.SF == state.rflags.OF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x7e:
                # jle rel8
                op_len += 2
                if state.rflags.ZF or state.rflags.SF != state.rflags.OF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x7f:
                # jg rel8
                op_len += 2
                if not state.rflags.ZF and state.rflags.SF == state.rflags.OF:
                    state.rip += read_int8(data[1:2])

            elif data[0] == 0x80:
                if o == 0:
                    # add r/m8, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int8(memory.read(translate_plus_r(rm, "b"), 1))
                            op2 = read_int8(data[2:3])
                        raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 3
                        op1 = translate_plus_r_b(rm, "b")
                        op2 = read_int8(data[2:3])
                        state.rflags.OF = op1.value + op2 > op1.max_signed
                        state.rflags.CF = op1.value + op2 > op1.max
                        op1.value = op1.value + op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << 7)
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # or r/m8, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op2 = data[2]
                            value = read_int8(memory.read(op1, 1))
                            value = value | op2
                            memory.write(op1, pack_uint8(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << 7)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = op_sib(data[2]) + read_int8(data[3:4])
                            op2 = data[4]
                            value = read_uint8(memory.read(op1, 1))
                            value = value | op2
                            memory.write(op1, pack_uint8(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << 7)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            op2 = data[3]
                            value = read_int8(memory.read(op1, 1))
                            value = value | op2
                            memory.write(op1, pack_uint8(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << 7)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        op_len += 3
                        op2 = data[2]
                        op1 = translate_plus_r(rm, "b")
                        op1.value = op1.value | op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << 7)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 4:
                    # and r/m8, imm8
                    if mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            op2 = data[3]
                            value = read_int8(memory.read(op1, 1))
                            value = value & op2
                            memory.write(op1, pack_int8(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << 7)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]

                    elif mod == 0b11:
                        op_len += 3
                        op2 = data[2]
                        op1 = translate_plus_r(rm, "b")
                        op1.value = op1.value & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << 7)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # cmp r/m8, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op1 = op_sib(data[2])
                            op2 = read_int8(data[3:4])
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int8(memory.read(state.rip.value + read_int32(data[2:6]) + op_len, 1))
                            op2 = read_int8(data[6:7])
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int8(memory.read(translate_plus_r(rm, "b"), 1))
                            op2 = read_int8(data[2:3])
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                            op2 = read_int8(data[4:5])
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int8(memory.read(translate_plus_r(rm, "b") + read_int8(data[2:3]), 1))
                            op2 = read_int8(data[3:4])
                    elif mod == 0b10:
                        if rm == 0b100:
                            op_len += 8
                            op1 = op_sib(data[2]) + read_int32(data[3:7])
                            op2 = read_int8(data[7:8])
                        else:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int8(memory.read(translate_plus_r(rm, "b") + read_int32(data[2:6]), 1))
                            op2 = read_int8(data[6:7])
                    elif mod == 0b11:
                        op_len += 3
                        op1 = translate_plus_r_b(rm, "b").value
                        op2 = read_int8(data[2:3])
                    else:
                        raise NotImplementedError
                    tmp = op1 - op2
                    state.rflags.OF = op1 - op2 < Int8.min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2
                    state.rflags.SF = tmp & (1 << 7)
                else:
                    raise NotImplementedError

            elif data[0] == 0x81:
                if o == 0:
                    # add r/m16/32/64, imm16/32
                    if mod == 0b11:
                        if rex_w:
                            op_len += 6
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(read_int32(data[2:6]), 32, 64)
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op_len += 6
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_int32(data[2:6])
                            msb = 31
                        state.rflags.OF = op1.value + op2 > op1.max_signed
                        state.rflags.CF = op1.value + op2 > op1.max
                        op1.value += op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # or r/m16/32/64, imm16/32
                    if mod == 0b00:
                        if rm == 0b100:
                            op1 = op_sib(data[2])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op_len += 7
                                value = read_int32(memory.read(op1, 4))
                                op2 = read_int32(data[3:7])
                                pack = pack_int32
                                msb = 31
                            value = value | op2
                            memory.write(op1, pack(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            raise NotImplementedError
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b").value + read_int8(data[2:3])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op_len += 7
                                value = read_int32(memory.read(op1, 4))
                                op2 = read_int32(data[3:7])
                                pack = pack_int32
                                msb = 31
                            value = value | op2
                            memory.write(op1, pack(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        if rex_w:
                            op_len += 6
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(read_int32(data[2:6]), 32, 64)
                            msb = 63
                        elif op_size_override:
                            op_len += 4
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = read_int16(data[2:4])
                            msb = 15
                        else:
                            op_len += 6
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_int32(data[2:6])
                            msb = 31
                        op1.value = op1.value | op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 4:
                    # and r/m16/32/64, imm16/32
                    if mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            if rex_w:
                                op_len += 7
                                value = read_int64(memory.read(op1, 8))
                                op2 = sign_extend(read_int32(data[3:7]), 32, 64)
                                pack = pack_int64
                                msb = 63
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op_len += 7
                                value = read_int32(memory.read(op1, 4))
                                op2 = read_int32(data[3:7])
                                pack = pack_int32
                                msb = 31
                            value = value & op2
                            memory.write(op1, pack(value))
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        if rex_w:
                            op_len += 6
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(read_int32(data[2:6]), 32, 64)
                            msb = 63
                        elif op_size_override:
                            op_len += 4
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = read_int16(data[2:4])
                            msb = 15
                        else:
                            op_len += 6
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_int32(data[2:6])
                            msb = 31
                        op1.value = op1.value & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # sub r/m16/32/64, imm16/32
                    if mod == 0b11:
                        if rex_w:
                            op_len += 6
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(read_int32(data[2:6]), 32, 64)
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op_len += 6
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_int32(data[2:6])
                            msb = 31
                        state.rflags.OF = op1.value - op2 < op1.min_signed
                        state.rflags.ZF = op1 == op2
                        state.rflags.AF = False
                        state.rflags.PF = parity[(op1 - op2) & 0xff]
                        state.rflags.CF = op1 < op2
                        state.rflags.SF = (op1 - op2) & (1 << msb)
                        op1.value = op1.value - op2
                    else:
                        raise NotImplementedError
                elif o == 6:
                    # xor r/m16/32/64, imm16/32
                    if mod == 0b11:
                        if rex_w:
                            op_len += 6
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(read_int32(data[2:6]), 32, 64)
                            msb = 63
                        elif op_size_override:
                            op_len += 4
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = read_int16(data[2:4])
                            msb = 15
                        else:
                            op_len += 6
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_int32(data[2:6])
                            msb = 31
                        op1.value = op1.value ^ op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.ZF = op1.value
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # cmp r/m16/32/64, imm16/32
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip.value
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                op_len += 8
                                op1 = read_int16(memory.read(op1 + op_len + read_int32(data[2:6]), 2))
                                op2 = read_int16(data[6:8])
                                min_signed = Int16.min_signed
                                msb = 15
                            else:
                                raise NotImplementedError
                        else:
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                op_len += 4
                                op1 = read_int16(memory.read(translate_plus_r(rm, "b"), 2))
                                op2 = read_int16(data[2:4])
                                min_signed = Int16.min_signed
                                msb = 15
                            else:
                                op_len += 6
                                op1 = read_int32(memory.read(translate_plus_r(rm, "b"), 4))
                                op2 = read_int32(data[2:6])
                                min_signed = Int32.min_signed
                                msb = 31
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                op_len += 5
                                op1 = read_int16(memory.read(op1 + read_int8(data[2:3]), 2))
                                op2 = read_int16(data[3:5])
                                min_signed = Int16.min_signed
                                msb = 15
                            else:
                                op_len += 7
                                op1 = read_int32(memory.read(op1 + read_int8(data[2:3]), 4))
                                op2 = read_int32(data[3:7])
                                min_signed = Int32.min_signed
                                msb = 31
                    elif mod == 0b11:
                        op_len += 6
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(read_int32(data[2:6]), 32, 64)
                            min_signed = op1.min_signed
                            msb = 63
                        elif op_size_override:
                            op_len -= 2
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = read_int16(data[2:4])
                            min_signed = op1.min_signed
                            msb = 15
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_int32(data[2:6])
                            min_signed = op1.min_signed
                            msb = 31
                    else:
                        raise NotImplementedError
                    tmp = op1 - op2
                    state.rflags.OF = op1 - op2 < min_signed
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.CF = op1 < op2
                    state.rflags.SF = tmp & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x83:
                if o == 0:
                    # add r/m16/32/64, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            op2 = data[2]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                                op2 = sign_extend(op2, 8, 64)
                                msb = 63
                                max_signed = Int64.max_signed
                                _max = Int64.max
                                pack = pack_int64
                            elif op_size_override:
                                value = read_int16(memory.read(op1, 2))
                                op2 = sign_extend(op2, 8, 16)
                                msb = 15
                                max_signed = Int16.max_signed
                                _max = Int16.max
                                pack = pack_int16
                            else:
                                value = read_int32(memory.read(op1, 4))
                                op2 = sign_extend(op2, 8, 32)
                                msb = 31
                                max_signed = Int32.max_signed
                                _max = Int32.max
                                pack = pack_int32
                            state.rflags.OF = value + op2 > max_signed
                            state.rflags.ZF = value + op2 == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[(value + op2) & 0xff]
                            state.rflags.CF = value + op2 > _max
                            state.rflags.SF = (value + op2) & (1 << msb)
                            value += op2
                            memory.write(op1, pack(value))
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = data[4]
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                        else:
                            op_len += 4
                            op2 = data[3]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                        if rex_w:
                            value = read_int64(memory.read(op1, 8))
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                            max_signed = Int64.max_signed
                            _max = Int64.max
                            pack = pack_int64
                        elif op_size_override:
                            value = read_int16(memory.read(op1, 2))
                            op2 = sign_extend(op2, 8, 16)
                            msb = 15
                            max_signed = Int16.max_signed
                            _max = Int16.max
                            pack = pack_int16
                        else:
                            value = read_int32(memory.read(op1, 4))
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                            max_signed = Int32.max_signed
                            _max = Int32.max
                            pack = pack_int32
                        state.rflags.OF = value + op2 > max_signed
                        state.rflags.ZF = value + op2 == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[(value + op2) & 0xff]
                        state.rflags.CF = value + op2 > _max
                        state.rflags.SF = (value + op2) & (1 << msb)
                        value += op2
                        memory.write(op1, pack(value & _max))
                    elif mod == 0b11:
                        op_len += 3
                        op2 = data[2]
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                        elif op_size_override:
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = sign_extend(op2, 8, 16)
                            msb = 15
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                        state.rflags.OF = op1.value + op2 > op1.__class__.max_signed
                        state.rflags.ZF = op1 + op2 == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[(op1 + op2) & 0xff]
                        state.rflags.CF = op1.value + op2 > op1.__class__.max
                        state.rflags.SF = (op1 + op2) & (1 << msb)
                        op1.value += op2
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # or r/m16/32/64, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            op2 = data[2]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                                value = value | sign_extend(op2, 8, 64)
                                memory.write(op1, pack_uint64(value))
                                msb = 63
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                value = value | sign_extend(op2, 8, 32)
                                memory.write(op1, pack_uint32(value))
                                msb = 31
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = data[4]
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                        else:
                            op_len += 4
                            op2 = data[3]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 += read_int8(data[2:3])
                        if rex_w:
                            value = read_uint64(memory.read(op1, 8))
                            value = value | sign_extend(op2, 8, 64)
                            memory.write(op1, pack_uint64(value))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_uint32(memory.read(op1, 4))
                            value = value | sign_extend(op2, 8, 32)
                            memory.write(op1, pack_uint32(value))
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 7
                            op2 = data[6]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 += read_int32(data[2:6])
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                                value = value | sign_extend(op2, 8, 64)
                                memory.write(op1, pack_int64(value))
                                msb = 63
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                value = value | sign_extend(op2, 8, 32)
                                memory.write(op1, pack_int32(value))
                                msb = 31
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        op_len += 3
                        op2 = data[2]
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            op1.value = op1.value | sign_extend(op2, 8, 64)
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            op1.value = op1.value | sign_extend(op2, 8, 32)
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 4:
                    # and r/m16/32/64, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op2 = data[3]
                            op1 = op_sib(data[2])
                        elif rm == 0b101:
                            op_len += 7
                            op2 = data[6]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip.value + read_int32(data[2:6]) + op_len
                        else:
                            op_len += 3
                            op2 = data[2]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                        if rex_w:
                            value = read_int64(memory.read(op1, 8))
                            value = value & sign_extend(op2, 8, 64)
                            memory.write(op1, pack_int64(value))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_int32(memory.read(op1, 4))
                            value = value & sign_extend(op2, 8, 32)
                            memory.write(op1, pack_int32(value))
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = data[4]
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                        else:
                            op_len += 4
                            op2 = data[3]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                        if rex_w:
                            value = read_int64(memory.read(op1, 8))
                            value = value & sign_extend(op2, 8, 64)
                            memory.write(op1, pack_int64(value))
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            value = read_int32(memory.read(op1, 4))
                            value = value & sign_extend(op2, 8, 32)
                            memory.write(op1, pack_int32(value))
                            msb = 31
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 7
                            op2 = data[6]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                                value = value & sign_extend(op2, 8, 64)
                                memory.write(op1, pack_int64(value))
                                msb = 63
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                value = value & sign_extend(op2, 8, 32)
                                memory.write(op1, pack_int32(value))
                                msb = 31
                            state.rflags.OF = False
                            state.rflags.CF = False
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        op_len += 3
                        op2 = data[2]
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                        elif op_size_override:
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = sign_extend(op2, 8, 16)
                            msb = 15
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                        op1.value = op1.value & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # sub r/m16/32/64, imm8
                    op2 = data[2]
                    if mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                        else:
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                        state.rflags.OF = op1.value - op2 < op1.min_signed
                        state.rflags.CF = op1 < op2
                        op1.value -= op2
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                        state.rflags.SF = op1.value & (1 << msb)
                    else:
                        raise NotImplementedError
                elif o == 6:
                    # xor r/m16/32/64, imm8
                    if mod == 0b11:
                        op_len += 3
                        op2 = data[2]
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                        op1.value = op1.value ^ op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.SF = op1.value & (1 << 7)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # cmp r/m16/32/64, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op1 = op_sib(data[2])
                            if rex_w:
                                op1 = read_int64(memory.read(op1, 8))
                                op2 = sign_extend(data[3], 8, 64)
                                msb = 63
                                min_signed = Int64.min_signed
                            elif op_size_override:
                                op1 = read_int16(memory.read(op1, 2))
                                op2 = sign_extend(data[3], 8, 16)
                                msb = 15
                                min_signed = Int16.min_signed
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = sign_extend(data[3], 8, 32)
                                msb = 31
                                min_signed = Int32.min_signed
                            tmp = op1 - op2
                            state.rflags.ZF = tmp == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[tmp & 0xff]
                            state.rflags.CF = op1 < op2
                            state.rflags.SF = tmp & (1 << msb)
                            state.rflags.OF = op1 - op2 < min_signed
                        elif rm == 0b101:
                            op_len += 7
                            op2 = read_int8(data[6:7])
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip + read_int32(data[2:6]) + op_len
                            if rex_w:
                                op1 = read_uint64(memory.read(op1, 8))
                                op2 = sign_extend(op2, 8, 64)
                                msb = 63
                                min_signed = Int32.min_signed
                            elif op_size_override:
                                op1 = read_int16(memory.read(op1, 2))
                                op2 = sign_extend(op2, 8, 16)
                                msb = 15
                                min_signed = Int32.min_signed
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = sign_extend(op2, 8, 32)
                                msb = 31
                                min_signed = Int32.min_signed
                            tmp = op1 - op2
                            state.rflags.ZF = tmp == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[tmp & 0xff]
                            state.rflags.CF = op1 < op2
                            state.rflags.SF = tmp & (1 << msb)
                            state.rflags.OF = op1 - op2 < min_signed
                        else:
                            op_len += 3
                            op2 = read_int8(data[2:3])
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                op1 = read_int64(memory.read(op1, 8))
                                op2 = sign_extend(op2, 8, 64)
                                msb = 63
                                min_signed = Int64.min_signed
                            elif op_size_override:
                                op1 = read_int16(memory.read(op1, 2))
                                op2 = sign_extend(op2, 8, 16)
                                msb = 15
                                min_signed = Int16.min_signed
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = sign_extend(op2, 8, 32)
                                msb = 31
                                min_signed = Int32.min_signed
                            tmp = op1 - op2
                            state.rflags.ZF = tmp == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[tmp & 0xff]
                            state.rflags.CF = op1 < op2
                            state.rflags.SF = tmp & (1 << msb)
                            state.rflags.OF = op1 - op2 < min_signed
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op2 = data[4]
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                        else:
                            op_len += 4
                            op2 = data[3]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                        if rex_w:
                            op1 = read_int64(memory.read(op1, 8))
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                            min_signed = Int64.min_signed
                        elif op_size_override:
                            op1 = read_int16(memory.read(op1, 2))
                            op2 = sign_extend(op2, 8, 16)
                            msb = 15
                            min_signed = Int16.min_signed
                        else:
                            op1 = read_int32(memory.read(op1, 4))
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                            min_signed = Int32.min_signed
                        tmp = op1 - op2
                        state.rflags.ZF = tmp == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[tmp & 0xff]
                        state.rflags.CF = op1 < op2
                        state.rflags.SF = tmp & (1 << msb)
                        state.rflags.OF = op1 - op2 < min_signed
                    elif mod == 0b10:
                        if rm == 0b100:
                            op_len += 8
                            op2 = data[7]
                            op1 = op_sib(data[2]) + read_int32(data[3:7])
                        else:
                            op_len += 7
                            op2 = data[7]
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                        if rex_w:
                            op1 = read_int64(memory.read(op1, 8))
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                            min_signed = Int64.min_signed
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = read_int32(memory.read(op1, 4))
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                            min_signed = Int32.min_signed
                        tmp = op1 - op2
                        state.rflags.ZF = tmp == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[tmp & 0xff]
                        state.rflags.CF = op1 < op2
                        state.rflags.SF = tmp & (1 << msb)
                        state.rflags.OF = op1 - op2 < min_signed
                    elif mod == 0b11:
                        op2 = data[2]
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            op2 = sign_extend(op2, 8, 64)
                            msb = 63
                        elif op_size_override:
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = sign_extend(op2, 8, 16)
                            msb = 15
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = sign_extend(op2, 8, 32)
                            msb = 31
                        tmp = op1.value - op2
                        state.rflags.OF = op1.value - op2 < op1.__class__.min_signed
                        state.rflags.ZF = tmp == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[tmp & 0xff]
                        state.rflags.CF = op1 < op2
                        state.rflags.SF = tmp & (1 << msb)
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0x84:
                # test r/m8, r8
                op2 = translate_plus_r_b(o)
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        op_len += 6
                        op1 = state.rip + read_int32(data[2:6]) + op_len
                        op1 = read_int8(memory.read(op1, 1))
                    else:
                        raise NotImplementedError
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op1 = op_sib(data[2]) + read_int8(data[3:4])
                        op1 = read_int8(memory.read(op1, 1))
                    else:
                        raise NotImplementedError
                elif mod == 0b11:
                    op_len += 2
                    op1 = translate_plus_r_b(rm, "b").value
                else:
                    raise NotImplementedError
                tmp = op2.value & op1
                state.rflags.OF = False
                state.rflags.CF = False
                state.rflags.ZF = tmp == 0
                state.rflags.PF = parity[tmp]
                state.rflags.SF = tmp & (1 << 7)

            elif data[0] == 0x85:
                # test r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                elif op_size_override:
                    op2 = translate_plus_r_w(o)
                else:
                    op2 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        raise NotImplementedError
                    elif rm == 0b101:
                        op_len += 6
                        op1 = state.rip + read_int32(data[2:6])
                    else:
                        raise NotImplementedError
                    if rex_w:
                        op1 = read_int64(memory.read(op1, 8))
                        msb = 63
                    elif op_size_override:
                        op1 = read_int16(memory.read(op1, 2))
                        msb = 15
                    else:
                        op1 = read_int32(memory.read(op1, 4))
                        msb = 31
                    tmp = op1 & op2.value
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.ZF = tmp == 0
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b10:
                    if rm == 0b100:
                        raise NotImplementedError
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                        if rex_w:
                            op1 = read_int64(memory.read(op1, 8))
                            msb = 63
                        elif op_size_override:
                            op1 = read_int16(memory.read(op1, 2))
                            msb = 15
                        else:
                            op1 = read_int32(memory.read(op1, 4))
                            msb = 31
                        tmp = op1 & op2.value
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.ZF = tmp == 0
                        state.rflags.PF = parity[tmp & 0xff]
                        state.rflags.SF = tmp & (1 << msb)
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, "b")
                        msb = 63
                    elif op_size_override:
                        op1 = translate_plus_r_w(rm, "b")
                        msb = 15
                    else:
                        op1 = translate_plus_r_e(rm, "b")
                        msb = 31
                    tmp = op1 & op2
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.ZF = tmp == 0
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                else:
                    raise NotImplementedError

            elif data[0] == 0x87:
                # xchg r16/32/64, r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op1 = translate_plus_r_w(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op2 = op_sib(data[2])
                    elif rm == 0b101:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = state.rip + read_int32(data[2:6]) + op_len
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                    if rex_w:
                        tmp = op1.value
                        op1.value = read_int64(memory.read(op2, 8))
                        memory.write(op2, pack_int64(tmp))
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        tmp = op1.value
                        op1.value = read_int32(memory.read(op2, 4))
                        memory.write(op2, pack_uint32(tmp))
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 += read_int8(data[2:3])
                    if rex_w:
                        tmp = op1.value
                        op1.value = read_int64(memory.read(op2, 8))
                        memory.write(op2, pack_int64(tmp))
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        tmp = op1.value
                        op1.value = read_int32(memory.read(op2, 4))
                        memory.write(op2, pack_int32(tmp))
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2]) + read_int32(data[3:7])
                    else:
                        raise NotImplementedError
                    if rex_w:
                        tmp = op1.value
                        op1.value = read_int64(memory.read(op2, 8))
                        memory.write(op2, pack_int64(tmp))
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0x88:
                # mov r/m8, r8
                op2 = translate_plus_r_b(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op1 = op_sib(data[2])
                    elif rm == 0b101:
                        op_len += 6
                        op1 = state.rip.value + read_int32(data[2:6])
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                    memory.write(op1, pack_uint8(op2.value))
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op1 = op_sib(data[2])
                        memory.write(op1 + read_int8(data[3:4]), pack_uint8(op2.value))
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                        memory.write(op1 + read_int8(data[2:3]), pack_uint8(op2.value))
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op1 = op_sib(data[2])
                        memory.write(op1 + read_int32(data[3:7]), pack_uint8(op2.value))
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                        memory.write(op1 + read_int32(data[2:6]), pack_uint8(op2.value))
                elif mod == 0b11:
                    op_len += 2
                    op1 = translate_plus_r_b(rm, "b")
                    op1.value = op2.value
                else:
                    raise NotImplementedError

            elif data[0] == 0x89:
                # mov r/m16/32/64, r16/32/64
                if rex_w:
                    op2 = translate_plus_r(o)
                elif op_size_override:
                    op2 = translate_plus_r_w(o)
                else:
                    op2 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op1 = op_sib(data[2])
                        if rex_w:
                            memory.write(op1, pack_uint64(op2.value))
                        elif op_size_override:
                            memory.write(op1, pack_uint16(op2.value))
                        else:
                            memory.write(op1, pack_uint32(op2.value))
                    elif rm == 0b101:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = state.rip + op_len
                        if rex_w:
                            memory.write(op1 + read_int32(data[2:6]), pack_uint64(op2.value))
                        elif op_size_override:
                            memory.write(op1 + read_int32(data[2:6]), pack_uint16(op2.value))
                        else:
                            memory.write(op1 + read_int32(data[2:6]), pack_uint32(op2.value))
                    else:
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op_len += 2
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                memory.write(op1, pack_uint64(op2))
                            elif op_size_override:
                                memory.write(op1, pack_uint16(op2))
                            else:
                                memory.write(op1, pack_uint32(op2))
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op1 = op_sib(data[2]) + read_int8(data[3:4])
                        if rex_w:
                            memory.write(op1, pack_uint64(op2.value))
                        elif op_size_override:
                            memory.write(op1, pack_uint16(op2.value))
                        else:
                            memory.write(op1, pack_uint32(op2.value))
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                        if rex_w:
                            memory.write(op1 + read_int8(data[2:3]), pack_uint64(op2.value))
                        elif op_size_override:
                            memory.write(op1 + read_int8(data[2:3]), pack_uint16(op2.value))
                        else:
                            memory.write(op1 + read_int8(data[2:3]), pack_uint32(op2.value))
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op1 = op_sib(data[2]) + read_int32(data[3:7])
                        if rex_w:
                            memory.write(op1, pack_int64(op2.value))
                        elif op_size_override:
                            memory.write(op1, pack_uint16(op2.value))
                        else:
                            memory.write(op1, pack_int32(op2.value))
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r(rm, "b")
                        if rex_w:
                            memory.write(op1 + read_int32(data[2:6]), pack_uint64(op2.value))
                        elif op_size_override:
                            memory.write(op1 + read_int32(data[2:6]), pack_uint16(op2.value))
                        else:
                            memory.write(op1 + read_int32(data[2:6]), pack_uint32(op2.value))
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op1 = translate_plus_r(rm, rex="b")
                    else:
                        op1 = translate_plus_r_e(rm, rex="b")
                    op1.value = op2.value
                else:
                    raise NotImplementedError

            elif data[0] == 0x8a:
                # mov r8, r/m8
                op1 = translate_plus_r_b(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op2 = op_sib(data[2])
                        op2 = read_int8(memory.read(op2, 1))
                    elif rm == 0b101:
                        raise NotImplementedError
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int8(memory.read(op2, 1))
                    op1.value = op2
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = read_int8(memory.read(op_sib(data[2]) + read_int8(data[3:4]), 1))
                        op1.value = op2
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int8(memory.read(op2 + read_int8(data[2:3]), 1))
                        op1.value = op2
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = read_int8(memory.read(op_sib(data[2]) + read_int32(data[3:7]), 1))
                        op1.value = op2
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        op2 = read_int8(memory.read(op2 + read_int32(data[2:6]), 1))
                        op1.value = op2
                elif mod == 0b11:
                    op_len += 2
                    op2 = translate_plus_r_b(rm, "b")
                    op1.value = op2.value
                else:
                    raise NotImplementedError

            elif data[0] == 0x8b:
                # mov r16/32/64, r/m16/32/64
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    op1 = translate_plus_r_w(o)
                else:
                    op1 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b101:
                        # op2 = m16/32/64
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = state.rip
                        if rex_w:
                            op1.value = read_int64(memory.read(op2 + read_int32(data[2:6]) + op_len, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = read_int32(memory.read(op2 + read_int32(data[2:6]) + op_len, 4))
                    elif rm == 0b100:
                        if gs:
                            op_len += 7
                            op2 = read_int32(data[3:7])
                            if rex_w:
                                op2 = read_int64(memory.read(op2, 8))
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                raise NotImplementedError
                            op1.value = op2
                        else:
                            op_len += 3
                            op2 = op_sib(data[2])
                            if rex_w:
                                op1.value = read_int64(memory.read(op2, 8))
                            elif op_size_override:
                                op1.value = read_int16(memory.read(op2, 2))
                            else:
                                op1.value = read_int32(memory.read(op2, 4))
                    else:
                        op_len += 2
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        if rex_w:
                            op1.value = read_int64(memory.read(op2, 8))
                        elif op_size_override:
                            op1.value = read_int16(memory.read(op2, 2))
                        else:
                            op1.value = read_int32(memory.read(op2, 4))
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                        if rex_w:
                            op1.value = read_int64(memory.read(op2, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = read_int32(memory.read(op2, 4))
                    else:
                        op_len += 3
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        if rex_w:
                            op1.value = read_int64(memory.read(op2 + read_int8(data[2:3]), 8))
                        elif op_size_override:
                            op1.value = read_int16(memory.read(op2 + read_int8(data[2:3]), 2))
                        else:
                            op1.value = read_int32(memory.read(op2 + read_int8(data[2:3]), 4))
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2]) + read_int32(data[3:7])
                        if rex_w:
                            op1.value = read_int64(memory.read(op2, 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = read_int32(memory.read(op2, 4))
                    else:
                        op_len += 6
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r(rm, "b")
                        if rex_w:
                            op1.value = read_int64(memory.read(op2 + read_int32(data[2:6]), 8))
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1.value = read_int32(memory.read(op2 + read_int32(data[2:6]), 4))
                elif mod == 0b11:
                    op_len += 2
                    if rex_w:
                        op2 = translate_plus_r(rm, "b")
                    elif op_size_override:
                        op2 = translate_plus_r_w(rm, "b")
                    else:
                        op2 = translate_plus_r_e(rm, "b")
                    op1.value = op2.value

            elif data[0] == 0x8d:
                # lea r16/32/64, m
                if rex_w:
                    op1 = translate_plus_r(o)
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op1 = translate_plus_r_e(o)
                if mod == 0b00:
                    if rm == 0b100:
                        op_len += 3
                        op2 = op_sib(data[2])
                    elif rm == 0b101:
                        op_len += 6
                        op2 = state.rip + read_int32(data[2:6]) + op_len
                    else:
                        raise NotImplementedError
                elif mod == 0b01:
                    if rm == 0b100:
                        op_len += 4
                        op2 = op_sib(data[2]) + read_int8(data[3:4])
                    else:
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            op2 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                elif mod == 0b10:
                    if rm == 0b100:
                        op_len += 7
                        op2 = op_sib(data[2]) + read_int32(data[3:7])
                    else:
                        if addr_size_override:
                            raise NotImplementedError
                        else:
                            op_len += 6
                            op2 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                else:
                    raise NotImplementedError
                op1.value = op2

            elif data[0] == 0x90:
                # nop
                op_len += 1
                pass

            elif data[0] == 0x98:
                # cbw/cwde/cdqe
                op_len += 1
                if rex_w:
                    state.rax.value = sign_extend(state.eax.value, 32, 64)
                else:
                    raise NotImplementedError

            elif data[0] == 0x99:
                # cwd/cdq/cqo
                op_len += 1
                if rex_w:
                    tmp = sign_extend(state.eax.value, 64, 128)
                    state.edx.value = (tmp & ((2 ** 64 - 1) << 64)) >> 64
                elif op_size_override:
                    raise NotImplementedError
                else:
                    tmp = sign_extend(state.eax.value, 32, 64)
                    state.edx.value = (tmp & ((2 ** 32 - 1) << 32)) >> 32

            elif data[0] == 0x9c:
                # pushfq
                op_len += 1
                state.rsp -= 8
                memory.write(state.rsp, pack_int64(state.rflags.value))

            elif data[0] == 0x9d:
                # popfq
                op_len += 1
                state.rflags.value = read_int64(memory.read(state.rsp, 8))
                state.rsp += 8

            elif data[0] == 0xa1:
                # mov rAX, moffs16/32/64
                if rex_w:
                    raise NotImplementedError
                elif op_size_override:
                    raise NotImplementedError
                else:
                    op_len += 5
                    op1 = state.eax
                    op2 = read_int32(memory.read(read_int32(data[1:5]), 4))
                    op1.value = op2

            elif data[0] == 0xa5:
                # movs m16/32/64, m16/32/64
                op_len += 1
                trace_rep = False
                if rex_w:
                    while not rep or state.rcx.value:
                        memory.write(state.rdi.value, pack_int64(state.rsi.value))
                        if rep:
                            state.rdi.value += 8
                            state.rsi.value += 8
                            state.rcx.value -= 1
                            if trace_rep:
                                self.inst_count += 1
                                if self.trace:
                                    self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                            else:
                                trace_rep = True
                        else:
                            break
                else:
                    raise NotImplementedError

            elif data[0] == 0xa8:
                # test AL, imm8
                op_len += 2
                op1 = state.al
                op2 = read_int8(data[1:2])
                tmp = op1 & op2
                state.rflags.OF = False
                state.rflags.CF = False
                state.rflags.ZF = tmp == 0
                state.rflags.PF = parity[tmp]
                state.rflags.SF = tmp & (1 << 7)

            elif data[0] == 0xa9:
                # test rAX, imm16/32
                if rex_w:
                    op_len += 5
                    op1 = state.rax
                    op2 = read_int32(data[1:5])
                    msb = 63
                elif op_size_override:
                    op_len += 3
                    op1 = state.ax
                    op2 = read_int16(data[1:3])
                    msb = 15
                else:
                    op_len += 5
                    op1 = state.eax
                    op2 = read_int32(data[1:5])
                    msb = 31
                tmp = op1 & op2
                state.rflags.OF = False
                state.rflags.CF = False
                state.rflags.ZF = tmp == 0
                state.rflags.PF = parity[tmp]
                state.rflags.SF = tmp & (1 << msb)

            elif data[0] == 0xab:
                # stos m16/32/64 rAX
                op_len += 1
                trace_rep = False
                if rex_w:
                    while not rep or state.rcx.value:
                        memory.write(state.rdi.value, pack_int64(state.rax.value))
                        if rep:
                            state.rdi.value += 8
                            state.rcx.value -= 1
                            if trace_rep:
                                self.inst_count += 1
                                if self.trace:
                                    self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                            else:
                                trace_rep = True
                        else:
                            break
                elif op_size_override:
                    while not rep or state.rcx.value:
                        memory.write(state.rdi.value, pack_int16(state.ax.value))
                        if rep:
                            state.rdi.value += 2
                            state.rcx.value -= 1
                            if trace_rep:
                                self.inst_count += 1
                                if self.trace:
                                    self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                            else:
                                trace_rep = True
                        else:
                            break
                else:
                    while not rep or state.rcx.value:
                        memory.write(state.rdi.value, pack_int32(state.eax.value))
                        if rep:
                            state.rdi.value += 4
                            state.rcx.value -= 1
                            if trace_rep:
                                self.inst_count += 1
                                if self.trace:
                                    self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                            else:
                                trace_rep = True
                        else:
                            break

            elif data[0] == 0xae:
                # scas m8, rAX
                op_len += 1
                trace_rep = False
                if addr_size_override:
                    raise NotImplementedError
                else:
                    src = state.rdi
                while not rep or state.rcx.value:
                    op = read_uint8(memory.read(src, 1))
                    tmp = state.al.value - op
                    state.rflags.OF = state.al.value - op < Int32.min_signed
                    state.rflags.CF = state.al.value < op
                    state.rflags.ZF = tmp == 0
                    state.rflags.AF = False
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << 31)
                    if rep:
                        state.rdi.value += 1
                        state.rcx.value -= 1
                        if trace_rep:
                            self.inst_count += 1
                            if self.trace:
                                self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                        else:
                            trace_rep = True
                    if repnz and state.rflags.ZF:
                        break
                    elif rep and not repnz and not state.rflags.ZF:
                        break

            elif data[0] == 0xaf:
                # scas m16/32/64 rAX
                op_len += 1
                trace_rep = False
                if addr_size_override:
                    raise NotImplementedError
                else:
                    src = state.rdi
                if rex_w:
                    raise NotImplementedError
                elif op_size_override:
                    while not rep or state.rcx.value:
                        op = read_uint16(memory.read(src, 2))
                        tmp = state.ax.value - op
                        state.rflags.OF = state.ax.value - op < Int16.min_signed
                        state.rflags.CF = state.ax.value < op
                        state.rflags.ZF = tmp == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[tmp & 0xff]
                        state.rflags.SF = tmp & (1 << 16)
                        if rep:
                            state.rdi.value += 2
                            state.rcx.value -= 1
                            if trace_rep:
                                self.inst_count += 1
                                if self.trace:
                                    self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                            else:
                                trace_rep = True
                        if repnz and state.rflags.ZF:
                            break
                        elif rep and not repnz and not state.rflags.ZF:
                            break
                else:
                    while not rep or state.rcx.value:
                        op = read_uint32(memory.read(src, 4))
                        tmp = state.eax.value - op
                        state.rflags.OF = state.eax.value - op < Int32.min_signed
                        state.rflags.CF = state.eax.value < op
                        state.rflags.ZF = tmp == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[tmp & 0xff]
                        state.rflags.SF = tmp & (1 << 31)
                        if rep:
                            state.rdi.value += 4
                            state.rcx.value -= 1
                            if trace_rep:
                                self.inst_count += 1
                                if self.trace:
                                    self.trace_file.write("%d\t%#x\n" % (self.inst_count, state.rip.value))
                            else:
                                trace_rep = True
                        if repnz and state.rflags.ZF:
                            break
                        elif rep and not repnz and not state.rflags.ZF:
                            break

            elif data[0] == 0xc0:
                if o == 0:
                    # rol r/m8, imm8
                    if mod == 0b11:
                        op_len += 3
                        op1 = translate_plus_r_b(rm, "b")
                        op2 = data[2]
                        value = op1.value
                        for _ in range(op2):
                            state.rflags.CF = (value & (1 << 7)) >> 7 == 1
                            value = (value << 1) | state.rflags.CF
                        state.rflags.OF = state.rflags.CF ^ bool(value & (1 << 7))
                        op1.value = value
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # ror r/m8, imm8
                    if mod == 0b11:
                        op_len += 3
                        op1 = translate_plus_r_b(rm, "b")
                        op2 = data[2]
                        value = op1.value
                        for _ in range(op2):
                            state.rflags.CF = value & 1 == 1
                            value = (value >> 1) | (state.rflags.CF << 7)
                        state.rflags.OF = bool(value & (1 << 7)) ^ bool(value & (1 << (7 - 1)))
                        op1.value = value
                    else:
                        raise NotImplementedError
                elif o == 2:
                    # rcl r/m8, imm8
                    if mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 = op1.value + read_int32(data[2:6])
                            op2 = data[6]
                            value = read_uint8(memory.read(op1, 1))
                            for _ in range(op2):
                                tmp = (value & (1 << 7)) >> 7 == 1
                                value = (value << 1) | state.rflags.CF
                                state.rflags.CF = tmp
                            state.rflags.OF = state.rflags.CF ^ bool(value & (1 << 7))
                            memory.write(op1, pack_int8(value))
                    elif mod == 0b11:
                        op_len += 3
                        op1 = translate_plus_r_b(rm, "b")
                        op2 = data[2]
                        value = op1.value
                        for _ in range(op2):
                            tmp = (value & (1 << 7)) >> 7 == 1
                            value = (value << 1) | state.rflags.CF
                            state.rflags.CF = tmp
                        state.rflags.OF = state.rflags.CF ^ bool(value & (1 << 7))
                        op1.value = value
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xc1:
                if o == 0:
                    # rol r/m16/32/64, imm8
                    if mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            bits = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            bits = 31
                        op2 = data[2]
                        value = op1.value
                        for _ in range(op2):
                            state.rflags.CF = (value & (1 << bits)) >> bits == 1
                            value = (value << 1) | state.rflags.CF
                        state.rflags.OF = state.rflags.CF ^ bool(value & (1 << bits))
                        op1.value = value
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # ror r/m16/32/64, imm8
                    if mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            bits = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            bits = 31
                        op2 = data[2]
                        value = op1.value
                        for _ in range(op2):
                            state.rflags.CF = value & 1 == 1
                            value = (value >> 1) | (state.rflags.CF << bits)
                        state.rflags.OF = bool(value & (1 << bits)) ^ bool(value & (1 << (bits - 1)))
                        op1.value = value
                    else:
                        raise NotImplementedError
                elif o == 4:
                    # shl r/m16/32/64, imm8
                    if mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            op1 = translate_plus_r_w(rm, "b")
                            msb = 15
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        if data[2] != 0:
                            op1.value = op1.value << (data[2] - 1)
                            state.rflags.CF = op1.value & (1 << msb) != 0
                            op1.value = op1.value << 1
                            if data[2] == 1:
                                raise NotImplementedError
                            state.rflags.SF = op1.value & (1 << msb)
                            state.rflags.ZF = op1.value == 0
                            state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # shr r/m16/32/64, imm8
                    if mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            op2 = read_int8(data[3:4])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                msb = 31
                                pack = pack_int32
                            if op2 != 0:
                                value = value >> (op2 - 1)
                                state.rflags.CF = value & 1 != 0
                                value = value >> 1
                                if op2 == 1:
                                    raise NotImplementedError
                                state.rflags.SF = value & (1 << msb)
                                state.rflags.ZF = value == 0
                                state.rflags.PF = parity[value & 0xff]
                                memory.write(op1, pack(value))

                    elif mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        if data[2] != 0:
                            op1.value = op1.value >> (data[2] - 1)
                            state.rflags.CF = op1.value & 1 != 0
                            op1.value = op1.value >> 1
                            if data[2] == 1:
                                raise NotImplementedError
                            state.rflags.SF = op1.value & (1 << msb)
                            state.rflags.ZF = op1.value == 0
                            state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # sar r/m16/32/64, imm8
                    if mod == 0b11:
                        op_len += 3
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        if data[2] != 0:
                            shift = data[2]
                            state.rflags.OF = op1.value & (1 << msb) != 0
                            while shift > 0:
                                state.rflags.CF = op1.value & 1 == 1
                                op1.value = op1.value >> 1
                                op1.value |= state.rflags.OF << msb
                                shift -= 1
                            state.rflags.SF = op1.value & (1 << msb)
                            state.rflags.ZF = op1.value == 0
                            state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xc2:
                # ret imm16
                op_len = 0
                state.rip.value = read_int64(memory.read(state.rsp, 8))
                state.rsp += 8 + read_int16(data[1:3])
                if self.exception:
                    if state.rip.value == 0xe8ce:
                        raise ExceptionReturn

            elif data[0] == 0xc3:
                # ret
                op_len = 0
                state.rip.value = read_int64(memory.read(state.rsp, 8))
                state.rsp += 8
                if self.exception:
                    if state.rip.value == 0xe8ce:
                        raise ExceptionReturn

            elif data[0] == 0xc6:
                if o == 0:
                    # mov r/m8, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len += 4
                            op1 = op_sib(data[2])
                            op2 = read_int8(data[3:4])
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip + read_int32(data[2:6]) + op_len
                            op2 = read_int8(data[6:7])
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op2 = read_int8(data[2:3])
                        memory.write(op1, pack_int8(op2))
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                            op2 = read_int8(data[4:5])
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            op2 = read_int8(data[3:4])
                        memory.write(op1, pack_int8(op2))
                    elif mod == 0b10:
                        if rm == 0b100:
                            op_len += 8
                            op1 = op_sib(data[2]) + read_int32(data[3:7])
                            op2 = read_int8(data[7:8])
                        else:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                            op2 = read_int8(data[6:7])
                        memory.write(op1, pack_int8(op2))
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xc7:
                if o == 0:
                    # mov r/m16/32/64, imm16/32
                    if mod == 0b00:
                        if rm == 0b100:
                            op1 = op_sib(data[2])
                            if rex_w:
                                op_len += 7
                                op2 = data[3:7]
                            elif op_size_override:
                                op_len += 5
                                op2 = data[3:5]
                            else:
                                op_len += 7
                                op2 = data[3:7]
                            memory.write(op1, op2)
                        elif rm == 0b101:
                            if rex_w:
                                op_len += 10
                                op2 = data[6:10]
                            elif op_size_override:
                                op_len += 8
                                op2 = data[6:8]
                            else:
                                op_len += 10
                                op2 = data[6:10]
                            op1 = state.rip + read_int32(data[2:6]) + op_len
                            if rex_w:
                                memory.write(op1, pack_int64(sign_extend(read_int32(op2), 32, 64)))
                            elif op_size_override:
                                memory.write(op1, op2)
                            else:
                                memory.write(op1, op2)
                        else:
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                op_len += 6
                                op2 = read_int32(data[2:6])
                                op2 = sign_extend(op2, 32, 64)
                                memory.write(op1, pack_uint64(op2))
                            elif op_size_override:
                                op_len += 4
                                op2 = data[2:4]
                                memory.write(op1, op2)
                            else:
                                op_len += 6
                                op2 = data[2:6]
                                memory.write(op1, op2)
                    elif mod == 0b01:
                        if rm == 0b100:
                            # sib
                            op_len += 4
                            op1 = op_sib(data[2]) + read_int8(data[3:4])
                            offset = 1
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 = op1 + read_int8(data[2:3])
                            offset = 0
                        if rex_w:
                            op_len += 4
                            value = read_int32(data[3 + offset:7 + offset])
                            memory.write(op1, pack_uint64(sign_extend(value, 32, 64)))
                        elif op_size_override:
                            op_len += 2
                            value = read_int16(data[3 + offset:5 + offset])
                            memory.write(op1, pack_int16(value))
                        else:
                            op_len += 4
                            value = read_uint32(data[3 + offset:7 + offset])
                            memory.write(op1, pack_uint32(value))
                    elif mod == 0b10:
                        if rm == 0b100:
                            # sib
                            op_len += 7
                            op1 = op_sib(data[2]) + read_int32(data[3:7])
                            offset = 1
                        else:
                            op_len += 6
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 = op1 + read_int32(data[2:6])
                            offset = 0
                        if rex_w:
                            op_len += 4
                            value = read_int32(data[6 + offset:10 + offset])
                            memory.write(op1, pack_uint64(sign_extend(value, 32, 64)))
                        elif op_size_override:
                            op_len += 2
                            value = read_uint16(data[6 + offset:8 + offset])
                            memory.write(op1, pack_uint16(value))
                        else:
                            op_len += 4
                            value = read_uint32(data[6 + offset:10 + offset])
                            memory.write(op1, pack_uint32(value))
                    elif mod == 0b11:
                        if rex_w:
                            op_len += 6
                            op1 = translate_plus_r(rm, "b")
                            op2 = read_int32(data[2:6])
                            op1.value = sign_extend(op2, 32, 64)
                        else:
                            raise NotImplementedError
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xd0:
                if o == 4:
                    # shl r/m8, 1
                    if mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        msb = 7
                        state.rflags.OF = op1.value & (1 << msb) != op1.value & (1 << (msb - 1))
                        state.rflags.CF = op1.value & (1 << msb) != 0
                        op1.value = op1.value << 1
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # shr r/m8, 1
                    if mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        msb = 7
                        state.rflags.OF = op1.value & (1 << msb) != 0
                        state.rflags.CF = op1.value & 1 == 1
                        op1.value = op1.value >> 1
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # sar r/m8, 1
                    if mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        msb = 7
                        state.rflags.OF = op1.value & (1 << msb) != 0
                        state.rflags.CF = op1.value & 1 == 1
                        op1.value = op1.value >> 1
                        op1.value |= state.rflags.OF << msb
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xd1:
                if o == 4:
                    # shl r/m16/32/64, 1
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            op1 = translate_plus_r_w(rm, "b")
                            msb = 15
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        state.rflags.OF = op1.value & (1 << msb) != op1.value & (1 << (msb - 1))
                        state.rflags.CF = op1.value & (1 << msb) != 0
                        op1.value = op1.value << 1
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # shr r/m16/32/64, 1
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        state.rflags.OF = op1.value & (1 << msb) != 0
                        state.rflags.CF = op1.value & 1 == 1
                        op1.value = op1.value >> 1
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # sar r/m16/32/64, 1
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        state.rflags.OF = op1.value & (1 << msb) != 0
                        state.rflags.CF = op1.value & 1 == 1
                        op1.value = op1.value >> 1
                        op1.value |= state.rflags.OF << msb
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xd2:
                if o == 4:
                    # shl r/m8, cl
                    if mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        if state.cl.value != 0:
                            op1.value = op1.value << (state.cl.value - 1)
                            state.rflags.CF = op1.value & (1 << 7) != 0
                            op1.value = op1.value << 1
                            if data[2] == 1:
                                raise NotImplementedError
                            state.rflags.SF = op1.value & (1 << 7)
                            state.rflags.ZF = op1.value == 0
                            state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xd3:
                if o == 1:
                    # ror r/m16/32/64, cl
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            bits = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            bits = 31
                        op2 = state.cl.value
                        value = op1.value
                        for _ in range(op2):
                            state.rflags.CF = value & 1 == 1
                            value = (value >> 1) | (state.rflags.CF << bits)
                        state.rflags.OF = bool(value & (1 << bits)) ^ bool(value & (1 << (bits - 1)))
                        op1.value = value
                    else:
                        raise NotImplementedError
                elif o == 4:
                    # shl r/m16/32/64, cl
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        if state.cl.value != 0:
                            op1.value = op1.value << (state.cl.value - 1)
                            state.rflags.CF = op1.value & (1 << msb) != 0
                            op1.value = op1.value << 1
                            if data[2] == 1:
                                raise NotImplementedError
                            state.rflags.SF = op1.value & (1 << msb)
                            state.rflags.ZF = op1.value == 0
                            state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # shr r/m16/32/64, cl
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        if state.cl.value != 0:
                            if state.cl.value == 1:
                                state.rflags.OF = op1.value & (1 << msb) == 1
                            op1.value = op1.value >> (state.cl.value - 1)
                            state.rflags.CF = op1.value & 1 != 0
                            op1.value = op1.value >> 1
                            state.rflags.SF = op1.value & (1 << msb)
                            state.rflags.ZF = op1.value == 0
                            state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xdc:
                op_len += 2
                breakpoint()

            elif data[0] == 0xdb:
                if data[1] == 0xe3:
                    # fninit?
                    op_len += 2
                    pass
                else:
                    raise NotImplementedError

            elif data[0] == 0xe8:
                # call rel16/32
                if op_size_override:
                    raise NotImplementedError
                else:
                    op_len += 5
                    state.rsp -= 8
                    memory.write(state.rsp, pack_int64(state.rip + op_len))
                    state.rip = state.rip + read_int32(data[1:5])

            elif data[0] == 0xe9:
                # jmp rel32
                op_len += 5
                state.rip = state.rip + read_int32(data[1:5])

            elif data[0] == 0xeb:
                # jmp rel8
                op_len += 2
                state.rip += read_int8(data[1:2])

            elif data[0] == 0xf6:
                if o == 0:
                    # test r/m8, imm8
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip + read_int32(data[2:6]) + op_len
                            op1 = read_int8(memory.read(op1, 1))
                            op2 = read_int8(data[6:7])
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 = read_int8(memory.read(op1, 1))
                            op2 = read_int8(data[2:3])
                        tmp = op1 & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.ZF = tmp == 0
                        state.rflags.PF = parity[tmp]
                        state.rflags.SF = tmp & (1 << 7)
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 5
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = op_sib(data[2])
                            op1 = read_int8(memory.read(op1 + read_int8(data[3:4]), 1))
                            op2 = read_int8(data[4:5])
                        else:
                            op_len += 4
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 = read_int8(memory.read(op1 + read_int8(data[2:3]), 1))
                            op2 = read_int8(data[3:4])
                        tmp = op1 & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.ZF = tmp == 0
                        state.rflags.PF = parity[tmp]
                        state.rflags.SF = tmp & (1 << 7)
                    elif mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 7
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            op1 = read_int8(memory.read(op1 + read_int32(data[2:6]), 1))
                            op2 = read_int8(data[6:7])
                        tmp = op1 & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.ZF = tmp == 0
                        state.rflags.PF = parity[tmp]
                        state.rflags.SF = tmp & (1 << 7)
                    elif mod == 0b11:
                        op_len += 3
                        op1 = translate_plus_r_b(rm, "b")
                        op2 = read_int8(data[2:3])
                        tmp = op1 & op2
                        state.rflags.OF = False
                        state.rflags.CF = False
                        state.rflags.ZF = tmp == 0
                        state.rflags.PF = parity[tmp]
                        state.rflags.SF = tmp & (1 << 7)
                    else:
                        raise NotImplementedError
                elif o == 2:
                    # not r/m8
                    if mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        op1.value = ~op1.value & op1.max
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xf7:
                if o == 0:
                    # test r/m16/32/64 imm16/32
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            if rex_w:
                                op_len += 10
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op_len += 10
                            op1 = state.rip + read_int32(data[2:6]) + op_len
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = read_int32(data[6:10])
                                msb = 31
                        else:
                            raise NotImplementedError
                        tmp = op1 & op2
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                op_len += 7
                                op1 = read_int32(memory.read(op1, 4))
                                op2 = read_int32(data[3:7])
                                msb = 31
                        tmp = op1 & op2
                    elif mod == 0b11:
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            op_len += 4
                            op1 = translate_plus_r_w(rm, "b")
                            op2 = read_uint16(data[2:4])
                            msb = 15
                        else:
                            op_len += 6
                            op1 = translate_plus_r_e(rm, "b")
                            op2 = read_uint32(data[2:6])
                            msb = 31
                        tmp = op1.value & op2
                    else:
                        raise NotImplementedError
                    state.rflags.OF = False
                    state.rflags.CF = False
                    state.rflags.ZF = tmp == 0
                    state.rflags.PF = parity[tmp & 0xff]
                    state.rflags.SF = tmp & (1 << msb)
                elif o == 2:
                    # not r/m16/32/64
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op = translate_plus_r(rm, rex="b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op = translate_plus_r_e(rm, "b")
                        op.value = ~op.value & op.max
                    else:
                        raise NotImplementedError
                elif o == 3:
                    # neg r/m16/32/64
                    if mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op, 4))
                                msb = 31
                                min_signed = Int32.min_signed
                                pack = pack_int32
                            state.rflags.CF = value != 0
                            state.rflags.OF = 0 - value < min_signed
                            value = -value
                            memory.write(op, pack(value))
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 6
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op = translate_plus_r(rm, "b") + read_int32(data[2:6])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op, 4))
                                msb = 31
                                min_signed = Int32.min_signed
                                pack = pack_int32
                            state.rflags.CF = value != 0
                            state.rflags.OF = 0 - value < min_signed
                            value = -value
                            memory.write(op, pack(value))
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            op = translate_plus_r_w(rm, "b")
                            msb = 15
                        else:
                            op = translate_plus_r_e(rm, "b")
                            msb = 31
                        state.rflags.CF = op.value != 0
                        state.rflags.OF = 0 - op.value < op.min_signed
                        op.value = -op.value
                        state.rflags.SF = op.value & (1 << msb)
                        state.rflags.ZF = op.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 4:
                    # mul rDX/rAX, r/m16/32/64
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = state.rax
                            op2 = translate_plus_r(rm, "b")
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = state.eax
                            op2 = translate_plus_r_e(rm, "b")
                        tmp = op1.value * op2.value
                        if rex_w:
                            state.rax.value = tmp & 0xffffffffffffffff
                            state.rdx.value = (tmp & (0xffffffffffffffff << 64)) >> 64
                            flag = state.rdx.value != 0
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            state.rax.value = tmp & 0xffffffff
                            state.rdx.value = (tmp & (0xffffffff << 32)) >> 32
                            flag = state.rdx.value != 0
                        state.rflags.CF = state.rflags.OF = flag
                    else:
                        raise NotImplementedError
                elif o == 5:
                    # imul rDX/rAX, r/m16/32/64
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = read_int64(pack_int64(state.rax.value))
                            op2 = translate_plus_r(rm, "b")
                            tmp = op1 * op2.value
                            state.rax.value = tmp & 0xffffffffffffffff
                            state.rdx.value = (tmp & (0xffffffffffffffff << 64)) >> 64
                            size = 64
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = state.eax
                            op2 = translate_plus_r_e(rm, "b")
                            tmp = op1.value * op2.value
                            state.rax.value = tmp & 0xffffffff
                            state.rdx.value = (tmp & (0xffffffff << 32)) >> 32
                            size = 32
                        state.rflags.CF = state.rflags.OF = tmp != sign_extend(tmp, size, size)
                    else:
                        raise NotImplementedError
                elif o == 6:
                    # div rDX/rAX, r/m16/32/64
                    if rex_w:
                        op1 = (state.rdx.value << 64) + state.rax.value
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = (state.edx.value << 32) + state.eax.value
                    if mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op2 = translate_plus_r(rm, "b").value
                            state.rax.value = op1 // op2
                            state.rdx.value = op1 % op2
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b").value
                            state.eax.value = op1 // op2
                            state.edx.value = op1 % op2
                    else:
                        raise NotImplementedError
                elif o == 7:
                    # idiv rDX/rAX, r/m16/32/64
                    if rex_w:
                        op1 = (state.edx.value << 64) + state.eax.value
                        op1 = read_int128(pack_int128(op1))
                    elif op_size_override:
                        raise NotImplementedError
                    else:
                        op1 = (state.edx.value << 32) + state.eax.value
                        op1 = read_int64(pack_int64(op1))
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 6
                            op2 = state.rip.value + read_int32(data[2:6]) + op_len
                            if rex_w:
                                op2 = read_int64(memory.read(op2, 8))
                                state.rax.value = op1 // op2
                                state.rdx.value == op1 % op2
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                raise NotImplementedError
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 2
                        if rex_w:
                            raise NotImplementedError
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op2 = translate_plus_r_e(rm, "b").value
                            state.eax.value = op1 // op2
                            state.edx.value = op1 % op2
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xfc:
                # cld
                op_len += 1
                state.rflags.DF = False

            elif data[0] == 0xfe:
                if o == 0:
                    # inc r/m8
                    if mod == 0b10:
                        if rm == 0b100:
                            op_len += 7
                            op1 = op_sib(data[2]) + read_int32(data[3:7])
                            value = read_int8(memory.read(op1, 1))
                            state.rflags.OF = value == Int8.max_signed
                            value = value + 1
                            memory.write(op1, pack_int8(value))
                            state.rflags.SF = value & (1 << 7)
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                        else:
                            raise NotImplementedError
                    elif mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        state.rflags.OF = op1.value == op1.max_signed
                        op1.value = op1.value + 1
                        state.rflags.SF = op1.value & (1 << 7)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # dec r/m8
                    if mod == 0b11:
                        op_len += 2
                        op1 = translate_plus_r_b(rm, "b")
                        state.rflags.OF = op1.value == 0
                        op1.value = op1.value - 1
                        state.rflags.SF = op1.value & (1 << 7)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif data[0] == 0xff:
                if o == 0:
                    # inc r/m16/32/64
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 6
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = state.rip.value + read_int32(data[2:6]) + op_len
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                max_signed = Int32.max_signed
                                msb = 31
                                pack = pack_int32
                        else:
                            op_len += 2
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                value = read_int64(memory.read(op1, 8))
                                max_signed = Int64.max_signed
                                msb = 63
                                pack = pack_int64
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                max_signed = Int32.max_signed
                                msb = 31
                                pack = pack_int32
                        state.rflags.OF = value == max_signed
                        value = value + 1
                        memory.write(op1, pack(value))
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                max_signed = Int32.max_signed
                                msb = 31
                                pack = pack_int32
                        state.rflags.OF = value == max_signed
                        value = value + 1
                        memory.write(op1, pack(value))
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b10:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 6
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int32(data[2:6])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                max_signed = Int32.max_signed
                                msb = 31
                                pack = pack_int32
                        state.rflags.OF = value == max_signed
                        value = value + 1
                        memory.write(op1, pack(value))
                        state.rflags.SF = value & (1 << msb)
                        state.rflags.ZF = value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        state.rflags.OF = op1.value == op1.max_signed
                        op1.value = op1.value + 1
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 1:
                    # dec r/m16/32/64
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            raise NotImplementedError
                        else:
                            op_len += 2
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b")
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                msb = 31
                                max_signed = Int32.max_signed
                                pack = pack_int32
                            value = value - 1
                            memory.write(op1, pack(value))
                            state.rflags.OF = value == max_signed
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            if rex_w:
                                raise NotImplementedError
                            elif op_size_override:
                                raise NotImplementedError
                            else:
                                value = read_int32(memory.read(op1, 4))
                                msb = 31
                                max_signed = Int32.max_signed
                                pack = pack_int32
                            value = value - 1
                            memory.write(op1, pack(value))
                            state.rflags.OF = value == max_signed
                            state.rflags.SF = value & (1 << msb)
                            state.rflags.ZF = value == 0
                            state.rflags.AF = False
                            state.rflags.PF = parity[value & 0xff]
                    elif mod == 0b11:
                        op_len += 2
                        if rex_w:
                            op1 = translate_plus_r(rm, "b")
                            msb = 63
                        elif op_size_override:
                            raise NotImplementedError
                        else:
                            op1 = translate_plus_r_e(rm, "b")
                            msb = 31
                        op1.value = op1.value - 1
                        state.rflags.OF = op1.value == op1.max_signed
                        state.rflags.SF = op1.value & (1 << msb)
                        state.rflags.ZF = op1.value == 0
                        state.rflags.AF = False
                        state.rflags.PF = parity[op1.value & 0xff]
                    else:
                        raise NotImplementedError
                elif o == 2:
                    # call r/m64
                    if mod == 0b00:
                        if rm == 0b100:
                            raise NotImplementedError
                        elif rm == 0b101:
                            op_len += 6
                            state.rsp -= 8
                            memory.write(state.rsp, pack_int64(state.rip + op_len))
                            state.rip.value = read_int64(memory.read(state.rip + read_int32(data[2:6]) + op_len, 8))
                            op_len = 0
                        else:
                            op_len += 2
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op = read_int64(memory.read(translate_plus_r(rm, "b"), 8))
                            state.rsp -= 8
                            memory.write(state.rsp, pack_int64(state.rip + op_len))
                            state.rip.value = op
                            op_len = 0
                    elif mod == 0b01:
                        if rm == 0b100:
                            op_len += 4
                            op = read_int64(memory.read(op_sib(data[2]) + read_int8(data[3:4]), 8))
                        else:
                            op_len += 3
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op = translate_plus_r(rm, "b")
                            op = read_int64(memory.read(op + read_int8(data[2:3]), 8))
                        state.rsp -= 8
                        memory.write(state.rsp, pack_int64(state.rip + op_len))
                        state.rip.value = op
                        op_len = 0
                    elif mod == 0b10:
                        if rm == 0b100:
                            op_len += 7
                            op = read_int64(memory.read(op_sib(data[2]) + read_int32(data[3:7]), 8))
                        else:
                            raise NotImplementedError
                        state.rsp -= 8
                        memory.write(state.rsp, pack_int64(state.rip + op_len))
                        state.rip.value = op
                        op_len = 0
                    elif mod == 0b11:
                        op_len += 2
                        op = translate_plus_r(rm, "b")
                        state.rsp -= 8
                        memory.write(state.rsp, pack_int64(state.rip + op_len))
                        state.rip.value = op.value
                        op_len = 0
                elif o == 4:
                    # jmp r/m64
                    if mod == 0b00:
                        if rm == 0b100:
                            op_len = 0
                            op1 = op_sib(data[2])
                            state.rip.value = read_int64(memory.read(op1, 8))
                        elif rm == 0b101:
                            op_len += 6
                            state.rip.value = read_int64(memory.read(state.rip + read_int32(data[2:6]) + op_len, 8))
                            op_len = 0
                        else:
                            raise NotImplementedError
                    elif mod == 0b01:
                        if rm == 0b100:
                            raise NotImplementedError
                        else:
                            op_len = 0
                            if addr_size_override:
                                raise NotImplementedError
                            else:
                                op1 = translate_plus_r(rm, "b") + read_int8(data[2:3])
                            state.rip.value = read_int64(memory.read(op1, 8))
                    elif mod == 0b11:
                        op_len = 0
                        state.rip.value = translate_plus_r(rm, "b").value
                    else:
                        raise NotImplementedError
                else:
                    raise NotImplementedError

            elif 0x50 <= data[0] < 0x58:
                # push r16/32 | push r64/16
                op_len += 1
                o = data[0] & 0b00000111
                if mode == 64:
                    state.rsp -= 8
                    op1 = translate_plus_r(o, "b")
                    if op_size_override:
                        raise NotImplementedError
                    else:
                        memory.write(state.rsp, pack_uint64(op1))
                elif mode == 32:
                    state.rsp -= 4
                    op1 = translate_plus_r_e(o, "b")
                    if op_size_override:
                        raise NotImplementedError
                    else:
                        memory.write(state.rsp, pack_int32(op1))
                else:
                    raise NotImplementedError

            elif 0x58 <= data[0] < 0x60:
                # pop r64/16
                op_len += 1
                o = data[0] & 0b00000111
                stack_value = memory.read(state.rsp, 8)
                reg = translate_plus_r(o, "b")
                if op_size_override:
                    raise NotImplementedError
                else:
                    reg.value = read_int64(stack_value)
                state.rsp += 8

            elif 0xb0 <= data[0] < 0xb8:
                # mov r8, imm8
                op_len += 2
                value = read_int8(data[1:2])
                o = data[0] & 0b00000111
                op1 = translate_plus_r_b(o, "b")
                op1.value = value

            elif 0xb8 <= data[0] < 0xc0:
                # mov r16/32/64, imm16/32/64
                if rex_w:
                    op_len += 9
                    value = read_int64(data[1:9])
                elif op_size_override:
                    op_len += 3
                    value = read_int16(data[1:3])
                else:
                    op_len += 5
                    value = read_int32(data[1:5])
                o = data[0] & 0b00000111
                if rex_w:
                    reg = translate_plus_r(o, "b")
                elif op_size_override:
                    reg = translate_plus_r_w(o, "b")
                else:
                    reg = translate_plus_r_e(o, "b")
                reg.value = value

            elif state.rip.value < 0x400000:
                check = state.rip.value
                # check import
                if check & 0xff == 0x06 and check // 256 < len(self.imports):
                    # direct call to import function
                    op_len = 0
                    import_name = self.imports[check // 256]
                    if self.debug and self.inst_count >= self.debug_start:
                        print("%#x  import handler %s" % (state.rip.value, import_name))
                    found = False
                    for func in api_list:
                        if import_name == func.__name__:
                            func(self)
                            found = True
                            break
                    if not found:
                        raise NotImplementedError
                    state.rip.value = read_int64(memory.read(state.rsp, 8))
                    state.rsp += 8
                elif check & 0xff == 0x07 and check // 256 < len(self.dynamic_imports):
                    op_len = 0
                    import_name = self.dynamic_imports[check // 256]
                    if self.debug and self.inst_count >= self.debug_start:
                        print("%#x  dynamic import handler %s" % (state.rip.value, import_name))
                    found = False
                    for func in api_list:
                        if import_name == func.__name__:
                            func(self)
                            found = True
                            break
                    if not found:
                        raise NotImplementedError
                    state.rip.value = read_int64(memory.read(state.rsp, 8))
                    state.rsp += 8
                else:
                    raise NotImplementedError

            else:
                breakpoint()
                raise NotImplementedError

        except NotImplementedError:
            breakpoint()
            raise

        except ExceptionReturn:
            if self.os == 1:
                # load regs
                context = state.rsp.value + 0x710
                state.rflags.value = read_uint64(memory.read(context + 0x44, 8))
                state.rax.value = read_uint64(memory.read(context + 0x78, 8))
                state.rcx.value = read_uint64(memory.read(context + 0x80, 8))
                state.rdx.value = read_uint64(memory.read(context + 0x88, 8))
                state.rbx.value = read_uint64(memory.read(context + 0x90, 8))
                state.rsp.value = read_uint64(memory.read(context + 0x98, 8))
                state.rbp.value = read_uint64(memory.read(context + 0xa0, 8))
                state.rsi.value = read_uint64(memory.read(context + 0xa8, 8))
                state.rdi.value = read_uint64(memory.read(context + 0xb0, 8))
                state.r8.value = read_uint64(memory.read(context + 0xb8, 8))
                state.r9.value = read_uint64(memory.read(context + 0xc0, 8))
                state.r10.value = read_uint64(memory.read(context + 0xc8, 8))
                state.r11.value = read_uint64(memory.read(context + 0xd0, 8))
                state.r12.value = read_uint64(memory.read(context + 0xd8, 8))
                state.r13.value = read_uint64(memory.read(context + 0xe0, 8))
                state.r14.value = read_uint64(memory.read(context + 0xe8, 8))
                state.r15.value = read_uint64(memory.read(context + 0xf0, 8))
                state.rip.value = read_uint64(memory.read(context + 0xf8, 8))
                # exit exception
                # self.cpu.dump()
                # breakpoint()
                self.exception = False
                op_len = 0
                # print("Exception handler return", file=sys.stderr)

        except (MemoryError, TrapException) as e:
            if self.os == 1:
                if not self.exception:
                    # enter exception
                    self.exception = True
                    if len(e.args) > 0:
                        text = "%s: %s" % (e.__class__.__name__, e.args[0])
                    else:
                        text = e.__class__.__name__
                    print(text, file=sys.stderr)
                    # self.cpu.dump()
                    # breakpoint()
                    # Exception handling
                    # save regs
                    context = state.rsp.value - 0x708
                    memory.write(context + 0x44, pack_uint64(state.rflags.value))
                    memory.write(context + 0x78, pack_uint64(state.rax))
                    memory.write(context + 0x80, pack_uint64(state.rcx))
                    memory.write(context + 0x88, pack_uint64(state.rdx))
                    memory.write(context + 0x90, pack_uint64(state.rbx))
                    memory.write(context + 0x98, pack_uint64(state.rsp))
                    memory.write(context + 0xa0, pack_uint64(state.rbp))
                    memory.write(context + 0xa8, pack_uint64(state.rsi))
                    memory.write(context + 0xb0, pack_uint64(state.rdi))
                    memory.write(context + 0xb8, pack_uint64(state.r8))
                    memory.write(context + 0xc0, pack_uint64(state.r9))
                    memory.write(context + 0xc8, pack_uint64(state.r10))
                    memory.write(context + 0xd0, pack_uint64(state.r11))
                    memory.write(context + 0xd8, pack_uint64(state.r12))
                    memory.write(context + 0xe0, pack_uint64(state.r13))
                    memory.write(context + 0xe8, pack_uint64(state.r14))
                    memory.write(context + 0xf0, pack_uint64(state.r15))
                    memory.write(context + 0xf8, pack_uint64(state.rip))
                    # find exception handler
                    exception_start = self.base + self.exception_va
                    handler = None
                    for i in range(self.exception_size // 12):
                        begin = self.base + read_int32(memory.read(exception_start + i * 12 + 0, 4))
                        end = self.base + read_int32(memory.read(exception_start + i * 12 + 4, 4))
                        info = self.base + read_int32(memory.read(exception_start + i * 12 + 8, 4))
                        if begin <= state.rip.value < end:
                            unwind_codes_count = read_int8(memory.read(info + 2, 1))
                            if unwind_codes_count > 0:
                                breakpoint()
                            handler = self.base + read_int32(memory.read(info + 4, 4))
                        if handler is not None:
                            break
                    # call exception handler
                    if handler is not None:
                        state.rsp.value -= 0xe20
                        state.rip.value = handler
                        state.rcx.value = 0xffffffffff
                        state.rdx.value = 0xffffffffff
                        state.r8.value = context
                        state.r9.value = 0xffffffffff
                        memory.write(state.rsp, pack_int64(0xe8ce))
                        op_len = 0
                        # print("Exception handler enter %#x" % handler, file=sys.stderr)
                    else:
                        breakpoint()
                        raise
                else:
                    raise
            else:
                raise

        state.rip += op_len
        # if self.inst_count == 250:
        #     breakpoint()