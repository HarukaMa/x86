from datatype import Int64, Int32, Int8, Int16, Int128


class CPU:

    class State:

        class Flags:

            def __init__(self):
                self.CF = False
                self.PF = False
                self.AF = False
                self.ZF = False
                self._SF = False
                self.TF = False
                self.IF = False
                self.DF = False
                self.OF = False
                self.IOPL = 0
                self.NT = False
                self.RF = False
                self.VM = False
                self.AC = False
                self.VIF = False
                self.VIP = False
                self.ID = False

            @property
            def SF(self):
                return self._SF

            @SF.setter
            def SF(self, value):
                self._SF = bool(value)

            @property
            def value(self):
                res = 0
                res |= self.CF << 0
                res |= self.PF << 2
                res |= self.AF << 4
                res |= self.ZF << 6
                res |= self.SF << 7
                res |= self.TF << 8
                res |= self.IF << 9
                res |= self.DF << 10
                res |= self.OF << 11
                res |= self.IOPL << 12
                res |= self.NT << 14
                res |= self.RF << 16
                res |= self.VM << 17
                res |= self.AC << 18
                res |= self.VIF << 19
                res |= self.VIP << 20
                res |= self.ID << 21
                return res

            @value.setter
            def value(self, value):
                self.CF = value & (1 << 0) > 0
                self.PF = value & (1 << 2) > 0
                self.AF = value & (1 << 4) > 0
                self.ZF = value & (1 << 6) > 0
                self.SF = value & (1 << 7) > 0
                self.TF = value & (1 << 8) > 0
                self.IF = value & (1 << 9) > 0
                self.DF = value & (1 << 10) > 0
                self.OF = value & (1 << 11) > 0
                self.IOPL = value & (1 << 12) > 0
                self.NT = value & (1 << 14) > 0
                self.RF = value & (1 << 16) > 0
                self.VM = value & (1 << 17) > 0
                self.AC = value & (1 << 18) > 0
                self.VIF = value & (1 << 19) > 0
                self.VIP = value & (1 << 20) > 0
                self.ID = value & (1 << 21) > 0

            def __str__(self):
                res = ""
                for k, v in vars(self).items():
                    if v:
                        res += k.replace("_", "") + " "
                return res[:-1]


        def __init__(self):
            self.rax = Int64(0, "rax")
            self.rbx = Int64(0, "rbx")
            self.rcx = Int64(0, "rcx")
            self.rdx = Int64(0, "rdx")
            self.rdi = Int64(0, "rdi")
            self.rsi = Int64(0, "rsi")
            self.rbp = Int64(0, "rbp")
            self.rsp = Int64(0, "rsp")
            self.r8 = Int64(0, "r8")
            self.r9 = Int64(0, "r9")
            self.r10 = Int64(0, "r10")
            self.r11 = Int64(0, "r11")
            self.r12 = Int64(0, "r12")
            self.r13 = Int64(0, "r13")
            self.r14 = Int64(0, "r14")
            self.r15 = Int64(0, "r15")

            self.xmm0 = Int128(0, "xmm0")
            self.xmm1 = Int128(0, "xmm1")
            self.xmm2 = Int128(0, "xmm2")

            self.rip = Int64(0, "rip")

            self.rflags = self.Flags()

        @property
        def eax(self):
            return Int32(self.rax.value, self.rax, "eax")

        @eax.setter
        def eax(self, value):
            self.rax.value = value

        @property
        def ax(self):
            return Int16(self.rax.value, self.rax, "ax")

        @ax.setter
        def ax(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def al(self):
            return Int8(self.rax.value, self.rax, True, "al")

        @al.setter
        def al(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def ebx(self):
            return Int32(self.rbx.value, self.rbx, "ebx")

        @ebx.setter
        def ebx(self, value):
            self.rbx.value = value

        @property
        def bx(self):
            return Int16(self.rbx.value, self.rbx, "bx")

        @bx.setter
        def bx(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def bh(self):
            return Int8(self.rbx.value, self.rbx, False, "bh")

        @bh.setter
        def bh(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def bl(self):
            return Int8(self.rbx.value, self.rbx, True, "bl")

        @bl.setter
        def bl(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def ecx(self):
            return Int32(self.rcx.value, self.rcx, "ecx")

        @ecx.setter
        def ecx(self, value):
            self.rcx.value = value

        @property
        def cx(self):
            return Int16(self.rcx.value, self.rcx, "cx")

        @cx.setter
        def cx(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def ch(self):
            return Int8(self.rcx.value, self.rcx, False, "ch")

        @ch.setter
        def ch(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def cl(self):
            return Int8(self.rcx.value, self.rcx, True, "cl")

        @cl.setter
        def cl(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def edx(self):
            return Int32(self.rdx.value, self.rdx, "edx")

        @edx.setter
        def edx(self, value):
            self.rdx.value = value

        @property
        def dx(self):
            return Int16(self.rdx.value, self.rdx, "dx")

        @dx.setter
        def dx(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def dh(self):
            return Int8(self.rdx.value, self.rdx, False, "dh")

        @dh.setter
        def dh(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def dl(self):
            return Int8(self.rdx.value, self.rdx, True, "dl")

        @dl.setter
        def dl(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def esp(self):
            return Int32(self.rsp.value, self.rsp, "esp")

        @esp.setter
        def esp(self, value):
            self.rsp.value = value

        @property
        def ebp(self):
            return Int32(self.rbp.value, self.rbp, "ebp")

        @ebp.setter
        def ebp(self, value):
            self.rbp.value = value

        @property
        def bp(self):
            return Int16(self.rbp.value, self.rbp, "bp")

        @bp.setter
        def bp(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def bpl(self):
            return Int8(self.rbp.value, self.rbp, True, "bpl")

        @bpl.setter
        def bpl(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def esi(self):
            return Int32(self.rsi.value, self.rsi, "esi")

        @esi.setter
        def esi(self, value):
            self.rsi.value = value

        @property
        def si(self):
            return Int16(self.rsi.value, self.rsi, "si")

        @si.setter
        def si(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def sil(self):
            return Int8(self.rsi.value, self.rsi, True, "sil")

        @sil.setter
        def sil(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def edi(self):
            return Int32(self.rdi.value, self.rdi, "edi")

        @edi.setter
        def edi(self, value):
            self.rdi.value = value

        @property
        def di(self):
            return Int16(self.rdi.value, self.rdi, "di")

        @di.setter
        def di(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def dil(self):
            return Int8(self.rdi.value, self.rdi, True, "dil")

        @dil.setter
        def dil(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r8d(self):
            return Int32(self.r8.value, self.r8, "r8d")

        @r8d.setter
        def r8d(self, value):
            self.r8.value = value

        @property
        def r8w(self):
            return Int16(self.r8.value, self.r8, "r8w")

        @r8w.setter
        def r8w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r8b(self):
            return Int8(self.r8.value, self.r8, True, "r8b")

        @r8b.setter
        def r8b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r9d(self):
            return Int32(self.r9.value, self.r9, "r9d")

        @r9d.setter
        def r9d(self, value):
            self.r9.value = value

        @property
        def r9w(self):
            return Int16(self.r9.value, self.r9, "r9w")

        @r9w.setter
        def r9w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r9b(self):
            return Int8(self.r9.value, self.r9, True, "r9b")

        @r9b.setter
        def r9b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r10d(self):
            return Int32(self.r10.value, self.r10, "r10d")

        @r10d.setter
        def r10d(self, value):
            self.r10.value = value

        @property
        def r10w(self):
            return Int16(self.r10.value, self.r10, "r10w")

        @r10w.setter
        def r10w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r10b(self):
            return Int8(self.r10.value, self.r10, True, "r10b")

        @r10b.setter
        def r10b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r11d(self):
            return Int32(self.r11.value, self.r11, "r11d")

        @r11d.setter
        def r11d(self, value):
            self.r11.value = value

        @property
        def r11w(self):
            return Int16(self.r11.value, self.r11, "r11w")

        @r11w.setter
        def r11w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r11b(self):
            return Int8(self.r11.value, self.r11, True, "r11b")

        @r11b.setter
        def r11b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r12d(self):
            return Int32(self.r12.value, self.r12, "r12d")

        @r12d.setter
        def r12d(self, value):
            self.r12.value = value

        @property
        def r12w(self):
            return Int16(self.r12.value, self.r12, "r12w")

        @r12w.setter
        def r12w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r12b(self):
            return Int8(self.r12.value, self.r12, True, "r12b")

        @r12b.setter
        def r12b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r13d(self):
            return Int32(self.r13.value, self.r13, "r13d")

        @r13d.setter
        def r13d(self, value):
            self.r13.value = value

        @property
        def r13w(self):
            return Int16(self.r13.value, self.r13, "r13w")

        @r13w.setter
        def r13w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r13b(self):
            return Int8(self.r13.value, self.r13, True, "r13b")

        @r13b.setter
        def r13b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r14d(self):
            return Int32(self.r14.value, self.r14, "r14d")

        @r14d.setter
        def r14d(self, value):
            self.r14.value = value

        @property
        def r14w(self):
            return Int16(self.r14.value, self.r14, "r14w")

        @r14w.setter
        def r14w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r14b(self):
            return Int8(self.r14.value, self.r14, True, "r14b")

        @r14b.setter
        def r14b(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r15d(self):
            return Int32(self.r15.value, self.r15, "r15d")

        @r15d.setter
        def r15d(self, value):
            self.r15.value = value

        @property
        def r15w(self):
            return Int16(self.r15.value, self.r15, "r15w")

        @r15w.setter
        def r15w(self, value):
            raise NotImplementedError("Use returned property variable")

        @property
        def r15b(self):
            return Int8(self.r15.value, self.r15, True, "r15b")

        @r15b.setter
        def r15b(self, value):
            raise NotImplementedError("Use returned property variable")

    def __init__(self):
        self.state = self.State()

    def dump(self):
        print("rax: {:#018x}  rbx: {:#018x}  rcx: {:#018x}  rdx: {:#018x}".format(self.state.rax, self.state.rbx, self.state.rcx, self.state.rdx))
        print("rdi: {:#018x}  rsi: {:#018x}  rbp: {:#018x}  rsp: {:#018x}".format(self.state.rdi, self.state.rsi, self.state.rbp, self.state.rsp))
        print("r8 : {:#018x}  r9 : {:#018x}  r10: {:#018x}  r11: {:#018x}".format(self.state.r8, self.state.r9, self.state.r10, self.state.r11))
        print("r12: {:#018x}  r13: {:#018x}  r14: {:#018x}  r15: {:#018x}".format(self.state.r12, self.state.r13, self.state.r14, self.state.r15))
        print("xmm0: {:#034x}          xmm1: {:#034x}".format(self.state.xmm0, self.state.xmm1))
        print("xmm2: {:#034x}          xmm3: {:#034x}".format(self.state.xmm2, 0))
        print("rip: {:#018x}  rflags: {:s}".format(self.state.rip, str(self.state.rflags)))