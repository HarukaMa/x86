from typing import Union


class Int:

    @property
    def value(self):
        raise NotImplementedError

    @value.setter
    def value(self, _value):
        raise NotImplementedError

    def __lt__(self, other):
        if isinstance(other, int):
            return self.value < other
        return self.value < other.value

    def __eq__(self, other):
        if isinstance(other, int):
            return self.value == other
        return self.value == other.value

    def __and__(self, other):
        if isinstance(other, int):
            return self.value & other
        return self.value & other.value

    def __format__(self, format_spec):
        return ("%" + format_spec) % self.value

    def __int__(self):
        return self.value

    def __repr__(self):
        return "%s %#x" % (self.name, self.value)


class Int128(Int):

    max = 0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff

    def __init__(self, _value: int, name = "BAD"):
        self.value = _value
        self.name = name

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, _value):
        self.__value = _value & self.max


class Int64(Int):

    max = 0xffffffffffffffff
    max_signed = 0x7fffffffffffffff
    min_signed = -0x8000000000000000

    def __init__(self, _value: int, name = "BAD"):
        self.value = _value
        self.name = name

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, _value):
        self.__value = _value & self.max

    def __add__(self, other):
        name = "BAD"
        if self.name in ["rsp", "rip"]:
            name = self.name
        if isinstance(other, int):
            return Int64(self.value + other, name)
        return Int64(self.value + other.value, name)

    def __sub__(self, other):
        name = "BAD"
        if self.name in ["rsp", "rip"]:
            name = self.name
        if isinstance(other, int):
            return Int64(self.value - other, name)
        return Int64(self.value - other.value, name)

class Int32(Int):

    max = 0xffffffff
    max_signed = 0x7fffffff
    min_signed = -0x80000000

    def __init__(self, _value: int, _parent: Union[Int64, None], name = "BAD"):
        self.init = True
        self.parent = _parent
        self.value = _value
        self.name = name

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, _value):
        self.__value = _value & self.max
        if self.init:
            self.init = False
            return
        if self.parent:
            self.parent.value = self.__value

    def __add__(self, other):
        return Int32(self.value + other, None)

    def __sub__(self, other):
        if isinstance(other, int):
            return Int32(self.value - other, None)
        return Int32(self.value - other.value, None)

class Int16(Int):

    max = 0xffff
    max_signed = 0x7fff
    min_signed = -0x8000

    def __init__(self, _value: int, _parent: Union[Int64, None], name = "BAD"):
        self.init = True
        self.parent = _parent
        self.value = _value
        self.name = name

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, _value):
        self.__value = _value & self.max
        if self.init:
            self.init = False
            return
        if self.parent:
            self.parent.value = self.parent.value & 0xffffffffffff0000 | self.__value

    def __add__(self, other):
        return Int16(self.value + other, None)

    def __sub__(self, other):
        if isinstance(other, int):
            return Int16(self.value - other, None)
        return Int16(self.value - other.value, None)

class Int8(Int):

    max = 0xff
    max_signed = 0x7f
    min_signed = -0x80

    def __init__(self, _value: int, _parent: Union[Int64, None], _low_byte: bool, name = "BAD"):
        self.init = True
        self.parent = _parent
        self.low_byte = _low_byte
        if self.low_byte:
            self.value = _value
        else:
            self.value = _value >> 8
        self.name = name

    @property
    def value(self):
        return self.__value

    @value.setter
    def value(self, _value):
        self.__value = _value & self.max
        if self.init:
            self.init = False
            return
        if self.parent:
            if self.low_byte:
                self.parent.value = self.parent.value & 0xffffffffffffff00 | self.__value
            else:
                self.parent.value = self.parent.value & 0xffffffffffff00ff | (self.__value << 8)

    def __add__(self, other):
        return Int8(self.value + other, None, self.low_byte)

    def __sub__(self, other):
        if isinstance(other, int):
            return Int8(self.value - other, None, self.low_byte)
        return Int8(self.value - other.value, None, self.low_byte)