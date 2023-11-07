import sys
from io import SEEK_SET
from typing import Union

from datatype import Int
from utils import read_int64, pack_int64

read_bp = [
    # 0x40000288
]

write_bp = [
    # 0x12e6a0,
    # 0x12f520
    # 0x12d7a0
0x10073dcb
]

class Memory:

    def __init__(self):
        self.mapped: dict[int: int] = {}
        self.data: dict[int: bytearray] = {}
        self.names: dict[int: str] = {}
        self.bases: dict[str: int] = {}
        self.alloc_size: dict[int: int] = {}
        self.free_alloc: list[list[int]] = []

    def map_file(self, file, offset: int, size: int, target: int, vsize: int, name: str = "unnamed"):
        for k, v in self.mapped.items():
            if k <= target < k + v or k <= target + vsize - 1 < k + v:
                raise MemoryError("File mapping %s(%#x - %#x) overlaps with existing mapping %s(%#x - %#x)" %
                                  (name, target, target + vsize - 1, self.names[k], k, k + v - 1))
        old = file.tell()
        file.seek(offset, SEEK_SET)
        self.mapped[target] = vsize
        data = bytearray(vsize)
        data[0:size] = file.read(size)
        if len(data) < vsize:
            raise MemoryError("Failed to read %d bytes from file" % size)
        self.data[target] = data
        self.names[target] = name
        file.seek(old, SEEK_SET)

    def map(self, target: int, size: int, name: str = "unnamed"):
        for k, v in self.mapped.items():
            if k <= target < k + v or k <= target + size - 1 < k + v:
                raise MemoryError("Memory mapping %s(%#x - %#x) overlaps with existing mapping %s(%#x - %#x)",
                                  (name, target, target + size - 1, self.names[k], k, k + v - 1))
        self.mapped[target] = size
        self.data[target] = bytearray(size)
        self.names[target] = name
        if name == "heap":
            self.free_alloc.append([target, size])

    def unmap(self, target: int):
        if target not in self.mapped.keys():
            raise MemoryError("Trying to unmap unmapped memory at %#x" % target)
        if target < 0x30000000:
            del self.mapped[target]
            del self.data[target]
            del self.names[target]

    def read(self, addr: Union[int, Int], size: int) -> bytearray:
        if isinstance(addr, Int):
            addr = addr.value
        for k, v in self.mapped.items():
            if k <= addr < k + v:
                offset = addr - k
                if addr in read_bp:
                    breakpoint()
                # print("read", hex(k + offset))
                data = self.data[k][offset:offset + size]
                if len(data) < size:
                    # check adjacent maps
                    next_start = len(data) + addr
                    if next_start in self.mapped.keys():
                        data += self.data[next_start][:size - len(data)]
                    else:
                        raise MemoryError("Reading unmapped memory at %#x" % next_start)
                return data
        raise MemoryError("Reading unmapped memory at %#x" % addr)

    def write(self, addr: Union[int, Int], value: bytes):
        if isinstance(addr, Int):
            addr = addr.value
        for k, v in self.mapped.items():
            if k <= addr and addr + len(value) - 1 < k + v:
                offset = addr - k
                self.data[k][offset:offset + len(value)] = value
                # print("write", hex(k + offset))
                if addr in write_bp:
                    breakpoint()
                if self.names[k] == "stack":
                    bottom = read_int64(self.read(0x10, 8))
                    if addr <= bottom:
                        if addr == bottom:
                            addr -= 1
                        self.write(0x10, pack_int64(addr & 0xfff000))
                return
        raise MemoryError("Writing to unmapped memory at %#x" % addr)

    def alloc(self, size: int) -> int:
        # print("-", file=sys.stderr)
        # for block in self.free_alloc:
        #     print(hex(block[0]), hex(block[1]), file=sys.stderr)
        res = (0, 0)
        for block in self.free_alloc:
            if size <= block[1]:
                res = block
                break
        if res[0] != 0:
            self.free_alloc.remove(res)
            self.free_alloc.append([res[0] + size, res[1] - size])
            self.free_alloc.sort(key = lambda b: b[0])
            self.alloc_size[res[0]] = size
        self.write(res[0], b"\xcc" * size)
        # print("-", file=sys.stderr)
        # for block in self.free_alloc:
        #     print(hex(block[0]), hex(block[1]), file=sys.stderr)
        return res[0]


    def free(self, addr: int):
        # print("-", file=sys.stderr)
        # for block in self.free_alloc:
        #     print(hex(block[0]), hex(block[1]), file=sys.stderr)
        size = self.alloc_size.get(addr, None)
        if size is None:
            return
        self.free_alloc.append([addr, size])
        self.free_alloc.sort(key = lambda b: b[0])
        last = (0, 0)
        d = []
        for block in self.free_alloc:
            if last[0] != 0:
                if block[0] == last[0] + last[1]:
                    last[1] += block[1]
                    d.append(block)
            else:
                last = block
        for db in d:
            self.free_alloc.remove(db)
        del self.alloc_size[addr]
        # print("-", file=sys.stderr)
        # for block in self.free_alloc:
        #     print(hex(block[0]), hex(block[1]), file=sys.stderr)