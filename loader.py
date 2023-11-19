from io import SEEK_CUR, SEEK_SET
from typing import Union

from unicorn import Uc, UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP

from machine import Machine
from utils import read_int32, read_int16, read_int64, pack_int64, pack_int32, pack_uint64, pack_uint16, pack_uint8, \
    pack_uint32

winapi = [
    "advapi32.dll",
    "crypt32.dll",
    "dnsapi.dll",
    "gdi32.dll",
    "hid.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "mpr.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "winmm.dll",
    "user32.dll",
    "winhttp.dll",
    "ws2_32.dll",
    "bcrypt.dll",
    "dbghelp.dll",
    "combase.dll",
    "wlanapi.dll",
    "rpcrt4.dll",
    "virtdisk.dll",
    "ole32.dll",
    "ntdll.dll",
    "kernelbase.dll",
]

import_index = 0

dll_exports = {}

def load_pe64_dll(machine: Machine, file: str, func: Union[str, int], path):
    if file.lower() in dll_exports.keys():
        return dll_exports[file.lower()][func]
    try:
        dll = open(file, "rb")
    except:
        try:
            dll = open(f"{path}/{file}", "rb")
        except:
            return -1
    assert dll.read(2) == b"MZ", "Non-EXE file!"
    dll.seek(0x3c, SEEK_SET)
    nt_header_offset = read_int32(dll.read(4))
    assert nt_header_offset != 0, "Non-PE file - zero NT header offset!"
    dll.seek(nt_header_offset, SEEK_SET)

    assert dll.read(4) == b"PE\x00\x00", "Non-PE file - no signature!"
    assert dll.read(2) == b"\x64\x86", "Non-64-bit dll file!"
    section_count = read_int16(dll.read(2))
    dll.seek(nt_header_offset + 0x14, SEEK_SET)
    optional_header_size = read_int16(dll.read(2))
    dll.seek(nt_header_offset + 0x24, SEEK_SET)
    uninit_size = read_int32(dll.read(4))
    ep = read_int32(dll.read(4))
    dll.seek(nt_header_offset + 0x30, SEEK_SET)
    image_base = read_int64(dll.read(8))
    memory = machine.memory
    dll.seek(nt_header_offset + 0x18 + optional_header_size, SEEK_SET)
    base = 0x180000000

    for k, v in memory.mapped.items():
        if k <= base < k + v:
            base = k + v - ((k + v) % 0x10000000) + 0x10000000
    reloc_diff = image_base - 0x180000000

    for _ in range(section_count):
        name = file + ":" + dll.read(8).rstrip(b"\x00").decode()
        virtual_size = read_int32(dll.read(4))
        va = read_int32(dll.read(4))
        size = read_int32(dll.read(4))
        ptr = read_int32(dll.read(4))
        if size == ptr == 0:
            dll.seek(12, SEEK_CUR)
            char = read_int32(dll.read(4))
            if char & 0x00000080:
                memory.map(base + va, uninit_size, name)
        else:
            memory.map_file(dll, ptr, size, base + va, virtual_size, name)
            dll.seek(16, SEEK_CUR)
    memory.bases[file] = base

    header_size = dll.tell()
    memory.map_file(dll, 0, header_size, base, header_size, f"{file}:header")
    dll.seek(nt_header_offset + 0x18 + optional_header_size - 0x80, SEEK_SET)
    export_va = read_int32(dll.read(4))
    dll.seek(4, SEEK_CUR)
    import_va = read_int32(dll.read(4))
    dll.seek(0x1c, SEEK_CUR)
    relocation_va = read_int32(dll.read(4))
    relocation_size = read_int32(dll.read(4))

    # import
    index = 0
    global import_index
    while True:
        first_thunk = read_int32(memory.read(base + import_va + index * 0x14 + 0x10, 4))
        if first_thunk == 0:
            break
        import_name = \
        memory.read(base + read_int32(memory.read(base + import_va + index * 0x14 + 0xc, 4)), 128).split(b"\x00")[
            0].decode()
        index2 = 0
        while True:
            ilt_entry = read_int64(memory.read(base + first_thunk + index2 * 8, 8))
            if ilt_entry == 0:
                break
            if ilt_entry & (1 << 63):
                ordinal = ilt_entry & 0xffff
                func_name = "%s_%s" % (import_name, ordinal)
            else:
                start = base + (ilt_entry & 0x7fffffff) + 2
                buffer = bytearray()
                while True:
                    byte = memory.read(start, 1)[0]
                    if byte == 0:
                        break
                    buffer.append(byte)
                    start += 1
                func_name = buffer.split(b"\x00")[0].decode()
            if import_name.lower() not in winapi and not import_name.lower().startswith("api-ms-win"):
                dll_import = load_pe64_dll(machine, import_name, func_name, path)
                if dll_import == -1:
                    raise FileNotFoundError(f"{import_name} is not implemented, module file not found")
                elif dll_import == 0:
                    raise AttributeError(f"{func} is not exported by {file}")
                memory.write(base + first_thunk + index2 * 8, pack_int64(dll_import))
            elif func_name not in machine.imports:
                machine.imports.append(func_name)
                memory.write(0x20000 + import_index * 8, pack_int64((len(machine.imports) - 1) * 256 + 6))
                memory.write(base + first_thunk + index2 * 8, pack_int64(0x20000 + import_index * 8))
                import_index += 1
            else:
                existing_index = machine.imports.index(func_name)
                memory.write(base + first_thunk + index2 * 8, pack_int64(0x20000 + existing_index * 8))
            index2 += 1
        index += 1

    # export
    if isinstance(func, int):
        raise NotImplementedError
    ordinal_base = read_int32(memory.read(base + export_va + 0x10, 4))
    function_count = read_int32(memory.read(base + export_va + 0x14, 4))
    name_count = read_int32(memory.read(base + export_va + 0x18, 4))
    function_start = read_int32(memory.read(base + export_va + 0x1c, 4))
    name_start = read_int32(memory.read(base + export_va + 0x20, 4))
    name_ordinal_start = read_int32(memory.read(base + export_va + 0x24, 4))
    data = {}
    ordinal_table = {}
    for i in range(function_count):
        function_rva = read_int32(memory.read(base + function_start + i * 4, 4))
        ordinal_table[i + ordinal_base] = function_rva
    name_table = {}
    for i in range(name_count):
        name_rva = read_int32(memory.read(base + name_start + i * 4, 4))
        name_ordinal = read_int16(memory.read(base + name_ordinal_start + i * 2, 2))
        buffer = bytearray()
        while True:
            byte = memory.read(base + name_rva, 1)[0]
            if byte == 0:
                break
            buffer.append(byte)
            name_rva += 1
        name = buffer.decode()
        name_table[name_ordinal] = name
    for name_ordinal, name in name_table.items():
        data[name] = base + ordinal_table[name_ordinal + ordinal_base]
    dll_exports[file.lower()] = data

    # relocation
    if reloc_diff != 0:
        ptr = base + relocation_va
        while ptr != base + relocation_va + relocation_size:
            block_rva = read_int32(memory.read(ptr, 4))
            ptr += 4
            block_size = read_int32(memory.read(ptr, 4))
            ptr += 4
            block_count = (block_size - 8) // 2
            for _ in range(block_count):
                reloc_item = read_int16(memory.read(ptr, 2))
                ptr += 2
                reloc_type = (reloc_item & 0xf000) >> 12
                reloc_rva = reloc_item & 0x0fff
                if reloc_type == 0:
                    pass
                elif reloc_type == 10:
                    reloc_target = base + block_rva + reloc_rva
                    memory.write(reloc_target, pack_int64(read_int64(memory.read(reloc_target, 8)) - reloc_diff))
                else:
                    raise NotImplementedError


    # entry
    machine.cpu.state.rip.value = base + ep
    machine.cpu.state.rsp.value = 0x12ff50
    memory.write(0x12ff50, pack_int64(0x0123456789abcdef))
    machine.cpu.state.rcx.value = base
    machine.cpu.state.rdx.value = 1
    machine.cpu.state.r8.value = 0
    while machine.cpu.state.rip.value != 0x0123456789abcdef:
        machine.step()
        if machine.debug and machine.inst_count > machine.debug_start:
            machine.cpu.dump()
    return dll_exports[file.lower()][func]

def load_pe64_u(u: Uc, file: str, arguments=None):
    if arguments is None:
        arguments = []
    exe = open(file, "rb")
    assert exe.read(2) == b"MZ", "Non-EXE file!"
    exe.seek(0x3c, SEEK_SET)
    nt_header_offset = read_int32(exe.read(4))
    assert nt_header_offset != 0, "Non-PE file - zero NT header offset!"
    exe.seek(nt_header_offset, SEEK_SET)

    assert exe.read(4) == b"PE\x00\x00", "Non-PE file - no signature!"
    assert exe.read(2) == b"\x64\x86", "Non-64-bit exe file!"
    section_count = read_int16(exe.read(2))
    exe.seek(nt_header_offset + 0x14, SEEK_SET)
    optional_header_size = read_int16(exe.read(2))
    exe.seek(nt_header_offset + 0x24, SEEK_SET)
    uninit_size = read_int32(exe.read(4))
    ep = read_int32(exe.read(4))
    exe.seek(4, SEEK_CUR)
    base = read_int64(exe.read(8))

    exe.seek(0x28, SEEK_CUR)
    stack_reserve = read_int64(exe.read(8))
    stack_commit = read_int64(exe.read(8))
    heap_reserve = read_int64(exe.read(8))
    heap_commit = read_int64(exe.read(8))
    exe.seek(nt_header_offset + 0x18 + optional_header_size, SEEK_SET)

    u.mem_map(0x10000, 0x10000, UC_PROT_READ | UC_PROT_WRITE) # internal
    cmdline = f"{file}"
    if arguments:
        cmdline += " " + " ".join(arguments)
    u.mem_write(0x10000, pack_uint64(0x10100))
    u.mem_write(0x10010, pack_uint64(0x10300))
    u.mem_write(0x10020, pack_uint64(0x10500))
    u.mem_write(0x10030, pack_uint64(0x10700))
    u.mem_write(0x10100, cmdline.encode() + b"\0")
    u.mem_write(0x10300, cmdline.encode("utf-16le") + b"\0\0")
    u.mem_write(0x10500, ' '.join(arguments).encode() + b"\0")
    u.mem_write(0x10700, ' '.join(arguments).encode("utf-16le") + b"\0\0")
    u.mem_write(0x1e8ce, b"\x0e")

    u.mem_map(0x20000, 0x10000) # imports
    u.mem_map(0x30000, 0x10000) # dynamic imports
    u.mem_map(0x100000, stack_reserve, UC_PROT_READ | UC_PROT_WRITE) # stack
    u.mem_map(0x10000000, heap_reserve, UC_PROT_READ | UC_PROT_WRITE) # heap
    u.__setattr__("free_alloc", [(0x10000000, heap_reserve)])
    u.__setattr__("free_map", [(0x30000000, 0x10000000)])

    u.mem_map(0x0, 0x10000, UC_PROT_READ | UC_PROT_WRITE) # TEB
    u.mem_write(0x8, pack_uint64(0x130000))
    u.mem_write(0x10, pack_uint64(0x12d000))
    u.mem_write(0x38, pack_uint64(0x8100))
    u.mem_write(0x40, pack_uint64(0x8000))
    u.mem_write(0x60, pack_uint64(0x2000))
    u.mem_write(0x2002, pack_uint8(0))
    u.mem_write(0x8000, pack_uint16(0x100))
    # debug port
    u.mem_write(0x8100, pack_uint32(0))

    for _ in range(section_count):
        name = file.split("/")[-1] + ":" + exe.read(8).rstrip(b"\x00").decode()
        virtual_size = read_int32(exe.read(4))
        if virtual_size % 0x1000 != 0:
            virtual_size = (virtual_size // 0x1000 + 1) * 0x1000
        va = read_int32(exe.read(4))
        size = read_int32(exe.read(4))
        ptr = read_int32(exe.read(4))
        exe.seek(12, SEEK_CUR)
        char = read_int32(exe.read(4))
        prot = 0
        if char & 0x20000000:
            prot |= UC_PROT_EXEC
        if char & 0x40000000:
            prot |= UC_PROT_READ
        if char & 0x80000000:
            prot |= UC_PROT_WRITE
        if size == ptr == 0:
            if char & 0x00000080:
                u.mem_map(base + va, uninit_size, prot)
        else:
            u.mem_map(base + va, virtual_size, prot)
            pos = exe.tell()
            exe.seek(ptr, SEEK_SET)
            u.mem_write(base + va, exe.read(size))
            exe.seek(pos, SEEK_SET)
    u.__setattr__("base", base)
    u.__setattr__("bases",{
        file.split("/")[-1]: base
    })

    header_size = exe.tell()
    pos = exe.tell()
    u.mem_map(base, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
    exe.seek(0, SEEK_SET)
    u.mem_write(base, exe.read(header_size))
    exe.seek(pos, SEEK_SET)
    exe.seek(nt_header_offset + 0x18 + optional_header_size - 0x78)
    import_va = read_int32(exe.read(4))
    exe.seek(0x0c, SEEK_CUR)
    exception_va = read_int32(exe.read(4))
    exception_size = read_int32(exe.read(4))
    u.mem_write(0x11000, pack_uint64(exception_va))
    u.mem_write(0x11008, pack_uint64(exception_size))
    index = 0
    global import_index
    u.__setattr__("imports", [])
    u.__setattr__("dynamic_imports", [])
    while True:
        first_thunk = read_int32(u.mem_read(base + import_va + index * 0x14 + 0x10, 4))
        if first_thunk == 0:
            break
        start = base + read_int32(u.mem_read(base + import_va + index * 0x14 + 0xc, 4))
        buffer = bytearray()
        while True:
            byte = u.mem_read(start, 1)[0]
            if byte == 0:
                break
            buffer.append(byte)
            start += 1
        import_name = buffer.decode()
        # import_name = memory.read(base + read_int32(memory.read(base + import_va + index * 0x14 + 0xc, 4)), 128).split(b"\x00")[0].decode()
        index2 = 0
        while True:
            ilt_entry = read_int64(u.mem_read(base + first_thunk + index2 * 8, 8))
            if ilt_entry == 0:
                break
            if ilt_entry & (1 << 63):
                ordinal = ilt_entry & 0xffff
                func_name = "%s_%s" % (import_name, ordinal)
            else:
                start = base + (ilt_entry & 0x7fffffff) + 2
                buffer = bytearray()
                while True:
                    byte = u.mem_read(start, 1)[0]
                    if byte == 0:
                        break
                    buffer.append(byte)
                    start += 1
                func_name = buffer.split(b"\x00")[0].decode()
            dll_import = 0
            if import_name.lower() not in winapi:
                dll_import = load_pe64_dll(machine, import_name, func_name, "/".join(file.split("/")[:-1]))
                if dll_import == -1:
                    raise FileNotFoundError(f"{import_name} is not implemented, module file not found")
                elif dll_import == 0:
                    raise AttributeError(f"{func_name} is not exported by {import_name}")
                memory.write(base + first_thunk + index2 * 8, pack_int64(dll_import))
            elif func_name not in u.__getattribute__("imports"):
                u.__getattribute__("imports").append(func_name)
                u.mem_write(0x20000 + import_index * 8, pack_int64((len(u.__getattribute__("imports")) - 1) * 256 + 6))
                u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x20000 + import_index * 8))
                import_index += 1
                if func_name == "_acmdln":
                    u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x10000))
                elif func_name == "_wcmdln":
                    u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x10010))
                elif func_name == "__argc":
                    u.mem_write(base + first_thunk + index2 * 8, pack_int64(len(arguments) + 1))
                elif func_name == "__argv":
                    u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x10020))
                elif func_name == "__wargv":
                    u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x10030))
                elif func_name == "__initenv":
                    u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x10008))
            else:
                existing_index = u.__getattribute__("imports").index(func_name)
                u.mem_write(base + first_thunk + index2 * 8, pack_int64(0x20000 + existing_index * 8))

            index2 += 1
        index += 1

    u.reg_write(UC_X86_REG_RIP, base + ep)
    u.reg_write(UC_X86_REG_RSP, 0x12ff58)

def load_pe64(machine: Machine, file: str, arguments=None):
    if arguments is None:
        arguments = []
    exe = open(file, "rb")
    assert exe.read(2) == b"MZ", "Non-EXE file!"
    exe.seek(0x3c, SEEK_SET)
    nt_header_offset = read_int32(exe.read(4))
    assert nt_header_offset != 0, "Non-PE file - zero NT header offset!"
    exe.seek(nt_header_offset, SEEK_SET)

    assert exe.read(4) == b"PE\x00\x00", "Non-PE file - no signature!"
    assert exe.read(2) == b"\x64\x86", "Non-64-bit exe file!"
    section_count = read_int16(exe.read(2))
    exe.seek(nt_header_offset + 0x14, SEEK_SET)
    optional_header_size = read_int16(exe.read(2))
    exe.seek(nt_header_offset + 0x24, SEEK_SET)
    uninit_size = read_int32(exe.read(4))
    ep = read_int32(exe.read(4))
    exe.seek(4, SEEK_CUR)
    base = read_int64(exe.read(8))
    machine.base = base
    exe.seek(0x28, SEEK_CUR)
    stack_reserve = read_int64(exe.read(8))
    stack_commit = read_int64(exe.read(8))
    heap_reserve = read_int64(exe.read(8))
    heap_commit = read_int64(exe.read(8))
    exe.seek(nt_header_offset + 0x18 + optional_header_size, SEEK_SET)

    memory = machine.memory

    memory.map(0x10000, 0x10000, "internal")
    cmdline = f"{file}"
    if arguments:
        cmdline += " " + " ".join(arguments)
    memory.write(0x10000, pack_int64(0x10100))
    memory.write(0x10010, pack_int64(0x10300))
    memory.write(0x10020, pack_int64(0x10500))
    memory.write(0x10030, pack_int64(0x10700))
    memory.write(0x10100, cmdline.encode() + b"\0")
    memory.write(0x10300, cmdline.encode("utf-16le") + b"\0\0")
    memory.write(0x10500, ' '.join(arguments).encode() + b"\0")
    memory.write(0x10700, ' '.join(arguments).encode("utf-16le") + b"\0\0")
    memory.write(0x10500, b"\0\0\0\0")
    memory.write(0x1e8ce, b"\x0e")

    memory.map(0x20000, 0x10000, "imports")
    memory.map(0x100000, stack_reserve, "stack")
    memory.map(0x10000000, heap_reserve, "heap")
    memory.map(0x0, 0x10000, "TIB")
    memory.write(0x10, pack_int64(0x12d000))

    for _ in range(section_count):
        name = file.split("/")[-1] + ":" + exe.read(8).rstrip(b"\x00").decode()
        virtual_size = read_int32(exe.read(4))
        va = read_int32(exe.read(4))
        size = read_int32(exe.read(4))
        ptr = read_int32(exe.read(4))
        if size == ptr == 0:
            exe.seek(12, SEEK_CUR)
            char = read_int32(exe.read(4))
            if char & 0x00000080:
                memory.map(base + va, uninit_size, name)
        else:
            memory.map_file(exe, ptr, size, base + va, virtual_size, name)
            exe.seek(16, SEEK_CUR)
    memory.bases[file.split("/")[-1]] = base

    header_size = exe.tell()
    memory.map_file(exe, 0, header_size, base, header_size, f'{file.split("/")[-1]}:header')
    exe.seek(nt_header_offset + 0x18 + optional_header_size - 0x78)
    import_va = read_int32(exe.read(4))
    exe.seek(0x0c, SEEK_CUR)
    exception_va = read_int32(exe.read(4))
    exception_size = read_int32(exe.read(4))
    machine.exception_va = exception_va
    machine.exception_size = exception_size
    index = 0
    global import_index
    while True:
        first_thunk = read_int32(memory.read(base + import_va + index * 0x14 + 0x10, 4))
        if first_thunk == 0:
            break
        start = base + read_int32(memory.read(base + import_va + index * 0x14 + 0xc, 4))
        buffer = bytearray()
        while True:
            byte = memory.read(start, 1)[0]
            if byte == 0:
                break
            buffer.append(byte)
            start += 1
        import_name = buffer.decode()
        # import_name = memory.read(base + read_int32(memory.read(base + import_va + index * 0x14 + 0xc, 4)), 128).split(b"\x00")[0].decode()
        index2 = 0
        while True:
            ilt_entry = read_int64(memory.read(base + first_thunk + index2 * 8, 8))
            if ilt_entry == 0:
                break
            if ilt_entry & (1 << 63):
                ordinal = ilt_entry & 0xffff
                func_name = "%s_%s" % (import_name, ordinal)
            else:
                start = base + (ilt_entry & 0x7fffffff) + 2
                buffer = bytearray()
                while True:
                    byte = memory.read(start, 1)[0]
                    if byte == 0:
                        break
                    buffer.append(byte)
                    start += 1
                func_name = buffer.split(b"\x00")[0].decode()
            dll_import = 0
            if import_name.lower() not in winapi:
                dll_import = load_pe64_dll(machine, import_name, func_name, "/".join(file.split("/")[:-1]))
                if dll_import == -1:
                    raise FileNotFoundError(f"{import_name} is not implemented, module file not found")
                elif dll_import == 0:
                    raise AttributeError(f"{func_name} is not exported by {import_name}")
                memory.write(base + first_thunk + index2 * 8, pack_int64(dll_import))
            elif func_name not in machine.imports:
                machine.imports.append(func_name)
                memory.write(0x20000 + import_index * 8, pack_int64((len(machine.imports) - 1) * 256 + 6))
                memory.write(base + first_thunk + index2 * 8, pack_int64(0x20000 + import_index * 8))
                import_index += 1
                if func_name == "_acmdln":
                    memory.write(base + first_thunk + index2 * 8, pack_int64(0x10000))
                elif func_name == "_wcmdln":
                    memory.write(base + first_thunk + index2 * 8, pack_int64(0x10010))
                elif func_name == "__argc":
                    memory.write(base + first_thunk + index2 * 8, pack_int64(len(arguments) + 1))
                elif func_name == "__argv":
                    memory.write(base + first_thunk + index2 * 8, pack_int64(0x10020))
                elif func_name == "__wargv":
                    memory.write(base + first_thunk + index2 * 8, pack_int64(0x10030))
                elif func_name == "__initenv":
                    memory.write(base + first_thunk + index2 * 8, pack_int64(0x10008))
            else:
                existing_index = machine.imports.index(func_name)
                memory.write(base + first_thunk + index2 * 8, pack_int64(0x20000 + existing_index * 8))

            index2 += 1
        index += 1


    machine.cpu.state.rip.value = base + ep
    machine.cpu.state.rsp.value = 0x12ff58

def load_pe32(machine: Machine, file: str):
    raise NotImplementedError
    exe = open(file, "rb")
    assert exe.read(2) == b"MZ", "Non-EXE file!"
    exe.seek(0x3c, SEEK_SET)
    nt_header_offset = read_int32(exe.read(4))
    assert nt_header_offset != 0, "Non-PE file - zero NT header offset!"
    exe.seek(nt_header_offset, SEEK_SET)

    assert exe.read(4) == b"PE\x00\x00", "Non-PE file - no signature!"
    assert exe.read(2) == b"\x4c\x01", "Non-32-bit exe file!"
    section_count = read_int16(exe.read(2))
    exe.seek(nt_header_offset + 0x14, SEEK_SET)
    optional_header_size = read_int16(exe.read(2))
    exe.seek(nt_header_offset + 0x24, SEEK_SET)
    uninit_size = read_int32(exe.read(4))
    ep = read_int32(exe.read(4))
    exe.seek(8, SEEK_CUR)
    base = read_int32(exe.read(4))
    exe.seek(0x28, SEEK_CUR)
    stack_reserve = read_int32(exe.read(4))
    stack_commit = read_int32(exe.read(4))
    heap_reserve = read_int32(exe.read(4))
    heap_commit = read_int32(exe.read(4))
    exe.seek(nt_header_offset + 0x18 + optional_header_size)

    memory = machine.memory

    memory.map(0x10000, 0x1000, "internal")

    for _ in range(section_count):
        name = exe.read(8).rstrip(b"\x00").decode()
        virtual_size = read_int32(exe.read(4))
        va = read_int32(exe.read(4))
        size = read_int32(exe.read(4))
        ptr = read_int32(exe.read(4))
        if size == ptr == 0:
            exe.seek(12, SEEK_CUR)
            char = read_int32(exe.read(4))
            if char & 0x00000080:
                memory.map(base + va, uninit_size, name)
        else:
            memory.map_file(exe, ptr, size, base + va, virtual_size, name)
            exe.seek(16, SEEK_CUR)
        if name == ".idata":
            index = 0
            while True:
                first_thunk = read_int32(memory.read(base + va + index * 0x14 + 0x10, 4))
                if first_thunk == 0:
                    break
                import_name = memory.read(base + read_int32(memory.read(base + va + index * 0x14 + 0xc, 4)), 128).split(b"\x00")[0].decode()
                index2 = 0
                while True:
                    ilt_entry = read_int32(memory.read(base + first_thunk + index2 * 4, 4))
                    if ilt_entry == 0:
                        break
                    memory.write(base + first_thunk + index2 * 4, pack_int32(len(machine.imports) * 256 + 6))
                    if ilt_entry & (1 << 31):
                        ordinal = ilt_entry & 0xffff
                        machine.imports.append("%s_%s" % (import_name, ordinal))
                    else:
                        func_name = memory.read(base + ilt_entry + 2, 128).split(b"\x00")[0].decode()
                        if func_name == "_acmdln":
                            memory.write(base + first_thunk + index2 * 4, pack_int32(0x10000))
                            memory.write(0x10000, pack_int32(0x10100))
                            memory.write(0x10100, file.encode() + b"\0")
                        elif func_name == "__initenv":
                            memory.write(base + first_thunk + index2 * 4, pack_int32(0x10004))
                        machine.imports.append(func_name)
                    index2 += 1
                index += 1
    header_size = exe.tell()
    memory.map_file(exe, 0, header_size, base, header_size, "header")


    machine.cpu.state.rip.value = base + ep
    machine.cpu.state.rsp.value = 0x10000000 + stack_commit
    memory.map(0x10000000, stack_commit, "stack")
    memory.map(0x20000000, heap_commit, "heap")
    memory.map(0x0, 0x10000, "TIB")



