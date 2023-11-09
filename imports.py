import datetime
import os
import re
import sys
import time
import random

from io import SEEK_SET
from typing import List, Dict, BinaryIO, Any, TextIO, Union, Optional

from unicorn import Uc, UC_QUERY_ARCH, UC_MODE_64, UC_QUERY_MODE, UC_MEM_READ, UC_PROT_NONE, UC_PROT_READ, UC_PROT_EXEC, \
    UC_PROT_WRITE
from unicorn.x86_const import UC_X86_REG_RCX, UC_X86_REG_RAX, UC_X86_REG_RSP, UC_X86_REG_RDX, UC_X86_REG_R8D, \
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RIP

from utils import pack_int64, read_int32, pack_int32, read_int64, pack_int16, read_int16, pack_int8, read_uint64, \
    read_uint32, pack_int128, pack_uint64, pack_uint32

log_file = open("api_log.txt", "w")

_FILETIME_null_date = datetime.datetime(1601, 1, 1)

file_handles: Dict[int, Union[BinaryIO, TextIO]] = {}
next_file_handle = 0
dir_handles: Dict[int, str] = {}
next_dir_handle = 0
file_mappings: Dict[int, int] = {}
file_mappings_name: Dict[int, str] = {}
next_file_mapping = 0
mutexes: Dict[int, str] = {}
next_mutex = 0
events: Dict[int, bool] = {}
events_name: Dict[int, str]
next_event = 0
addr_mappings: Dict[int, int] = {}
fibers: List[List[Any]] = [[]]
fiber = 0
threads: List[List[Any]] = [[]]
thread = 0
lasterror = 0
dynamic_imports: dict[str, int] = {}
start_time = time.time()
last_time = start_time
module_handles: dict[str, int] = {}
valloc_size: dict[int, int] = {}

printf_re = re.compile(r"%(?P<flags>[-+ #0]*)(?P<width>\d+|\*)?(?:\.(?P<precision>\d+|\*))?(?P<length>hh|h|l|ll|j|z|t|L|I64)?(?P<specifier>[%csdioxXufFeEaAgGnp])")

def log(u: Uc, s: str):
    print(f"{datetime.datetime.now()} {u.__getattribute__('inst_count')} {hex(read_int64(u.mem_read(u.reg_read(UC_X86_REG_RSP), 8)))} {s}", file=log_file, flush=True)

def error(value: int):
    # TODO: TEB lasterror
    global lasterror
    lasterror = value

def epoch_to_filetime(epoch: float) -> int:
    return int(epoch * 10000000 + 116444736000000000)

def filetime_to_epoch(filetime: int) -> float:
    return (filetime - 116444736000000000) / 10000000

def write_systemtime(u: Uc, addr: int, utc: bool, start: bool):
    # typedef struct _SYSTEMTIME {
    #   WORD wYear;
    #   WORD wMonth;
    #   WORD wDayOfWeek;
    #   WORD wDay;
    #   WORD wHour;
    #   WORD wMinute;
    #   WORD wSecond;
    #   WORD wMilliseconds;
    # } SYSTEMTIME, *PSYSTEMTIME;
    global last_time
    if not start:
        date = datetime.datetime.utcfromtimestamp(last_time)
    else:
        date = datetime.datetime.utcfromtimestamp(start_time)
    if not utc:
        date = date.replace(tzinfo=datetime.timezone.utc).astimezone()
    u.mem_write(addr, pack_int16(date.year))
    u.mem_write(addr + 2, pack_int16(date.month))
    u.mem_write(addr + 4, pack_int16(date.weekday()))
    u.mem_write(addr + 6, pack_int16(date.day))
    u.mem_write(addr + 8, pack_int16(date.hour))
    u.mem_write(addr + 10, pack_int16(date.minute))
    u.mem_write(addr + 12, pack_int16(date.second))
    u.mem_write(addr + 14, pack_int16(date.microsecond // 1000))
    last_time += random.randint(10, 1000) / 1000000
    return date

def read_stack_param(u: Uc, index: int):
    if u.query(UC_QUERY_MODE) == UC_MODE_64:
        return read_uint64(u.mem_read(u.reg_read(UC_X86_REG_RSP) + 0x28 + 8 * index, 8))
    else:
        return read_uint32(u.mem_read(u.reg_read(UC_X86_REG_RSP) + 0x14 + 4 * index, 4))

def alloc_memory(alloc_list: list[tuple[int, int]], size: int) -> Optional[int]:
    if size % 4096 != 0:
        size = (size // 4096 + 1) * 4096
    for block in alloc_list:
        if block[1] >= size:
            res = block[0]
            alloc_list.append((block[0] + size, block[1] - size))
            alloc_list.remove(block)
            alloc_list.sort(key=lambda b: b[0])
            return res
    return None

def enlarge_memory(u: Uc, alloc_list: list[tuple[int, int]], size):
    blocks = size // 0x100000 + 1
    last_block = alloc_list[-1]
    last_address = last_block[0] + last_block[1]
    alloc_list.remove(last_block)
    alloc_list.append((last_block[0], last_block[1] + 0x100000 * blocks))
    u.mem_map(last_address, 0x100000 * blocks)

def dealloc_memory(alloc_list: list[tuple[int, int]], start: int, size: int):
    if start % 4096 != 0:
        start = (start // 4096) * 4096
    if size % 4096 != 0:
        size = (size // 4096 + 1) * 4096
    alloc_list.append((start, size))
    alloc_list.sort(key=lambda b: b[0])
    last = (0, 0)
    d = []
    for block in alloc_list:
        if last[0] + last[1] == block[0]:
            d.append(last)
            d.append(block)
            alloc_list.append((last[0], last[1] + block[1]))
            last = (last[0], last[1] + block[1])
        else:
            last = block
    alloc_list.sort(key=lambda b: b[0])
    for block in d:
        alloc_list.remove(block)

def GetSystemTimeAsFileTime(u: Uc):
    # void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
    lpSystemTimeAsFileTime = u.reg_read(UC_X86_REG_RCX)
    u.mem_write(lpSystemTimeAsFileTime, pack_int64(epoch_to_filetime(time.time())))
    log(u, "GetSystemTimeAsFileTime(%#x)" % lpSystemTimeAsFileTime)

def GetCurrentProcessId(u: Uc):
    # DWORD GetCurrentProcessId()
    u.reg_write(UC_X86_REG_RAX, 0x100)
    log(u, "GetCurrentProcessId() => %d" % u.reg_read(UC_X86_REG_RAX))

def GetCurrentThreadId(u: Uc):
    # DWORD GetCurrentThreadId()
    u.reg_write(UC_X86_REG_RAX, 0x100)
    log(u, "GetCurrentThreadId() => %d" % u.reg_read(UC_X86_REG_RAX))

def GetCurrentThread(machine):
    # HANDLE GetCurrentThread();
    machine.cpu.state.rax.value = 0
    log(machine, "GetCurrentThread() => %d" % machine.cpu.state.rax.value)

def GetThreadTimes(machine):
    # BOOL GetThreadTimes( HANDLE hThread, LPFILETIME lpCreationTime, LPFILETIME lpExitTime, LPFILETIME lpKernelTime, LPFILETIME lpUserTime );
    hThread = machine.cpu.state.rcx
    lpCreationTime = machine.cpu.state.rdx
    lpExitTime = machine.cpu.state.r8
    lpKernelTime = machine.cpu.state.r9
    lpUserTime = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    time = pack_int64(int((datetime.datetime.utcnow() - _FILETIME_null_date).total_seconds() * 10000000))
    machine.memory.write(lpCreationTime, time)
    machine.memory.write(lpExitTime, time)
    machine.memory.write(lpKernelTime, time)
    machine.memory.write(lpUserTime, time)
    machine.cpu.state.rax.value = 1
    log(machine, "GetThreadTimes(%#x, %#x, %#x, %#x, %#x) => %d" % (
        hThread.value, lpCreationTime.value, lpExitTime.value, lpKernelTime.value,
        lpUserTime, machine.cpu.state.rax.value
    ))
    error(0)

def GetTickCount(machine):
    # DWORD GetTickCount()
    machine.cpu.state.rax.value = 3600000
    log(machine, "GetTickCount() => %d" % machine.cpu.state.rax.value)

def QueryPerformanceCounter(u: Uc):
    # BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
    lpPerformanceCount = u.reg_read(UC_X86_REG_RCX)
    now = int(time.time() * 10000000)
    u.mem_write(lpPerformanceCount, pack_int64(now))
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "QueryPerformanceCounter(%#x) => %d (%d)" % (
        lpPerformanceCount, u.reg_read(UC_X86_REG_RAX), now
    ))
    error(0)

def QueryPerformanceFrequency(machine):
    # BOOL QueryPerformanceFrequency( LARGE_INTEGER *lpFrequency );
    lpFrequency = machine.cpu.state.rcx
    machine.memory.write(lpFrequency, pack_int64(10000000))
    machine.cpu.state.rax.value = 1
    log(machine, "QueryPerformanceFrequency(%#x) => %d" % (lpFrequency.value, machine.cpu.state.rax.value))
    error(0)

def SetUnhandledExceptionFilter(u: Uc):
    # LPTOP_LEVEL_EXCEPTION_FILTER __stdcall SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
    lpTopLevelExceptionFilter = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "SetUnhandledExceptionFilter(%#x) => %d" % (lpTopLevelExceptionFilter, 0))

def GetModuleHandle(u: Uc, a: bool, ex: bool, lpModuleName, dwFlags, phModule):
    if ex:
        function_name = "GetModuleHandleExA" if a else "GetModuleHandleExW"
    else:
        function_name = "GetModuleHandleA" if a else "GetModuleHandleW"
    if lpModuleName == 0:
        if u.query(UC_QUERY_MODE) == UC_MODE_64:
            handle = 0x140000000
        else:
            handle = 0x400000
        if a:
            buf = b"NULL"
        else:
            buf = "NULL".encode("utf-16le")
    else:
        tmp = u.reg_read(UC_X86_REG_RCX)
        u.reg_write(UC_X86_REG_RCX, lpModuleName)
        if a:
            strlen(u)
        else:
            wcslen(u)
        u.reg_write(UC_X86_REG_RCX, tmp)
        size = u.reg_read(UC_X86_REG_RAX) * (1 if a else 2)
        buf = u.mem_read(lpModuleName, size)
        name = (buf.decode() if a else buf.decode("utf-16le")).lower()
        if name in module_handles:
            handle = module_handles[name]
        else:
            if name == "ntdll.dll":
                handle = 0x40000000
                do_map = True
                for mem in u.mem_regions():
                    if mem[0] <= 0x40000000 <= mem[1]:
                        do_map = False
                        break
                if do_map:
                    data = open("ntdll.dll", "rb").read()
                    u.mem_map(0x40000000, 0x100000)
                    u.mem_write(0x40000000, data)
            else:
                handle = 0x60000000 + len(module_handles) * 0x100000
                u.mem_map(handle, 0x100000)
            module_handles[name] = handle
    if ex:
        u.mem_write(phModule, pack_int64(handle))
        u.reg_write(UC_X86_REG_RAX, 1)
        log(u, f"{function_name}({dwFlags:#x}, \"{buf.decode()}\", {phModule:#x}) => 1 ({handle:#x})")
    else:
        u.reg_write(UC_X86_REG_RAX, handle)
        log(u, f"{function_name}(\"{buf.decode()}\") => {handle:#x}")
    error(0)

def GetModuleHandleA(u: Uc):
    # HMODULE GetModuleHandleA(LPCSTR lpModuleName)
    return GetModuleHandle(u, True, False,  u.reg_read(UC_X86_REG_RCX), 0, 0)

def GetModuleHandleW(u: Uc):
    # HMODULE GetModuleHandleW(LPCWSTR lpModuleName)
    return GetModuleHandle(u, False, False, u.reg_read(UC_X86_REG_RCX), 0, 0)

def GetModuleHandleExA(u: Uc):
    # BOOL GetModuleHandleExA( DWORD dwFlags, LPCSTR lpModuleName, HMODULE *phModule );
    dwFlags = u.reg_read(UC_X86_REG_RCX)
    lpModuleName = u.reg_read(UC_X86_REG_RDX)
    phModule = u.reg_read(UC_X86_REG_R8)
    return GetModuleHandle(u, True, True, lpModuleName, dwFlags, phModule)

def GetModuleHandleExW(u: Uc):
    # BOOL GetModuleHandleExW( DWORD dwFlags, LPCWSTR lpModuleName, HMODULE *phModule );
    dwFlags = u.reg_read(UC_X86_REG_RCX)
    lpModuleName = u.reg_read(UC_X86_REG_RDX)
    phModule = u.reg_read(UC_X86_REG_R8)
    return GetModuleHandle(u, False, True, lpModuleName, dwFlags, phModule)

def GetProcAddress(u: Uc):
    # FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    hModule = u.reg_read(UC_X86_REG_RCX)
    lpProcName = u.reg_read(UC_X86_REG_RDX)
    module = "UNKNOWN"
    for k, v in module_handles.items():
        if v == hModule:
            module = k
            break
    tmp = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RCX, lpProcName)
    strlen(u)
    u.reg_write(UC_X86_REG_RCX, tmp)
    size = u.reg_read(UC_X86_REG_RAX)
    proc = u.mem_read(lpProcName, size).decode()
    found = False
    for func in api_list:
        if proc == func.__name__:
            found = True
            break
    if not found:
        log(u, f"NOT IMPLEMENTED {module} {proc}")
        # raise NotImplementedError
    if proc in dynamic_imports:
        handle = dynamic_imports[proc]
    else:
        pos = len(u.__getattribute__("dynamic_imports"))
        module_handle = module_handles[module]
        handle = module_handle + 0x1000 + 0x40 * pos
        u.mem_write(handle, pack_int64(pos * 256 + 7))
        u.__getattribute__("dynamic_imports").append(proc)
        dynamic_imports[proc] = handle
    u.reg_write(UC_X86_REG_RAX, handle)
    log(u, "GetProcAddress(\"%s\", \"%s\") => %#x" % (module, proc, handle))
    error(0)

mem_protect_u_w = {
    UC_PROT_NONE: 0x01,
    UC_PROT_READ: 0x02,
    UC_PROT_READ | UC_PROT_WRITE: 0x04,
    UC_PROT_READ | UC_PROT_EXEC: 0x20,
    UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC: 0x40,
}

mem_protect_w_u = {
    0x01: UC_PROT_NONE,
    0x02: UC_PROT_READ,
    0x04: UC_PROT_READ | UC_PROT_WRITE,
    0x20: UC_PROT_READ | UC_PROT_EXEC,
    0x40: UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
}

def VirtualProtect(u: Uc):
    # BOOL VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
    lpAddress = u.reg_read(UC_X86_REG_RCX)
    dwSize = u.reg_read(UC_X86_REG_RDX)
    flNewProtect = u.reg_read(UC_X86_REG_R8)
    lpflOldProtect = u.reg_read(UC_X86_REG_R9)
    if 0x10000000 <= lpAddress <= 0x40000000:
        # conflict with current simplified memory alloc model
        raise NotImplementedError
    for mem in u.mem_regions():
        if mem[0] <= lpAddress <= mem[1]:
            old_protect = mem_protect_u_w[mem[2]]
            u.mem_write(lpflOldProtect, pack_int32(old_protect))
            u.mem_protect(lpAddress, dwSize, mem_protect_w_u[flNewProtect])
            u.reg_write(UC_X86_REG_RAX, 1)
            log(u, "VirtualProtect(%#x, %#x, %#x, %#x) => %d" % (
                lpAddress, dwSize, flNewProtect, lpflOldProtect, u.reg_read(UC_X86_REG_RAX)
            ))
            error(0)
            return
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "VirtualProtect(%#x, %#x, %#x, %#x) => %d" % (
        lpAddress, dwSize, flNewProtect, lpflOldProtect, u.reg_read(UC_X86_REG_RAX)
    ))
    error(6)


def GetModuleFileNameW(u: Uc):
    # DWORD GetModuleFileNameW( HMODULE hModule, LPWSTR lpFilename, DWORD nSize );
    hModule = u.reg_read(UC_X86_REG_RCX)
    lpFilename = u.reg_read(UC_X86_REG_RDX)
    nSize = u.reg_read(UC_X86_REG_R8)
    if hModule == (0x140000000 if u.query(UC_QUERY_MODE) == UC_MODE_64 else 0x400000) or hModule == 0:
        tmp = u.reg_read(UC_X86_REG_RCX)
        u.reg_write(UC_X86_REG_RCX, 0x10100)
        strlen(u)
        u.reg_write(UC_X86_REG_RCX, tmp)
        size = u.reg_read(UC_X86_REG_RAX)
        filename = u.mem_read(0x10100, size).decode()
        if size > nSize:
            filename = filename[:nSize]
            size = nSize
        data = filename.encode("utf-16le")
        u.mem_write(lpFilename, data + b"\x00\x00")
        u.reg_write(UC_X86_REG_RAX, size)
        log(u, "GetModuleFileNameW(%#x, %#x, %d) => %d (\"%s\")" %(
            hModule, lpFilename, nSize, size, filename
        ))
        error(0)
    else:
        u.reg_write(UC_X86_REG_RAX, 0)
        log(u, "GetModuleFileNameW(%#x, %#x, %d) => %d" % (
            hModule, lpFilename, nSize, 0
        ))
        raise NotImplementedError

def GetModuleFileNameA(u: Uc):
    # DWORD GetModuleFileNameA( HMODULE hModule, LPSTR lpFilename, DWORD nSize );
    hModule = u.reg_read(UC_X86_REG_RCX)
    lpFilename = u.reg_read(UC_X86_REG_RDX)
    nSize = u.reg_read(UC_X86_REG_R8)
    filename = None
    if hModule == 0 or hModule == (0x140000000 if u.query(UC_QUERY_MODE) == UC_MODE_64 else 0x400000):
        tmp = u.reg_read(UC_X86_REG_RCX)
        u.reg_write(UC_X86_REG_RCX, 0x10100)
        strlen(u)
        u.reg_write(UC_X86_REG_RCX, tmp)
        size = u.reg_read(UC_X86_REG_RAX)
        filename = u.mem_read(0x10100, size).decode()
    else:
        raise NotImplementedError
    err = 0
    if filename is None:
        err = 6
        size = 0
    else:
        size = len(filename)
        if size > nSize:
            filename = filename[:nSize - 1]
            size = nSize
            err = 122
        data = filename.encode()
        u.mem_write(lpFilename, data + b"\x00")
    u.reg_write(UC_X86_REG_RAX, size)
    log(u, "GetModuleFileNameW(%#x, %#x, %d) => %d (\"%s\")" % (
        hModule, lpFilename, nSize, size, filename
    ))
    error(err)

def CreateFile(u: Uc, a: bool):
    function_name = "CreateFileA" if a else "CreateFileW"
    lpFileName = u.reg_read(UC_X86_REG_RCX)
    dwDesiredAccess = u.reg_read(UC_X86_REG_RDX)
    dwShareMode = u.reg_read(UC_X86_REG_R8)
    lpSecurityAttributes = u.reg_read(UC_X86_REG_R9)
    dwCreationDisposition = read_stack_param(u, 0)
    dwFlagsAndAttributes = read_stack_param(u, 1)
    hTemplateFile = read_stack_param(u, 2)
    if a:
        strlen(u)
    else:
        wcslen(u)
    size = u.reg_read(UC_X86_REG_RAX)
    if a:
        filename = u.mem_read(lpFileName, size).decode()
    else:
        filename = u.mem_read(lpFileName, size * 2).decode("utf-16le")
    if dwFlagsAndAttributes & 0x2000000:
        # try dir
        if os.path.exists(filename):
            global next_dir_handle
            handle = next_dir_handle + 0x40000
            dir_handles[next_dir_handle] = filename
            next_dir_handle += 1
            u.reg_write(UC_X86_REG_RAX, handle)
            log(u, f"{function_name}(\"{filename}\", {dwDesiredAccess:#x}, {dwShareMode}, "
                   f"{lpSecurityAttributes}, {dwCreationDisposition}, {dwFlagsAndAttributes}, "
                   f"{hTemplateFile}) => {u.reg_read(UC_X86_REG_RAX):#x}")
            return
    global next_file_handle
    handle = next_file_handle + 0x10000

    if "\\\\.\\" in filename:
        fs_filename = filename.replace("\\\\.\\", "c:\\temp\\")
    else:
        fs_filename = filename
    mode = ""
    write = False
    failed = False
    exist = False
    err = 0
    if dwDesiredAccess & 0x40000000:
        write = True
    if os.path.exists(filename):
        exist = True
    if dwCreationDisposition == 1:
        if exist:
            err = 80
            failed = True
        else:
            mode = "wb" if write else "rb"
    elif dwCreationDisposition == 2:
        mode = "wb"
        if exist:
            err = 183
    elif dwCreationDisposition == 3:
        if "\\\\.\\" in filename:
            mode = "ab+"
        else:
            mode = "rb+" if write else "rb"
            if not exist:
                err = 2
                failed = True
    elif dwCreationDisposition == 4:
        mode = "rb+" if write else "rb"
        if not exist:
            err = 183
    elif dwCreationDisposition == 5:
        if not exist:
            err = 2
            failed = True
        else:
            mode = "wb"

    if not failed:
        try:
            file = open(fs_filename, mode)
            file_handles[next_file_handle] = file
            next_file_handle += 1
            u.reg_write(UC_X86_REG_RAX, handle)
            err = 0
        except:
            u.reg_write(UC_X86_REG_RAX, -1)
            err = 2
    else:
        u.reg_write(UC_X86_REG_RAX, -1)
    log(u, f"{function_name}(\"{filename}\", {dwDesiredAccess:#x}, {dwShareMode}, "
           f"{lpSecurityAttributes}, {dwCreationDisposition}, {dwFlagsAndAttributes}, "
           f"{hTemplateFile}) => {u.reg_read(UC_X86_REG_RAX):#x}")
    error(err)

def CreateFileW(u: Uc):
    # HANDLE CreateFileW( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    # LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    # HANDLE hTemplateFile );
    return CreateFile(u, False)

def CreateFileA(u: Uc):
    # HANDLE CreateFileA( LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    # LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    # HANDLE hTemplateFile );
    return CreateFile(u, True)

def CreateFileMappingA(u: Uc):
    # HANDLE CreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
    # DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName );
    hFile = u.reg_read(UC_X86_REG_RCX)
    lpFileMappingAttributes = u.reg_read(UC_X86_REG_RDX)
    flProtect = u.reg_read(UC_X86_REG_R8)
    dwMaximumSizeHigh = u.reg_read(UC_X86_REG_R9)
    rsp = u.reg_read(UC_X86_REG_RSP)
    dwMaximumSizeLow = read_int64(u.mem_read(rsp + 0x28, 8))
    lpName = read_int64(u.mem_read(rsp + 0x30, 8))
    if dwMaximumSizeHigh or dwMaximumSizeLow:
        raise NotImplementedError
    if file_handles.get(hFile - 0x10000) is None:
        raise ValueError
    global next_file_mapping
    handle = next_file_mapping + 0x20000
    if lpName != 0:
        tmp = u.reg_read(UC_X86_REG_RCX)
        u.reg_write(UC_X86_REG_RCX, lpName)
        strlen(u)
        u.reg_write(UC_X86_REG_RCX, tmp)
        size = u.reg_read(UC_X86_REG_RAX)
        mapping_name = u.mem_read(lpName, size).decode()
    else:
        mapping_name = "\0"
    if mapping_name != "\0" and mapping_name in file_mappings_name.values():
        for k, v in file_mappings_name.items():
            if v == mapping_name:
                handle = k
                u.reg_write(UC_X86_REG_RAX, handle)
                log(u, "CreateFileMappingA(%#x(\"%s\"), %#x, %#x, %#x, %#x, \"%s\") => %#x" % (
                    hFile, file_handles[hFile - 0x10000].name, lpFileMappingAttributes, flProtect,
                    dwMaximumSizeHigh, dwMaximumSizeLow, mapping_name, u.reg_read(UC_X86_REG_RAX)
                ))
                error(183)
                return
    file_mappings[next_file_mapping] = hFile - 0x10000
    file_mappings_name[next_file_mapping] = mapping_name
    next_file_mapping += 1
    u.reg_write(UC_X86_REG_RAX, handle)
    log(u, "CreateFileMappingA(%#x(\"%s\"), %#x, %#x, %#x, %#x, \"%s\") => %#x" % (
        hFile, file_handles[hFile - 0x10000].name, lpFileMappingAttributes, flProtect,
        dwMaximumSizeHigh, dwMaximumSizeLow, mapping_name, u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def CreateFileMappingW(machine):
    # HANDLE CreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
    # DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName );
    hFile = machine.cpu.state.rcx
    lpFileMappingAttributes = machine.cpu.state.rdx
    flProtect = machine.cpu.state.r8
    dwMaximumSizeHigh = machine.cpu.state.r9
    dwMaximumSizeLow = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    lpName = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    file_size = 0
    if dwMaximumSizeHigh.value or dwMaximumSizeLow:
        file_size = (dwMaximumSizeHigh.value << 32) + dwMaximumSizeLow
    page = False
    if hFile.value == 0xFFFFFFFFFFFFFFFF:
        page = True
    elif file_handles.get(hFile.value - 0x10000) is None:
        raise ValueError
    global next_file_mapping
    handle = next_file_mapping + 0x20000
    if page:
        file_mappings[next_file_mapping] = 0x100000000 + file_size
        filename = "Pagefile"
    else:
        file_mappings[next_file_mapping] = hFile.value - 0x10000
        filename = file_handles[hFile.value - 0x10000].name
    if lpName != 0:
        tmp = machine.cpu.state.rcx.value
        machine.cpu.state.rcx.value = lpName
        wcslen(machine)
        machine.cpu.state.rcx.value = tmp
        size = machine.cpu.state.rax.value
        mapping_name = machine.memory.read(lpName, size * 2).decode("utf-16le")
    else:
        mapping_name = "\0"
    file_mappings_name[next_file_mapping] = mapping_name
    next_file_mapping += 1
    machine.cpu.state.rax.value = handle
    log(machine, "CreateFileMappingW(%#x(\"%s\"), %#x, %#x, %#x, %#x, \"%s\") => %#x" % (
        hFile.value, filename, lpFileMappingAttributes.value, flProtect.value,
        dwMaximumSizeHigh.value, dwMaximumSizeLow, mapping_name, machine.cpu.state.rax.value
    ))
    error(0)

def OpenFileMappingW(machine):
    # HANDLE OpenFileMappingW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName );
    dwDesiredAccess = machine.cpu.state.rcx
    bInheritHandle = machine.cpu.state.rdx
    lpName = machine.cpu.state.r8
    machine.cpu.state.rcx.value = lpName
    wcslen(machine)
    size = machine.cpu.state.rax.value
    name = machine.memory.read(lpName, size * 2).decode("utf-16le")
    res = 0
    err = 2
    for k, v in file_mappings_name.items():
        if v == name:
            res = k + 0x20000
            err = 0
            break
    machine.cpu.state.rax.value = res
    log(machine, "OpenFileMappingW(%#x, %#x, \"%s\") => %#x" % (
        dwDesiredAccess.value, bInheritHandle.value, name, machine.cpu.state.rax.value
    ))
    error(err)

def MapViewOfFile(u: Uc):
    # LPVOID MapViewOfFile( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap );
    hFileMappingObject = u.reg_read(UC_X86_REG_RCX)
    dwDesiredAccess = u.reg_read(UC_X86_REG_RDX)
    dwFileOffsetHigh = u.reg_read(UC_X86_REG_R8)
    dwFileOffsetLow = u.reg_read(UC_X86_REG_R9)
    dwNumberOfBytesToMap = read_stack_param(u, 0)
    handle = hFileMappingObject - 0x20000
    if file_mappings.get(handle) is None:
        raise ValueError
    offset = (dwFileOffsetHigh << 32) + dwFileOffsetLow
    if file_mappings[handle] < 0x100000000:
        file = file_handles[file_mappings[handle]]
        file.seek(offset, SEEK_SET)
        if dwNumberOfBytesToMap == 0:
            data = file.read()
        else:
            raise NotImplementedError
        name = file_mappings_name[handle]
    else:
        data = bytearray([0]) * (file_mappings[handle] & 0xffffffff)
        name = "Pagefile %#x" % handle

    if dwNumberOfBytesToMap == 0:
        size = len(data)
    else:
        size = dwNumberOfBytesToMap
    if size % 4096 != 0:
        size = (size // 4096 + 1) * 4096

    free_map: list[tuple[int, int]] = u.__getattribute__("free_map")
    res = alloc_memory(free_map, size)
    if res is None:
        u.reg_write(UC_X86_REG_RAX, 0)
        log(u, "MapViewOfFile(%#x(%#x, \"%s\"), %#x, %#x, %#x, %d) => %#x" % (
            hFileMappingObject, file_mappings[handle], name, dwDesiredAccess, dwFileOffsetHigh,
            dwFileOffsetLow, dwNumberOfBytesToMap, 0
        ))
        error(8)
        return
    u.mem_map(res, size)
    u.mem_write(res, data)

    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "MapViewOfFile(%#x(%#x, \"%s\"), %#x, %#x, %#x, %d) => %#x" % (
        hFileMappingObject, file_mappings[handle], name, dwDesiredAccess, dwFileOffsetHigh,
        dwFileOffsetLow, dwNumberOfBytesToMap, res
    ))
    error(0)

def UnmapViewOfFile(u: Uc):
    # BOOL UnmapViewOfFile( LPCVOID lpBaseAddress );
    lpBaseAddress = u.reg_read(UC_X86_REG_RCX)
    if 0x30000000 <= lpBaseAddress < 0x40000000:
        for start, end, _ in u.mem_regions():
            size = end - start + 1
            if start == lpBaseAddress:
                u.mem_unmap(start, size)
                free_map = u.__getattribute__("free_map")
                dealloc_memory(free_map, start, size)
                u.reg_write(UC_X86_REG_RAX, 1)
                log(u, "UnmapViewOfFile(%#x) => %d" % (lpBaseAddress, u.reg_read(UC_X86_REG_RAX)))
                error(0)
                return

    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "UnmapViewOfFile(%#x => %d" % (lpBaseAddress, 0))
    error(487)

def CloseHandle(u: Uc):
    # BOOL CloseHandle( HANDLE hObject );
    hObject = u.reg_read(UC_X86_REG_RCX)
    handle = hObject & 0xffff
    if hObject & 0x10000:
        if file_handles.get(handle) is None:
            raise ValueError
        file_handles[handle].close()
        del file_handles[handle]
        # log(machine, "CloseHandle file handle %#x" % hObject.value)
    elif hObject & 0x20000:
        if file_mappings.get(handle) is None:
            raise ValueError
        del file_mappings[handle]
        # log(machine, "CloseHandle file mapping %#x" % hObject.value)
    elif hObject & 0x40000:
        if dir_handles.get(handle) is None:
            raise ValueError
        del dir_handles[handle]
        # log(machine, "CloseHandle dir handle %#x" % hObject.value)
    elif hObject & 0x80000:
        if mutexes.get(handle) is None:
            raise ValueError
        name = mutexes[handle]
        del mutexes[handle]
        # log(machine, "CloseHandle mutex %s" % name)
    else:
        raise NotImplementedError
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "CloseHandle(%#x) => %d" % (hObject, u.reg_read(UC_X86_REG_RAX)))
    error(0)

def Beep(machine):
    # BOOL Beep( DWORD dwFreq, DWORD dwDuration );
    dwFreq = machine.cpu.state.rcx
    dwDuration = machine.cpu.state.rdx
    machine.cpu.state.rax.value = 1
    log(machine, "Beep(%d, %d) => %d" % (dwFreq.value, dwDuration.value, machine.cpu.state.rax.value))
    error(0)

def LoadLibrary(u: Uc, a: bool, ex: bool, hFile, dwFlags):
    if a:
        function_name = "LoadLibraryExA" if ex else "LoadLibraryA"
    else:
        function_name = "LoadLibraryExW" if ex else "LoadLibraryW"
    lpLibFileName = u.reg_read(UC_X86_REG_RCX)
    hFile = u.reg_read(UC_X86_REG_RDX)
    dwFlags = u.reg_read(UC_X86_REG_R8)
    if a:
        strlen(u)
    else:
        wcslen(u)
    size = u.reg_read(UC_X86_REG_RAX) * (1 if a else 2)
    buffer = u.mem_read(lpLibFileName, size)
    filename = buffer.decode() if a else buffer.decode("utf-16le")
    if filename in module_handles:
        handle = module_handles[filename]
    else:
        if filename == "ntdll.dll":
            handle = 0x40000000
            do_map = True
            for mem in u.mem_regions():
                if mem[0] <= 0x40000000 <= mem[1]:
                    do_map = False
                    break
            if do_map:
                data = open("ntdll.dll", "rb").read()
                u.mem_map(0x40000000, 0x100000)
                u.mem_write(0x40000000, data)
        else:
            handle = 0x60000000 + len(module_handles) * 0x100000
            u.mem_map(handle, 0x100000)
        module_handles[filename] = handle
    u.reg_write(UC_X86_REG_RAX, handle)
    if not ex:
        log(u, "%s(\"%s\") => %#x" % (function_name, filename, handle))
    else:
        log(u, "%s(\"%s\", %#x, %#x) => %#x" % (function_name, filename, hFile, dwFlags, handle))
    error(0)

def LoadLibraryA(machine):
    # HMODULE LoadLibraryA( LPCSTR lpLibFileName );
    return LoadLibrary(machine, True, False, 0, 0)

def LoadLibraryExW(u: Uc):
    # HMODULE LoadLibraryExW( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags );
    return LoadLibrary(u, False, True, u.reg_read(UC_X86_REG_RDX), u.reg_read(UC_X86_REG_R8))

def TerminateProcess(machine):
    # BOOL TerminateProcess( HANDLE hProcess, UINT uExitCode );
    hProcess = machine.cpu.state.rcx
    uExitCode = machine.cpu.state.rdx
    log(machine, "TerminateProcess(%#x, %d) => %d" % (hProcess.value, uExitCode.value, machine.cpu.state.rax.value))
    raise NotImplementedError

def GetCurrentProcess(machine):
    # HANDLE GetCurrentProcess();
    machine.cpu.state.rax.value = 0xffffffffffffffff
    log(machine, "GetCurrentProcess() => %#x" % machine.cpu.state.rax.value)

def UnhandledExceptionFilter(machine):
    # LONG UnhandledExceptionFilter( _EXCEPTION_POINTERS *ExceptionInfo );
    ExceptionInfo = machine.cpu.state.rcx
    log(machine, "UnhandledExceptionFilter(%#x) => %d" % (ExceptionInfo, machine.cpu.state.rax.value))
    raise NotImplementedError

def IsDebuggerPresent(u: Uc):
    # BOOL IsDebuggerPresent();
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "IsDebuggerPresent() => %d" % 0)

def GetLocalTime(u: Uc):
    # void GetLocalTime( LPSYSTEMTIME lpSystemTime );
    lpSystemTime = u.reg_read(UC_X86_REG_RCX)
    date = write_systemtime(u, lpSystemTime, False, False)
    log(u, "GetLocalTime(%#x) (%s)" % (lpSystemTime, date))

def SystemTimeToFileTime(u: Uc):
    # BOOL SystemTimeToFileTime( const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime );
    lpSystemTime = u.reg_read(UC_X86_REG_RCX)
    lpFileTime = u.reg_read(UC_X86_REG_RDX)
    year = read_int16(u.mem_read(lpSystemTime + 0, 2))
    month = read_int16(u.mem_read(lpSystemTime + 2, 2))
    day = read_int16(u.mem_read(lpSystemTime + 6, 2))
    hour = read_int16(u.mem_read(lpSystemTime + 8, 2))
    minute = read_int16(u.mem_read(lpSystemTime + 10, 2))
    second = read_int16(u.mem_read(lpSystemTime + 12, 2))
    ms = read_int16(u.mem_read(lpSystemTime + 14, 2))
    date = datetime.datetime(year, month, day, hour, minute, second, ms * 1000)
    u.mem_write(lpFileTime,
                pack_int64(int((date - _FILETIME_null_date).total_seconds() * 10000000)))
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "SystemTimeToFileTime(%#x, %#x) => %d (%s)" % (
        lpSystemTime, lpFileTime, u.reg_read(UC_X86_REG_RAX), date
    ))
    error(0)

def GetTempPathW(u: Uc):
    # DWORD GetTempPathW( DWORD nBufferLength, LPWSTR lpBuffer );
    nBufferLength = u.reg_read(UC_X86_REG_RCX)
    lpBuffer = u.reg_read(UC_X86_REG_RDX)
    filename = "c:\\temp\\".encode("utf-16le")
    u.mem_write(lpBuffer, filename + b"\x00\x00")
    u.reg_write(UC_X86_REG_RAX, 8)
    log(u, "GetTempPathW(%d, %#x) => %d (\"%s\")" % (
        nBufferLength, lpBuffer, 8, "c:\\temp\\"
    ))
    error(0)

def GetVersion(machine):
    # NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion();
    machine.cpu.state.rax.value = 0x0000000a
    log(machine, "GetVersion() => %#x" % machine.cpu.state.rax.value)

def GetVersionExA(u: Uc):
    # BOOL GetVersionExA( LPOSVERSIONINFOA lpVersionInformation );
    lpVersionInformation = u.reg_read(UC_X86_REG_RCX)
    size = read_int32(u.mem_read(lpVersionInformation, 4))
    if size == 148:
        # OSVERSIONINFOA
        u.mem_write(lpVersionInformation + 4, pack_int32(10))
        u.mem_write(lpVersionInformation + 8, pack_int32(0))
        u.mem_write(lpVersionInformation + 12, pack_int32(0))
        u.mem_write(lpVersionInformation + 16, pack_int32(2))
        u.mem_write(lpVersionInformation + 20, b"\x00")
    else:
        # OSVERSIONINFOEXA
        raise NotImplementedError
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "GetVersionExA(%#x) => %d" % (lpVersionInformation, 1))
    error(0)

def GetVersionExW(machine):
    # NOT_BUILD_WINDOWS_DEPRECATE BOOL GetVersionExW( LPOSVERSIONINFOW lpVersionInformation );
    lpVersionInformation = machine.cpu.state.rcx
    size = read_int32(machine.memory.read(lpVersionInformation, 4))
    if size == 276:
        # OSVERSIONINFOW
        machine.memory.write(lpVersionInformation + 4, pack_int32(10))
        machine.memory.write(lpVersionInformation + 8, pack_int32(0))
        machine.memory.write(lpVersionInformation + 12, pack_int32(0))
        machine.memory.write(lpVersionInformation + 16, pack_int32(2))
        machine.memory.write(lpVersionInformation + 20, b"\x00\x00")
    else:
        # OSVERSIONINFOEXW
        raise NotImplementedError
    machine.cpu.state.rax.value = 1
    log(machine, "GetVersionExW(%#x) => %d" % (lpVersionInformation.value, machine.cpu.state.rax.value))
    error(0)

def GetTempFileNameW(u: Uc):
    # UINT GetTempFileNameW( LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName );
    lpPathName = u.reg_read(UC_X86_REG_RCX)
    lpPrefixString = u.reg_read(UC_X86_REG_RDX)
    uUnique = u.reg_read(UC_X86_REG_R8)
    lpTempFileName = u.reg_read(UC_X86_REG_R9)
    wcslen(u)
    total_size = 0
    size = u.reg_read(UC_X86_REG_RAX)
    total_size += size
    buffer = u.mem_read(lpPathName, size * 2)
    pathname = buffer.decode("utf-16le")
    tmp = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RCX, lpPrefixString)
    wcslen(u)
    u.reg_write(UC_X86_REG_RCX, tmp)
    size = u.reg_read(UC_X86_REG_RAX)
    buffer += u.mem_read(lpPrefixString, size * 2)
    prefixstring = u.mem_read(lpPrefixString, size * 2).decode("utf-16le")
    total_size += size + len(str(uUnique))
    u.mem_write(lpTempFileName, bytes(buffer + str(uUnique).encode("utf-16le") + b"\x00\x00"))
    u.reg_write(UC_X86_REG_RAX, total_size)
    log(u, "GetTempFileNameW(\"%s\", \"%s\", %d, %#x) => %d (%s%d)" % (
        pathname, prefixstring, uUnique, lpTempFileName, u.reg_read(UC_X86_REG_RAX),
        buffer.decode("utf-16le"), uUnique
    ))
    error(0)

def DeleteFileW(u: Uc):
    # BOOL DeleteFileW( LPCWSTR lpFileName );
    lpFileName = u.reg_read(UC_X86_REG_RCX)
    wcslen(u)
    size = u.reg_read(UC_X86_REG_RAX)
    buffer = u.mem_read(lpFileName, size * 2)
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "DeleteFileW(\"%s\") => %d" % (buffer.decode("utf-16le"), 0))
    error(2)

def GetVolumeInformationW(u: Uc):
    # BOOL GetVolumeInformationW(
    # LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,
    # LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize );
    lpRootPathName = u.reg_read(UC_X86_REG_RCX)
    lpVolumeNameBuffer = u.reg_read(UC_X86_REG_RDX)
    nVolumeNameSize = u.reg_read(UC_X86_REG_R8)
    lpVolumeSerialNumber = u.reg_read(UC_X86_REG_R9)
    lpMaximumComponentLength = read_stack_param(u, 0)
    lpFileSystemFlags = read_stack_param(u, 1)
    lpFileSystemNameBuffer = read_stack_param(u, 2)
    nFileSystemNameSize = read_stack_param(u, 3)
    if lpVolumeNameBuffer != 0:
        raise NotImplementedError
    if lpVolumeSerialNumber != 0:
        u.mem_write(lpVolumeSerialNumber, pack_int32(0x0123ab67))
    u.mem_write(lpMaximumComponentLength, pack_int32(255))
    u.mem_write(lpFileSystemFlags, pack_int32(0x4))
    if lpFileSystemNameBuffer != 0:
        raise NotImplementedError
    wcslen(u)
    size = u.reg_read(UC_X86_REG_RAX)
    buffer = u.mem_read(lpRootPathName, size * 2)
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "GetVolumeInformationW(\"%s\", %#x, %d, %#x, %#x, %#x, %#x, %d) => %d" % (
        buffer.decode("utf-16le"), lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber,
        lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize,
        1
    ))
    error(0)

def GetSystemTime(u: Uc):
    # void GetSystemTime( LPSYSTEMTIME lpSystemTime );
    # UTC
    lpSystemTime = u.reg_read(UC_X86_REG_RCX)
    date = write_systemtime(u, lpSystemTime, True, False)
    log(u, "GetSystemTime(%#x) (%s)" % (lpSystemTime, date))

def GetFileTime(u: Uc):
    # BOOL GetFileTime( HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime );
    hFile = u.reg_read(UC_X86_REG_RCX)
    lpCreationTime = u.reg_read(UC_X86_REG_RDX)
    lpLastAccessTime = u.reg_read(UC_X86_REG_R8)
    lpLastWriteTime = u.reg_read(UC_X86_REG_R9)
    if hFile & 0x10000:
        raise NotImplementedError
    elif hFile & 0x40000:
        filename = dir_handles[hFile % 0x40000]
    else:
        raise ValueError
    if lpCreationTime:
        u.mem_write(lpCreationTime, pack_int128(epoch_to_filetime(start_time - 3600)))
        # u.mem_write(lpCreationTime, pack_int128(133170480000000000))
    if lpLastAccessTime:
        raise NotImplementedError
    if lpLastWriteTime:
        raise NotImplementedError
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "GetFileTime(%#x(\"%s\"), %#x, %#x, %#x) => %d" % (
        hFile, filename, lpCreationTime, lpLastAccessTime, lpLastWriteTime,
        1
    ))
    error(0)

def GetFullPathNameW(u: Uc):
    # DWORD GetFullPathNameW( LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart );
    lpFileName = u.reg_read(UC_X86_REG_RCX)
    nBufferLength = u.reg_read(UC_X86_REG_RDX)
    lpBuffer = u.reg_read(UC_X86_REG_R8)
    lpFilePart = u.reg_read(UC_X86_REG_R9)
    wcslen(u)
    size = u.reg_read(UC_X86_REG_RAX)
    filename = u.mem_read(lpFileName, size * 2).decode("utf-16le")
    if len(filename) + 1 > nBufferLength:
        raise ValueError
    if os.path.isdir(filename):
        u.mem_write(lpBuffer, filename.encode("utf-16le") + b"\x00\x00")
        if lpFilePart:
            u.mem_write(lpFilePart, b"\x00\x00")
    u.mem_write(lpBuffer, filename.encode("utf-16le") + b"\x00\x00")
    if lpFilePart:
        if os.path.isdir(filename):
            u.mem_write(lpFilePart, pack_int64(0))
        else:
            try:
                pos = filename.rindex("/")
            except ValueError:
                pos = filename.rindex("\\")
            u.mem_write(lpFilePart, pack_int64(lpBuffer + pos * 2 + 2))
    if "/" in filename:
        u.reg_write(UC_X86_REG_RAX, len(filename.split("/")[:-1]))
    else:
        u.reg_write(UC_X86_REG_RAX, len(filename.split("\\")[:-1]))
    log(u, "GetFullPathNameW(\"%s\", %d, %#x, %#x) => %d" % (
        filename, nBufferLength, lpBuffer, lpFilePart, u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def VirtualAlloc(u: Uc):
    # LPVOID VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
    lpAddress = u.reg_read(UC_X86_REG_RCX)
    dwSize = u.reg_read(UC_X86_REG_RDX)
    flAllocationType = u.reg_read(UC_X86_REG_R8)
    flProtect = u.reg_read(UC_X86_REG_R9)
    if not flAllocationType & 0x00001000:
        raise NotImplementedError
    if lpAddress == 0:
        free_alloc = u.__getattribute__("free_alloc")
        res = alloc_memory(free_alloc, dwSize)
        if res is None:
            # add more to the heap
            enlarge_memory(u, free_alloc, dwSize)
            res = alloc_memory(free_alloc, dwSize)
    else:
        raise NotImplementedError
    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "VirtualAlloc(%#x, %d, %#x, %#x) => %#x" % (
        lpAddress, dwSize, flAllocationType, flProtect, res
    ))
    if res == 0:
        error(8)
    else:
        valloc_size[res] = dwSize
        error(0)

def VirtualFree(u: Uc):
    # BOOL VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );
    lpAddress = u.reg_read(UC_X86_REG_RCX)
    dwSize = u.reg_read(UC_X86_REG_RDX)
    dwFreeType = u.reg_read(UC_X86_REG_R8)
    if dwFreeType != 0x00008000:
        raise NotImplementedError
    free_alloc = u.__getattribute__("free_alloc")
    size = dwSize
    if dwSize == 0:
        size = valloc_size[lpAddress]
    if dwSize != 0:
        dealloc_memory(free_alloc, lpAddress, size)
        res = 1
        err = 0
    else:
        res = 0
        err = 6

    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "VirtualFree(%#x, %d, %#x) => %d" % (
        lpAddress, dwSize, dwFreeType, res
    ))
    error(err)

def CheckRemoteDebuggerPresent(u: Uc):
    # BOOL CheckRemoteDebuggerPresent( HANDLE hProcess, PBOOL pbDebuggerPresent );
    hProcess = u.reg_read(UC_X86_REG_RCX)
    pbDebuggerPresent = u.reg_read(UC_X86_REG_RDX)
    u.mem_write(pbDebuggerPresent, pack_int8(0))
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "CheckRemoteDebuggerPresent(%#x, %#x) => %d" % (
        hProcess, pbDebuggerPresent, 1
    ))
    error(0)

def WriteFile(u: Uc):
    # BOOL WriteFile( HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
    hFile = u.reg_read(UC_X86_REG_RCX)
    lpBuffer = u.reg_read(UC_X86_REG_RDX)
    nNumberOfBytesToWrite = u.reg_read(UC_X86_REG_R8)
    lpNumberOfBytesWritten = u.reg_read(UC_X86_REG_R9)
    lpOverlapped = read_stack_param(u, 0)
    if lpOverlapped != 0:
        raise NotImplementedError
    data = u.mem_read(lpBuffer, nNumberOfBytesToWrite)
    if hFile == 1:
        file = sys.stdout
        file.write(data.decode())
    elif hFile == 2:
        file = sys.stderr
        file.write(data.decode())
    else:
        file = file_handles[hFile - 0x10000]
        file.write(data)
    u.reg_write(UC_X86_REG_R9, nNumberOfBytesToWrite)
    u.reg_write(UC_X86_REG_RAX, 1)
    try:
        text = data.decode()
    except UnicodeDecodeError:
        text = data.hex()
    log(u, "WriteFile(%#x, \"%s\", %d, %#x, %#x) => %d" % (
        hFile, text, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped,
        u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def GetProcessHeap(u: Uc):
    # HANDLE GetProcessHeap();
    u.reg_write(UC_X86_REG_RAX, 0x10000000)
    log(u, "GetProcessHeap() => %#x" % u.reg_read(UC_X86_REG_RAX))
    error(0)

def HeapCreate(machine):
    # HANDLE HeapCreate( DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize );
    flOptions = machine.cpu.state.rcx
    dwInitialSize = machine.cpu.state.rdx
    dwMaximumSize = machine.cpu.state.r8
    machine.cpu.state.rax.value = 0x10000000
    log(machine, "STUB HeapCreate(%#x, %d, %d) => %#x" % (
        flOptions.value, dwInitialSize.value, dwMaximumSize.value, machine.cpu.state.rax.value
    ))
    error(0)

def HeapAlloc(u: Uc):
    # DECLSPEC_ALLOCATOR LPVOID HeapAlloc( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
    hHeap = u.reg_read(UC_X86_REG_RCX)
    dwFlags = u.reg_read(UC_X86_REG_RDX)
    dwBytes = u.reg_read(UC_X86_REG_R8)
    if hHeap != 0x10000000:
        raise NotImplementedError
    free_alloc = u.__getattribute__("free_alloc")
    res = alloc_memory(free_alloc, dwBytes)
    if res is None:
        # add more to the heap
        enlarge_memory(u, free_alloc, dwBytes)
        res = alloc_memory(free_alloc, dwBytes)
    if dwFlags & 8:
        u.mem_write(res, b"\x00" * dwBytes)
    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "HeapAlloc(%#x, %#x, %d) => %#x" % (hHeap, dwFlags, dwBytes, u.reg_read(UC_X86_REG_RAX)))
    if res == 0:
        error(8)
    else:
        valloc_size[res] = dwBytes
        error(0)

def HeapFree(u: Uc):
    # BOOL HeapFree( HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem );
    hHeap = u.reg_read(UC_X86_REG_RCX)
    dwFlags = u.reg_read(UC_X86_REG_RDX)
    lpMem = u.reg_read(UC_X86_REG_R8)
    if hHeap != 0x10000000:
        raise NotImplementedError
    free_alloc = u.__getattribute__("free_alloc")
    size = valloc_size[lpMem]
    if size != 0:
        dealloc_memory(free_alloc, lpMem, size)
        res = 1
        err = 0
    else:
        res = 0
        err = 6
    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "HeapFree(%#x, %#x, %#x) => %d" % (hHeap, dwFlags, lpMem, res))
    error(err)

def HeapSize(machine):
    # SIZE_T HeapSize( HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem );
    hHeap = machine.cpu.state.rcx
    dwFlags = machine.cpu.state.rdx
    lpMem = machine.cpu.state.r8
    if hHeap.value != 0x10000000:
        raise NotImplementedError
    res = machine.memory.alloc_size.get(lpMem.value, -1)
    machine.cpu.state.rax.value = res
    log(machine, "HeapSize(%#x, %#x, %#x) => %d" % (hHeap.value, dwFlags.value, lpMem.value, machine.cpu.state.rax.value))

def HeapReAlloc(machine):
    # DECLSPEC_ALLOCATOR LPVOID HeapReAlloc( HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem, SIZE_T dwBytes );
    hHeap = machine.cpu.state.rcx
    dwFlags = machine.cpu.state.rdx
    lpMem = machine.cpu.state.r8
    dwBytes = machine.cpu.state.r9
    if dwFlags & 0x10:
        raise NotImplementedError
    if dwFlags & 0x8:
        raise NotImplementedError
    size = machine.memory.alloc_size.get(lpMem.value, None)
    if size is None:
        log(machine, "HeapReAlloc %d at %#x" % (dwBytes.value, lpMem.value))
        machine.cpu.state.rax.value = 0
        return
    res = machine.memory.alloc(dwBytes.value)
    machine.memory.write(res, machine.memory.read(lpMem.value, size))
    machine.cpu.state.rax.value = res
    log(machine, "HeapReAlloc(%#x, %#x, %#x, %d) => %#x" % (
        hHeap.value, dwFlags.value, lpMem.value, dwBytes.value, machine.cpu.state.rax.value
    ))

def EncodePointer(machine):
    # PVOID EncodePointer( _In_ PVOID Ptr );
    Ptr = machine.cpu.state.rcx
    machine.cpu.state.rax.value = machine.cpu.state.rcx.value
    log(machine, "EncodePointer(%#x)" % Ptr.value)

def DecodePointer(machine):
    # PVOID DecodePointer( PVOID Ptr );
    Ptr = machine.cpu.state.rcx
    machine.cpu.state.rax.value = machine.cpu.state.rcx.value
    log(machine, "DecodePointer(%#x)" % Ptr.value)

def InitializeCriticalSection(machine):
    # void InitializeCriticalSection( LPCRITICAL_SECTION lpCriticalSection );
    lpCriticalSection = machine.cpu.state.rcx
    log(machine, "InitializeCriticalSection(%#x)" % lpCriticalSection.value)

def InitializeCriticalSectionAndSpinCount(machine):
    # BOOL InitializeCriticalSectionAndSpinCount( LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount );
    lpCriticalSection = machine.cpu.state.rcx
    dwSpinCount = machine.cpu.state.rdx
    machine.cpu.state.rax.value = 1
    log(machine, "InitializeCriticalSectionAndSpinCount(%#x, %d) => %d" % (
        lpCriticalSection.value, dwSpinCount.value, machine.cpu.state.rax.value
    ))
    error(0)

def InitializeCriticalSectionEx(u: Uc):
    # BOOL InitializeCriticalSectionEx( LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags );
    lpCriticalSection = u.reg_read(UC_X86_REG_RCX)
    dwSpinCount = u.reg_read(UC_X86_REG_RDX)
    Flags = u.reg_read(UC_X86_REG_R8)
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "InitializeCriticalSectionEx(%#x, %d, %#x) => %d" % (
        lpCriticalSection, dwSpinCount, Flags, u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def EnterCriticalSection(u: Uc):
    # void EnterCriticalSection( LPCRITICAL_SECTION lpCriticalSection );
    lpCriticalSection = u.reg_read(UC_X86_REG_RCX)
    log(u, "EnterCriticalSection(%#x)" % lpCriticalSection)

def LeaveCriticalSection(u: Uc):
    # void LeaveCriticalSection( LPCRITICAL_SECTION lpCriticalSection );
    lpCriticalSection = u.reg_read(UC_X86_REG_RCX)
    log(u, "LeaveCriticalSection(%#x)" % lpCriticalSection)

def FlsAlloc(u: Uc):
    # DWORD FlsAlloc( PFLS_CALLBACK_FUNCTION lpCallback );
    lpCallback = u.reg_read(UC_X86_REG_RCX)
    index = len(fibers[fiber])
    fibers[fiber].append(0)
    u.reg_write(UC_X86_REG_RAX, index)
    log(u, "FlsAlloc(%#x) => %d" % (lpCallback, u.reg_read(UC_X86_REG_RAX)))

def FlsSetValue(u: Uc):
    # BOOL FlsSetValue( DWORD dwFlsIndex, PVOID lpFlsData );
    dwFlsIndex = u.reg_read(UC_X86_REG_RCX)
    lpFlsData = u.reg_read(UC_X86_REG_RDX)
    fibers[fiber][dwFlsIndex] = lpFlsData
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "FlsSetValue(%d, %#x) => %d" % (dwFlsIndex, lpFlsData, u.reg_read(UC_X86_REG_RAX)))

def FlsGetValue(u: Uc):
    # PVOID FlsGetValue( DWORD dwFlsIndex );
    dwFlsIndex = u.reg_read(UC_X86_REG_RCX)
    if len(fibers[fiber]) < dwFlsIndex:
        res = 0
        error(87)
    else:
        res = fibers[fiber][dwFlsIndex]
        error(0)
    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "FlsGetValue(%d) => %#x" % (dwFlsIndex, u.reg_read(UC_X86_REG_RAX)))

def TlsAlloc(machine):
    # DWORD TlsAlloc();
    index = len(threads[thread])
    threads[thread].append(0)
    machine.cpu.state.rax.value = index
    log(machine, "TlsAlloc() => %d" % machine.cpu.state.rax.value)

def GetStartupInfoW(u: Uc):
    # void GetStartupInfoW( LPSTARTUPINFOW lpStartupInfo );
    lpStartupInfo = u.reg_read(UC_X86_REG_RCX)
    u.mem_write(lpStartupInfo, pack_int32(96))
    u.mem_write(lpStartupInfo + 4, b"\x00" * 92)
    log(u, "GetStartupInfoW(%#x)" % lpStartupInfo)

def GetStdHandle(u: Uc):
    # HANDLE WINAPI GetStdHandle( _In_ DWORD nStdHandle );
    nStdHandle = u.reg_read(UC_X86_REG_RCX)
    if nStdHandle == 4294967286:
        name = "stdin"
        handle = 0
    elif nStdHandle == 4294967285:
        name = "stdout"
        handle = 1
    elif nStdHandle == 4294967284:
        name = "stderr"
        handle = 2
    else:
        log(u, "GetStdHandle %d" % nStdHandle)
        raise NotImplementedError
    u.reg_write(UC_X86_REG_RAX, handle)
    log(u, "GetStdHandle(\"%s\") => %#x" % (name, u.reg_read(UC_X86_REG_RAX)))
    error(0)

def GetFileType(u: Uc):
    # DWORD GetFileType( HANDLE hFile );
    hFile = u.reg_read(UC_X86_REG_RCX)
    if 0 <= hFile <= 2:
        res = 2
    else:
        raise NotImplementedError
    u.reg_write(UC_X86_REG_RAX, res)
    log(u, "GetFileType(%#x) => %d" % (hFile, u.reg_read(UC_X86_REG_RAX)))
    error(0)

def GetCommandLineA(u: Uc):
    # LPSTR GetCommandLineA();
    u.reg_write(UC_X86_REG_RAX, 0x10100)
    log(u, "GetCommandLineA() => %#x" % u.reg_read(UC_X86_REG_RAX))

def GetCommandLineW(u: Uc):
    # LPWSTR GetCommandLineW();
    u.reg_write(UC_X86_REG_RAX, 0x10300)
    log(u, "GetCommandLineW() => %#x" % u.reg_read(UC_X86_REG_RAX))

def GetEnvironmentStringsW(u: Uc):
    # LPWCH GetEnvironmentStringsW();
    u.reg_write(UC_X86_REG_RAX, 0x10500)
    log(u, "GetEnvironmentStringsW() => %#x" % u.reg_read(UC_X86_REG_RAX))

def FreeEnvironmentStringsW(u: Uc):
    # BOOL FreeEnvironmentStringsW( LPWCH penv );
    penv = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "FreeEnvironmentStringsW(%#x) => %d" % (penv, u.reg_read(UC_X86_REG_RAX)))
    error(0)

def GetLastError(u: Uc):
    # _Post_equals_last_error_ DWORD GetLastError();
    u.reg_write(UC_X86_REG_RAX, lasterror)
    log(u, "GetLastError() => %d" % u.reg_read(UC_X86_REG_RAX))

def SetLastError(u: Uc):
    # void SetLastError( DWORD dwErrCode );
    global lasterror
    dwErrCode = u.reg_read(UC_X86_REG_RCX)
    log(u, "SetLastError(%d)" % dwErrCode)
    lasterror = dwErrCode

def GetACP(u: Uc):
    # UINT GetACP();
    u.reg_write(UC_X86_REG_RAX, 932)
    log(u, "GetACP() => %d" % u.reg_read(UC_X86_REG_RAX))

def GetCPInfo(u: Uc):
    # BOOL GetCPInfo( UINT CodePage, LPCPINFO lpCPInfo );
    CodePage = u.reg_read(UC_X86_REG_RCX)
    lpCPInfo = u.reg_read(UC_X86_REG_RDX)
    u.mem_write(lpCPInfo + 0x0, pack_int32(2))
    u.mem_write(lpCPInfo + 0x4, b"\x3f\x00")
    u.mem_write(lpCPInfo + 0x6, b"\x81\x9f\xe0\xfc\x00\x00\x00\x00\x00\x00\x00\x00")
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "GetCPInfo(%d, %#x) => %d" % (CodePage, lpCPInfo, u.reg_read(UC_X86_REG_RAX)))
    error(0)

def MultiByteToWideChar(u: Uc):
    # int MultiByteToWideChar(
    # UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte,
    # LPWSTR lpWideCharStr, int cchWideChar );
    CodePage = u.reg_read(UC_X86_REG_RCX)
    dwFlags = u.reg_read(UC_X86_REG_RDX)
    lpMultiByteStr = u.reg_read(UC_X86_REG_R8)
    cbMultiByte = u.reg_read(UC_X86_REG_R9)
    lpWideCharStr = read_stack_param(u, 0)
    cchWideChar = read_stack_param(u, 1)
    try:
        "".encode(f"cp{CodePage}")
    except LookupError:
        print(CodePage)
        raise NotImplementedError
    buffer = u.mem_read(lpMultiByteStr, cbMultiByte).decode(f"cp{CodePage}")
    res = buffer.encode("utf-16le")
    if cchWideChar != 0 and lpWideCharStr != 0:
        u.mem_write(lpWideCharStr, res)
    u.reg_write(UC_X86_REG_RAX, len(res) // 2)
    log(u, "MultiByteToWideChar(%d, %#x, \"%s\", %d, %#x, %d) => %d" % (
        CodePage, dwFlags, buffer, cbMultiByte, lpWideCharStr, cchWideChar, u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def WideCharToMultiByte(u: Uc):
    # int WideCharToMultiByte( UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
    # int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar );
    CodePage = u.reg_read(UC_X86_REG_RCX)
    dwFlags = u.reg_read(UC_X86_REG_RDX)
    lpWideCharStr = u.reg_read(UC_X86_REG_R8)
    cchWideChar = u.reg_read(UC_X86_REG_R9)
    lpMultiByteStr = read_stack_param(u, 0)
    cbMultiByte = read_stack_param(u, 1)
    lpDefaultChar = read_stack_param(u, 2)
    lpUsedDefaultChar = read_stack_param(u, 3)
    if CodePage == 0:
        CodePage = 932
    try:
        "".encode(f"cp{CodePage}")
    except LookupError:
        print(CodePage)
        raise NotImplementedError
    if cchWideChar == 0xffffffff:
        tmp = u.reg_read(UC_X86_REG_RCX)
        u.reg_write(UC_X86_REG_RCX, lpWideCharStr)
        wcslen(u)
        u.reg_write(UC_X86_REG_RCX, tmp)
        cchWideChar = u.reg_read(UC_X86_REG_RAX) + 2
    buffer = u.mem_read(lpWideCharStr, cchWideChar * 2).decode("utf-16le")
    res = buffer.encode(f"cp{CodePage}")
    if cbMultiByte != 0 and lpMultiByteStr != 0:
        u.mem_write(lpMultiByteStr, res)
    u.reg_write(UC_X86_REG_RAX, len(res))
    log(u, "WideCharToMultiByte(%d, %#x, \"%s\", %d, %#x, %d, %#x, %d) => %d" % (
        CodePage, dwFlags, buffer, cchWideChar, lpMultiByteStr, cbMultiByte,
        lpDefaultChar, lpUsedDefaultChar, u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def GetStringTypeW(u: Uc):
    # BOOL GetStringTypeW( DWORD dwInfoType, _In_NLS_string_(cchSrc)LPCWCH lpSrcStr, int cchSrc, LPWORD lpCharType );
    dwInfoType = u.reg_read(UC_X86_REG_RCX)
    lpSrcStr = u.reg_read(UC_X86_REG_RDX)
    cchSrc = u.reg_read(UC_X86_REG_R8)
    lpCharType = u.reg_read(UC_X86_REG_R9)
    # breakpoint()
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "STUB GetStringTypeW(%#x, %#x, %d, %#x) => %d" % (
        dwInfoType, lpSrcStr, cchSrc, lpCharType, u.reg_read(UC_X86_REG_RAX)
    ))
    error(120)

def LCMapStringW(machine):
    # int LCMapStringW( LCID Locale, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest );
    Locale = machine.cpu.state.rcx
    dwMapFlags = machine.cpu.state.rdx
    lpSrcStr = machine.cpu.state.r8
    cchSrc = machine.cpu.state.r9
    lpDestStr = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    cchDest = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    machine.cpu.state.rax.value = 0
    log(machine, "STUB LCMapStringW(%d, %#x, %#x, %d, %#x, %d) => %d" % (
        Locale.value, dwMapFlags.value, lpSrcStr.value, cchSrc.value, lpDestStr, cchDest,
        machine.cpu.state.rax.value
    ))
    error(120)

def LCMapStringEx(u: Uc):
    # int LCMapStringEx(
    # LPCWSTR lpLocaleName, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest,
    # LPNLSVERSIONINFO lpVersionInformation, LPVOID lpReserved, LPARAM sortHandle );
    lpLocaleName = u.reg_read(UC_X86_REG_RCX)
    dwMapFlags = u.reg_read(UC_X86_REG_RDX)
    lpSrcStr = u.reg_read(UC_X86_REG_R8)
    cchSrc = u.reg_read(UC_X86_REG_R9)
    lpDestStr = read_stack_param(u, 0)
    cchDest = read_stack_param(u, 1)
    lpVersionInformation = read_stack_param(u, 2)
    lpReserved = read_stack_param(u, 3)
    sortHandle = read_stack_param(u, 4)
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "STUB LCMapStringEx(%#x, %#x, %#x, %d, %#x, %d, %#x, %#x, %#x) => %d" % (
        lpLocaleName, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, lpVersionInformation,
        lpReserved, sortHandle, u.reg_read(UC_X86_REG_RAX)
    ))
    error(120)

def InitializeSListHead(u: Uc):
    # void InitializeSListHead( PSLIST_HEADER ListHead );
    ListHead = u.reg_read(UC_X86_REG_RCX)
    log(u, "STUB InitializeSListHead(%#x)" % ListHead)

def InterlockedPopEntrySList(machine):
    # PSLIST_ENTRY InterlockedPopEntrySList( PSLIST_HEADER ListHead );
    ListHead = machine.cpu.state.rcx
    machine.cpu.state.rax.value = 0
    log(machine, "STUB InterlockedPopEntrySList(%#x) => %#x" % (ListHead.value, machine.cpu.state.rax.value))

def RtlPcToFileHeader(machine):
    # NTSYSAPI PVOID RtlPcToFileHeader( PVOID PcValue, PVOID *BaseOfImage );
    PcValue = machine.cpu.state.rcx
    BaseOfImage = machine.cpu.state.rdx
    base = 0
    for start, size in machine.memory.mapped.items():
        if start <= PcValue.value < start + size:
            name = machine.memory.names[start]
            if ":" not in name:
                raise ValueError
            base = machine.memory.bases[name.split(":")[0]]
    machine.memory.write(read_int64(machine.memory.read(BaseOfImage.value, 8)), pack_int64(base))
    machine.cpu.state.rax.value = base
    log(machine, "RtlPcToFileHeader(%#x, %#x) => %#x" % (PcValue.value, BaseOfImage.value, machine.cpu.state.rax.value))

def NetUserEnum(machine):
    # NET_API_STATUS NET_API_FUNCTION NetUserEnum( LPCWSTR servername, DWORD level, DWORD filter, LPBYTE *bufptr,
    # DWORD prefmaxlen, LPDWORD entriesread, LPDWORD totalentries, PDWORD resume_handle );
    servername = machine.cpu.state.rcx
    level = machine.cpu.state.rdx
    _filter = machine.cpu.state.r8
    bufptr = machine.cpu.state.r9
    prefmaxlen = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    entriesread = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    totalentries = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    resume_handle = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x40, 8))
    if servername.value != 0:
        raise NotImplementedError
    if _filter.value != 2:
        raise NotImplementedError
    usernames = ["Administrator"]
    orig_len = len(usernames)
    if resume_handle != 0:
        resume = read_int32(machine.memory.read(resume_handle, 4))
        if resume != 0:
            raise NotImplementedError
    else:
        resume = 0
    if level == 0:
        if 0 < prefmaxlen < 8:
            buffer = 0
            res = 0x8007084B
        elif 0 < prefmaxlen < len(usernames) * 8:
            usernames = usernames[:prefmaxlen // 8]
            buffer = machine.memory.alloc(len(usernames) * 8 + sum(map(lambda x: len(x) + 1, usernames)) * 2)
            res = 234
        else:
            buffer = machine.memory.alloc(len(usernames) * 8 + sum(map(lambda x: len(x) + 1, usernames)) * 2)
            res = 0
        if buffer != 0:
            for i in range(len(usernames)):
                str_buffer = buffer + len(usernames) * 8 + sum(map(lambda x: len(x) + 1, usernames[:i])) * 2
                machine.memory.write(
                    buffer + i * 8,
                    pack_int64(str_buffer))
                machine.memory.write(str_buffer, usernames[i].encode("utf-16le") + b"\x00\x00")
        machine.memory.write(bufptr.value, pack_int64(buffer))
        machine.memory.write(entriesread, pack_int32(len(usernames)))
        machine.memory.write(totalentries, pack_int32(orig_len - len(usernames)))
        if resume_handle != 0:
            machine.memory.write(resume_handle, pack_int32(len(usernames) + resume))
        log(machine, machine.memory.read(buffer, len(usernames) * 8 + sum(map(lambda x: len(x) + 1, usernames)) * 2))
    else:
        raise NotImplementedError
    machine.cpu.state.rax.value = res
    log(machine, "NetUserEnum(%#x, %d, %#x, %#x, %d, %#x, %#x, %#x) => %d" % (
        servername.value, level.value, _filter.value, bufptr.value, prefmaxlen, entriesread, totalentries,
        resume_handle, machine.cpu.state.rax.value
    ))

def NetApiBufferFree(machine):
    # NET_API_STATUS NET_API_FUNCTION NetApiBufferFree( _Frees_ptr_opt_ LPVOID Buffer );
    Buffer = machine.cpu.state.rcx
    machine.memory.free(Buffer.value)
    machine.cpu.state.rax.value = 0
    log(machine, "NetApiBufferFree(%#x) => %d" % (Buffer.value, machine.cpu.state.rax.value))

def CreateMutexA(machine):
    # HANDLE CreateMutexA( LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName );
    lpMutexAttributes = machine.cpu.state.rcx
    bInitialOwner = machine.cpu.state.rdx
    lpName = machine.cpu.state.r8
    machine.cpu.state.rcx.value = lpName.value
    strlen(machine)
    size = machine.cpu.state.rax.value
    global next_mutex
    if size == 0:
        buffer = "unnamed %d" % next_mutex
    else:
        buffer = machine.memory.read(lpName.value, size).decode()
    err = 0
    res = 0
    for k, v in mutexes.items():
        if v == buffer:
            err = 183
    if err == 0:
        res = next_mutex + 0x80000
        mutexes[next_mutex] = buffer
        next_mutex += 1
    machine.cpu.state.rax.value = res
    log(machine, "CreateMutexA(%#x, %d, \"%s\") => %#x" % (
        lpMutexAttributes.value, bInitialOwner.value, buffer, machine.cpu.state.rax.value
    ))
    error(err)

def CreateMutexW(machine):
    # HANDLE CreateMutexW( LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCWSTR lpName );
    lpMutexAttributes = machine.cpu.state.rcx
    bInitialOwner = machine.cpu.state.rdx
    lpName = machine.cpu.state.r8
    machine.cpu.state.rcx.value = lpName.value
    wcslen(machine)
    size = machine.cpu.state.rax.value
    buffer = machine.memory.read(lpName.value, size * 2).decode("utf-16le")
    err = 0
    res = 0
    for k, v in mutexes.items():
        if v == buffer:
            err = 183
    if err == 0:
        global next_mutex
        res = next_mutex + 0x80000
        mutexes[next_mutex] = buffer
        next_mutex += 1
    machine.cpu.state.rax.value = res
    log(machine, "CreateMutexW(%#x, %d, \"%s\") => %#x" % (
        lpMutexAttributes.value, bInitialOwner.value, buffer, machine.cpu.state.rax.value
    ))
    error(err)

def OpenMutexW(machine):
    # HANDLE OpenMutexW( DWORD dwDesiredAccess, BOOL bInheritHandle, LPCWSTR lpName );
    dwDesiredAccess = machine.cpu.state.rcx
    bInheritHandle = machine.cpu.state.rdx
    lpName = machine.cpu.state.r8
    machine.cpu.state.rcx.value = lpName.value
    wcslen(machine)
    size = machine.cpu.state.rax.value
    buffer = machine.memory.read(lpName.value, size * 2).decode("utf-16le")
    res = 0
    err = 2
    for k, v in mutexes.items():
        if v == buffer:
            res = k
            err = 0
    machine.cpu.state.rax.value = res
    log(machine, "OpenMutexW(%#x, %#x, \"%s\") => %#x" % (
        dwDesiredAccess.value, bInheritHandle.value, buffer, machine.cpu.state.rax.value
    ))
    error(err)

def ReleaseMutex(machine):
    # BOOL ReleaseMutex( HANDLE hMutex );
    hMutex = machine.cpu.state.rcx
    handle = hMutex.value - 0x80000
    if mutexes.get(handle) is None:
        raise ValueError
    name = mutexes[handle]
    # del mutexes[handle]
    machine.cpu.state.rax.value = 1
    log(machine, "ReleaseMutex(%#x(\"%s\") => %d" % (hMutex.value, name, machine.cpu.state.rax.value))
    error(0)

def WaitForSingleObject(machine):
    # DWORD WaitForSingleObject( HANDLE hHandle, DWORD dwMilliseconds );
    hHandle = machine.cpu.state.rcx
    dwMilliseconds = machine.cpu.state.rdx
    machine.cpu.state.rax.value = 0
    log(machine, "STUB WaitForSingleObject(%#x, %d) => %d" % (
        hHandle.value, dwMilliseconds.value, machine.cpu.state.rax.value
    ))

def WSAStartup(machine):
    # int WSAStartup( WORD wVersionRequired, LPWSADATA lpWSAData );
    wVersionRequired = machine.cpu.state.rcx
    lpWSAData = machine.cpu.state.rdx
    machine.cpu.state.rax.value = 0
    log(machine, "STUB WSAStartup(%#x, %#x) => %d" % (wVersionRequired.value, lpWSAData.value, machine.cpu.state.rax.value))

def DisableThreadLibraryCalls(machine):
    # BOOL DisableThreadLibraryCalls( HMODULE hLibModule );
    hLibModule = machine.cpu.state.rcx
    machine.cpu.state.rax.value = 1
    log(machine, "STUB DisableThreadLibraryCalls(%#x) => %d" % (hLibModule.value, machine.cpu.state.rax.value))

def SetHandleCount(machine):
    # UINT SetHandleCount( UINT uNumber );
    uNumber = machine.cpu.state.rcx
    machine.cpu.state.rax.value = 0
    log(machine, "SetHandleCount(%d) => %d" % (uNumber.value, machine.cpu.state.rax.value))

def timeGetTime(machine):
    # DWORD timeGetTime();
    machine.cpu.state.rax.value = 0
    log(machine, "timeGetTime() => %d" % machine.cpu.state.rax.value)

def SetConsoleCtrlHandler(machine):
    # BOOL WINAPI SetConsoleCtrlHandler( _In_opt_ PHANDLER_ROUTINE HandlerRoutine, _In_ BOOL Add );
    HandlerRoutine = machine.cpu.state.rcx
    Add = machine.cpu.state.rdx
    machine.cpu.state.rax.value = 1
    log(machine, "STUB SetConsoleCtrlHandler(%#x, %d) => %d" % (
        HandlerRoutine.value, Add.value, machine.cpu.state.rax.value
    ))
    error(0)

def GetConsoleMode(machine):
    # BOOL WINAPI GetConsoleMode( _In_ HANDLE hConsoleHandle, _Out_ LPDWORD lpMode );
    hConsoleHandle = machine.cpu.state.rcx
    lpMode = machine.cpu.state.rdx
    if hConsoleHandle.value == 0:
        machine.memory.write(lpMode.value, pack_int32(0x277))
    else:
        machine.memory.write(lpMode.value, pack_int32(0x3))
    machine.cpu.state.rax.value = 1
    log(machine, "GetConsoleMode(%#x, %#x) => %d" % (
        hConsoleHandle.value, lpMode.value, machine.cpu.state.rax.value
    ))
    error(0)

def GetProcessAffinityMask(machine):
    # BOOL GetProcessAffinityMask( HANDLE hProcess, PDWORD_PTR lpProcessAffinityMask, PDWORD_PTR lpSystemAffinityMask );
    hProcess = machine.cpu.state.rcx
    lpProcessAffinityMask = machine.cpu.state.rdx
    lpSystemAffinityMask = machine.cpu.state.r8
    machine.memory.write(lpProcessAffinityMask.value, pack_int32(1))
    machine.memory.write(lpSystemAffinityMask.value, pack_int32(1))
    machine.cpu.state.rax.value = 1
    log(machine, "GetProcessAffinityMask(%#x, %#x, %#x) => %d" % (
        hProcess.value, lpProcessAffinityMask.value, lpSystemAffinityMask.value, machine.cpu.state.rax.value
    ))
    error(0)

def GetLogicalProcessorInformationEx(machine):
    # BOOL GetLogicalProcessorInformationEx( LOGICAL_PROCESSOR_RELATIONSHIP RelationshipType,
    # PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Buffer, PDWORD ReturnedLength );

    """
    [
      {
        0: Relationship = 1
        4: Size = 48
        8: NodeNumber = 1
        12: Reserved[20]
        32: Mask
        40: Group = 0
        42: Reserved[6]
        48
      }
      {
        0: Relationship = 3
        4: Size = 48
        8: Flags = 0
        9: EfficiencyClass = 0
        10: Reserved[20]
        30: GroupCount = 1
        32: Mask
        40: Group = 0
        42: Reserved[6]
        48
      }
    ]
    """

    RelationshipType = machine.cpu.state.rcx
    Buffer = machine.cpu.state.rdx
    ReturnedLength = machine.cpu.state.r8
    length = read_int32(machine.memory.read(ReturnedLength.value, 4))
    if RelationshipType == 0xffff:
        required = 96
    else:
        required = 0
    if length < required:
        err = 122
        machine.memory.write(ReturnedLength.value, pack_int32(required))
        machine.cpu.state.rax.value = 0
    else:
        if RelationshipType == 0xffff:
            err = 0
            machine.memory.write(Buffer.value + 0, pack_int32(1))
            machine.memory.write(Buffer.value + 4, pack_int32(48))
            machine.memory.write(Buffer.value + 8, pack_int32(1))
            machine.memory.write(Buffer.value + 32, pack_int64(1))
            machine.memory.write(Buffer.value + 40, pack_int16(0))
            machine.memory.write(Buffer.value + 48, pack_int32(3))
            machine.memory.write(Buffer.value + 52, pack_int32(48))
            machine.memory.write(Buffer.value + 56, pack_int8(0))
            machine.memory.write(Buffer.value + 57, pack_int8(0))
            machine.memory.write(Buffer.value + 78, pack_int16(1))
            machine.memory.write(Buffer.value + 80, pack_int64(1))
            machine.memory.write(Buffer.value + 88, pack_int16(0))
            machine.cpu.state.rax.value = 1
        else:
            err = 120
            machine.cpu.state.rax.value = 0
    log(machine, "GetLogicalProcessorInformationEx(%d, %#x, %#x(%d)) => %d" % (
        RelationshipType.value, Buffer.value, ReturnedLength.value, length, machine.cpu.state.rax.value
    ))
    error(err)

def RaiseException(machine):
    # __analysis_noreturn VOID RaiseException( DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments,
    # const ULONG_PTR *lpArguments );
    dwExceptionCode = machine.cpu.state.rcx
    dwExceptionFlags = machine.cpu.state.rdx
    nNumberOfArguments = machine.cpu.state.r8
    lpArguments = machine.cpu.state.r9
    log(machine, "RaiseException(%#x, %#x, %d, %#x)" % (
        dwExceptionCode.value, dwExceptionFlags.value, nNumberOfArguments.value, lpArguments.value
    ))
    machine.cpu.state.rflags.TF = True

def RegisterTraceGuidsW(machine):
    # ULONG WMIAPI RegisterTraceGuidsW( WMIDPREQUEST RequestAddress, PVOID RequestContext, LPCGUID ControlGuid,
    # ULONG GuidCount, PTRACE_GUID_REGISTRATION TraceGuidReg, LPCWSTR MofImagePath, LPCWSTR MofResourceName,
    # PTRACEHANDLE RegistrationHandle );
    RequestAddress = machine.cpu.state.rcx
    RequestContext = machine.cpu.state.rdx
    ControlGuid = machine.cpu.state.r8
    GuidCount = machine.cpu.state.r9
    TraceGuidReg = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    MofImagePath = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    MofResourceName = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    RegistrationHandle = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x40, 8))
    machine.cpu.state.rax.value = 120
    log(machine, "STUB RegisterTraceGuidsW(%#x, %#x, %#x, %d, %#x, %#x, %#x, %#x) => %d" % (
        RequestAddress.value, RequestContext.value, ControlGuid.value, GuidCount.value, TraceGuidReg, MofImagePath,
        MofResourceName, RegistrationHandle, machine.cpu.state.rax.value
    ))

def CreateEventW(machine):
    # HANDLE CreateEventW( LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName );
    lpEventAttributes = machine.cpu.state.rcx
    bManualReset = machine.cpu.state.rdx
    bInitialState = machine.cpu.state.r8
    lpName = machine.cpu.state.r9
    machine.cpu.state.rax.value = 1
    log(machine, "STUB CreateEventW(%#x, %#x, %#x, %#x) => %d" % (
        lpEventAttributes.value, bManualReset.value, bInitialState.value, lpName.value, machine.cpu.state.rax.value
    ))
    error(0)

def RegisterWaitForSingleObject(machine):
    # BOOL RegisterWaitForSingleObject( PHANDLE phNewWaitObject, HANDLE hObject, WAITORTIMERCALLBACK Callback,
    # PVOID Context, ULONG dwMilliseconds, ULONG dwFlags );
    phNewWaitObject = machine.cpu.state.rcx
    hObject = machine.cpu.state.rdx
    Callback = machine.cpu.state.r8
    Context = machine.cpu.state.r9
    dwMilliseconds = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    dwFlags = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    machine.cpu.state.rax.value = 1
    log(machine, "STUB RegisterWaitForSingleObject(%#x, %#x, %#x, %#x, %d, %#x) => %d" % (
        phNewWaitObject.value, hObject.value, Callback.value, Context.value, dwMilliseconds, dwFlags,
        machine.cpu.state.rax.value
    ))
    error(0)

def CreateTimerQueueTimer(machine):
    # BOOL CreateTimerQueueTimer( PHANDLE phNewTimer, HANDLE TimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter,
    # DWORD DueTime, DWORD Period, ULONG Flags );
    phNewTimer = machine.cpu.state.rcx
    TimerQueue = machine.cpu.state.rdx
    Callback = machine.cpu.state.r8
    Parameter = machine.cpu.state.r9
    DueTime = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    Period = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    Flags = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    machine.cpu.state.rax.value = 1
    log(machine, "STUB CreateTimerQueueTimer(%#x, %#x, %#x, %#x, %d, %d, %#x) => %d" % (
        phNewTimer.value, TimerQueue.value, Callback.value, Parameter.value, DueTime, Period, Flags,
        machine.cpu.state.rax.value
    ))
    error(0)

def GetNumaHighestNodeNumber(machine):
    # BOOL GetNumaHighestNodeNumber( PULONG HighestNodeNumber );
    HighestNodeNumber = machine.cpu.state.rcx
    machine.memory.write(HighestNodeNumber.value, pack_int32(0))
    machine.cpu.state.rax.value = 1
    log(machine, "GetNumaHighestNodeNumber(%#x) => %d" % (HighestNodeNumber.value, machine.cpu.state.rax.value))
    error(0)

def HeapSetInformation(machine):
    # BOOL HeapSetInformation( HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass,
    # PVOID HeapInformation, SIZE_T HeapInformationLength );
    HeapHandle = machine.cpu.state.rcx
    HeapInformationClass = machine.cpu.state.rdx
    HeapInformation = machine.cpu.state.r8
    HeapInformationLength = machine.cpu.state.r9
    machine.cpu.state.rax.value = 1
    log(machine, "STUB HeapSetInformation(%#x, %d, %#x, %d) => %d" % (
        HeapHandle.value, HeapInformationClass.value, HeapInformation.value, HeapInformationLength.value,
        machine.cpu.state.rax.value
    ))
    error(0)

def ExitProcess(u: Uc):
    # void ExitProcess( UINT uExitCode );
    uExitCode = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RIP, 0)
    log(u, "ExitProcess(%d)" % uExitCode)
    error(0)

def NtQueryInformationProcess(u: Uc):
    # NTSTATUS NtQueryInformationProcess( HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
    # PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength );
    ProcessHandle = u.reg_read(UC_X86_REG_RCX)
    ProcessInformationClass = u.reg_read(UC_X86_REG_RDX)
    ProcessInformation = u.reg_read(UC_X86_REG_R8)
    ProcessInformationLength = u.reg_read(UC_X86_REG_R9)
    ReturnLength = read_stack_param(u, 0)
    if ProcessInformationClass == 7:
        # ProcessDebugPort
        if ProcessInformationLength != 8:
            u.reg_write(UC_X86_REG_RAX, 0xC0000004)
        else:
            u.reg_write(UC_X86_REG_RAX, 0)
            u.mem_write(ProcessInformation, pack_uint64(0))
            if ReturnLength != 0:
                u.mem_write(ReturnLength, pack_uint32(8))
    else:
        raise NotImplementedError
    log(u, "NtQueryInformationProcess(%#x, %d, %#x, %d, %#x) => %d" % (
        ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength,
        u.reg_read(UC_X86_REG_RAX)
    ))
    error(0)

def AreFileApisANSI(u: Uc):
    # BOOL AreFileApisANSI();
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "AreFileApisANSI() => %d" % u.reg_read(UC_X86_REG_RAX))

def DeleteCriticalSection(u: Uc):
    # void DeleteCriticalSection( LPCRITICAL_SECTION lpCriticalSection );
    lpCriticalSection = u.reg_read(UC_X86_REG_RCX)
    log(u, "DeleteCriticalSection(%#x)" % lpCriticalSection)

def AppPolicyGetProcessTerminationMethod(u: Uc):
    # LONG AppPolicyGetProcessTerminationMethod( HANDLE processToken, AppPolicyProcessTerminationMethod *pPolicy );
    processToken = u.reg_read(UC_X86_REG_RCX)
    pPolicy = u.reg_read(UC_X86_REG_RDX)
    u.mem_write(pPolicy, pack_uint32(0))
    u.reg_write(UC_X86_REG_RAX, 0)
    log(u, "AppPolicyGetProcessTerminationMethod(%#x, %#x) => %d" % (
        processToken, pPolicy, u.reg_read(UC_X86_REG_RAX)
    ))

def CorExitProcess(u: Uc):
    # void CorExitProcess( int exitCode );
    exitCode = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RIP, 0)
    log(u, "CorExitProcess(%d)" % exitCode)
    error(0)

def FreeLibrary(u: Uc):
    # BOOL FreeLibrary( HMODULE hLibModule );
    hLibModule = u.reg_read(UC_X86_REG_RCX)
    u.reg_write(UC_X86_REG_RAX, 1)
    log(u, "FreeLibrary(%#x) => %d" % (hLibModule, u.reg_read(UC_X86_REG_RAX)))

# def _initterm(machine):
#     # ?
#     log(machine, "_initterm STUB!!")
#     machine.cpu.state.rax.value = 0
#
# def _initterm_e(machine):
#     # ?
#     log(machine, "_initterm_e STUB!!")
#     machine.cpu.state.rax.value = 0
#
# def _onexit(machine):
#     # _onexit_t _onexit( _onexit_t function );
#     function = machine.cpu.state.rcx
#     log(machine, "_onexit STUB!!")
#     machine.cpu.state.rax.value = function
#
# def __crtGetShowWindowMode(machine):
#     # ?
#     log(machine, "__crtGetShowWindowMode STUB!!")
#     machine.cpu.state.rax.value = 0
#
# def __iob_func(machine):
#     # ?
#     machine.cpu.state.rax.value = 0
#
# def __2_YAPEAX_K_Z(machine):
#     # void* operator new( std::size_t count );
#     count = machine.cpu.state.rcx
#     res = machine.memory.alloc(count.value)
#     machine.cpu.state.rax.value = res
#
# def __3_YAXPEAX_Z(machine):
#     # void operator delete( void* ptr ) ;
#     ptr = machine.cpu.state.rcx
#     machine.memory.free(ptr.value)
#
# def __1_Container_base12_std__QEAA_XZ(machine):
#     # void std::_Container_base12:~_Container_base12(void)
#     obj = machine.cpu.state.rcx
#     log(machine, "~_Container_base12 STUB!!")
#
def strlen(u: Uc):
    # size_t strlen( const char *str )
    _str = u.reg_read(UC_X86_REG_RCX)
    res = 0
    while True:
        buf: bytearray = u.mem_read(_str + res, 8)
        tmp = buf.find(b"\x00")
        if tmp == -1:
            res += 8
            continue
        u.reg_write(UC_X86_REG_RAX, res + tmp)
        return

def wcslen(u: Uc):
    # size_t wcslen( const wchar_t *str );
    _str = u.reg_read(UC_X86_REG_RCX)
    res = 0
    while True:
        buf: bytearray = u.mem_read(_str + res * 2, 16)
        tmp = buf.find(b"\x00\x00")
        if tmp == -1:
            res += 8
            continue
        u.reg_write(UC_X86_REG_RAX, res + tmp // 2 + 1)
        return
#
# def strncmp(machine):
#     # int strncmp( const char *lhs, const char *rhs, size_t count )
#     lhs = machine.cpu.state.rcx
#     rhs = machine.cpu.state.rdx
#     count = machine.cpu.state.r8d.value
#     pos = 0
#     while pos < count:
#         c1 = machine.memory.read(lhs + pos, 1)[0]
#         c2 = machine.memory.read(rhs + pos, 1)[0]
#         if c1 != c2:
#             machine.cpu.state.eax.value = c1 - c2
#             return
#         pos += 1
#     machine.cpu.state.eax.value = 0
#
# def malloc(machine):
#     # void* malloc( size_t size );
#     size = machine.cpu.state.rcx.value
#     res = machine.memory.alloc(size)
#     if res < 0:
#         machine.cpu.state.rax.value = 0
#     else:
#         machine.cpu.state.rax.value = res
#
# def puts(machine):
#     # int puts( const char *str );
#     _str = machine.cpu.state.rcx
#     strlen(machine)
#     size = machine.cpu.state.rax.value
#     buf = machine.memory.read(_str, size)
#     try:
#         buf = buf.decode()
#     except:
#         pass
#     log(machine, buf)
#
# def printf(machine):
#     # int printf( const char *format, ... );
#     _format = machine.cpu.state.rcx
#     va_1 = machine.cpu.state.rdx
#     va_2 = machine.cpu.state.r8
#     va_3 = machine.cpu.state.r9
#     strlen(machine)
#     size = machine.cpu.state.rax.value
#     fmt = machine.memory.read(_format, size).decode()
#
#     breakpoint()
#
# def fwprintf_s(machine):
#     # int fwprintf_s( FILE *restrict stream, const wchar_t *restrict format, ...);
#     stream = machine.cpu.state.rcx
#     _format = machine.cpu.state.rdx
#     a1 = machine.cpu.state.r8
#     a2 = machine.cpu.state.r9
#
#     if stream.value == 0x30:
#         file = sys.stdout
#     elif stream.value == 0x60:
#         file = sys.stderr
#     else:
#         raise ValueError
#
#     machine.cpu.state.rcx.value = _format.value
#     wcslen(machine)
#     size = machine.cpu.state.rax.value
#     fmt = machine.memory.read(_format, size * 2).decode("utf-16le")
#     conv = 0
#     while printf_re.search(fmt):
#         raise NotImplementedError
#     print(fmt, file=file)
#
# def swprintf_s(machine):
#     # int swprintf( wchar_t *buffer, size_t bufsz, const wchar_t* format, ... );
#     buffer = machine.cpu.state.rcx
#     bufsz = machine.cpu.state.rdx
#     _format = machine.cpu.state.r8
#     a1 = machine.cpu.state.r9
#
#     tmp = machine.cpu.state.rcx.value
#     machine.cpu.state.rcx.value = _format.value
#     wcslen(machine)
#     machine.cpu.state.rcx.value = tmp
#     size = machine.cpu.state.rax.value
#     fmt: str = machine.memory.read(_format, size * 2).decode("utf-16le")
#     conv = 0
#     while printf_re.search(fmt):
#         match = printf_re.search(fmt)
#         span = match.span()
#         groups = match.groupdict()
#         if conv == 0:
#             value = a1.value
#         else:
#             raise NotImplementedError
#         if groups["specifier"] == "d":
#             if groups["flags"]:
#                 raise NotImplementedError
#             if groups["width"]:
#                 raise NotImplementedError
#             if groups["length"]:
#                 raise NotImplementedError
#             fmt = fmt[:span[0]] + str(read_int64(pack_int64(value))) + fmt[span[1]:]
#         elif groups["specifier"] == "u":
#             if groups["flags"]:
#                 raise NotImplementedError
#             if groups["width"]:
#                 raise NotImplementedError
#             if groups["length"]:
#                 if groups["length"] == "I64":
#                     pass
#                 else:
#                     raise NotImplementedError
#             fmt = fmt[:span[0]] + str(value) + fmt[span[1]:]
#         else:
#             print(fmt, fmt[span[0]:span[1]])
#             raise NotImplementedError
#     buf = fmt.encode("utf-16le") + b"\x00\x00"
#     size = len(buf) // 2 - 1
#     if bufsz.value * 2 < len(fmt):
#         buf = buf[:bufsz.value * 2]
#         size = len(buf) // 2
#     machine.memory.write(buffer.value, buf)
#     machine.cpu.state.rax.value = size
#
# def exit(machine):
#     # void exit( int const status );
#     status = machine.cpu.state.rcx.value
#     raise Exited(status)
#
# def memcpy(machine):
#     # void* memcpy( void *dest, const void *src, size_t count );
#     dest = machine.cpu.state.rcx
#     src = machine.cpu.state.rdx
#     count = machine.cpu.state.r8
#     machine.memory.write(dest.value, machine.memory.read(src.value, count.value))
#     machine.cpu.dump()
#     machine.cpu.state.rax.value = dest.value
#
# def memset(machine):
#     # void *memset( void *dest, int ch, size_t count );
#     dest = machine.cpu.state.rcx
#     ch = machine.cpu.state.rdx
#     count = machine.cpu.state.r8
#     byte = ch.value & 0xff
#     machine.memory.write(dest.value, bytearray([byte]) * count.value)
#     machine.cpu.state.rax.value = dest.value
#
# def wcscpy_s(machine):
#     # errno_t wcscpy_s( wchar_t *restrict dest, rsize_t destsz, const wchar_t *restrict src );
#     dest = machine.cpu.state.rcx
#     destsz = machine.cpu.state.rdx
#     src = machine.cpu.state.r8
#     buf = machine.memory.read(src, 2)
#     count = 0
#     while True:
#         if count == destsz.value:
#             break
#         machine.memory.write(dest, buf)
#         if buf == "\x00\x00":
#             break
#         src.value += 2
#         dest.value += 2
#         count += 1
#     machine.cpu.state.rax.value = 0

def NOTIMP(machine):
    raise NotImplementedError

api_list = [
    GetSystemTimeAsFileTime,
    GetCurrentProcessId,
    GetCurrentThreadId,
    GetCurrentThread,
    GetThreadTimes,
    GetTickCount,
    QueryPerformanceCounter,
    QueryPerformanceFrequency,
    SetUnhandledExceptionFilter,
    GetModuleHandleA,
    GetModuleHandleW,
    GetModuleHandleExA,
    GetModuleHandleExW,
    GetProcAddress,
    VirtualProtect,
    GetModuleFileNameW,
    GetModuleFileNameA,
    CreateFileW,
    CreateFileA,
    CreateFileMappingA,
    CreateFileMappingW,
    OpenFileMappingW,
    MapViewOfFile,
    UnmapViewOfFile,
    CloseHandle,
    Beep,
    LoadLibraryA,
    LoadLibraryExW,
    TerminateProcess,
    GetCurrentProcess,
    UnhandledExceptionFilter,
    IsDebuggerPresent,
    GetLocalTime,
    SystemTimeToFileTime,
    GetTempPathW,
    GetVersion,
    GetVersionExA,
    GetVersionExW,
    GetTempFileNameW,
    DeleteFileW,
    GetVolumeInformationW,
    GetSystemTime,
    GetFileTime,
    GetFullPathNameW,
    VirtualAlloc,
    VirtualFree,
    CheckRemoteDebuggerPresent,
    WriteFile,
    GetProcessHeap,
    HeapCreate,
    HeapAlloc,
    HeapFree,
    HeapSize,
    HeapReAlloc,
    EncodePointer,
    DecodePointer,
    InitializeCriticalSection,
    InitializeCriticalSectionAndSpinCount,
    InitializeCriticalSectionEx,
    EnterCriticalSection,
    LeaveCriticalSection,
    FlsAlloc,
    FlsSetValue,
    FlsGetValue,
    TlsAlloc,
    GetStartupInfoW,
    GetStdHandle,
    GetFileType,
    GetCommandLineA,
    GetCommandLineW,
    GetEnvironmentStringsW,
    FreeEnvironmentStringsW,
    GetLastError,
    SetLastError,
    GetACP,
    GetCPInfo,
    MultiByteToWideChar,
    WideCharToMultiByte,
    GetStringTypeW,
    LCMapStringW,
    LCMapStringEx,
    InitializeSListHead,
    InterlockedPopEntrySList,
    RtlPcToFileHeader,
    NetUserEnum,
    NetApiBufferFree,
    CreateMutexA,
    CreateMutexW,
    OpenMutexW,
    ReleaseMutex,
    WaitForSingleObject,
    WSAStartup,
    DisableThreadLibraryCalls,
    SetHandleCount,
    timeGetTime,
    SetConsoleCtrlHandler,
    GetConsoleMode,
    GetProcessAffinityMask,
    GetLogicalProcessorInformationEx,
    RaiseException,
    RegisterTraceGuidsW,
    CreateEventW,
    RegisterWaitForSingleObject,
    CreateTimerQueueTimer,
    GetNumaHighestNodeNumber,
    HeapSetInformation,
    ExitProcess,
    NtQueryInformationProcess,
    AreFileApisANSI,
    DeleteCriticalSection,
    AppPolicyGetProcessTerminationMethod,
    CorExitProcess,
    FreeLibrary,
    # _initterm,
    # _initterm_e,
    # _onexit,
    # __crtGetShowWindowMode,
    # __iob_func,
    # __2_YAPEAX_K_Z,
    # __3_YAXPEAX_Z,
    # __1_Container_base12_std__QEAA_XZ,
    # strlen,
    # strncmp,
    # malloc,
    # puts,
    # # printf,
    # fwprintf_s,
    # swprintf_s,
    # exit,
    # memcpy,
    # memset,
    # wcscpy_s,
    NOTIMP
]