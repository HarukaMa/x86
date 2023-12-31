import datetime
import os
import re
import sys
import time

from io import SEEK_SET
from typing import List, Dict, BinaryIO, Any, TextIO, Union

from exc import Exited
from utils import pack_int64, read_int32, pack_int32, read_int64, pack_int16, read_int16, pack_int8

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

printf_re = re.compile(r"%(?P<flags>[-+ #0]*)(?P<width>\d+|\*)?(?:\.(?P<precision>\d+|\*))?(?P<length>hh|h|l|ll|j|z|t|L|I64)?(?P<specifier>[%csdioxXufFeEaAgGnp])")

def log(machine, s: str):
    print(f"{hex(read_int64(machine.memory.read(machine.cpu.state.rsp.value, 8)))} {s}", file=log_file, flush=True)

def error(value: int):
    global lasterror
    lasterror = value

def GetSystemTimeAsFileTime(machine):
    # void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
    lpSystemTimeAsFileTime = machine.cpu.state.rcx
    machine.memory.write(lpSystemTimeAsFileTime, pack_int64(int((datetime.datetime.utcnow() - _FILETIME_null_date).total_seconds() * 10000000)))
    log(machine, "GetSystemTimeAsFileTime(%#x)" % lpSystemTimeAsFileTime.value)

def GetCurrentProcessId(machine):
    # DWORD GetCurrentProcessId()
    machine.cpu.state.rax.value = 1
    log(machine, "GetCurrentProcessId() => %d" % machine.cpu.state.rax.value)

def GetCurrentThreadId(machine):
    # DWORD GetCurrentThreadId()
    machine.cpu.state.rax.value = 1
    log(machine, "GetCurrentThreadId() => %d" % machine.cpu.state.rax.value)

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

def QueryPerformanceCounter(machine):
    # BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
    lpPerformanceCount = machine.cpu.state.rcx
    now = int(time.time() * 10000000)
    machine.memory.write(lpPerformanceCount, pack_int64(now))
    machine.cpu.state.rax.value = 1
    log(machine, "QueryPerformanceCounter(%#x) => %d (%d)" % (
        lpPerformanceCount.value, machine.cpu.state.rax.value, now
    ))
    error(0)

def QueryPerformanceFrequency(machine):
    # BOOL QueryPerformanceFrequency( LARGE_INTEGER *lpFrequency );
    lpFrequency = machine.cpu.state.rcx
    machine.memory.write(lpFrequency, pack_int64(10000000))
    machine.cpu.state.rax.value = 1
    log(machine, "QueryPerformanceFrequency(%#x) => %d" % (lpFrequency.value, machine.cpu.state.rax.value))
    error(0)

def SetUnhandledExceptionFilter(machine):
    # LPTOP_LEVEL_EXCEPTION_FILTER __stdcall SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
    lpTopLevelExceptionFilter = machine.cpu.state.rcx
    machine.cpu.state.rax.value = 0
    log(machine, "SetUnhandledExceptionFilter(%#x) => %d" % (lpTopLevelExceptionFilter.value, machine.cpu.state.rax.value))

def GetModuleHandleA(machine):
    # HMODULE GetModuleHandleA(LPCSTR lpModuleName)
    lpModuleName = machine.cpu.state.rcx
    strlen(machine)
    if lpModuleName.value == 0:
        if machine.mode == 64:
            handle = 0x140000000
        else:
            handle = 0x400000
        buf = b"NULL"
    else:
        size = machine.cpu.state.rax.value
        buf = machine.memory.read(lpModuleName, size)
        if buf.decode().lower() == "ntdll.dll":
            handle = 0x40000000
            try:
                machine.memory.map_file(open("ntdll.dll", "rb"), 0, 0x400, 0x40000000, 0x400, "ntdll.dll")
            except MemoryError:
                pass
        else:
            handle = read_int32(buf[:4])
    machine.cpu.state.rax.value = handle
    log(machine, "GetModuleHandleA(\"%s\") => %#x" % (buf.decode(), handle))
    error(0)

def GetModuleHandleW(machine):
    # HMODULE GetModuleHandleW(LPCWSTR lpModuleName)
    lpModuleName = machine.cpu.state.rcx
    wcslen(machine)
    if lpModuleName.value == 0:
        if machine.mode == 64:
            handle = 0x140000000
        else:
            handle = 0x400000
        buf = b"N\x00U\x00L\x00L\x00"
    else:
        size = machine.cpu.state.rax.value
        buf = machine.memory.read(lpModuleName, size * 2)
        if buf.decode("utf-16le").lower() == "ntdll.dll":
            handle = 0x40000000
            try:
                machine.memory.map_file(open("ntdll.dll", "rb"), 0, 0x400, 0x40000000, 0x400, "ntdll.dll")
            except MemoryError:
                pass
        else:
            handle = read_int32(buf[:8:2])
    machine.cpu.state.rax.value = handle
    log(machine, "GetModuleHandleW(\"%s\") => %#x" % (buf.decode("utf-16le"), handle))
    error(0)

def GetProcAddress(machine):
    # FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
    hModule = machine.cpu.state.rcx
    lpProcName = machine.cpu.state.rdx
    module = pack_int32(hModule.value).decode()
    tmp = machine.cpu.state.rcx.value
    machine.cpu.state.rcx.value = lpProcName.value
    strlen(machine)
    machine.cpu.state.rcx.value = tmp
    size = machine.cpu.state.rax.value
    proc = machine.memory.read(lpProcName, size).decode()
    found = False
    for func in machine.api_list:
        if proc == func.__name__:
            found = True
            break
    if not found:
        log(machine, f"NOT IMPLEMENTED {module} {proc}")
        # raise NotImplementedError
    pos = len(machine.dynamic_imports)
    machine.cpu.state.rax.value = pos * 256 + 7
    log(machine, "GetProcAddress(\"%s\", \"%s\") => %#x" % (module, proc, machine.cpu.state.rax.value))
    machine.dynamic_imports.append(proc)
    error(0)

def VirtualProtect(machine):
    # BOOL VirtualProtect( LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect );
    lpAddress = machine.cpu.state.rcx
    dwSize = machine.cpu.state.rdx
    flNewProtect = machine.cpu.state.r8d
    lpflOldProtect = machine.cpu.state.r9d
    machine.memory.write(lpflOldProtect, pack_int32(0x40))
    machine.cpu.state.rax.value = 1
    log(machine, "VirtualProtect(%#x, %#x, %#x, %#x) => %d" % (
        lpAddress.value, dwSize.value, flNewProtect.value, lpflOldProtect.value, machine.cpu.state.rax.value
    ))
    error(0)

def GetModuleFileNameW(machine):
    # DWORD GetModuleFileNameW( HMODULE hModule, LPWSTR lpFilename, DWORD nSize );
    hModule = machine.cpu.state.rcx
    lpFilename = machine.cpu.state.rdx
    nSize = machine.cpu.state.r8
    if hModule.value == (0x140000000 if machine.mode == 64 else 0x400000) or hModule.value == 0:
        tmp = machine.cpu.state.rcx.value
        machine.cpu.state.rcx.value = 0x10100
        strlen(machine)
        machine.cpu.state.rcx.value = tmp
        size = machine.cpu.state.rax.value
        filename = machine.memory.read(0x10100, size).decode()
        if size > nSize.value:
            filename = filename[:nSize]
            size = nSize.value
        data = filename.encode("utf-16le")
        machine.memory.write(lpFilename, data + b"\x00\x00")
        machine.cpu.state.rax.value = size
        log(machine, "GetModuleFileNameW(%#x, %#x, %d) => %d (\"%s\")" %(
            hModule.value, lpFilename.value, nSize.value, machine.cpu.state.rax.value, filename
        ))
        error(0)
    else:
        machine.cpu.state.rax.value = 0
        log(machine, "GetModuleFileNameW(%#x, %#x, %d) => %d" % (
            hModule.value, lpFilename.value, nSize.value, machine.cpu.state.rax.value
        ))
        raise NotImplementedError

def GetModuleFileNameA(machine):
    # DWORD GetModuleFileNameA( HMODULE hModule, LPSTR lpFilename, DWORD nSize );
    hModule = machine.cpu.state.rcx
    lpFilename = machine.cpu.state.rdx
    nSize = machine.cpu.state.r8
    filename = None
    if hModule.value == 0:
        for start, size in machine.memory.mapped.items():
            if start <= machine.cpu.state.rip.value < start + size:
                filename = machine.memory.names[start]
    else:
        if hModule.value == (0x140000000 if machine.mode == 64 else 0x400000):
            tmp = machine.cpu.state.rcx.value
            machine.cpu.state.rcx.value = 0x10100
            strlen(machine)
            machine.cpu.state.rcx.value = tmp
            size = machine.cpu.state.rax.value
            filename = machine.memory.read(0x10100, size).decode()
        else:
            raise NotImplementedError
    err = 0
    if filename is None:
        err = 6
        size = 0
    else:
        size = len(filename)
        if size > nSize.value:
            filename = filename[:nSize - 1]
            size = nSize.value
            err = 122
        data = filename.encode()
        machine.memory.write(lpFilename, data + b"\x00")
    machine.cpu.state.rax.value = size
    log(machine, "GetModuleFileNameW(%#x, %#x, %d) => %d (\"%s\")" % (
        hModule.value, lpFilename.value, nSize.value, machine.cpu.state.rax.value, filename
    ))
    error(err)

def CreateFileW(machine):
    # HANDLE CreateFileW( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    # LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    # HANDLE hTemplateFile );
    lpFileName = machine.cpu.state.rcx
    dwDesiredAccess = machine.cpu.state.rdx
    dwShareMode = machine.cpu.state.r8
    lpSecurityAttributes = machine.cpu.state.r9
    dwCreationDisposition = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    dwFlagsAndAttributes = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    hTemplateFile = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    wcslen(machine)
    size = machine.cpu.state.rax.value
    filename = machine.memory.read(lpFileName, size * 2).decode("utf-16le")
    filename_converted = filename.replace("\\", "/")
    if dwFlagsAndAttributes & 0x2000000:
        # try dir
        if os.path.exists(filename_converted):
            global next_dir_handle
            handle = next_dir_handle + 0x40000
            dir_handles[next_dir_handle] = filename_converted
            next_dir_handle += 1
            log(machine, "CreateFileW dir %s" % filename)
            machine.cpu.state.rax.value = handle
            return
    global next_file_handle
    handle = next_file_handle + 0x10000
    mode = ""
    if dwDesiredAccess.value & 0x40000000 == 0x40000000:
        mode = "wb"
    if dwDesiredAccess.value & 0x80000000 == 0x80000000:
        mode = "rb"
    if dwDesiredAccess.value & 0xC0000000 == 0xC0000000:
        mode = "rb+"
    try:
        file = open(filename_converted, mode)
        file_handles[next_file_handle] = file
        next_file_handle += 1
        machine.cpu.state.rax.value = handle
        error(0)
    except:
        machine.cpu.state.rax.value = -1
        error(2)
    log(machine, "CreateFileW(\"%s\", %#x, %#x, %#x, %#x, %#x, %#x) => %#x" % (
        filename, dwDesiredAccess.value, dwShareMode.value, lpSecurityAttributes.value,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, machine.cpu.state.rax.value
    ))

def CreateFileA(machine):
    # HANDLE CreateFileA( LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile );
    lpFileName = machine.cpu.state.rcx
    dwDesiredAccess = machine.cpu.state.rdx
    dwShareMode = machine.cpu.state.r8
    lpSecurityAttributes = machine.cpu.state.r9
    dwCreationDisposition = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    dwFlagsAndAttributes = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    hTemplateFile = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    strlen(machine)
    size = machine.cpu.state.rax.value
    filename = machine.memory.read(lpFileName, size).decode()
    filename_converted = filename.replace("\\", "/")
    if dwFlagsAndAttributes & 0x2000000:
        # try dir
        if os.path.exists(filename_converted):
            global next_dir_handle
            handle = next_dir_handle + 0x40000
            dir_handles[next_dir_handle] = filename_converted
            next_dir_handle += 1
            log(machine, "CreateFileW dir %s" % filename)
            machine.cpu.state.rax.value = handle
            return
    global next_file_handle
    handle = next_file_handle + 0x10000
    log(machine, "CreateFileA %s access %s" % (filename, dwDesiredAccess))
    mode = ""
    if dwDesiredAccess.value & 0x40000000 == 0x40000000:
        mode = "wb"
    if dwDesiredAccess.value & 0x80000000 == 0x80000000:
        mode = "rb"
    if dwDesiredAccess.value & 0xC0000000 == 0xC0000000:
        mode = "rb+"
    try:
        file = open(filename, mode)
        file_handles[next_file_handle] = file
        next_file_handle += 1
        machine.cpu.state.rax.value = handle
        error(0)
    except:
        machine.cpu.state.rax.value = -1
        error(2)
    log(machine, "CreateFileA(\"%s\", %#x, %#x, %#x, %#x, %#x, %#x) => %#x" % (
        filename, dwDesiredAccess.value, dwShareMode.value, lpSecurityAttributes.value,
        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, machine.cpu.state.rax.value
    ))

def CreateFileMappingA(machine):
    # HANDLE CreateFileMappingA( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect,
    # DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName );
    hFile = machine.cpu.state.rcx
    lpFileMappingAttributes = machine.cpu.state.rdx
    flProtect = machine.cpu.state.r8
    dwMaximumSizeHigh = machine.cpu.state.r9
    dwMaximumSizeLow = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    lpName = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    if dwMaximumSizeHigh.value or dwMaximumSizeLow:
        raise NotImplementedError
    if file_handles.get(hFile.value - 0x10000) is None:
        raise ValueError
    global next_file_mapping
    handle = next_file_mapping + 0x20000
    file_mappings[next_file_mapping] = hFile.value - 0x10000
    if lpName != 0:
        tmp = machine.cpu.state.rcx.value
        machine.cpu.state.rcx.value = lpName
        strlen(machine)
        machine.cpu.state.rcx.value = tmp
        size = machine.cpu.state.rax.value
        mapping_name = machine.memory.read(lpName, size).decode()
    else:
        mapping_name = "NULL"
    file_mappings_name[next_file_mapping] = mapping_name
    next_file_mapping += 1
    machine.cpu.state.rax.value = handle
    log(machine, "CreateFileMappingA(%#x(\"%s\"), %#x, %#x, %#x, %#x, \"%s\") => %#x" % (
        hFile.value, file_handles[hFile.value - 0x10000].name, lpFileMappingAttributes.value, flProtect.value,
        dwMaximumSizeHigh.value, dwMaximumSizeLow, mapping_name, machine.cpu.state.rax.value
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
        mapping_name = "NULL"
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

def MapViewOfFile(machine):
    # LPVOID MapViewOfFile( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap );
    hFileMappingObject = machine.cpu.state.rcx
    dwDesiredAccess = machine.cpu.state.rdx
    dwFileOffsetHigh = machine.cpu.state.r8
    dwFileOffsetLow = machine.cpu.state.r9
    dwNumberOfBytesToMap = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    handle = hFileMappingObject.value - 0x20000
    if file_mappings.get(handle) is None:
        raise ValueError
    offset = (dwFileOffsetHigh.value << 32) + dwFileOffsetLow.value
    if file_mappings[handle] < 0x100000000:
        file = file_handles[file_mappings[handle]]
        file.seek(offset, SEEK_SET)
        if dwNumberOfBytesToMap == 0:
            data = file.read()
        else:
            raise NotImplementedError
        name = file.name
    else:
        data = bytearray([0]) * (file_mappings[handle] & 0xffffffff)
        name = "Pagefile %#x" % handle
    map_base = 0x30000000
    res = 0
    for k, v in machine.memory.names.items():
        if v == name:
            res = k
            break
    if res == 0:
        for k, v in machine.memory.mapped.items():
            if k <= map_base < k + v:
                map_base = k + v - ((k + v) % 0x1000) + 0x1000
        machine.memory.map(map_base, len(data), name)
        machine.memory.write(map_base, data)
        res = map_base
    addr_mappings[res] = handle
    machine.cpu.state.rax.value = res
    log(machine, "MapViewOfFile(%#x(%#x, \"%s\"), %#x, %#x, %#x, %d) => %#x" % (
        hFileMappingObject.value, file_mappings[handle], name, dwDesiredAccess.value, dwFileOffsetHigh.value,
        dwFileOffsetLow.value, dwNumberOfBytesToMap, machine.cpu.state.rax.value
    ))
    error(0)

def UnmapViewOfFile(machine):
    # BOOL UnmapViewOfFile( LPCVOID lpBaseAddress );
    lpBaseAddress = machine.cpu.state.rcx
    mapping = addr_mappings.get(lpBaseAddress.value, None)
    if mapping is None:
        raise ValueError
    machine.memory.unmap(lpBaseAddress.value)
    if file_mappings[mapping] < 0x100000000:
        name = file_handles[file_mappings[mapping]].name
    else:
        name = "Pagefile %#x" % mapping
    machine.cpu.state.rax.value = 1
    log(machine, "UnmapViewOfFile(%#x(\"%s\") => %d" % (lpBaseAddress.value, name, machine.cpu.state.rax.value))
    error(0)

def CloseHandle(machine):
    # BOOL CloseHandle( HANDLE hObject );
    hObject = machine.cpu.state.rcx
    handle = hObject.value & 0xffff
    if hObject.value & 0x10000:
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
    machine.cpu.state.rax.value = 1
    log(machine, "CloseHandle(%#x) => %d" % (hObject.value, machine.cpu.state.rax.value))
    error(0)

def Beep(machine):
    # BOOL Beep( DWORD dwFreq, DWORD dwDuration );
    dwFreq = machine.cpu.state.rcx
    dwDuration = machine.cpu.state.rdx
    machine.cpu.state.rax.value = 1
    log(machine, "Beep(%d, %d) => %d" % (dwFreq.value, dwDuration.value, machine.cpu.state.rax.value))
    error(0)

def LoadLibraryA(machine):
    # HMODULE LoadLibraryA( LPCSTR lpLibFileName );
    lpLibFileName = machine.cpu.state.rcx
    strlen(machine)
    size = machine.cpu.state.rax.value
    filename = machine.memory.read(lpLibFileName, size).decode()
    log(machine, "LoadLibraryA(\"%s\") => %#x" % (filename, machine.cpu.state.rax.value))
    raise NotImplementedError

def LoadLibraryExW(machine):
    # HMODULE LoadLibraryExW( LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags );
    lpLibFileName = machine.cpu.state.rcx
    hFile = machine.cpu.state.rdx
    dwFlags = machine.cpu.state.r8
    wcslen(machine)
    size = machine.cpu.state.rax.value
    buffer = machine.memory.read(lpLibFileName, size * 2)
    filename = buffer.decode("utf-16le")
    handle = read_int32(buffer[:8:2])
    machine.cpu.state.rax.value = handle
    log(machine, "LoadLibraryExW(\"%s\", %#x, %#x) => %#x" % (filename, hFile.value, dwFlags.value, machine.cpu.state.rax.value))
    error(0)

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

def IsDebuggerPresent(machine):
    # BOOL IsDebuggerPresent();
    machine.cpu.state.rax.value = 0
    log(machine, "IsDebuggerPresent() => %d" % machine.cpu.state.rax.value)

def GetLocalTime(machine):
    # void GetLocalTime( LPSYSTEMTIME lpSystemTime );
    lpSystemTime = machine.cpu.state.rcx
    machine.memory.write(lpSystemTime + 0, pack_int16(1970))
    machine.memory.write(lpSystemTime + 2, pack_int16(1))
    machine.memory.write(lpSystemTime + 4, pack_int16(1))
    machine.memory.write(lpSystemTime + 6, pack_int16(4))
    machine.memory.write(lpSystemTime + 8, pack_int16(0))
    machine.memory.write(lpSystemTime + 10, pack_int16(0))
    machine.memory.write(lpSystemTime + 12, pack_int16(0))
    machine.memory.write(lpSystemTime + 14, pack_int16(0))
    log(machine, "GetLocalTime(%#x) (1970-01-01 00:00:00)" % lpSystemTime.value)

def SystemTimeToFileTime(machine):
    # BOOL SystemTimeToFileTime( const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime );
    lpSystemTime = machine.cpu.state.rcx
    lpFileTime = machine.cpu.state.rdx
    year = read_int16(machine.memory.read(lpSystemTime + 0, 2))
    month = read_int16(machine.memory.read(lpSystemTime + 2, 2))
    day = read_int16(machine.memory.read(lpSystemTime + 4, 2))
    hour = read_int16(machine.memory.read(lpSystemTime + 8, 2))
    minute = read_int16(machine.memory.read(lpSystemTime + 10, 2))
    second = read_int16(machine.memory.read(lpSystemTime + 12, 2))
    ms = read_int16(machine.memory.read(lpSystemTime + 14, 2))
    date = datetime.datetime(year, month, day, hour, minute, second, ms)
    machine.memory.write(lpFileTime,
                         pack_int64(int((date - _FILETIME_null_date).total_seconds() * 10000000)))
    machine.cpu.state.rax.value = 1
    log(machine, "SystemTimeToFileTime(%#x, %#x) => %d (%s)" % (
        lpSystemTime.value, lpFileTime.value, machine.cpu.state.rax.value, date
    ))
    error(0)

def GetTempPathW(machine):
    # DWORD GetTempPathW( DWORD nBufferLength, LPWSTR lpBuffer );
    nBufferLength = machine.cpu.state.rcx
    lpBuffer = machine.cpu.state.rdx
    filename = "c:\\temp\\".encode("utf-16le")
    machine.memory.write(lpBuffer, filename + b"\x00\x00")
    machine.cpu.state.rax.value = 5
    log(machine, "GetTempPathW(%d, %#x) => %d (\"%s\")" % (
        nBufferLength.value, lpBuffer.value, machine.cpu.state.rax.value, "/tmp"
    ))
    error(0)

def GetVersion(machine):
    # NOT_BUILD_WINDOWS_DEPRECATE DWORD GetVersion();
    machine.cpu.state.rax.value = 0x0000000a
    log(machine, "GetVersion() => %#x" % machine.cpu.state.rax.value)

def GetVersionExA(machine):
    # BOOL GetVersionExA( LPOSVERSIONINFOA lpVersionInformation );
    lpVersionInformation = machine.cpu.state.rcx
    size = read_int32(machine.memory.read(lpVersionInformation, 4))
    if size == 148:
        # OSVERSIONINFOA
        machine.memory.write(lpVersionInformation + 4, pack_int32(10))
        machine.memory.write(lpVersionInformation + 8, pack_int32(0))
        machine.memory.write(lpVersionInformation + 12, pack_int32(0))
        machine.memory.write(lpVersionInformation + 16, pack_int32(2))
        machine.memory.write(lpVersionInformation + 20, b"\x00")
    else:
        # OSVERSIONINFOEXA
        raise NotImplementedError
    machine.cpu.state.rax.value = 1
    log(machine, "GetVersionExA(%#x) => %d" % (lpVersionInformation.value, machine.cpu.state.rax.value))
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

def GetTempFileNameW(machine):
    # UINT GetTempFileNameW( LPCWSTR lpPathName, LPCWSTR lpPrefixString, UINT uUnique, LPWSTR lpTempFileName );
    lpPathName = machine.cpu.state.rcx
    lpPrefixString = machine.cpu.state.rdx
    uUnique = machine.cpu.state.r8
    lpTempFileName = machine.cpu.state.r9
    wcslen(machine)
    total_size = 0
    size = machine.cpu.state.rax.value
    total_size += size
    buffer = machine.memory.read(lpPathName, size * 2)
    pathname = buffer.decode("utf-16le")
    tmp = machine.cpu.state.rcx.value
    machine.cpu.state.rcx.value = machine.cpu.state.rdx.value
    wcslen(machine)
    machine.cpu.state.rcx.value = tmp
    size = machine.cpu.state.rax.value
    buffer += machine.memory.read(lpPrefixString, size * 2)
    prefixstring = machine.memory.read(lpPrefixString, size * 2).decode("utf-16le")
    total_size += size + len(str(uUnique.value))
    machine.memory.write(lpTempFileName, buffer + str(uUnique.value).encode("utf-16le") + b"\x00\x00")
    machine.cpu.state.rax.value = total_size
    log(machine, "GetTempFileNameW(\"%s\", \"%s\", %d, %#x) => %d (%s%d)" % (
        pathname, prefixstring, uUnique.value, lpTempFileName.value, machine.cpu.state.rax.value,
        buffer.decode("utf-16le"), uUnique.value
    ))
    error(0)

def DeleteFileW(machine):
    # BOOL DeleteFileW( LPCWSTR lpFileName );
    lpFileName = machine.cpu.state.rcx
    wcslen(machine)
    size = machine.cpu.state.rax.value
    buffer = machine.memory.read(lpFileName, size * 2)
    machine.cpu.state.rax.value = 0
    log(machine, "DeleteFileW(\"%s\") => %d" % (buffer.decode("utf-16le"), machine.cpu.state.rax.value))
    error(2)

def GetVolumeInformationW(machine):
    # BOOL GetVolumeInformationW(
    # LPCWSTR lpRootPathName, LPWSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber,
    # LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPWSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize );
    lpRootPathName = machine.cpu.state.rcx
    lpVolumeNameBuffer = machine.cpu.state.rdx
    nVolumeNameSize = machine.cpu.state.r8
    lpVolumeSerialNumber = machine.cpu.state.r9
    lpMaximumComponentLength = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    lpFileSystemFlags = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    lpFileSystemNameBuffer = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    nFileSystemNameSize = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x40, 8))
    if lpVolumeNameBuffer.value != 0:
        raise NotImplementedError
    if lpVolumeSerialNumber.value != 0:
        machine.memory.write(lpVolumeSerialNumber, pack_int32(0x0123ab67))
    machine.memory.write(lpMaximumComponentLength, pack_int32(255))
    machine.memory.write(lpFileSystemFlags, pack_int32(0x4))
    if lpFileSystemNameBuffer != 0:
        raise NotImplementedError
    wcslen(machine)
    size = machine.cpu.state.rax.value
    buffer = machine.memory.read(lpRootPathName, size * 2)
    machine.cpu.state.rax.value = 1
    log(machine, "GetVolumeInformationW(\"%s\", %#x, %d, %#x, %#x, %#x, %#x, %d) => %d" % (
        buffer.decode("utf-16le"), lpVolumeNameBuffer.value, nVolumeNameSize.value, lpVolumeSerialNumber.value,
        lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize,
        machine.cpu.state.rax.value
    ))
    error(0)

def GetSystemTime(machine):
    # void GetSystemTime( LPSYSTEMTIME lpSystemTime );
    lpSystemTime = machine.cpu.state.rcx
    machine.memory.write(lpSystemTime + 0, pack_int16(2020))
    machine.memory.write(lpSystemTime + 2, pack_int16(1))
    machine.memory.write(lpSystemTime + 4, pack_int16(1))
    machine.memory.write(lpSystemTime + 6, pack_int16(3))
    machine.memory.write(lpSystemTime + 8, pack_int16(0))
    machine.memory.write(lpSystemTime + 10, pack_int16(0))
    machine.memory.write(lpSystemTime + 12, pack_int16(0))
    machine.memory.write(lpSystemTime + 14, pack_int16(0x361))
    log(machine, "GetSystemTime(%#x) (2020-01-01 00:00:00)" % lpSystemTime.value)

def GetFileTime(machine):
    # BOOL GetFileTime( HANDLE hFile, LPFILETIME lpCreationTime, LPFILETIME lpLastAccessTime, LPFILETIME lpLastWriteTime );
    hFile = machine.cpu.state.rcx
    lpCreationTime = machine.cpu.state.rdx
    lpLastAccessTime = machine.cpu.state.r8
    lpLastWriteTime = machine.cpu.state.r9
    if hFile.value & 0x10000:
        raise NotImplementedError
    elif hFile.value & 0x40000:
        filename = dir_handles[hFile.value % 0x40000]
    else:
        raise ValueError
    if lpCreationTime.value:
        machine.memory.write(lpCreationTime, bytes.fromhex("d021055936c0d501"))
    if lpLastAccessTime.value:
        raise NotImplementedError
    if lpLastWriteTime.value:
        raise NotImplementedError
    machine.cpu.state.rax.value = 1
    log(machine, "GetFileTime(%#x(\"%s\"), %#x, %#x, %#x) => %d" % (
        hFile.value, filename, lpCreationTime.value, lpLastAccessTime.value, lpLastWriteTime.value,
        machine.cpu.state.rax.value
    ))
    error(0)

def GetFullPathNameW(machine):
    # DWORD GetFullPathNameW( LPCWSTR lpFileName, DWORD nBufferLength, LPWSTR lpBuffer, LPWSTR *lpFilePart );
    lpFileName = machine.cpu.state.rcx
    nBufferLength = machine.cpu.state.rdx
    lpBuffer = machine.cpu.state.r8
    lpFilePart = machine.cpu.state.r9
    wcslen(machine)
    size = machine.cpu.state.rax.value
    filename = machine.memory.read(lpFileName, size * 2).decode("utf-16le")
    if len(filename) + 1 > nBufferLength.value:
        raise ValueError
    if os.path.isdir(filename):
        machine.memory.write(lpBuffer, filename.encode("utf-16le") + b"\x00\x00")
        if lpFilePart.value:
            machine.memory.write(lpFilePart, b"\x00\x00")
    machine.memory.write(lpBuffer, filename.encode("utf-16le") + b"\x00\x00")
    if lpFilePart.value:
        if os.path.isdir(filename):
            machine.memory.write(lpFilePart, pack_int64(0))
        else:
            try:
                pos = filename.rindex("/")
            except ValueError:
                pos = filename.rindex("\\")
            machine.memory.write(lpFilePart, pack_int64(lpBuffer.value + pos * 2 + 2))
    if "/" in filename:
        machine.cpu.state.rax.value = len(filename.split("/")[:-1])
    else:
        machine.cpu.state.rax.value = len(filename.split("\\")[:-1])
    log(machine, "GetFullPathNameW(\"%s\", %d, %#x, %#x) => %d" % (
        filename, nBufferLength.value, lpBuffer.value, lpFilePart.value, machine.cpu.state.rax.value
    ))
    error(0)

def VirtualAlloc(machine):
    # LPVOID VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );
    lpAddress = machine.cpu.state.rcx
    dwSize = machine.cpu.state.rdx
    flAllocationType = machine.cpu.state.r8
    flProtect = machine.cpu.state.r9
    if lpAddress.value == 0:
        res = machine.memory.alloc(dwSize.value)
    else:
        raise NotImplementedError
    machine.cpu.state.rax.value = res
    log(machine, "VirtualAlloc(%#x, %d, %#x, %#x) => %#x" % (
        lpAddress.value, dwSize.value, flAllocationType.value, flProtect.value, machine.cpu.state.rax.value
    ))
    error(0)

def VirtualFree(machine):
    # BOOL VirtualFree( LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType );
    lpAddress = machine.cpu.state.rcx
    dwSize = machine.cpu.state.rdx
    dwFreeType = machine.cpu.state.r8
    if dwFreeType != 0x00008000:
        raise NotImplementedError
    machine.memory.free(lpAddress.value)
    machine.cpu.state.rax.value = 1
    log(machine, "VirtualFree(%#x, %d, %#x) => %d" % (
        lpAddress.value, dwSize.value, dwFreeType.value, machine.cpu.state.rax.value
    ))
    error(0)

def CheckRemoteDebuggerPresent(machine):
    # BOOL CheckRemoteDebuggerPresent( HANDLE hProcess, PBOOL pbDebuggerPresent );
    hProcess = machine.cpu.state.rcx
    pbDebuggerPresent = machine.cpu.state.rdx
    machine.memory.write(pbDebuggerPresent.value, pack_int8(0))
    machine.cpu.state.rax.value = 1
    log(machine, "CheckRemoteDebuggerPresent(%#x, %#x) => %d" % (
        hProcess.value, pbDebuggerPresent.value, machine.cpu.state.rax.value
    ))
    error(0)

def WriteFile(machine):
    # BOOL WriteFile( HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped );
    hFile = machine.cpu.state.rcx
    lpBuffer = machine.cpu.state.rdx
    nNumberOfBytesToWrite = machine.cpu.state.r8
    lpNumberOfBytesWritten = machine.cpu.state.r9
    lpOverlapped = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    if lpOverlapped != 0:
        raise NotImplementedError
    data = machine.memory.read(lpBuffer, nNumberOfBytesToWrite.value)
    if hFile.value == 1:
        file = sys.stdout
        file.write(data.decode())
    elif hFile.value == 2:
        file = sys.stderr
        file.write(data.decode())
    else:
        file = file_handles[hFile.value - 0x10000]
        file.write(data)
    lpNumberOfBytesWritten.value = nNumberOfBytesToWrite.value
    machine.cpu.state.rax.value = 1
    log(machine, "WriteFile(%#x, \"%s\", %d, %#x, %#x) => %d" % (
        hFile.value, data.decode(), nNumberOfBytesToWrite.value, lpNumberOfBytesWritten.value, lpOverlapped,
        machine.cpu.state.rax.value
    ))
    error(0)

def GetProcessHeap(machine):
    # HANDLE GetProcessHeap();
    machine.cpu.state.rax.value = 0x10000000
    log(machine, "GetProcessHeap() => %#x" % machine.cpu.state.rax.value)
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

def HeapAlloc(machine):
    # DECLSPEC_ALLOCATOR LPVOID HeapAlloc( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes );
    hHeap = machine.cpu.state.rcx
    dwFlags = machine.cpu.state.rdx
    dwBytes = machine.cpu.state.r8
    if hHeap.value != 0x10000000:
        raise NotImplementedError
    res = machine.memory.alloc(dwBytes.value)
    if dwFlags.value & 8:
        machine.memory.write(res, b"\x00" * dwBytes.value)
    machine.cpu.state.rax.value = res
    log(machine, "HeapAlloc(%#x, %#x, %d) => %#x" % (hHeap.value, dwFlags.value, dwBytes.value, machine.cpu.state.rax.value))
    error(0)

def HeapFree(machine):
    # BOOL HeapFree( HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem );
    hHeap = machine.cpu.state.rcx
    dwFlags = machine.cpu.state.rdx
    lpMem = machine.cpu.state.r8
    if hHeap.value != 0x10000000:
        raise NotImplementedError
    machine.memory.free(lpMem.value)
    machine.cpu.state.rax.value = 1
    log(machine, "HeapFree(%#x, %#x, %#x) => %d" % (hHeap.value, dwFlags.value, lpMem.value, machine.cpu.state.rax.value))
    error(0)

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

def InitializeCriticalSectionEx(machine):
    # BOOL InitializeCriticalSectionEx( LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount, DWORD Flags );
    lpCriticalSection = machine.cpu.state.rcx
    dwSpinCount = machine.cpu.state.rdx
    Flags = machine.cpu.state.r8
    machine.cpu.state.rax.value = 1
    log(machine, "InitializeCriticalSectionEx(%#x, %d, %#x) => %d" % (
        lpCriticalSection.value, dwSpinCount.value, Flags.value, machine.cpu.state.rax.value
    ))
    error(0)

def EnterCriticalSection(machine):
    # void EnterCriticalSection( LPCRITICAL_SECTION lpCriticalSection );
    lpCriticalSection = machine.cpu.state.rcx
    log(machine, "EnterCriticalSection(%#x)" % lpCriticalSection.value)

def LeaveCriticalSection(machine):
    # void LeaveCriticalSection( LPCRITICAL_SECTION lpCriticalSection );
    lpCriticalSection = machine.cpu.state.rcx
    log(machine, "LeaveCriticalSection(%#x)" % lpCriticalSection.value)

def FlsAlloc(machine):
    # DWORD FlsAlloc( PFLS_CALLBACK_FUNCTION lpCallback );
    lpCallback = machine.cpu.state.rcx
    index = len(fibers[fiber])
    fibers[fiber].append(0)
    machine.cpu.state.rax.value = index
    log(machine, "FlsAlloc(%#x) => %d" % (lpCallback.value, machine.cpu.state.rax.value))

def FlsSetValue(machine):
    # BOOL FlsSetValue( DWORD dwFlsIndex, PVOID lpFlsData );
    dwFlsIndex = machine.cpu.state.rcx
    lpFlsData = machine.cpu.state.rdx
    fibers[fiber][dwFlsIndex.value] = lpFlsData.value
    machine.cpu.state.rax.value = 1
    log(machine, "FlsSetValue(%d, %#x) => %d" % (dwFlsIndex.value, lpFlsData.value, machine.cpu.state.rax.value))

def FlsGetValue(machine):
    # PVOID FlsGetValue( DWORD dwFlsIndex );
    dwFlsIndex = machine.cpu.state.rcx
    if len(fibers[fiber]) < dwFlsIndex.value:
        res = 0
        error(87)
    else:
        res = fibers[fiber][dwFlsIndex.value]
        error(0)
    machine.cpu.state.rax.value = res
    log(machine, "FlsGetValue(%d) => %#x" % (dwFlsIndex.value, machine.cpu.state.rax.value))

def TlsAlloc(machine):
    # DWORD TlsAlloc();
    index = len(threads[thread])
    threads[thread].append(0)
    machine.cpu.state.rax.value = index
    log(machine, "TlsAlloc() => %d" % machine.cpu.state.rax.value)

def GetStartupInfoW(machine):
    # void GetStartupInfoW( LPSTARTUPINFOW lpStartupInfo );
    lpStartupInfo = machine.cpu.state.rcx
    machine.memory.write(lpStartupInfo, pack_int32(96))
    machine.memory.write(lpStartupInfo + 4, b"\x00" * 92)
    log(machine, "GetStartupInfoW(%#x)" % lpStartupInfo.value)

def GetStdHandle(machine):
    # HANDLE WINAPI GetStdHandle( _In_ DWORD nStdHandle );
    nStdHandle = machine.cpu.state.rcx
    if nStdHandle.value == 4294967286:
        name = "stdin"
        handle = 0
    elif nStdHandle.value == 4294967285:
        name = "stdout"
        handle = 1
    elif nStdHandle.value == 4294967284:
        name = "stderr"
        handle = 2
    else:
        log(machine, "GetStdHandle %d" % nStdHandle.value)
        raise NotImplementedError
    machine.cpu.state.rax.value = handle
    log(machine, "GetStdHandle(\"%s\") => %#x" % (name, machine.cpu.state.rax.value))
    error(0)

def GetFileType(machine):
    # DWORD GetFileType( HANDLE hFile );
    hFile = machine.cpu.state.rcx
    if 0 <= hFile.value <= 2:
        res = 2
    else:
        raise NotImplementedError
    machine.cpu.state.rax.value = res
    log(machine, "GetFileType(%#x) => %d" % (hFile.value, machine.cpu.state.rax.value))
    error(0)

def GetCommandLineA(machine):
    # LPSTR GetCommandLineA();
    machine.cpu.state.rax.value = 0x10100
    log(machine, "GetCommandLineA() => %#x" % machine.cpu.state.rax.value)

def GetCommandLineW(machine):
    # LPWSTR GetCommandLineW();
    machine.cpu.state.rax.value = 0x10300
    log(machine, "GetCommandLineW() => %#x" % machine.cpu.state.rax.value)

def GetEnvironmentStringsW(machine):
    # LPWCH GetEnvironmentStringsW();
    machine.cpu.state.rax.value = 0x10500
    log(machine, "GetEnvironmentStringsW() => %#x" % machine.cpu.state.rax.value)

def FreeEnvironmentStringsW(machine):
    # BOOL FreeEnvironmentStringsW( LPWCH penv );
    penv = machine.cpu.state.rcx
    machine.cpu.state.rax.value = 1
    log(machine, "FreeEnvironmentStringsW(%#x) => %d" % (penv.value, machine.cpu.state.rax.value))
    error(0)

def GetLastError(machine):
    # _Post_equals_last_error_ DWORD GetLastError();
    machine.cpu.state.rax.value = lasterror
    log(machine, "GetLastError() => %d" % machine.cpu.state.rax.value)

def SetLastError(machine):
    # void SetLastError( DWORD dwErrCode );
    global lasterror
    dwErrCode = machine.cpu.state.rcx
    log(machine, "SetLastError(%d)" % dwErrCode.value)
    lasterror = dwErrCode.value

def GetACP(machine):
    # UINT GetACP();
    machine.cpu.state.rax.value = 932
    log(machine, "GetACP() => %d" % machine.cpu.state.rax.value)

def GetCPInfo(machine):
    # BOOL GetCPInfo( UINT CodePage, LPCPINFO lpCPInfo );
    CodePage = machine.cpu.state.rcx
    lpCPInfo = machine.cpu.state.rdx
    machine.memory.write(lpCPInfo.value + 0x0, pack_int32(2))
    machine.memory.write(lpCPInfo.value + 0x4, b"\x3f\x00")
    machine.memory.write(lpCPInfo.value + 0x6, b"\x81\x9f\xe0\xfc\x00\x00\x00\x00\x00\x00\x00\x00")
    machine.cpu.state.rax.value = 1
    log(machine, "GetCPInfo(%d, %#x) => %d" % (CodePage.value, lpCPInfo.value, machine.cpu.state.rax.value))
    error(0)

def MultiByteToWideChar(machine):
    # int MultiByteToWideChar(
    # UINT CodePage, DWORD dwFlags, _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr, int cbMultiByte,
    # LPWSTR lpWideCharStr, int cchWideChar );
    CodePage = machine.cpu.state.rcx
    dwFlags = machine.cpu.state.rdx
    lpMultiByteStr = machine.cpu.state.r8
    cbMultiByte = machine.cpu.state.r9
    lpWideCharStr = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    cchWideChar = read_int32(machine.memory.read(machine.cpu.state.rsp + 0x30, 4))
    try:
        "".encode(f"cp{CodePage.value}")
    except LookupError:
        print(CodePage.value)
        raise NotImplementedError
    buffer = machine.memory.read(lpMultiByteStr, cbMultiByte.value).decode(f"cp{CodePage.value}")
    res = buffer.encode("utf-16le")
    if cchWideChar != 0:
        machine.memory.write(lpWideCharStr, res)
    machine.cpu.state.rax.value = len(res) // 2
    log(machine, "MultiByteToWideChar(%d, %#x, \"%s\", %d, %#x, %d) => %d" % (
        CodePage.value, dwFlags.value, buffer, cbMultiByte.value, lpWideCharStr, cchWideChar,
        machine.cpu.state.rax.value
    ))
    error(0)

def WideCharToMultiByte(machine):
    # int WideCharToMultiByte( UINT CodePage, DWORD dwFlags, _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
    # int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar );
    CodePage = machine.cpu.state.rcx
    dwFlags = machine.cpu.state.rdx
    lpWideCharStr = machine.cpu.state.r8
    cchWideChar = machine.cpu.state.r9
    lpMultiByteStr = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    cbMultiByte = read_int32(machine.memory.read(machine.cpu.state.rsp + 0x30, 4))
    lpDefaultChar = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    lpUsedDefaultChar = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x40, 8))
    if CodePage.value == 0:
        CodePage.value = 932
    try:
        "".encode(f"cp{CodePage.value}")
    except LookupError:
        print(CodePage.value)
        raise NotImplementedError
    buffer = machine.memory.read(lpWideCharStr, cchWideChar.value * 2).decode("utf-16le")
    res = buffer.encode(f"cp{CodePage.value}")
    if cbMultiByte != 0:
        machine.memory.write(lpMultiByteStr, res)
    machine.cpu.state.rax.value = len(res)
    log(machine, "WideCharToMultiByte(%d, %#x, \"%s\", %d, %#x, %d, %#x, %d) => %d" % (
        CodePage.value, dwFlags.value, buffer, cchWideChar.value, lpMultiByteStr, cbMultiByte,
        lpDefaultChar, lpUsedDefaultChar, machine.cpu.state.rax.value
    ))
    error(0)

def GetStringTypeW(machine):
    # BOOL GetStringTypeW( DWORD dwInfoType, _In_NLS_string_(cchSrc)LPCWCH lpSrcStr, int cchSrc, LPWORD lpCharType );
    dwInfoType = machine.cpu.state.rcx
    lpSrcStr = machine.cpu.state.rdx
    cchSrc = machine.cpu.state.r8
    lpCharType = machine.cpu.state.r9
    # breakpoint()
    machine.cpu.state.rax.value = 0
    log(machine, "STUB GetStringTypeW(%#x, %#x, %d, %#x) => %d" % (
        dwInfoType.value, lpSrcStr.value, cchSrc.value, lpCharType.value, machine.cpu.state.rax.value
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

def LCMapStringEx(machine):
    # int LCMapStringEx(
    # LPCWSTR lpLocaleName, DWORD dwMapFlags, LPCWSTR lpSrcStr, int cchSrc, LPWSTR lpDestStr, int cchDest,
    # LPNLSVERSIONINFO lpVersionInformation, LPVOID lpReserved, LPARAM sortHandle );
    lpLocaleName = machine.cpu.state.rcx
    dwMapFlags = machine.cpu.state.rdx
    lpSrcStr = machine.cpu.state.r8
    cchSrc = machine.cpu.state.r9
    lpDestStr = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x28, 8))
    cchDest = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x30, 8))
    lpVersionInformation = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x38, 8))
    lpReserved = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x40, 8))
    sortHandle = read_int64(machine.memory.read(machine.cpu.state.rsp + 0x48, 8))
    machine.cpu.state.rax.value = 0
    log(machine, "STUB LCMapStringEx(%#x, %#x, %#x, %d, %#x, %d, %#x, %#x, %#x) => %d" % (
        lpLocaleName.value, dwMapFlags.value, lpSrcStr.value, cchSrc.value, lpDestStr, cchDest, lpVersionInformation,
        lpReserved, sortHandle, machine.cpu.state.rax.value
    ))
    error(120)

def InitializeSListHead(machine):
    # void InitializeSListHead( PSLIST_HEADER ListHead );
    ListHead = machine.cpu.state.rcx
    log(machine, "STUB InitializeSListHead(%#x)" % ListHead.value)

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
def strlen(machine):
    # size_t strlen( const char *str )
    _str = machine.cpu.state.rcx
    res = 0
    while True:
        buf: bytearray = machine.memory.read(_str + res, 8)
        tmp = buf.find(b"\x00")
        if tmp == -1:
            res += 8
            continue
        machine.cpu.state.rax.value = res + tmp
        return

def wcslen(machine):
    # size_t wcslen( const wchar_t *str );
    _str = machine.cpu.state.rcx
    res = 0
    while True:
        buf: bytearray = machine.memory.read(_str + res * 2, 16)
        tmp = buf.find(b"\x00\x00")
        if tmp == -1:
            res += 8
            continue
        machine.cpu.state.rax.value = res + tmp // 2 + 1
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