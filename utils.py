from struct import pack, unpack
from typing import Union

from datatype import Int64, Int32, Int8, Int16, Int128


def read_int128(data: bytes):
    assert len(data) == 16
    return int.from_bytes(data, "little")

def read_int64(data: bytes):
    return unpack("<q", data)[0]

def read_int32(data: bytes):
    return unpack("<i", data)[0]

def read_int16(data: bytes):
    return unpack("<h", data)[0]

def read_int8(data: bytes):
    return unpack("<b", data)[0]

def read_uint64(data: bytes):
    return unpack("<Q", data)[0]

def read_uint32(data: bytes):
    return unpack("<I", data)[0]

def read_uint16(data: bytes):
    return unpack("<H", data)[0]

def read_uint8(data: bytes):
    return unpack("<B", data)[0]

def read_float(data: bytes):
    return unpack("<f", data)[0]

def read_double(data: bytes):
    return unpack("<d", data)[0]

def pack_int128(data: Union[int, Int128]):
    if isinstance(data, Int128):
        data = data.value
    return data.to_bytes(16, "little")

def pack_int64(data: Union[int, Int64]):
    if isinstance(data, Int64):
        data = data.value
    return pack("<q", data)

def pack_uint64(data: Union[int, Int64]):
    if isinstance(data, Int64):
        data = data.value
    return pack("<Q", data)

def pack_int32(data: Union[int, Int32]):
    if isinstance(data, Int32):
        data = data.value
    return pack("<i", data)

def pack_uint32(data: Union[int, Int32]):
    if isinstance(data, Int32):
        data = data.value
    return pack("<I", data)

def pack_int16(data: Union[int, Int16]):
    if isinstance(data, Int16):
        data = data.value
    return pack("<h", data)

def pack_uint16(data: Union[int, Int16]):
    if isinstance(data, Int16):
        data = data.value
    return pack("<H", data)

def pack_int8(data: Union[int, Int8]):
    if isinstance(data, Int8):
        data = data.value
    return pack("<b", data)

def pack_uint8(data: Union[int, Int8]):
    if isinstance(data, Int8):
        data = data.value
    return pack("<B", data)

def pack_float(data: float):
    return pack("<f", data)

def pack_double(data: float):
    return pack("<d", data)