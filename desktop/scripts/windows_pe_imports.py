"""Read native PE imports without loading code or relying on developer tools."""
import mmap
from pathlib import Path
import re
import struct


def imported_libraries(path):
    with Path(path).open('rb') as file:
        if file.seek(0, 2) < 64:
            raise ValueError('Invalid Windows executable header')
        with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as data:
            def read(format, position):
                if position < 0 or position + struct.calcsize(format) > len(data):
                    raise ValueError('Windows executable structure exceeds its file')
                return struct.unpack_from(format, data, position)

            pe, = read('<I', 0x3c)
            if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
                raise ValueError('Invalid Windows executable header')
            sections, = read('<H', pe + 6)
            optional_size, = read('<H', pe + 20)
            optional = pe + 24
            magic, = read('<H', optional)
            if magic not in (0x10b, 0x20b) or not 0 < sections <= 96:
                raise ValueError('Unsupported Windows executable layout')
            directories = optional + (112 if magic == 0x20b else 96)
            count, = read('<I', directories - 4)
            if directories + min(count, 16) * 8 > optional + optional_size:
                raise ValueError('Windows import directory exceeds its header')
            image_base, = read('<Q' if magic == 0x20b else '<I', optional + (24 if magic == 0x20b else 28))
            regions = []
            for index in range(sections):
                size, address, raw_size, raw = read('<IIII', optional + optional_size + index * 40 + 8)
                regions.append((address, max(size, raw_size), raw, raw_size))

            def offset(address, length):
                for start, size, raw, raw_size in regions:
                    relative = address - start
                    if 0 <= relative < size and relative + length <= raw_size and raw + relative + length <= len(data):
                        return raw + relative
                raise ValueError('Windows import address is not backed by file data')

            libraries = set()
            for index, stride in [(1, 20), (13, 32)]:
                if count <= index:
                    continue
                address, size = read('<II', directories + index * 8)
                if not address:
                    continue
                if size < stride:
                    raise ValueError('Windows import directory is incomplete')
                for entry in range(min(size // stride, 4096)):
                    position = offset(address + entry * stride, stride)
                    record = data[position:position + stride]
                    if not any(record):
                        break
                    if index == 1:
                        name, = read('<I', position + 12)
                    else:
                        flags, name = read('<II', position)
                        if not flags & 1:
                            name -= image_base
                    start = offset(name, 1)
                    end = data.find(b'\0', start, min(start + 512, len(data)))
                    if end < 0 or end == start:
                        raise ValueError('Invalid Windows import name')
                    offset(name, end - start + 1)
                    try:
                        libraries.add(data[start:end].decode('ascii').lower())
                    except UnicodeDecodeError:
                        raise ValueError('Invalid Windows import name') from None
                else:
                    raise ValueError('Windows import directory has no bounded terminator')
            return libraries


def assert_no_developer_crt(path):
    if any(re.fullmatch(r'(?:(?:vcruntime|msvcp|msvcr|concrt|vcomp).*|ucrtbased)\.dll', name)
           for name in imported_libraries(path)):
        raise ValueError('Scarlett executable requires a separately installed developer CRT')
