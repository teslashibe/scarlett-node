from pathlib import Path
import struct
import tempfile
import unittest

from windows_pe_imports import assert_no_developer_crt, imported_libraries


class WindowsImportsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'fixture.exe'

    def executable(self, library, delay=False):
        data = bytearray(0x600)
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 0x3c, 0x80)
        data[0x80:0x84] = b'PE\0\0'
        struct.pack_into('<HH', data, 0x84, 0x8664, 1)
        struct.pack_into('<H', data, 0x94, 240)
        struct.pack_into('<H', data, 0x98, 0x20b)
        struct.pack_into('<Q', data, 0xb0, 0x140000000)
        struct.pack_into('<I', data, 0x104, 16)
        index, stride = (13, 32) if delay else (1, 20)
        struct.pack_into('<II', data, 0x108 + 8 * index, 0x1000, 2 * stride)
        struct.pack_into('<IIII', data, 0x190, 0x400, 0x1000, 0x400, 0x200)
        if delay:
            struct.pack_into('<II', data, 0x200, 1, 0x1060)
        else:
            struct.pack_into('<I', data, 0x20c, 0x1060)
        name = library.encode('ascii') + b'\0'
        data[0x260:0x260 + len(name)] = name
        self.path.write_bytes(data)

    def test_system_import_is_allowed(self):
        self.executable('KERNEL32.dll')
        self.assertEqual(imported_libraries(self.path), {'kernel32.dll'})
        assert_no_developer_crt(self.path)

    def test_system_universal_crt_is_allowed(self):
        self.executable('api-ms-win-crt-runtime-l1-1-0.dll')
        assert_no_developer_crt(self.path)

    def test_developer_runtime_is_rejected_without_changing_bytes(self):
        self.executable('VCRUNTIME140.dll')
        before = self.path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'separately installed developer CRT'):
            assert_no_developer_crt(self.path)
        self.assertEqual(before, self.path.read_bytes())

    def test_delay_loaded_cpp_runtime_is_rejected(self):
        self.executable('MSVCP140.dll', delay=True)
        with self.assertRaisesRegex(ValueError, 'developer CRT'):
            assert_no_developer_crt(self.path)

    def test_debug_runtime_is_rejected(self):
        self.executable('ucrtbased.dll')
        with self.assertRaisesRegex(ValueError, 'developer CRT'):
            assert_no_developer_crt(self.path)

    def test_unbacked_name_is_rejected(self):
        self.executable('kernel32.dll')
        data = bytearray(self.path.read_bytes())
        struct.pack_into('<I', data, 0x20c, 0x7fffffff)
        self.path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'not backed'):
            imported_libraries(self.path)

    def test_truncated_header_is_rejected(self):
        self.path.write_bytes(b'MZ')
        with self.assertRaisesRegex(ValueError, 'header'):
            imported_libraries(self.path)


if __name__ == '__main__':
    unittest.main()
