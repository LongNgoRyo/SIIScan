#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tạo mẫu PE (Windows executable) GIẢ để kiểm thử phân tích PE header.

File .exe giả này có header MZ + header PE hợp lệ tối thiểu để `pefile`
có thể phân tích được, PHỤC VỤ MỤC ĐÍCH KIỂM THỬ / HỌC TẬP.
Không phải mã độc thật, chỉ là shellcode giả đặt sau header.
"""
import struct
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dataset")
MAL = os.path.join(BASE, "malicious")
os.makedirs(MAL, exist_ok=True)

def build_fake_pe(path, upx_packed=False):
    # MZ header
    mz = b'MZ' + b'\x00' * 0x3c
    # e_lfanew -> PE header offset
    pe_offset = 0x80
    mz = mz[:0x3c] + struct.pack('<I', pe_offset)

    # PE signature
    pe_sig = b'PE\x00\x00'

    # COFF header (20 bytes)
    machine = struct.pack('<H', 0x14c)  # x86
    num_sections = struct.pack('<H', 3 if upx_packed else 2)
    time_date = struct.pack('<I', 1609459200)  # 2021-01-01
    coff = machine + num_sections + time_date
    coff += b'\x00' * 12  # ptr sym, num sym, size opt header, characteristics

    # Optional header (giả tối thiểu, 224 bytes cho PE32)
    magic_pe32 = struct.pack('<H', 0x10b)
    entry_point = struct.pack('<I', 0x1000)
    image_base = struct.pack('<I', 0x400000)
    opt = magic_pe32 + b'\x00\x00' + entry_point + image_base
    opt += b'\x00' * (224 - len(opt))

    header = pe_sig + coff + opt

    # Section table: 2 sections
    sections = b''
    if upx_packed:
        sections += b'UPX0' + b'\x00' * 4 + struct.pack('<IIIIIIII', 0x1000, 0x1000, 0x400, 0x400, 0, 0, 0, 0xE0000020)
        sections += b'UPX1' + b'\x00' * 4 + struct.pack('<IIIIIIII', 0x2000, 0x5000, 0x800, 0x400, 0, 0, 0, 0xE0000040)
    else:
        sections += b'.text' + b'\x00' * 3 + struct.pack('<IIIIIIII', 0x1000, 0x1000, 0x400, 0x400, 0, 0, 0, 0x60000020)
        sections += b'.data' + b'\x00' * 3 + struct.pack('<IIIIIIII', 0x2000, 0x2000, 0x200, 0x200, 0, 0, 0, 0xC0000040)

    # payload giả (không thực thi thật - chỉ để tạo entropy)
    payload = b'\x90' * 0x400  # NOP sled
    if upx_packed:
        # giả lập dữ liệu "nén" entropy cao
        import random
        random.seed(7)
        payload = bytes(random.getrandbits(8) for _ in range(0x800))

    with open(path, 'wb') as f:
        f.write(mz)
        f.write(b'\x00' * (pe_offset - len(mz)))
        f.write(header)
        f.write(sections)
        f.write(payload)

# Tạo 2 mẫu PE: thường và upx-packed
build_fake_pe(os.path.join(MAL, 'sample_normal.exe'), upx_packed=False)
build_fake_pe(os.path.join(MAL, 'sample_upx_packed.exe'), upx_packed=True)

print("Da tao 2 mau PE gia:")
print("  -> sample_normal.exe")
print("  -> sample_upx_packed.exe (gia lap UPX packed, entropy cao)")