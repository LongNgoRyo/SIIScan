# Bộ Test Dataset & Tài liệu cải tiến PIIScan Server Pro

Bộ mẫu dùng để kiểm thử độ chính xác của PIIScan: có bắt đúng mã độc (recall)
và có báo nhầm code lành hay không (precision / false positive).

## Cấu trúc

```
SIIScan-main/
├── piiscan.py              # Code chính (ĐÃ NÂNG CẤP)
├── webshell_detector.py    # Module phát hiện webshell nâng cao (mới)
├── make_test_dataset.py    # Tạo 16 file mẫu cơ bản
├── make_test_dataset_extra.py  # Tạo thêm 22 file mẫu (obfuscation + đa ngôn ngữ)
├── test_dataset/
│   ├── malicious/          # 23 file webshell/backdoor THẬT
│   └── benign/             # 15 file code AN TOÀN
└── report_*.html / .csv    # Kết quả quét
```

## Cách chạy

```bash
# 1. Tạo / bổ sung dataset
python3 make_test_dataset.py
python3 make_test_dataset_extra.py

# 2. Quét folder mã độc
python3 piiscan.py --path test_dataset/malicious --output-html report_malicious.html --output-csv report_malicious.csv

# 3. Quét folder an toàn
python3 piiscan.py --path test_dataset/benign --output-html report_benign.html --output-csv report_benign.csv
```

---

## CẢI TIẾN CHÍNH ĐÃ LÀM (dựa trên pattern GitHub)

Module `webshell_detector.py` nâng cấp khả năng phát hiện, tham khảo từ các
công cụ/rule mã nguồn mở uy tín:

| Nguồn tham khảo | Đóng góp |
|-----------------|----------|
| `nbs-system/php-malware-finder` | Ý tưởng phát hiện ngữ nghĩa (biến -> giải mã -> hàm nguy hiểm) |
| `Panelica/malware-signatures` | Danh sách hàm nguy hiểm + pattern obfuscation |
| `tstillz/webshell-analyzer` | Giải mã đa lớp (base64, gzinflate, char code) |
| `Velociraptor Generic.Detection.WebShells` | Regex phát hiện eval kèm obfuscator |

### 1. Giải mã đa lớp trước khi khớp
- `base64_decode(...)`, chuỗi base64 thuần dài
- `str_rot13(...)`, `gzinflate(base64_decode(...))`
- `hex2bin(...)`, `pack(...)`, `strrev(...)`, `chr(.).chr(.)`

### 2. Khử obfuscation
- **Nối chuỗi**: `"sys"."tem"` → `system` (kỹ thuật né regex phổ biến nhất)
- **XOR/bitwise**: `'a'^'b'`, `$_^"\x00..."`, biến động `${_GET}` (loại trừ template literal JS)

### 3. Mở rộng danh sách vector phát hiện
- Thêm `proc_open`, `popen`, `pcntl_exec`, `create_function`, `preg_replace /e`
- Thêm remote file inclusion (`require/include $_GET[...]`)
- Thêm reverse shell (`/dev/tcp/`, `bash -i`, `python -c`)
- Thêm ASP/ASP.NET/JSP: `Process.Start`, `Runtime.getRuntime()`, `WScript.Shell`, `cmd.exe`, `powershell.exe`

### 4. Sửa lỗi false positive
- **Mật khẩu**: không còn bắt nhầm `getElementById('password')` (negative lookbehind `(?<![\w.])`, loại trừ `document`)
- **`require`**: phân biệt `require` PHP (include file) với `require('express')` Node.js. Chỉ cảnh báo khi `require` đi kèm biến input hoặc URL từ xa
- **Template literal JS**: `${port}` không còn bị hiểu nhầm là obfuscation `${...}` PHP

### 5. Mở rộng loại file quét
Thêm `.phtml`, `.jsx`, `.ts`, `.asp`, `.aspx`, `.jsp`, `.jspx`, `.sh`, `.pl`, `.cgi`, `.rb`, `.ini`, `.conf`.

---

## KẾT QUẢ KIỂM THỬ (sau khi nâng cấp)

### Malicious: 23/23 bắt được — recall 100%

Tất cả webshell đều bị phát hiện, gồm cả các loại obfuscation khó:
- Nối chuỗi `"sys"."tem"` ✓
- base64 đơn / đa lớp ✓
- gzinflate + base64 ✓
- str_rot13 ✓
- hex2bin ✓
- XOR obfuscation ✓
- preg_replace /e, create_function ✓
- include/require biến người dùng (RFI) ✓
- ASP, ASP.NET, JSP, Shell, Perl, Python reverse shell ✓

### Benign: 15 file, 0 false positive mã độc

Chỉ 2 "cảnh báo" là PII hợp lệ (không phải mã độc):
- `python_flask_app.py` → tên "Nguyen Van A" (dữ liệu mẫu)
- `php_contact_form.php` → email `admin@example.com` (email thật trong form liên hệ)

→ **Không còn false positive về mã độc** sau khi sửa.

---

## So sánh trước / sau nâng cấp

| Chỉ số | Trước | Sau |
|--------|-------|-----|
| Recall (bắt đúng webshell) | 88.9% (8/9) | **100% (23/23)** |
| False positive mã độc | 1 (js_frontend.js) | **0** |
| Loại file hỗ trợ | ~14 | ~24 |
| Giải mã obfuscation | Không | base64/rot13/hex/gzip/strrev/XOR/concat |

---

## Gợi ý mở rộng tiếp (nếu muốn nâng cao hơn nữa)

1. **Tích hợp YARA trực tiếp** (`yara-python`) để dùng bộ rule có sẵn của
   `php-malware-finder` và `Panelica/malware-signatures` — mạnh hơn regex thuần.

2. **Phân tích data-flow đầy đủ** (giống php-malware-finder): theo dõi biến từ
   `$_GET/$_POST` → qua chuỗi giải mã → đến hàm `system/eval`.

3. **Thêm hash-based detection**: lưu SHA256 các webshell đã biết (Panelica có
   sẵn bảng hash) để bắt nhanh webshell không obfuscate.

4. **Entropy analysis**: phát hiện file có entropy cao (dấu hiệu payload mã hóa).

> ⚠️ Lưu ý an toàn: file trong `malicious/` là mã độc THẬT. KHÔNG chạy (`php`,
> `python`, `node`) hay đặt vào thư mục web đang hoạt động. Chỉ dùng để PIIScan
> đọc nội dung tĩnh.