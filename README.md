# Malware Analysis Platform (PIIScan)

Nền tảng phân tích mã độc tự động: phân tích tĩnh chuyên sâu webshell, backdoor và các mẫu mã độc đa định dạng (PHP, Python, JS, ASP, JSP, Shell, PowerShell, Batch, VBScript, PE/EXE...).

## Trang web demo

https://longngoryo.github.io/SIIScan/

## Tính năng cốt lõi (môn Phân tích mã độc)

### 1. Phân tích tĩnh (Static Analysis)
- **Trích xuất hash**: MD5, SHA-1, SHA-256, SHA-512 + fuzzy hash (để tra IoC, VirusTotal, so sánh tương đồng)
- **Entropy Shannon** — phát hiện file bị packed/encrypted
- **Nhận diện loại file** bằng magic bytes (PE/EXE, ELF, PDF, archive, script...)
- **Phân tích PE header** (dùng `pefile`): kiến trúc x86/x64, sections, entry point, compile time, **phát hiện packer**, suspicious imports (socket, CreateProcess, VirtualAlloc...)
- **Trích xuất IoC** (Indicators of Compromise): IP, URL, domain
- **Phân loại họ mã độc**: Webshell, PowerShell fileless, VBScript persistence, Python RAT, Batch, Ransomware, Keylogger, Stealer, Windows PE/ELF...

### 2. Phát hiện webshell/backdoor
- **Phát hiện webshell/backdoor** bằng **YARA rules thật** (`yara-python` + `rules/malware_rules.yar`) — nhận diện các họ webshell (eval, command exec, reverse shell, upload, PowerShell downloader, Python RAT, VBS persistence) + fallback regex `yara_style_rules.py`

### 3. Đánh giá (CVSS + CWE + MITRE)
- Chấm điểm CVSS 3.1 chuẩn FIRST.org
- Ánh xạ CWE (CWE-78, CWE-94, CWE-506, CWE-434...)
- MITRE ATT&CK (T1059, T1505.003, T1027, T1071...)

### 4. Báo cáo
- HTML/CSV/PDF với trích đoạn mã nguồn, hash, entropy, IoC, family

## Chạy nhanh

```bash
pip install -r requirements.txt
python3 piiscan.py --path /duong/dan/can/quét --output-html report.html --output-csv report.csv
```

## Bộ test dataset

```bash
python3 make_test_dataset.py          # 16 file mẫu cơ bản
python3 make_test_dataset_extra.py    # +22 file mẫu (obfuscation + đa ngôn ngữ)
python3 make_test_dataset_malware.py  # +5 mẫu đa định dạng (ps1/bat/vbs/py)

python3 piiscan.py --path test_dataset/malicious --output-html report_malicious.html --output-csv report_malicious.csv
```

## Cấu trúc

```
piiscan.py              # Code chính (backend + API)
webshell_detector.py    # Phát hiện webshell + giải mã obfuscation + data-flow
malware_analyzer.py     # Phân tích tĩnh: hash/entropy/PE/IoC/phân loại họ
yara_engine.py          # YARA engine (yara-python) chạy rules thật
rules/malware_rules.yar # Bộ YARA rules phát hiện mã độc
cvss_scoring.py         # CVSS 3.1 + CWE + MITRE + risk rating
yara_style_rules.py     # Fallback regex (khi không có yara-python)
index.html / app.js / style.css  # Giao diện web
test_dataset/           # Bộ mẫu kiểm thử
```

> ⚠️ File trong `test_dataset/malicious/` là mã độc mẫu dùng cho nghiên cứu/học tập.
> KHÔNG chạy hay triển khai chúng trên môi trường thật.