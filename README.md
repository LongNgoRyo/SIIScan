# PIIScan Server Pro

Công cụ quét mã độc (webshell/backdoor) & rò rỉ dữ liệu cá nhân (PII) trên máy chủ web, tuân thủ Nghị định 13/2023/NĐ-CP, PCI-DSS và ISO 27001.

## Trang web demo

https://longngoryo.github.io/SIIScan/

## Tính năng

- Quét đệ quy thư mục máy chủ, tệp cấu hình, nhật ký, mã nguồn
- Phát hiện webshell/backdoor (PHP, Python, JS, ASP, JSP, Shell...) bằng module `webshell_detector.py` với khả năng giải mã obfuscation (base64, rot13, hex, gzip, XOR, nối chuỗi)
- **Chấm điểm CVSS 3.1** (0.0–10.0) cho từng lỗ hổng mã độc theo chuẩn FIRST.org, kèm vector CVSS và mức độ (None/Low/Medium/High/Critical)
- **Phân loại mã độc** chi tiết (webshell RCE, command execution, reverse shell, RFI, obfuscation, lỗ hổng upload...) + **ánh xạ mã CWE** (CWE-78, CWE-94, CWE-506, CWE-434...)
- Phát hiện dữ liệu cá nhân theo Nghị định 13 (CCCD, thẻ tín dụng, tài khoản ngân hàng, email, sức khỏe, sinh trắc...)
- Đánh giá tuân thủ + đề xuất khắc phục tự động (CHMOD 600, mã hóa AES-256, cách ly mã độc)
- Báo cáo HTML/CSV trực quan (kèm cột CVSS, CWE)

## Chạy nhanh

```bash
pip install -r requirements.txt
python3 piiscan.py --path /duong/dan/can/quét --output-html report.html --output-csv report.csv
```

## Bộ test dataset

```bash
python3 make_test_dataset.py        # 16 file mẫu cơ bản
python3 make_test_dataset_extra.py  # +22 file mẫu (obfuscation + đa ngôn ngữ)

python3 piiscan.py --path test_dataset/malicious --output-html report_malicious.html --output-csv report_malicious.csv
python3 piiscan.py --path test_dataset/benign --output-html report_benign.html --output-csv report_benign.csv
```

Kết quả: recall 100% (23/23 webshell), 0 false positive mã độc.

## Cấu trúc

```
piiscan.py              # Code chính
webshell_detector.py    # Module phát hiện webshell nâng cao
index.html / app.js / style.css  # Giao diện web
test_dataset/           # Bộ mẫu kiểm thử
```

> ⚠️ File trong `test_dataset/malicious/` là mã độc mẫu dùng cho nghiên cứu/học tập.
> KHÔNG chạy hay triển khai chúng trên môi trường thật.