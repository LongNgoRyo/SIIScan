#!/usr/bin/env python3
import os
import re
import sys
import json
import argparse
import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

# Webshell/backdoor detector nâng cao (dựa trên pattern GitHub: php-malware-finder, Panelica, webshell-analyzer)
try:
    from webshell_detector import detect_malware, detect_data_flow
except ImportError:
    detect_malware = detect_data_flow = None

# Chấm điểm CVSS 3.1 + phân loại + CWE + MITRE + entropy + risk rating cho mã độc
try:
    from cvss_scoring import (classify_finding, get_profile, compute_cvss_from_vector,
                              severity_from_score, shannon_entropy, entropy_flag, owasp_risk_rating)
except ImportError:
    classify_finding = get_profile = compute_cvss_from_vector = severity_from_score = None
    shannon_entropy = entropy_flag = owasp_risk_rating = None

# Rule detection theo kiểu YARA (thuần Python, thay thế yara-python)
try:
    from yara_style_rules import match_file_rules
except ImportError:
    match_file_rules = None

# Phân tích mã độc tĩnh chuyên sâu (hash, entropy, PE, IoC, phân loại họ)
try:
    from malware_analyzer import analyze_malware_file
except ImportError:
    analyze_malware_file = None

# Try importing parsing and data libraries, with fallback
try:
    import pandas as pd
except ImportError:
    pd = None

try:
    from jinja2 import Template
except ImportError:
    Template = None

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    import docx
except ImportError:
    docx = None

try:
    import openpyxl
except ImportError:
    openpyxl = None


# ==========================================
# CONSTANTS & REGEXES
# ==========================================
PII_PATTERNS = {
    "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)": re.compile(
        r"\b(?:eval|shell_exec|passthru|system|exec|base64_decode|assert|subprocess\.Popen|os\.system|child_process\.exec)\s*\(|\b(?:webshell|backdoor|reverse_shell|c99shell|r57shell|wso_shell|cmd\.exe|/bin/sh|/bin/bash)\b",
        re.IGNORECASE
    ),
    "Số định danh (CCCD/CMND)": re.compile(r"\b\d{9}\b|\b\d{12}\b|\b\d{3}-\d{2}-\d{4}\b"),
    "Số thẻ tín dụng": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|[56][0-9]{14}|3[47][0-9]{13})\b|"
        r"\b(?:4[0-9]{3}[-\s][0-9]{4}[-\s][0-9]{4}[-\s][0-9]{4}|"
        r"5[1-5][0-9]{2}[-\s][0-9]{4}[-\s][0-9]{4}[-\s][0-9]{4})\b"
    ),
    "Số tài khoản ngân hàng / IBAN": re.compile(
        r"(?:stk|số tài khoản|so tai khoan|tài khoản|số tk|so tk|bank account|account number|account_number|iban|swift|vietcombank|vcb|techcombank|tcb|bidv|vietinbank|agribank|mbbank|acb|vpbank|sacombank|tpbank)\s*[:=-]?\s*\b[A-Z0-9]{8,34}\b",
        re.IGNORECASE
    ),
    "Thông tin xác thực / API Key / Mật khẩu": re.compile(
        r"(?<![\w.])"
        r"(?:password|passwd|pwd|secret|db_pass|access_token|apikey|api_key|token)\s*[:=]\s*['\"]?"
        r"((?!placeholder|your_|todo|my_secure_|document\b)[A-Za-z0-9_@#$%-]{4,})['\"]?",
        re.IGNORECASE
    ),
    "Hồ sơ y tế / Thông tin sức khỏe": re.compile(
        r"\b(?:bệnh án|benh an|nhóm máu|nhom mau|tiền sử bệnh|tien su benh|đơn thuốc|don thuoc|chẩn đoán|chan doan|phác đồ|phac do|bệnh nhân|benh nhan|bệnh lý|benh ly|khám bệnh|kham benh|điều trị|dieu tri|blood type|medical record|prescription|diagnosis|health record|patient)\b",
        re.IGNORECASE
    ),
    "Dữ liệu sinh trắc học": re.compile(
        r"\b(?:vân tay|van tay|mống mắt|mong mat|sinh trắc|sinh trac|nhận diện khuôn mặt|nhan dien khuon mat|fingerprint|faceid|iris scan|biometric)\b",
        re.IGNORECASE
    ),
    "Số điện thoại": re.compile(r"\b(?:0|\+84|\+1|\+44)(?:[1-9]\d{7,10}|[35789]\d{2}[-\s.]?\d{3}[-\s.]?\d{3})\b"),
    "Họ và tên": re.compile(
        r"\b(?!Quận|Phường|Đường|Thành phố|Tỉnh|Huyện|Xã|Việt|Thành)"
        r"(?:Nguyễn|Trần|Lê|Phạm|Hoàng|Huỳnh|Phan|Vũ|Võ|Đặng|Bùi|Đỗ|Hồ|Ngô|Dương|Lý|Nguyen|Tran|Le|Pham|Hoang|Huynh|Vu|Vo|Dang|Bui|Do|Ho|Ngo|Duong|Ly|John|Mary|James|Patricia|Robert|Jennifer|Michael|Elizabeth|William|Linda|David|Barbara|Richard|Susan|Joseph|Jessica|Thomas|Sarah|Charles|Karen)"
        r"\s+[A-ZÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚĂĐĨŨƠƯẠẢẤẦẨẪẬẮẰẲẴẶẸẺẼỀỀỂỬỮỰỈỊỌỎỐỒỔỖỘỚỜỞỠỢỤỦỨỪỬỮỰỲỴÝỶỸ][a-zàáâãèéêìíòóôõùúăđĩũơưạảấầẩẫậắằẳẵặẹẻẽềềểửữựỉịọỏốồổỗộớờởỡợụủứừửữựỳỵýỷỹđ]*(?:\s+[A-ZÀÁÂÃÈÉÊÌÍÒÓÔÕÙÚĂĐĨŨƠƯẠẢẤẦẨẪẬẮẰẲẴẶẸẺẼỀỀỂỬỮỰỈỊỌỎỐỒỔỖỘỚỜỞỠỢỤỦỨỪỬỮỰỲỴÝỶỸ][a-zàáâãèéêìíòóôõùúăđĩũơưạảấầẩẫậắằẳẵặẹẻẽềềểửữựỉịọỏốồổỗộớờởỡợụủứừửữựỳỵýỷỹđ]*){1,3}\b"
    ),
    "Ngày sinh": re.compile(
        r"(?:ngày sinh|ngay sinh|năm sinh|nam sinh|dob|birth|birthdate|sinh ngày|sinh ngay)\s*[:=-]?\s*\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b|\b\d{1,2}[/-]\d{1,2}[/-](?:19\d{2}|20[0-2]\d)\b",
        re.IGNORECASE
    ),
    "Địa chỉ": re.compile(
        r"(?:địa chỉ(?![\s]*(?:email|mail|thư điện tử))|dia chi(?![\s]*(?:email|mail|thu dien tu))|home address|street address|thường trú|thuong tru)\s*[:=-]?\s*['\"]?(?:[^'\"\n\r]{10,100})['\"]?|"
        r"\b(?:số|so)?\s*\d+\s+(?:đường|street|phố|pho|ngõ|ngo|hẻm|hem|ấp|ap|thôn|thon)\s+[^,\n\r]{2,30}(?:,\s*[^,\n\r]{2,30}){1,4}\b",
        re.IGNORECASE
    ),
    "Địa chỉ email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "Địa chỉ IP": re.compile(r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    "Cookie phiên": re.compile(
        r"\b(?:sessid|sessionid|sid|phpsessid|jsessionid|session_id|connect\.sid)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{16,64})['\"]?",
        re.IGNORECASE
    )
}

SENSITIVITY_LEVELS = {
    "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)": "high",
    "Số định danh (CCCD/CMND)": "high",
    "Số thẻ tín dụng": "high",
    "Số tài khoản ngân hàng / IBAN": "high",
    "Thông tin xác thực / API Key / Mật khẩu": "high",
    "Hồ sơ y tế / Thông tin sức khỏe": "high",
    "Dữ liệu sinh trắc học": "high",
    "Số điện thoại": "medium",
    "Họ và tên": "medium",
    "Ngày sinh": "medium",
    "Địa chỉ": "medium",
    "Địa chỉ email": "low",
    "Địa chỉ IP": "low",
    "Cookie phiên": "low"
}


# ==========================================
# UTILITY FUNCTIONS
# ==========================================
def is_valid_luhn(card_number_str):
    """Validate Credit Card numbers using the Luhn Algorithm."""
    sanitized = re.sub(r"[-\s]", "", card_number_str)
    if not sanitized.isdigit() or not (13 <= len(sanitized) <= 19):
        return False
    
    total = 0
    should_double = False
    for digit_char in reversed(sanitized):
        digit = int(digit_char)
        if should_double:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
        should_double = not should_double
    return total % 10 == 0


def is_sequential_or_repeated(num_str):
    """Check if number string consists of sequential or repeated digits to prevent false positives."""
    if len(num_str) < 4:
        return False
    if len(set(num_str)) == 1:
        return True
    
    # Check ascending/descending
    ascending = "01234567890123456789"
    descending = "98765432109876543210"
    if num_str in ascending or num_str in descending:
        return True
    return False


def get_file_permissions(file_path):
    """Return permissions string and risk flag on unix systems."""
    try:
        stat_info = os.stat(file_path)
        mode = stat_info.st_mode
        # Standard CHMOD representation
        chmod_octal = oct(mode & 0o777)
        
        # Check if world readable/writable (last digit in octal is readable 4, 5, 6, 7)
        last_digit = mode & 0o007
        is_world_accessible = last_digit >= 4
        
        return chmod_octal, is_world_accessible
    except Exception:
        # Fallback on Windows
        return "N/A", False


def mask_pii_value_python(pii_type, value):
    """Mask PII sensitive values for file remediation."""
    if not value:
        return ""
    value = value.strip()
    if pii_type == "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)":
        return value
    elif pii_type == "Số định danh (CCCD/CMND)":
        if len(value) == 12:
            return value[0:3] + "••••••" + value[9:]
        else:
            return value[0:3] + "•••" + value[6:]
    elif pii_type == "Số điện thoại":
        if len(value) >= 7:
            return value[0:4] + "•••" + value[7:]
        return "•••••••"
    elif pii_type == "Địa chỉ email":
        parts = value.split("@")
        if len(parts) == 2:
            name, domain = parts
            if len(name) > 2:
                return name[0:2] + "•••@" + domain
            return "•••@" + domain
        return "••••@••••"
    elif pii_type == "Số thẻ tín dụng":
        clean = re.sub(r"[-\s]", "", value)
        if len(clean) >= 15:
            return "•••• •••• •••• " + clean[-4:]
        return "•••• •••• •••• ••••"
    elif pii_type == "Thông tin xác thực / API Key / Mật khẩu":
        return "••••••••"
    elif pii_type == "Số tài khoản ngân hàng / IBAN":
        if len(value) > 6:
            return value[0:3] + "••••" + value[-3:]
        return "••••••••"
    elif pii_type == "Họ và tên":
        words = value.split()
        if len(words) > 1:
            return words[0] + " " + " ".join([w[0] + "••" for w in words[1:]])
        return value[0] + "••" if len(value) > 0 else "••"
    elif pii_type == "Ngày sinh":
        if len(value) >= 10:
            return value[0:6] + "••••"
        return "••/••/••••"
    elif pii_type == "Địa chỉ":
        if len(value) > 12:
            return value[0:12] + "••••"
        return value[0:2] + "••••"
    return "••••"


# ==========================================
# MODULES: SCANNER, PARSER, ANALYZER
# ==========================================
# Magic bytes của các định dạng ảnh phổ biến (để phát hiện file "giả ảnh" chứa mã nhúng)
_MAGIC_SIGNATURES = {
    ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"], ".png": [b"\x89PNG\r\n\x1a\n"],
    ".gif": [b"GIF87a", b"GIF89a"], ".bmp": [b"BM"],
    ".pdf": [b"%PDF-"], ".zip": [b"PK\x03\x04"],
}

def detect_polyglot_file(file_path):
    """
    Phát hiện file polyglot: đuôi file là ảnh/pdf nhưng nội dung chứa mã PHP/lệnh nhúng.
    Trả về (bool, str) — (có nghi ngờ, mô tả).
    """
    if not isinstance(file_path, Path):
        file_path = Path(file_path)
    suffix = file_path.suffix.lower()
    sigs = _MAGIC_SIGNATURES.get(suffix)
    if not sigs:
        return (False, "")
    try:
        with open(file_path, "rb") as f:
            head = f.read(2048)
        has_valid_magic = any(head.startswith(s) for s in sigs)
        # Tìm mã độc nhúng phía sau header ảnh hợp lệ
        tail = head
        # bỏ magic bytes rồi quét phần còn lại
        for s in sigs:
            if tail.startswith(s):
                tail = tail[len(s):]
                break
        # dấu hiệu mã PHP/lệnh nhúng trong phần sau magic
        payload_flags = [b"<?php", b"<?=", b"eval", b"base64_decode", b"system", b"shell_exec", b"<?", b"GIF89a<?php"]
        found = [pf.decode('latin1') for pf in payload_flags if pf in tail]
        if found:
            return (True, f"nghi ngờ polyglot: file {suffix} chứa mã nhúng {', '.join(found)} sau magic bytes")
        return (False, "")
    except Exception:
        return (False, "")


class PIIScanner:
    """Core PII Scanner Engine."""
    
    def __init__(self, target_path, exclude_dirs=None):
        self.target_path = Path(target_path)
        self.exclude_dirs = exclude_dirs or [".git", "node_modules", "venv", ".idea", "__pycache__"]
        self.supported_exts = {
            ".txt", ".csv", ".log", ".json", ".xml", ".pdf", ".docx", ".xlsx",
            ".env", ".config", ".yaml", ".yml", ".ini", ".conf",
            ".php", ".phtml", ".php3", ".php4", ".php5", ".js", ".jsx", ".ts", ".py", ".sql",
            ".asp", ".aspx", ".jsp", ".jspx", ".sh", ".pl", ".cgi", ".rb",
        }
        # Các phần mở rộng nhị phân KHÔNG thể đọc dưới dạng văn bản — sẽ bỏ qua
        # để tránh parse rác. Mọi thứ khác (kể cả file không đuôi) đều được quét.
        self.binary_exts = {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp",
            ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv", ".flac", ".ogg",
            ".zip", ".gz", ".tar", ".rar", ".7z", ".jar", ".war", ".ear",
            ".exe", ".dll", ".so", ".bin", ".dat", ".class", ".o", ".a",
            ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf_img",
            ".db", ".sqlite", ".sqlite3", ".pyc", ".pyo",
        }
        
    def scan_directories(self):
        """Quét ĐỆ QUY toàn bộ thư mục, gồm cả file lạ/không đuôi.
        Chỉ bỏ qua: thư mục hệ thống (exclude_dirs) và file nhị phân."""
        if not self.target_path.exists():
            print(f"Error: Target path {self.target_path} does not exist.", file=sys.stderr)
            return
        
        if self.target_path.is_file():
            yield self.target_path
            return

        for path in self.target_path.rglob("*"):
            if not path.is_file():
                continue
            # Bỏ qua các thư mục hệ thống
            if any(part in path.parts for part in self.exclude_dirs):
                continue
            # Bỏ qua file nhị phân (không đọc được dưới dạng text)
            if path.suffix.lower() in self.binary_exts:
                continue
            # Quét MỌI thứ còn lại: code, cấu hình, log, và cả file không đuôi
            yield path


class FileParser:
    """Extract text from diverse file types."""
    
    @staticmethod
    def parse_plain_text(file_path):
        """Streams lines of plaintext files."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f, 1):
                    yield line_idx, line
        except Exception as e:
            print(f"Warning: Failed reading text from {file_path} - {e}", file=sys.stderr)

    @staticmethod
    def parse_pdf(file_path):
        """Extract lines of text from PDF files."""
        if PyPDF2 is None:
            print(f"Warning: PyPDF2 is missing. Skipping PDF file {file_path.name}", file=sys.stderr)
            return
        
        try:
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                line_idx = 1
                for page in reader.pages:
                    text = page.extract_text()
                    if text:
                        for line in text.splitlines():
                            yield line_idx, line
                            line_idx += 1
        except Exception as e:
            print(f"Warning: Failed parsing PDF {file_path.name} - {e}", file=sys.stderr)

    @staticmethod
    def parse_docx(file_path):
        """Extract paragraph lines from Docx documents."""
        if docx is None:
            print(f"Warning: python-docx is missing. Skipping Word file {file_path.name}", file=sys.stderr)
            return
        
        try:
            doc = docx.Document(file_path)
            for line_idx, para in enumerate(doc.paragraphs, 1):
                if para.text:
                    yield line_idx, para.text
        except Exception as e:
            print(f"Warning: Failed parsing DOCX {file_path.name} - {e}", file=sys.stderr)

    @staticmethod
    def parse_xlsx(file_path):
        """Extract rows from Excel sheets as lines of CSV-formatted text."""
        if openpyxl is None:
            print(f"Warning: openpyxl is missing. Skipping Excel file {file_path.name}", file=sys.stderr)
            return
        
        try:
            wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
            line_idx = 1
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    # Join cell values with comma to simulate CSV rows
                    row_values = [str(cell) for cell in row if cell is not None]
                    if row_values:
                        yield line_idx, ", ".join(row_values)
                        line_idx += 1
        except Exception as e:
            print(f"Warning: Failed parsing XLSX {file_path.name} - {e}", file=sys.stderr)

    def extract_lines(self, file_path):
        """Delegates reading to correct parser."""
        suffix = file_path.suffix.lower()
        if suffix in {".pdf"}:
            return self.parse_pdf(file_path)
        elif suffix in {".docx"}:
            return self.parse_docx(file_path)
        elif suffix in {".xlsx"}:
            return self.parse_xlsx(file_path)
        else:
            return self.parse_plain_text(file_path)


class PIIAnalyzer:
    """Detect PII matching regex patterns."""
    
    def __init__(self):
        self.parser = FileParser()

    def analyze_file(self, file_path):
        """Audits file and returns detected PII matches and metadata."""
        findings = []
        
        for line_num, line_text in self.parser.extract_lines(file_path):
            cleaned_line = line_text.strip()
            if not cleaned_line:
                continue
                
            for pii_type, pattern in PII_PATTERNS.items():
                # === Mã độc: dùng detector nâng cao (giải mã + danh sách hàm mở rộng) ===
                if pii_type == "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)":
                    if detect_malware is not None:
                        for value, reason in detect_malware(cleaned_line):
                            finding = {
                                "type": pii_type,
                                "value": value,
                                "line": line_num,
                                "context": cleaned_line[:100] + ("..." if len(cleaned_line) > 100 else "")
                            }
                            # Gắn thêm CVSS + CWE + MITRE + phân loại mã độc
                            if classify_finding is not None and get_profile is not None:
                                prof_key = classify_finding(reason)
                                profile = get_profile(prof_key)
                                if profile:
                                    finding["profile"] = prof_key
                                    finding["malware_name"] = profile["name"]
                                    finding["cwe"] = profile["cwe"]
                                    finding["cwe_id"] = profile["cwe_id"]
                                    finding["cvss_vector"] = profile["vector"]
                                    finding["cvss_score"] = profile["score"]
                                    finding["cvss_severity"] = profile["severity"]
                                    finding["reason"] = reason
                                    mitre = profile.get("mitre", {})
                                    finding["mitre_id"] = mitre.get("id", "")
                                    finding["mitre_name"] = mitre.get("name", "")
                                    finding["mitre_tactic"] = mitre.get("tactic", "")
                            findings.append(finding)
                    # Vẫn quét regex gốc làm dự phòng nếu module không nạp được
                    else:
                        for match in pattern.finditer(cleaned_line):
                            findings.append({
                                "type": pii_type,
                                "value": match.group(0).strip(),
                                "line": line_num,
                                "context": cleaned_line[:100] + ("..." if len(cleaned_line) > 100 else "")
                            })
                    continue
                
                for match in pattern.finditer(cleaned_line):
                    # Lấy group(1) nếu có capture group và pii_type là Thông tin xác thực hoặc Cookie phiên
                    if pii_type in ["Thông tin xác thực / API Key / Mật khẩu", "Cookie phiên"] and match.lastindex is not None and match.lastindex >= 1:
                        match_val = match.group(1)
                    else:
                        match_val = match.group(0)
                    
                    match_val = match_val.strip()
                    if not match_val:
                        continue
                        
                    is_valid = True
                    # Luật kiểm tra hậu xử lý
                    if pii_type == "Số định danh (CCCD/CMND)":
                        clean_val = re.sub(r"[-\s]", "", match_val)
                        if is_sequential_or_repeated(clean_val):
                            is_valid = False
                        elif len(clean_val) == 12:
                            try:
                                province = int(clean_val[0:3])
                                gender = int(clean_val[3:4])
                                is_valid = (1 <= province <= 96) and (0 <= gender <= 9)
                            except ValueError:
                                is_valid = False
                        elif len(clean_val) == 9:
                            is_valid = True
                        elif "-" in match_val:
                            is_valid = bool(re.match(r"^\d{3}-\d{2}-\d{4}$", match_val))
                        else:
                            is_valid = False
                    elif pii_type == "Số thẻ tín dụng":
                        is_valid = is_valid_luhn(match_val)
                    elif pii_type == "Thông tin xác thực / API Key / Mật khẩu":
                        lower_val = match_val.lower()
                        if any(x in lower_val for x in ["placeholder", "your_", "todo", "my_secure_"]):
                            is_valid = False
                    elif pii_type == "Họ và tên":
                        name_blacklist = ["hồ chí minh", "thành phố", "thành phố hồ chí minh", "hà nội", "đà nẵng", "hải phòng", "cần thơ", "việt nam", "viet nam", "quận", "phường", "đường", "tỉnh", "huyện", "xã"]
                        val_lower = match_val.lower().strip()
                        if any(bl in val_lower for bl in name_blacklist):
                            is_valid = False
                            
                    if is_valid:
                        findings.append({
                            "type": pii_type,
                            "value": match_val,
                            "line": line_num,
                            "context": cleaned_line[:100] + ("..." if len(cleaned_line) > 100 else "")
                        })
                        
        # === Data-flow analysis: theo dõi biến từ input -> hàm nguy hiểm (toàn file) ===
        if detect_data_flow is not None:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as _f:
                    full_text = _f.read(200000)  # tối đa 200KB
                for flow_desc in detect_data_flow(full_text):
                    findings.append({
                        "type": "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)",
                        "value": flow_desc,
                        "line": 0,
                        "context": flow_desc[:100],
                        "reason": "data-flow (biến người dùng → hàm nguy hiểm)",
                        "data_flow": True,
                    })
            except Exception:
                pass

        return findings


# ==========================================
# COMPLIANCE SCORING ENGINE
# ==========================================
class ComplianceEngine:
    """Evaluates risk levels and remediation policies."""
    
    def __init__(self, public_dirs=None):
        self.public_dirs = public_dirs or ["public", "uploads", "www", "public_html", "var/www/html"]
        
    def evaluate(self, file_path, findings):
        """Scores a file compliance risk based on its findings."""
        chmod_val, is_world_accessible = get_file_permissions(file_path)
        if not findings:
            return {
                "level": "Safe",
                "score": 100,
                "is_unsecured": False,
                "remediation": "Không cần hành động.",
                "permissions": chmod_val
            }
            
        chmod_val, is_world_accessible = get_file_permissions(file_path)
        
        # Check if in a public directory
        is_in_public_dir = any(pub in str(file_path.as_posix()) for pub in self.public_dirs)
        is_unsecured = is_world_accessible or is_in_public_dir
        
        # Calculate severity
        has_malware = any(f["type"] == "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)" for f in findings)
        has_high = any(SENSITIVITY_LEVELS[f["type"]] == "high" for f in findings)
        has_medium = any(SENSITIVITY_LEVELS[f["type"]] == "medium" for f in findings)
        
        if has_malware:
            level = "Critical"
            score = 10 if is_unsecured else 30
            remediation = "CẢNH BÁO NGUY HIỂM: Phát hiện lệnh thực thi hệ thống nguy hiểm hoặc dấu hiệu webshell/backdoor. Cần lập tức cách ly hoặc xóa tệp tin này khỏi máy chủ!"
        elif has_high:
            level = "Critical"
            score = 25 if is_unsecured else 45
            remediation = "YÊU CẦU HÀNH ĐỘNG NGAY: Mã hóa tệp tin bằng AES-256 và giới hạn quyền truy cập chỉ cho Chủ sở hữu (CHMOD 600)."
        elif has_medium:
            level = "Warning"
            score = 55 if is_unsecured else 75
            remediation = "KHUYẾN NGHỊ CAO: Xem xét lại quyền hạn truy cập (CHMOD 600) và hạn chế chia sẻ công khai thư mục chứa tệp tin này."
        else:
            level = "Low"
            score = 85 if is_unsecured else 92
            remediation = "KHUYẾN NGHỊ: Xem xét chu kỳ kiểm toán hoặc xóa nếu dữ liệu không còn sử dụng."
            
        return {
            "level": level,
            "score": score,
            "is_unsecured": is_unsecured,
            "remediation": remediation,
            "permissions": chmod_val
        }


# ==========================================
# REPORTING MODULE
# ==========================================
import html as _html

# Mô tả hậu quả + khai thác theo CWE (dùng để "trình bày lỗ hổng gì, làm gì, dẫn đến gì")
CWE_IMPACT = {
    "CWE-94": {
        "what": "Tiêm mã động (Code Injection)",
        "do": "Kẻ tấn công gửi mã PHP độc qua tham số người dùng; hàm eval/assert thực thi mã này trực tiếp trên máy chủ.",
        "impact": "Chiếm toàn quyền điều khiển máy chủ web, đọc/sửa/xóa toàn bộ mã nguồn và cơ sở dữ liệu, cài backdoor lâu dài.",
    },
    "CWE-78": {
        "what": "Tiêm lệnh hệ điều hành (OS Command Injection)",
        "do": "Lệnh người dùng nhập được truyền cho hàm system/exec/shell_exec mà không lọc, cho phép chạy lệnh shell tùy ý.",
        "impact": "Thực thi lệnh với quyền của tiến trình web, kiểm soát hoàn toàn máy chủ, đánh cắp dữ liệu, cài mã độc.",
    },
    "CWE-506": {
        "what": "Mã độc được nhúng/che giấu (Embedded Malicious Code)",
        "do": "Payload độc bị mã hóa (base64/rot13/gzip/XOR) để né các công cụ quét và tường lửa.",
        "impact": "Phát hiện khó khăn, mã độc tồn tại lâu dài trên hệ thống, hoạt động ngầm khi có điều kiện kích hoạt.",
    },
    "CWE-98": {
        "what": "Nhúng tệp từ xa (Remote File Inclusion - RFI)",
        "do": "include/require nhận đường dẫn từ người dùng, cho phép nhúng và thực thi mã từ máy chủ khác.",
        "impact": "Thực thi mã từ xa, tải webshell từ URL ngoài, chiếm quyền máy chủ.",
    },
    "CWE-434": {
        "what": "Tải tệp tin không kiểm soát (Unrestricted File Upload)",
        "do": "Cho phép tải tệp lên mà không kiểm tra phần mở rộng/nội dung, kẻ tấn công tải webshell lên.",
        "impact": "Cài webshell trực tiếp vào máy chủ, mở cửa hậu truy cập từ xa bất cứ lúc nào.",
    },
    "CWE-522": {
        "what": "Thông tin xác thực không được bảo vệ",
        "do": "Mật khẩu/API key/token lưu dạng văn bản thuần trong mã nguồn hoặc cấu hình.",
        "impact": "Kẻ tấn công đọc được thông tin đăng nhập, truy cập trái phép vào hệ thống và dịch vụ liên quan.",
    },
    "CWE-200": {
        "what": "Lộ thông tin hệ thống (Information Exposure)",
        "do": "Gọi phpinfo()/show_source lộ cấu hình máy chủ, đường dẫn, phiên bản phần mềm.",
        "impact": "Cung cấp thông tin để kẻ tấn công lập kế hoạch khai thác các lỗ hổng khác chính xác hơn.",
    },
}

def describe_impact(cwe_id):
    """Trả về dict {what, do, impact} từ mã CWE, hoặc mô tả chung."""
    if cwe_id in CWE_IMPACT:
        return CWE_IMPACT[cwe_id]
    return {
        "what": "Lệnh/đoạn mã nguy hiểm",
        "do": "Đoạn mã chứa hàm thực thi hoặc gọi hệ thống với dữ liệu không kiểm soát.",
        "impact": "Có thể dẫn đến thực thi mã từ xa hoặc rò rỉ thông tin trên máy chủ.",
    }

def highlight_context(context, value):
    """Tô đậm (màu đỏ + khung) phần `value` trong `context`, trả về HTML an toàn."""
    ctx = _html.escape(context or "")
    val = _html.escape(value or "")
    if val and val in ctx:
        # thay lần đầu tiên bằng phiên bản tô màu
        highlighted = '<mark class="danger-match">' + val + '</mark>'
        return ctx.replace(val, highlighted, 1)
    return ctx


class ReportGenerator:
    """Exports CSV and Jinja2-rendered HTML reports."""
    
    def __init__(self, scan_results, start_time, duration):
        self.results = scan_results
        self.start_time = start_time
        self.duration = duration
        self.total_files = len(scan_results)
        self.violating_files = sum(1 for r in scan_results if len(r["findings"]) > 0)
        
    def generate_csv(self, output_path):
        """Export CSV report using pandas."""
        # Mapping helpers for translation
        level_map = {"Critical": "Nguy cơ cao", "Warning": "Cảnh báo", "Low": "Nguy cơ thấp", "Safe": "An toàn"}
        status_map = {"Unsecured/Leaked": "Chưa bảo mật/Rò rỉ", "Protected": "Được bảo vệ", "Compliant": "Tuân thủ"}
        
        if pd is None:
            # Fallback to standard CSV output if pandas is missing
            import csv
            with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["Đường dẫn tệp", "Định dạng", "Mức độ nhạy cảm", "Quyền hạn tệp", "Trạng thái bảo mật", "Loại rủi ro phát hiện", "Giá trị trùng khớp", "Dòng", "CWE", "MITRE ATT&CK", "Điểm CVSS", "Mức CVSS", "Đề xuất khắc phục"])
                for r in self.results:
                    if not r["findings"]:
                        writer.writerow([r["file_path"], r["format"], "An toàn", r["permissions"], "Tuân thủ", "Không có", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "Không cần hành động."])
                    for f in r["findings"]:
                        writer.writerow([
                            r["file_path"],
                            r["format"],
                            level_map.get(r["compliance"]["level"], r["compliance"]["level"]),
                            r["permissions"],
                            "Chưa bảo mật/Rò rỉ" if r["compliance"]["is_unsecured"] else "Được bảo vệ",
                            f["type"],
                            f["value"],
                            f["line"],
                            f.get("cwe_id", "N/A"),
                            f.get("mitre_id", "N/A"),
                            f.get("cvss_score", "N/A"),
                            f.get("cvss_severity", "N/A"),
                            r["compliance"]["remediation"]
                        ])
            print(f"Bao cao CSV da duoc luu (Standard Fallback) tai: {output_path}")
            return
            
        # Compile pandas dataframe
        data_rows = []
        for r in self.results:
            if not r["findings"]:
                data_rows.append({
                    "Đường dẫn tệp": r["file_path"],
                    "Định dạng": r["format"],
                    "Mức độ nhạy cảm": "An toàn",
                    "Quyền hạn tệp": r["permissions"],
                    "Trạng thái bảo mật": "Tuân thủ",
                    "Loại rủi ro phát hiện": "Không có",
                    "Giá trị trùng khớp": "N/A",
                    "Dòng": "N/A",
                    "CWE": "N/A",
                    "MITRE ATT&CK": "N/A",
                    "Điểm CVSS": "N/A",
                    "Mức CVSS": "N/A",
                    "Đề xuất khắc phục": "Không cần hành động."
                })
            for f in r["findings"]:
                data_rows.append({
                    "Đường dẫn tệp": r["file_path"],
                    "Định dạng": r["format"],
                    "Mức độ nhạy cảm": level_map.get(r["compliance"]["level"], r["compliance"]["level"]),
                    "Quyền hạn tệp": r["permissions"],
                    "Trạng thái bảo mật": "Chưa bảo mật/Rò rỉ" if r["compliance"]["is_unsecured"] else "Được bảo vệ",
                    "Loại rủi ro phát hiện": f["type"],
                    "Giá trị trùng khớp": f["value"],
                    "Dòng": f["line"],
                    "CWE": f.get("cwe_id", "N/A"),
                    "MITRE ATT&CK": f.get("mitre_id", "N/A"),
                    "Điểm CVSS": f.get("cvss_score", "N/A"),
                    "Mức CVSS": f.get("cvss_severity", "N/A"),
                    "Đề xuất khắc phục": r["compliance"]["remediation"]
                })
                
        df = pd.DataFrame(data_rows)
        df.to_csv(output_path, index=False, encoding="utf-8-sig")
        print(f"Bao cao CSV da duoc luu (Pandas) tai: {output_path}")
        
    def generate_html(self, output_path):
        """Export high-end premium Jinja2 HTML report."""
        if Template is None:
            print("Error: Jinja2 is required to render the HTML dashboard. Report skipped.", file=sys.stderr)
            return

        # Prepare summary stats
        critical_count = sum(1 for r in self.results if r["compliance"]["level"] == "Critical")
        warning_count = sum(1 for r in self.results if r["compliance"]["level"] == "Warning")
        low_count = sum(1 for r in self.results if r["compliance"]["level"] == "Low")
        safe_count = self.total_files - self.violating_files

        # Calculate average security score
        unsecured_high = sum(1 for r in self.results if r["compliance"]["level"] == "Critical" and r["compliance"]["is_unsecured"])
        unsecured_med = sum(1 for r in self.results if r["compliance"]["level"] == "Warning" and r["compliance"]["is_unsecured"])
        warning_files = sum(1 for r in self.results if not r["compliance"]["is_unsecured"] and r["compliance"]["level"] == "Warning")
        
        avg_score = 100
        if self.total_files > 0:
            avg_score -= (unsecured_high * 15)
            avg_score -= (unsecured_med * 8)
            avg_score -= (warning_files * 3)
            
            # Capping rules to align with compliance state
            if unsecured_high > 0:
                avg_score = max(15, min(30, 45 - unsecured_high * 5))
            elif unsecured_med > 0:
                avg_score = max(50, min(65, 75 - unsecured_med * 3))
            
            if avg_score < 15 and self.violating_files > 0:
                avg_score = 15
        
        avg_score = int(avg_score)

        # Detailed breakdown of detected PII types
        pii_counts = {}
        for r in self.results:
            for f in r["findings"]:
                pii_counts[f["type"]] = pii_counts.get(f["type"], 0) + 1
        
        # HTML Template containing embedded styles and charts
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PIIScan Server Pro - Audit Compliance Report</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet" />
    <style>
        :root {
            --bg-main: #0B0F19;
            --bg-card: rgba(20, 26, 40, 0.7);
            --bg-card-hover: rgba(30, 38, 56, 0.8);
            --text-primary: #F3F4F6;
            --text-secondary: #9CA3AF;
            --text-muted: #6B7280;
            --accent-primary: #3B82F6;
            --color-critical: #EF4444;
            --color-warning: #F59E0B;
            --color-clean: #10B981;
            --border-color: rgba(255, 255, 255, 0.08);
            --radius-md: 12px;
            --radius-sm: 6px;
            --transition: all 0.25s ease;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-main);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 40px 24px;
            margin: 0;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }

        .header-title h1 {
            font-size: 2rem;
            font-weight: 800;
            margin: 0 0 8px 0;
            background: linear-gradient(to right, #60A5FA, #A78BFA);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .header-title p {
            color: var(--text-secondary);
            margin: 0;
            font-size: 0.95rem;
        }

        .meta-tag {
            background: rgba(59, 130, 246, 0.1);
            color: var(--accent-primary);
            border: 1px solid rgba(59, 130, 246, 0.2);
            padding: 6px 12px;
            border-radius: 99px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        /* ===== METRICS GRID ===== */
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 24px;
            display: flex;
            flex-direction: column;
            transition: var(--transition);
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: rgba(255,255,255,0.15);
        }

        .metric-label {
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }

        .metric-val {
            font-size: 2.25rem;
            font-weight: 800;
            margin: 0;
        }

        .metric-val.critical { color: var(--color-critical); }
        .metric-val.warning { color: var(--color-warning); }
        .metric-val.clean { color: var(--color-clean); }

        /* ===== COMPLIANCE HIGHLIGHT ===== */
        .dashboard-row {
            display: grid;
            grid-template-columns: 1fr 340px;
            gap: 24px;
            margin-bottom: 32px;
        }

        .main-card {
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 24px;
        }

        .main-card h3 {
            margin: 0 0 20px 0;
            font-size: 1.2rem;
            font-weight: 700;
        }

        /* ===== PIE/BAR CHART COMPONENT ===== */
        .distribution-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .dist-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .dist-label {
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .dist-bar-wrap {
            flex: 1;
            height: 8px;
            background: rgba(255,255,255,0.05);
            border-radius: 99px;
            margin: 0 16px;
            overflow: hidden;
        }

        .dist-bar-fill {
            height: 100%;
            background: var(--accent-primary);
            border-radius: 99px;
        }

        .dist-val {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            font-weight: 600;
            min-width: 30px;
            text-align: right;
        }

        /* ===== ACCORDION LIST ===== */
        .accordion-item {
            margin-bottom: 12px;
            border-radius: var(--radius-md);
            border: 1px solid var(--border-color);
            overflow: hidden;
            background: var(--bg-card);
            transition: var(--transition);
        }

        .accordion-item.critical { border-color: rgba(239, 68, 68, 0.2); }
        .accordion-item.warning { border-color: rgba(245, 158, 11, 0.2); }
        .accordion-item.clean { border-color: rgba(16, 185, 129, 0.2); }

        .accordion-header {
            padding: 16px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            user-select: none;
        }

        .file-info {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .file-path {
            font-weight: 500;
            font-size: 0.95rem;
            word-break: break-all;
        }

        .badge {
            font-size: 0.75rem;
            padding: 3px 8px;
            border-radius: 4px;
            font-weight: 700;
            text-transform: uppercase;
        }

        .badge.critical { background: rgba(239, 68, 68, 0.15); color: var(--color-critical); }
        .badge.warning { background: rgba(245, 158, 11, 0.15); color: var(--color-warning); }
        .badge.low { background: rgba(59, 130, 246, 0.15); color: var(--accent-primary); }
        .badge.clean { background: rgba(16, 185, 129, 0.15); color: var(--color-clean); }

        .accordion-body {
            display: none;
            padding: 20px;
            background: rgba(0, 0, 0, 0.2);
            border-top: 1px solid var(--border-color);
        }

        .remediation-box {
            background: rgba(255, 255, 255, 0.03);
            border-left: 4px solid var(--accent-primary);
            padding: 12px 16px;
            border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
            margin-bottom: 20px;
            font-size: 0.9rem;
        }

        .remediation-box strong {
            display: block;
            margin-bottom: 4px;
            color: var(--text-primary);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }

        th {
            text-align: left;
            padding: 10px;
            color: var(--text-secondary);
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            text-transform: uppercase;
        }

        td {
            padding: 12px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.03);
        }

        .td-line { font-family: 'JetBrains Mono', monospace; color: var(--accent-primary); }
        .td-value { font-family: 'JetBrains Mono', monospace; font-weight: 500; }
        .td-context { font-family: 'JetBrains Mono', monospace; color: var(--text-secondary); }

        /* Khối mã nguồn chứa lệnh nguy hiểm */
        .code-block {
            background: #0d1117;
            border: 1px solid rgba(239, 68, 68, 0.35);
            border-left: 4px solid #EF4444;
            border-radius: 8px;
            padding: 12px 16px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            color: #E5E7EB;
            position: relative;
            margin: 8px 0 12px 0;
            white-space: pre-wrap;
            word-break: break-all;
            line-height: 1.6;
        }
        .code-block .line-num {
            color: #6B7280;
            margin-right: 12px;
            user-select: none;
            font-weight: 400;
        }
        mark.danger-match {
            background: rgba(239, 68, 68, 0.28);
            color: #FCA5A5;
            font-weight: 700;
            padding: 1px 4px;
            border-radius: 3px;
            border: 1px solid #EF4444;
        }
        .arrow-hint {
            color: #EF4444;
            font-weight: 700;
            font-size: 0.8rem;
            margin: 4px 0 8px 20px;
        }

        /* Ba mục giải thích lỗ hổng */
        .vuln-explain {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin: 8px 0 16px 0;
        }
        .vuln-explain .cell {
            background: rgba(255,255,255,0.02);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            font-size: 0.82rem;
        }
        .vuln-explain .cell .lbl {
            display: block;
            font-weight: 700;
            margin-bottom: 6px;
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .vuln-explain .cell.what .lbl { color: #60A5FA; }
        .vuln-explain .cell.how .lbl { color: #F59E0B; }
        .vuln-explain .cell.impact .lbl { color: #EF4444; }
        @media (max-width: 800px) {
            .vuln-explain { grid-template-columns: 1fr; }
        }

        .arrow {
            transition: transform 0.2s ease;
            color: var(--text-secondary);
        }

        .footer {
            margin-top: 48px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border-color);
            padding-top: 24px;
        }
    </style>
    <script>
        function toggleAccordion(header) {
            const body = header.nextElementSibling;
            const arrow = header.querySelector('.arrow');
            const isVisible = body.style.display === 'block';
            
            body.style.display = isVisible ? 'none' : 'block';
            arrow.style.transform = isVisible ? 'rotate(0deg)' : 'rotate(180deg)';
        }
    </script>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>PIIScan Server Pro</h1>
                <p>Báo cáo Đánh giá Tuân thủ An toàn Dữ liệu & Phát hiện Mã độc</p>
            </div>
            <div>
                <span class="meta-tag">Nghị định 13/2023/NĐ-CP & An toàn Thông tin</span>
            </div>
        </header>

        <!-- ===== STATS CARDS ===== -->
        <div class="metrics-grid">
            <div class="metric-card">
                <span class="metric-label">Điểm số An toàn</span>
                <p class="metric-val {{ 'clean' if avg_score >= 80 else 'warning' if avg_score >= 55 else 'critical' }}">{{ avg_score }}/100</p>
            </div>
            <div class="metric-card">
                <span class="metric-label">Tổng số tệp đã quét</span>
                <p class="metric-val">{{ total_files }}</p>
            </div>
            <div class="metric-card">
                <span class="metric-label">Tệp chứa rủi ro</span>
                <p class="metric-val {{ 'critical' if violating_files > 0 else 'clean' }}">{{ violating_files }}</p>
            </div>
            <div class="metric-card">
                <span class="metric-label">Tệp Nguy cơ cao</span>
                <p class="metric-val critical">{{ critical_count }}</p>
            </div>
        </div>

        <div class="dashboard-row">
            <!-- ===== MAIN ACCORDION DETAILS ===== -->
            <div class="main-card">
                <h3>🔍 Chi tiết Phát hiện Dữ liệu Cá nhân và Lỗ hổng</h3>
                {% if violating_files == 0 %}
                <div style="text-align: center; padding: 40px 0; color: var(--text-secondary);">
                    <p style="font-size: 3rem; margin: 0 0 10px 0;">🟢</p>
                    <p style="font-weight: 600;">Hệ thống an toàn. Không phát hiện dữ liệu rò rỉ hay mã độc.</p>
                </div>
                {% else %}
                {% for r in results %}
                {% if r.findings %}
                <div class="accordion-item {{ r.compliance.level.lower() }}">
                    <div class="accordion-header" onclick="toggleAccordion(this)">
                        <div class="file-info">
                            <span>{{ '🗄️' if r.format == '.sql' else '📊' if r.format == '.csv' else '📄' }}</span>
                            <span class="file-path">{{ r.file_path }}</span>
                        </div>
                        <div style="display:flex; align-items:center; gap: 12px;">
                            <span class="badge {{ r.compliance.level.lower() }}">
                                {{ 'Nguy cơ cao' if r.compliance.level == 'Critical' else 'Cảnh báo' if r.compliance.level == 'Warning' else 'Nguy cơ thấp' }}
                            </span>
                            <span class="arrow">▼</span>
                        </div>
                    </div>
                    <div class="accordion-body">
                        <div class="remediation-box">
                            <strong>Đề xuất khắc phục rủi ro:</strong>
                            {{ r.compliance.remediation }}
                            <p style="margin: 8px 0 0 0; font-size: 0.8rem; color: var(--text-secondary);">
                                Quyền hạn tệp: <code>{{ r.permissions }}</code> | Định dạng tệp: <code>{{ r.format }}</code>
                            </p>
                        </div>
                        <!-- ===== Danh sách lỗ hổng chi tiết (khung mã + mũi tên + giải thích) ===== -->
                        {% for f in r.findings %}
                        <div style="margin-bottom: 18px; border-bottom: 1px solid var(--border-color); padding-bottom: 16px;">
                            <div style="display:flex; align-items:center; gap: 10px; flex-wrap: wrap; margin-bottom: 8px;">
                                <span class="badge {{ r.compliance.level.lower() }}">{{ f.type }}</span>
                                <span class="td-line" style="font-family:'JetBrains Mono',monospace;">Dòng {{ f.line }}</span>
                                {% if f.cwe_id %}
                                <span style="font-size:0.72rem; font-family:'JetBrains Mono',monospace; color:#A78BFA;">{{ f.cwe_id }}</span>
                                {% endif %}
                                {% if f.cvss_score %}
                                <span style="font-size:0.72rem; font-family:'JetBrains Mono',monospace; color:#F87171; font-weight:700;">CVSS {{ f.cvss_score }} ({{ f.cvss_severity }})</span>
                                {% endif %}
                                {% if f.mitre_id %}
                                <span style="font-size:0.72rem; font-family:'JetBrains Mono',monospace; color:#60A5FA;">MITRE {{ f.mitre_id }}</span>
                                {% endif %}
                            </div>

                            <!-- Khối mã nguồn chứa lệnh nguy hiểm -->
                            <div class="code-block">
                                <span class="line-num">{{ f.line }} |</span>{{ highlight_context(f.context, f.value) | safe }}
                            </div>
                            <div class="arrow-hint">▲ Lệnh nguy hiểm: <code>{{ f.value }}</code></div>

                            <!-- Ba mục: lỗ hổng gì / làm gì / dẫn đến gì -->
                            {% set imp = describe_impact(f.cwe_id) %}
                            <div class="vuln-explain">
                                <div class="cell what">
                                    <span class="lbl">🔍 Lỗ hổng gì</span>
                                    {{ imp.what }}
                                </div>
                                <div class="cell how">
                                    <span class="lbl">⚙️ Kẻ tấn công làm gì</span>
                                    {{ imp.do }}
                                </div>
                                <div class="cell impact">
                                    <span class="lbl">💥 Dẫn đến hậu quả</span>
                                    {{ imp.impact }}
                                </div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
                {% endif %}
                {% endfor %}
                {% endif %}
            </div>

            <!-- ===== SIDEBAR PIE CHART / DETAILS ===== -->
            <div style="display: flex; flex-direction: column; gap: 24px;">
                <div class="main-card">
                    <h3 style="margin-bottom:16px;">📊 Mật độ Rủi ro phát hiện</h3>
                    <div class="distribution-list">
                        {% for type, count in pii_counts.items() %}
                        <div class="dist-item">
                            <span class="dist-label">{{ type }}</span>
                            <div class="dist-bar-wrap">
                                <div class="dist-bar-fill" style="width: {{ (count / violating_files * 100)|int if violating_files > 0 else 0 }}%;"></div>
                            </div>
                            <span class="dist-val">{{ count }}</span>
                        </div>
                        {% endfor %}
                        {% if not pii_counts %}
                        <p style="color:var(--text-muted); font-size:0.85rem; text-align:center;">Không có dữ liệu phân bổ rủi ro.</p>
                        {% endif %}
                    </div>
                </div>

                <div class="main-card">
                    <h3>💡 Tóm tắt Đánh giá</h3>
                    <div style="font-size: 0.85rem; color: var(--text-secondary); display:flex; flex-direction:column; gap:10px;">
                        <div><strong>Bắt đầu:</strong> {{ start_time }}</div>
                        <div><strong>Thời gian quét:</strong> {{ duration }}</div>
                        <div><strong>Tệp an toàn:</strong> {{ safe_count }}</div>
                        <div><strong>Tệp cảnh báo:</strong> {{ warning_count }}</div>
                        <div><strong>Tệp nguy cơ cao:</strong> {{ critical_count }}</div>
                    </div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>© 2026 PIIScan Server Pro. Báo cáo được tạo tự động lúc {{ start_time }}.</p>
        </div>
    </div>
</body>
</html>"""

        template = Template(html_template)
        rendered_html = template.render(
            results=self.results,
            total_files=self.total_files,
            violating_files=self.violating_files,
            critical_count=critical_count,
            warning_count=warning_count,
            low_count=low_count,
            safe_count=safe_count,
            avg_score=avg_score,
            pii_counts=pii_counts,
            start_time=self.start_time,
            duration=self.duration,
            highlight_context=highlight_context,
            describe_impact=describe_impact,
        )
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)
        print(f"Gorgeous HTML Report saved to: {output_path}")


# ==========================================
# AUTOMATION MODULE (SMTP EMAIL & SCHEDULER)
# ==========================================
def send_email_report(subject, recipient, csv_path, html_path, smtp_conf, stats):
    """Sends email report using smtplib."""
    if not smtp_conf.get("user") or not smtp_conf.get("pass"):
        print("SMTP config username or password missing. Skipping email notification.", file=sys.stderr)
        return
        
    msg = MIMEMultipart()
    msg["From"] = smtp_conf["user"]
    msg["To"] = recipient
    msg["Subject"] = subject
    
    # HTML body
    body_html = f"""
    <h3>PIIScan Server Pro - Daily PII Scan Alert</h3>
    <p>An automated scan was executed on your server. Below is a summary of the compliance findings:</p>
    <ul>
        <li><strong>Audit Date:</strong> {stats['time']}</li>
        <li><strong>Total Files Scanned:</strong> {stats['total']}</li>
        <li><strong>Violating Files:</strong> {stats['violators']}</li>
        <li><strong>Critical Vulnerabilities:</strong> {stats['critical']}</li>
    </ul>
    <p>Please open the attached <code>report.html</code> file in your browser to view the interactive dashboard, charts, and exact file leakage lines.</p>
    <br>
    <p>Regards,<br>PIIScan Server Pro System</p>
    """
    msg.attach(MIMEText(body_html, "html"))
    
    # Attach files if they exist
    for path, filename in [(csv_path, "report.csv"), (html_path, "report.html")]:
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as attachment:
                    part = MIMEText(attachment.read(), "html" if path == html_path else "csv")
                    part.add_header("Content-Disposition", f"attachment; filename= {filename}")
                    msg.attach(part)
            except Exception as e:
                print(f"Error attaching {filename} - {e}", file=sys.stderr)

    try:
        server = smtplib.SMTP(smtp_conf["server"], smtp_conf["port"])
        server.starttls()
        server.login(smtp_conf["user"], smtp_conf["pass"])
        server.send_message(msg)
        server.quit()
        print("SMTP email alert dispatched successfully.")
    except Exception as e:
        print(f"Failed sending email via SMTP - {e}", file=sys.stderr)


def show_scheduler_instructions():
    """Print setup guidelines for Windows Task Scheduler and Linux Cron."""
    script_path = os.path.abspath(__file__)
    print("""
======================================================================
PIISCAN AUTOMATION & SCHEDULER SETUP
======================================================================

To automate this scan to run daily at 2:00 AM, follow the guides below:

1. LINUX CRONJOB SETUP:
-----------------------
Open your crontab manager:
  crontab -e

Add the following cron expression to run at 2:00 AM daily:
  0 2 * * * python3 """ + script_path + """ --path /var/www/html/ --output-html /var/www/html/report.html

2. WINDOWS TASK SCHEDULER:
--------------------------
To create a Task Schedule via Command Prompt (Admin), run:
  schtasks /create /tn "PIIScan_Daily_Audit" /tr "python.exe """ + script_path + """ --path D:\\doan\\ --output-html D:\\doan\\report.html" /sc daily /st 02:00

Or construct it in the Task Scheduler UI:
  - Create Basic Task -> Name: "PIIScan Daily Audit"
  - Trigger: Daily -> Start Time: 02:00:00 AM
  - Action: Start a Program
  - Program/Script: python.exe
  - Add Arguments: """ + script_path + """ --path D:\\doan\\ --output-html D:\\doan\\report.html
======================================================================
""")


from http.server import HTTPServer, BaseHTTPRequestHandler

class PIIScanAPIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence default terminal logs to keep interface clean
        pass
        
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, x-apikey')
        super().end_headers()
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        # Clean path to avoid path traversal or query parameters
        path = self.path.split('?')[0]
        if path == '/' or path == '':
            path = '/index.html'
            
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_path = os.path.normpath(os.path.join(script_dir, 'virusscan', path.lstrip('/')))
        
        # Security check: ensure path is inside the virusscan directory
        virusscan_dir = os.path.normpath(os.path.join(script_dir, 'virusscan'))
        if not local_path.startswith(virusscan_dir):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"403 Forbidden")
            return
            
        if os.path.exists(local_path) and os.path.isfile(local_path):
            self.send_response(200)
            if local_path.endswith('.html'):
                self.send_header('Content-Type', 'text/html; charset=utf-8')
            elif local_path.endswith('.css'):
                self.send_header('Content-Type', 'text/css; charset=utf-8')
            elif local_path.endswith('.js'):
                self.send_header('Content-Type', 'application/javascript; charset=utf-8')
            elif local_path.endswith('.json'):
                self.send_header('Content-Type', 'application/json; charset=utf-8')
            elif local_path.endswith('.png'):
                self.send_header('Content-Type', 'image/png')
            elif local_path.endswith('.jpg') or local_path.endswith('.jpeg'):
                self.send_header('Content-Type', 'image/jpeg')
            elif local_path.endswith('.ico'):
                self.send_header('Content-Type', 'image/x-icon')
            elif local_path.endswith('.svg'):
                self.send_header('Content-Type', 'image/svg+xml')
            else:
                self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            
            with open(local_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
        
    def do_POST(self):
        if self.path == '/api/scan/path':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(post_data)
                target_path = data.get('path', '.')
            except Exception:
                target_path = '.'
                
            print(f"API Server: Scanning path: {target_path}")
            
            scanner = PIIScanner(target_path)
            analyzer = PIIAnalyzer()
            compliance = ComplianceEngine()
            
            scan_results = []
            target_root = Path(target_path)
            for file_path in scanner.scan_directories():
                findings = analyzer.analyze_file(file_path)
                eval_result = compliance.evaluate(file_path, findings)
                
                # Phát hiện polyglot (file ảnh/pdf chứa mã nhúng)
                is_poly, poly_desc = detect_polyglot_file(file_path)
                if is_poly:
                    findings.append({
                        "type": "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)",
                        "value": poly_desc,
                        "line": 0,
                        "context": poly_desc[:100],
                        "reason": "polyglot (mã nhúng trong file đa định dạng)",
                        "cwe_id": "CWE-506",
                        "cvss_score": 9.8,
                        "cvss_severity": "Critical",
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "mitre_id": "T1027",
                        "mitre_name": "Obfuscated Files or Information",
                        "mitre_tactic": "Defense Evasion",
                    })
                    eval_result = compliance.evaluate(file_path, findings)
                
                # Đường dẫn tương đối so với thư mục gốc đã quét (hiển thị folder/subfolder)
                try:
                    if target_root.is_dir():
                        rel_path = str(file_path.relative_to(target_root))
                    else:
                        rel_path = file_path.name
                except ValueError:
                    rel_path = str(file_path)
                
                # Tính entropy Shannon của file (phát hiện payload mã hóa)
                file_entropy = 0.0
                file_entropy_risk = "none"
                file_signatures = []
                try:
                    if shannon_entropy is not None:
                        with open(file_path, "rb") as _fb:
                            raw_bytes = _fb.read(65536)  # đọc tối đa 64KB đầu
                            file_entropy = shannon_entropy(raw_bytes)
                            if entropy_flag is not None:
                                file_entropy_risk = entropy_flag(file_entropy)["risk"]
                            # Quét signature rules (YARA-style) trên nội dung đã đọc
                            if match_file_rules is not None:
                                try:
                                    text_content = raw_bytes.decode("utf-8", errors="ignore")
                                    file_signatures = match_file_rules(text_content)
                                except Exception:
                                    file_signatures = []
                except Exception:
                    pass

                # Phân tích mã độc tĩnh chuyên sâu (hash, entropy, PE, IoC, phân loại họ)
                malware_analysis = None
                if analyze_malware_file is not None:
                    try:
                        malware_analysis = analyze_malware_file(file_path)
                    except Exception:
                        malware_analysis = None
                
                # Deduplicate and group findings by PII type
                grouped_pii = {}
                file_cvss_score = 0.0
                file_cvss_severity = None
                file_cvss_vector = None
                for f in findings:
                    t = f["type"]
                    if t not in grouped_pii:
                        grouped_pii[t] = []
                    grouped_pii[t].append({
                        "line": f["line"],
                        "text": f["context"],
                        "value": f["value"],
                        "cwe_id": f.get("cwe_id", ""),
                        "cwe": f.get("cwe", ""),
                        "malware_name": f.get("malware_name", ""),
                        "reason": f.get("reason", ""),
                        "cvss_score": f.get("cvss_score"),
                        "cvss_severity": f.get("cvss_severity", ""),
                        "cvss_vector": f.get("cvss_vector", ""),
                        "mitre_id": f.get("mitre_id", ""),
                        "mitre_name": f.get("mitre_name", ""),
                        "mitre_tactic": f.get("mitre_tactic", ""),
                    })
                    # Theo dõi CVSS cao nhất của file
                    if f.get("cvss_score") is not None:
                        if file_cvss_score < f["cvss_score"]:
                            file_cvss_score = f["cvss_score"]
                            file_cvss_severity = f.get("cvss_severity")
                            file_cvss_vector = f.get("cvss_vector")
                
                pii_found_list = []
                for pii_name, details in grouped_pii.items():
                    pii_found_list.append({
                        "name": pii_name,
                        "count": len(details),
                        "level": SENSITIVITY_LEVELS[pii_name],
                        "details": details
                    })
                
                # Chuẩn hóa level về high/medium/low/safe (thống nhất với frontend & scanStats)
                raw_level = eval_result["level"]
                if raw_level == "Critical":
                    level_field = "high"
                elif raw_level == "Warning":
                    level_field = "medium"
                elif raw_level == "Low":
                    level_field = "low"
                else:
                    level_field = "safe"

                # Tính OWASP Risk Rating cho file (nếu có mã độc)
                file_risk = None
                if file_cvss_severity and owasp_risk_rating is not None:
                    try:
                        is_in_public = any(pub in str(file_path.as_posix()) for pub in compliance.public_dirs)
                        file_risk = owasp_risk_rating(
                            file_cvss_severity,
                            eval_result["is_unsecured"],
                            is_in_public,
                            file_entropy,
                        )
                    except Exception:
                        file_risk = None

                scan_results.append({
                    "fileName": file_path.name,
                    "path": str(file_path),
                    "relativePath": rel_path,
                    "format": file_path.suffix.lower(),
                    "level": level_field,
                    "securityStatus": "unsecured" if eval_result["is_unsecured"] else ("warning" if raw_level == "Warning" else "secured"),
                    "permissions": eval_result["permissions"],
                    "size": f"{os.path.getsize(file_path)/1024:.1f} KB" if os.path.exists(file_path) else "0 KB",
                    "date": datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d') if os.path.exists(file_path) else "",
                    "cvss": {
                        "score": file_cvss_score,
                        "severity": file_cvss_severity,
                        "vector": file_cvss_vector,
                    },
                    "entropy": file_entropy,
                    "entropyRisk": file_entropy_risk,
                    "signatures": file_signatures,
                    "malwareAnalysis": malware_analysis,
                    "riskRating": file_risk,
                    "piiFound": pii_found_list
                })
                
            # Sort unsecured high risk first
            scan_results.sort(key=lambda x: (0 if x["securityStatus"] == "unsecured" else 1, 0 if x["level"] == "high" else 1))
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            # Statistics
            total_files = len(scan_results)
            files_with_pii = sum(1 for r in scan_results if len(r["piiFound"]) > 0)
            high_count = sum(1 for r in scan_results if r["level"] == "high")
            medium_count = sum(1 for r in scan_results if r["level"] == "medium")
            low_count = sum(1 for r in scan_results if r["level"] == "low")
            
            response_data = {
                "success": True,
                "stats": {
                    "totalFiles": total_files,
                    "filesWithPii": files_with_pii,
                    "high": high_count,
                    "medium": medium_count,
                    "low": low_count
                },
                "results": scan_results
            }
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        elif self.path == '/api/remediate':
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length).decode('utf-8')
            try:
                data = json.loads(post_data)
                target_path = data.get('path', '.')
            except Exception:
                target_path = '.'
                
            print(f"API Server: Remediating path: {target_path}")
            
            scanner = PIIScanner(target_path)
            analyzer = PIIAnalyzer()
            compliance = ComplianceEngine()
            
            remediation_logs = []
            remediated_count = 0
            
            for file_path in scanner.scan_directories():
                if not file_path.exists():
                    continue
                findings = analyzer.analyze_file(file_path)
                if not findings:
                    continue
                    
                # Evaluate compliance
                eval_result = compliance.evaluate(file_path, findings)
                
                # Check for malware / webshell
                has_malware = any(f["type"] == "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)" for f in findings)
                
                if has_malware:
                    # Quarantine file by appending .quarantine and changing permission to 0o600
                    old_name = file_path.name
                    quarantine_path = file_path.with_suffix(file_path.suffix + ".quarantine")
                    try:
                        # Rename the file
                        if quarantine_path.exists():
                            os.remove(quarantine_path)
                        os.rename(file_path, quarantine_path)
                        
                        # Set permission 0o600
                        try:
                            os.chmod(quarantine_path, 0o600)
                        except Exception:
                            pass
                            
                        remediation_logs.append(f"[CÁCH LY] Tệp tin chứa mã độc '{old_name}' đã được đổi tên thành '{quarantine_path.name}' và thu hồi quyền thực thi (CHMOD 600).")
                        remediated_count += 1
                    except Exception as e:
                        remediation_logs.append(f"[THẤT BẠI] Không thể cách ly tệp tin chứa mã độc '{old_name}': {str(e)}")
                else:
                    # Contains PII or credentials. Mask and set chmod 600
                    try:
                        # Read file
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            
                        modified = False
                        # Helper mapping logic
                        for pii_type, pattern in PII_PATTERNS.items():
                            if pii_type == "Mã độc & Lệnh nguy hiểm (Webshell/Backdoor)":
                                continue
                            
                            def repl_func(match):
                                nonlocal modified
                                if pii_type in ["Thông tin xác thực / API Key / Mật khẩu", "Cookie phiên"] and match.lastindex is not None and match.lastindex >= 1:
                                    full_match = match.group(0)
                                    secret_val = match.group(1)
                                    masked = mask_pii_value_python(pii_type, secret_val)
                                    modified = True
                                    return full_match.replace(secret_val, masked)
                                else:
                                    val = match.group(0)
                                    is_valid = True
                                    if pii_type == "Số định danh (CCCD/CMND)":
                                        clean_val = re.sub(r"[-\s]", "", val)
                                        if is_sequential_or_repeated(clean_val):
                                            is_valid = False
                                        elif len(clean_val) == 12:
                                            try:
                                                province = int(clean_val[0:3])
                                                gender = int(clean_val[3:4])
                                                is_valid = (1 <= province <= 96) and (0 <= gender <= 9)
                                            except ValueError:
                                                is_valid = False
                                        elif len(clean_val) == 9:
                                            is_valid = True
                                        elif "-" in val:
                                            is_valid = bool(re.match(r"^\d{3}-\d{2}-\d{4}$", val))
                                        else:
                                            is_valid = False
                                    elif pii_type == "Số thẻ tín dụng":
                                        is_valid = is_valid_luhn(val)
                                    elif pii_type == "Thông tin xác thực / API Key / Mật khẩu":
                                        lower_val = val.lower()
                                        if any(x in lower_val for x in ["placeholder", "your_", "todo", "my_secure_"]):
                                            is_valid = False
                                    elif pii_type == "Họ và tên":
                                        name_blacklist = ["hồ chí minh", "thành phố", "thành phố hồ chí minh", "hà nội", "đà nẵng", "hải phòng", "cần thơ", "việt nam", "viet nam", "quận", "phường", "đường", "tỉnh", "huyện", "xã"]
                                        val_lower = val.lower().strip()
                                        if any(bl in val_lower for bl in name_blacklist):
                                            is_valid = False
                                            
                                    if is_valid:
                                        modified = True
                                        return mask_pii_value_python(pii_type, val)
                                    return val
                                    
                            content = pattern.sub(repl_func, content)
                            
                        if modified:
                            with open(file_path, "w", encoding="utf-8") as f:
                                f.write(content)
                                
                        # Change permissions to 0o600
                        try:
                            os.chmod(file_path, 0o600)
                            perm_msg = " và phân quyền bảo mật thành công (CHMOD 600)"
                        except Exception:
                            perm_msg = " (chmod không được hỗ trợ hoặc bị chặn trên hệ thống tệp tin)"
                            
                        remediation_logs.append(f"[CHE DỮ LIỆU] Đã che thông tin nhạy cảm trong tệp '{file_path.name}'{perm_msg}.")
                        remediated_count += 1
                    except Exception as e:
                        remediation_logs.append(f"[THẤT BẠI] Không thể xử lý bảo mật tệp '{file_path.name}': {str(e)}")
                        
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            response_data = {
                "success": True,
                "count": remediated_count,
                "logs": remediation_logs
            }
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

def run_api_server(port=None):
    if port is None:
        port = int(os.environ.get("PORT", 5000))
    server_address = ('', port)
    httpd = HTTPServer(server_address, PIIScanAPIHandler)
    print(f"PIIScan Server Pro - API Server running on port {port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping API Server...")
        httpd.server_close()


# ==========================================
# MAIN COMMAND-LINE RUNNER
# ==========================================
def main():
    parser = argparse.ArgumentParser(
        description="PIIScan Server Pro - Scan servers for exposed PII and compliance vulnerabilities."
    )
    parser.add_argument("--path", default=".", help="Root directory or file to scan.")
    parser.add_argument("--output-html", default="report.html", help="HTML report output path.")
    parser.add_argument("--output-csv", default="report.csv", help="CSV report output path.")
    parser.add_argument("--email", help="Recipient email address for scan alerts.")
    parser.add_argument("--smtp-server", default="smtp.gmail.com", help="SMTP Server host.")
    parser.add_argument("--smtp-port", type=int, default=587, help="SMTP Server port.")
    parser.add_argument("--smtp-user", help="SMTP username credentials.")
    parser.add_argument("--smtp-pass", help="SMTP password credentials.")
    parser.add_argument("--show-schedule", action="store_true", help="Print scheduler configuration details.")
    parser.add_argument("--server", action="store_true", help="Start the local HTTP REST API server on port 5000.")
    
    args = parser.parse_args()
    
    if args.show_schedule:
        show_scheduler_instructions()
        return

    if args.server:
        run_api_server()
        return

    start_time = datetime.datetime.now()
    start_time_str = start_time.strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"PIIScan Server Pro - Scan started at {start_time_str}")
    print(f"Scanning target: {args.path}")

    # Core Execution
    scanner = PIIScanner(args.path)
    analyzer = PIIAnalyzer()
    compliance = ComplianceEngine()
    
    scan_results = []
    
    for file_path in scanner.scan_directories():
        print(f"Auditing file: {file_path.name}")
        findings = analyzer.analyze_file(file_path)
        eval_result = compliance.evaluate(file_path, findings)
        
        scan_results.append({
            "file_path": str(file_path.relative_to(scanner.target_path) if scanner.target_path.is_dir() else file_path.name),
            "format": file_path.suffix.lower(),
            "findings": findings,
            "permissions": eval_result["permissions"],
            "compliance": eval_result
        })

    end_time = datetime.datetime.now()
    duration = str(end_time - start_time)
    
    # Reports compiling
    reporter = ReportGenerator(scan_results, start_time_str, duration)
    reporter.generate_csv(args.output_csv)
    reporter.generate_html(args.output_html)
    
    # Email alert checks
    if args.email and args.smtp_user and args.smtp_pass:
        stats = {
            "time": start_time_str,
            "total": reporter.total_files,
            "violators": reporter.violating_files,
            "critical": sum(1 for r in scan_results if r["compliance"]["level"] == "Critical")
        }
        send_email_report(
            subject="[PIIScan ALERT] Exposed PII / Compliance Vulnerabilities Found",
            recipient=args.email,
            csv_path=args.output_csv,
            html_path=args.output_html,
            smtp_conf={
                "server": args.smtp_server,
                "port": args.smtp_port,
                "user": args.smtp_user,
                "pass": args.smtp_pass
            },
            stats=stats
        )

    print(f"Audit run complete. Duration: {duration}.")
    print(f"Total files audited: {reporter.total_files} | Exposed files: {reporter.violating_files}")


if __name__ == "__main__":
    main()
