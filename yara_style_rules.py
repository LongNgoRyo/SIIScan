#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bộ rule phát hiện mã độc theo kiểu YARA (signature-based) — thuần Python.

LÝ DO DÙNG MODULE NÀY THAY VÌ YARA-PYTHON:
  - Máy không có trình biên dịch C (gcc/clang) và không có quyền sudo để cài.
  - yara-python không có wheel prebuilt cho Python 3.14 (quá mới).
  Vì vậy thay bằng regex-signature engine tự viết, kế thừa các pattern từ
  php-malware-finder (nbs-system) và Panelica/malware-signatures.

Mỗi rule gồm: tên, mã CWE/MITRE, và một list chuỗi/regex dấu hiệu.
File bị "khớp rule" khi chứa ÍT NHẤT một dấu hiệu của rule đó.

Các rule tập trung vào các họ webshell/malware PHP phổ biến + kỹ thuật.
"""

import re

# ==========================================================
# DANH SÁCH RULE (theo kiểu YARA metadata)
# ==========================================================
RULES = [
    {
        "id": "webshell_c99",
        "name": "c99 Shell",
        "description": "c99shell - webshell PHP phổ biến cho phép quản trị máy chủ từ xa.",
        "cwe": "CWE-94",
        "mitre": "T1505.003",
        "patterns": [
            r"c99shell", r"c99_madnet", r"shm_php", r"Safe_Mode",
            r"\$GLOBALS\[['\"]c99", r"edoced_46esab",  # base64_decode đảo ("edoced_46esab")
        ],
    },
    {
        "id": "webshell_r57",
        "name": "r57 Shell",
        "description": "r57shell - webshell cổ điển với giao diện quản lý file/lệnh.",
        "cwe": "CWE-94",
        "mitre": "T1505.003",
        "patterns": [
            r"r57", r"r57shell", r"r57_", r"starhack",
        ],
    },
    {
        "id": "webshell_wso",
        "name": "WSO Web Shell (FilesMan)",
        "description": "WSO/Web Shell by oRb - webshell nổi tiếng với module FilesMan.",
        "cwe": "CWE-94",
        "mitre": "T1505.003",
        "patterns": [
            r"wso_version", r"FilesMan", r"\$default_action\s*=\s*['\"]FilesMan",
            r"wso", r"mixid", r"oRb", r"\$auth_pass",
        ],
    },
    {
        "id": "webshell_b374k",
        "name": "b374k Shell",
        "description": "b374k - webshell tối giản bằng PHP.",
        "cwe": "CWE-94",
        "mitre": "T1505.003",
        "patterns": [
            r"b374k", r"b374k_root", r"yoShell",
        ],
    },
    {
        "id": "webshell_weevely",
        "name": "Weevely3",
        "description": "Weevely - webshell stealth C/S có payload mã hóa và session.",
        "cwe": "CWE-94",
        "mitre": "T1505.003",
        "patterns": [
            r"weevely", r"\.\.'\$|'\$\.\.", r"\$k\\x..", r"uuencode",
        ],
    },
    {
        "id": "webshell_chopper",
        "name": "China Chopper / Caidao",
        "description": "China Chopper (菜刀) - webshell 1 dòng của hacker Trung Quốc.",
        "cwe": "CWE-94",
        "mitre": "T1505.003",
        "patterns": [
            r"@eval\s*\(\s*\$_(?:POST|GET|REQUEST)", r"chopper", r"caidao",
            r"@\$_\+\[['\"]",  # biến XOR che giấu
        ],
    },
    {
        "id": "obfuscator_best_php",
        "name": "Best PHP Obfuscator",
        "description": "Dấu hiệu của Best PHP Obfuscator (chuỗi base64 dài + eval + gz).",
        "cwe": "CWE-506",
        "mitre": "T1027",
        "patterns": [
            r"eval\s*\(\s*(?:gzuncompress|gzinflate|base64_decode)",
            r"base64_decode\s*\(\s*['\"][A-Za-z0-9+/]{100,}=*['\"]",
            r"\$_\[.{6}\]\.\$_\[",  # mẫu obfuscator điển hình
        ],
    },
    {
        "id": "eval_chained",
        "name": "Phân rã chuỗi đa tầng (multi-layer)",
        "description": "Payload qua nhiều lớp giải mã (base64 > gz > eval).",
        "cwe": "CWE-94",
        "mitre": "T1027",
        "patterns": [
            r"eval\s*\(.+base64_decode.+eval",
            r"eval\s*\(.*str_rot13.*eval",
            r"eval\s*\(.*gzinflate.*base64",
        ],
    },
    {
        "id": "rfi_lfi",
        "name": "Local/Remote File Inclusion",
        "description": "include/require với biến người dùng hoặc wrapper stream.",
        "cwe": "CWE-98",
        "mitre": "T1190",
        "patterns": [
            r"(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)",
            r"(?:include|require).*php://(?:input|filter)",
            r"(?:include|require).*https?://",
        ],
    },
    {
        "id": "upload_webshell",
        "name": "Upload tệp tin không kiểm soát",
        "description": "move_uploaded_file / upload không lọc phần mở rộng.",
        "cwe": "CWE-434",
        "mitre": "T1190",
        "patterns": [
            r"move_uploaded_file\s*\(",
            r"\$_FILES\s*\[.+move_uploaded",
        ],
    },
    {
        "id": "reverse_shell_net",
        "name": "Reverse Shell qua socket",
        "description": "Kết nối ngược qua fsockopen/stream_socket_client/popen /dev/tcp.",
        "cwe": "CWE-78",
        "mitre": "T1071",
        "patterns": [
            r"fsockopen\s*\(\s*['\"]?\$(?:GET|POST|REQUEST)",
            r"stream_socket_client\s*\(",
            r"/dev/tcp/",
            r"popen\s*\(\s*['\"][^'\"]*(?:sh|bash|cmd)",
        ],
    },
    {
        "id": "backconnect_shell",
        "name": "Backconnect Shell",
        "description": "Webshell backconnect - tạo tunnel ngược từ máy chủ.",
        "cwe": "CWE-78",
        "mitre": "T1505.003",
        "patterns": [
            r"backconnect", r"back_connect", r"connectback",
        ],
    },
    {
        "id": "php_info_expose",
        "name": "Lộ phpinfo / thông tin hệ thống",
        "description": "Gọi phpinfo() hoặc show_source để lộ cấu hình máy chủ.",
        "cwe": "CWE-200",
        "mitre": "T1082",
        "patterns": [
            r"\bphpinfo\s*\(", r"\bshow_source\s*\(\s*\$_(?:GET|POST)",
        ],
    },
]


def match_file_rules(text_content):
    """
    Quét nội dung (text) của file qua toàn bộ rule.
    Trả về list các rule khớp, mỗi phần tử là dict {id, name, cwe, mitre, ...}.
    """
    matched = []
    for rule in RULES:
        for pat in rule["patterns"]:
            try:
                if re.search(pat, text_content, re.IGNORECASE):
                    matched.append({
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "description": rule["description"],
                        "cwe": rule["cwe"],
                        "mitre": rule["mitre"],
                    })
                    break  # khớp 1 pattern là đủ
            except re.error:
                continue
    return matched


def list_rules():
    """Trả về danh sách tất cả rule để hiển thị/thống kê."""
    return list(RULES)