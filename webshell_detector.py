#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Webshell/Backdoor Detector nâng cao cho PIIScan.

Dựa trên các pattern từ các công cụ/bộ rule mã nguồn mở uy tín:
  - nbs-system/php-malware-finder (YARA rules)
  - Panelica/malware-signatures (YARA + regex signature)
  - tstillz/webshell-analyzer (multi-layer decoding)
  - Velociraptor Generic.Detection.WebShells

Các kỹ thuật phát hiện được bổ sung so với regex đơn giản ban đầu:
  1. Giải mã đa lớp trước khi khớp: base64, rot13, hex, gzinflate,
     gzuncompress, gzdecode, strrev, str_rot13, pack/unpack, char().
  2. Khôi phục chuỗi nối (string concatenation) và XOR/bitwise obfuscation.
  3. Danh sách hàm nguy hiểm + vector webshell mở rộng.
  4. Phát hiện "biến người dùng -> giải mã -> hàm nguy hiểm" (data-flow đơn giản).
"""

import re
import base64
import codecs
import binascii
import zlib

# ==========================================================
# DANH SÁCH TỪ KHÓA / HÀM NGUY HIỂM (mở rộng)
# ==========================================================
DANGEROUS_FUNCTIONS = [
    # Thực thi lệnh hệ thống
    "system", "exec", "shell_exec", "passthru", "proc_open", "popen",
    "pcntl_exec", "pcntl_fork", "pcntl_alarm",
    # Đánh giá / thực thi mã động
    "eval", "assert", "create_function", "call_user_func", "call_user_func_array",
    "forward_static_call", "preg_replace", "include", "include_once",
    "require_once",
    # Mã hóa phổ biến trong webshell
    "base64_decode", "str_rot13", "gzinflate", "gzuncompress", "gzdecode",
    "gzopen", "gzread", "convert_uudecode", "hex2bin", "unserialize",
    "strrev", "strtr", "chr", "ord",
    # Mạng / reverse shell
    "fsockopen", "pfsockopen", "stream_socket_client", "socket_create",
    "curl_exec", "curl_multi_exec", "get_headers", "get_meta_tags",
    # Đọc/ghi file nhạy cảm
    "move_uploaded_file", "copy", "rename", "unlink", "rmdir", "mkdir",
    "fopen", "file_put_contents", "file_get_contents", "readfile",
    "show_source", "highlight_file", "phpinfo",
    # Python / Node
    "subprocess.popen", "subprocess.call", "subprocess.run", "os.system",
    "os.popen", "os.exec", "child_process.exec", "child_process.spawn",
    "child_process.execsync", "spawn_sync", "pty.spawn",
    # ASP / ASP.NET / JSP
    "process.start", "processstartinfo", "createnodirectory", "wscript.shell",
    "runtime.getruntime", "server.createobject", "system.diagnostics",
    "cmd.exe", "cmd /c", "powershell.exe", "wget", "curl ",
]

# Tên webshell / backdoor nổi tiếng
WEBSHELL_NAMES = [
    "webshell", "backdoor", "c99shell", "r57shell", "wso", "b374k",
    "php_shell", "phpshell", "shell.php", "cmd.asp", "cmd.aspx", "cmd.jsp",
    "china chopper", "chopper", "caidao", "antichat", "weevely", "phpspy",
    "phtml", "reverse_shell", "revshell", "one-liner", "oneline",
]

# Ban đầu: các chuỗi dấu hiệu rất đáng ngờ khi xuất hiện cùng nhau
SUSPICIOUS_TOKENS = [
    r"/dev/tcp/", r"0>&1", r"2>&1", r">&3", r"&\d>&",
    r"php://input", r"php://filter", r"data://",
]

# ==========================================================
# NORMALIZATION: giải mã & khử obfuscation trước khi match
# ==========================================================

def normalize_concat(text):
    """
    Gộp các chuỗi nối kiểu "sys"."tem", 'sys'.'tem', $a="sys";$a.="tem";
    Trả về text đã gộp (chỉ xử lý string literal cạnh nhau).
    """
    # Gộp chuỗi liền kề phân tách bởi dấu chấm: "sys"."tem" -> "system"
    # Pattern: ('...'|"...") \s* \. \s* ('...'|"...")  lặp
    pattern = re.compile(r"""(['"])([^'"\\]*)\1\s*\.\s*((?:['"][^'"\\]*['"]\s*\.\s*)*['"][^'"\\]*['"])""")
    def repl(m):
        parts = [m.group(2)]
        tail = m.group(3)
        # tách các phần còn lại
        for pm in re.finditer(r"""(['"])([^'"\\]*)\1""", tail):
            parts.append(pm.group(2))
        return '"' + "".join(parts) + '"'
    return pattern.sub(repl, text)


def try_decode(text):
    """
    Thử giải mã các chuỗi base64/rot13/hex đáng ngờ trong một dòng.
    Trả về text đã "giải mã hóa" (nối thêm các kết quả giải mã để quét tiếp).
    """
    results = []

    # 1. base64_decode('....')  và  base64_decode("....")
    for m in re.finditer(r"base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=]{8,})\1\s*\)", text, re.IGNORECASE):
        try:
            decoded = base64.b64decode(m.group(2)).decode("utf-8", errors="ignore")
            results.append(decoded)
        except Exception:
            pass

    # 2. chuỗi base64 thuần dài (payload thường dài > 20 ký tự)
    for m in re.finditer(r"(['\"])([A-Za-z0-9+/=]{40,})\1", text):
        s = m.group(2)
        if len(s) % 4 == 0:
            try:
                decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
                # chỉ giữ nếu trông như mã/shell
                if any(k in decoded.lower() for k in ["<?php", "system", "eval", "exec", "cmd", "shell", "sh "]):
                    results.append(decoded)
            except Exception:
                pass

    # 3. str_rot13('...') / rot13
    for m in re.finditer(r"(?:str_rot13|rot13)\s*\(\s*(['\"])([^'\"]+)\1\s*\)", text, re.IGNORECASE):
        try:
            results.append(codecs.decode(m.group(2), "rot_13"))
        except Exception:
            pass

    # 4. gzinflate / gzuncompress / gzdecode base64 payload
    for m in re.finditer(r"(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*base64_decode\s*\(\s*(['\"])([A-Za-z0-9+/=]{10,})\1\s*\)\s*\)", text, re.IGNORECASE):
        try:
            raw = base64.b64decode(m.group(2))
            decompressed = zlib.decompress(raw, -15)
            results.append(decompressed.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    # 5. hex2bin / chuỗi hex dài
    for m in re.finditer(r"(?:hex2bin|pack)\s*\(\s*(['\"])([0-9a-fA-F]{16,})\1\s*\)", text):
        try:
            results.append(bytes.fromhex(m.group(2)).decode("utf-8", errors="ignore"))
        except Exception:
            pass

    # 6. strrev('...') đảo ngược chuỗi
    for m in re.finditer(r"strrev\s*\(\s*(['\"])([^'\"]+)\1\s*\)", text, re.IGNORECASE):
        results.append(m.group(2)[::-1])

    # 7. chr(..).chr(..) — nối các mã ký tự
    for m in re.finditer(r"(?:chr|ord)\((\d{2,3})\)(?:\s*\.\s*(?:chr|ord)\((\d{2,3})\))+", text, re.IGNORECASE):
        try:
            nums = re.findall(r"(?:chr|ord)\((\d{2,3})\)", m.group(0))
            results.append("".join(chr(int(n)) for n in nums))
        except Exception:
            pass

    return results


def detect_xor_obfuscation(text):
    """Phát hiện XOR obfuscation kiểu $_^"/", 'str'^'ing', biến kết hợp bitwise."""
    # Bỏ qua các đoạn nằm trong backtick (template literal JS) trước khi quét
    text_no_template = re.sub(r"`[^`]*`", "", text)

    # Kiểu: $_="assert"; $_=$_^"..." hoặc ('a'^'b') hay $_GET['x']('...')
    if re.search(r"(\$\w+|['\"][^'\"\n]{1,8}['\"])\s*\^\s*['\"][^'\"]+['\"]", text_no_template):
        return True
    # PHP biến động ${...} — khớp ${_GET}/${$var}/${'x'} (không phải template literal JS ${port})
    if re.search(r"\$\{(?:\$|['\"])[^}]*\}", text_no_template):
        return True
    if re.search(r"\$\{_[A-Z_]+\}", text_no_template):
        return True
    return False


# ==========================================================
# KHỚP CHÍNH
# ==========================================================

def _build_danger_regex():
    fns = "|".join(re.escape(f) for f in DANGEROUS_FUNCTIONS)
    names = "|".join(re.escape(n) for n in WEBSHELL_NAMES)
    tokens = "|".join(SUSPICIOUS_TOKENS)
    return re.compile(
        r"\b(?:" + fns + r")\s*\(|"
        r"\b(?:" + names + r")\b|"
        r"(?:" + tokens + r")",
        re.IGNORECASE,
    )


_DANGER_RE = _build_danger_regex()

# Regex bắt shell ẩn trong chuỗi $a=$b('cmd') / biến gọi hàm
_VAR_CALL_RE = re.compile(
    r"\$[a-zA-Z_][\w]*\s*\([^)]*\)", re.IGNORECASE
)

# require/include trong PHP kèm biến người dùng hoặc URL (remote file inclusion)
_REQUIRE_INPUT_RE = re.compile(
    r"\brequire(?:_once)?\s*\(\s*(\$|['\"][^'\"]*(?:http|ftp)://)",
    re.IGNORECASE
)

# Regex bắt lệnh đảo kèm eval/assert + obfuscation
_EVAL_OBFUSC_RE = re.compile(
    r"(?:eval|assert|preg_replace|create_function)\s*\(\s*[^)]*(?:base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|strrev|hex2bin|pack|unpack|chr|ord|\\x[0-9a-f]{2}|\\[0-7]{3})",
    re.IGNORECASE,
)

# Regex bắt reverse shell qua /dev/tcp hoặc bash -i
_REVERSE_SHELL_RE = re.compile(
    r"(?:/dev/tcp/|bash\s+-i|sh\s+-i|>\s*&|0>&1|2>&1|perl\s+-e\s|python\s+-c\s)",
    re.IGNORECASE,
)


def detect_malware(line_text):
    """
    Phát hiện dấu hiệu mã độc trên MỘT DÒNG.
    Trả về danh sách (value, reason) các dấu hiệu tìm được.
    """
    hits = []

    original = line_text
    # Tạo bản đã khử obfuscation để khớp
    expanded = normalize_concat(original)

    # 1. Khớp trực tiếp hàm nguy hiểm + tên webshell + token
    for m in _DANGER_RE.finditer(expanded):
        hits.append((m.group(0).strip(), "hàm/từ khóa nguy hiểm"))

    # 2. eval/assert kèm obfuscator
    for m in _EVAL_OBFUSC_RE.finditer(expanded):
        hits.append((m.group(0)[:80], "eval/assert kèm giải mã/obfuscation"))

    # 3. Reverse shell
    for m in _REVERSE_SHELL_RE.finditer(expanded):
        hits.append((m.group(0)[:80], "reverse shell / kết nối ngược"))

    # 4. XOR obfuscation
    if detect_xor_obfuscation(expanded):
        hits.append(("XOR/bitwise obfuscation", "obfuscation XOR"))

    # 5. Giải mã các chuỗi và khớp lại trên nội dung đã giải mã
    for decoded in try_decode(expanded):
        # quét trên chuỗi đã giải mã
        for m in _DANGER_RE.finditer(decoded):
            hits.append((m.group(0).strip(), "tìm thấy sau khi giải mã (base64/rot13/hex/gzip)"))
        if _REVERSE_SHELL_RE.search(decoded):
            hits.append(("reverse_shell (ẩn trong payload)", "reverse shell sau giải mã"))

    # 6. Biến gọi hàm động kiểu $a($_POST['x']) kèm dấu hiệu input
    if _VAR_CALL_RE.search(expanded) and re.search(r"\$(?:_GET|_POST|_REQUEST|_COOKIE|_FILES)", expanded):
        hits.append(("gọi hàm động từ biến người dùng", "web shell gọi hàm qua biến input"))

    # 7. require/include kèm biến người dùng hoặc URL từ xa (PHP remote file inclusion)
    for m in _REQUIRE_INPUT_RE.finditer(expanded):
        hits.append((m.group(0)[:60], "include/require file từ biến người dùng hoặc URL từ xa"))

    # Loại bỏ trùng lặp giữ theo thứ tự
    seen = set()
    deduped = []
    for value, reason in hits:
        key = (value.lower(), reason)
        if key not in seen:
            seen.add(key)
            deduped.append((value, reason))

    return deduped


# ==========================================================
# DATA-FLOW ANALYSIS (theo dõi biến từ input -> hàm nguy hiểm)
# ==========================================================
# Phân tích trên TOÀN BỘ nội dung file (nhiều dòng), bắt được webshell
# tách biến qua nhiều dòng mà regex theo từng dòng không thấy.

_DANGEROUS_FUNC_LIST = [
    "system", "shell_exec", "passthru", "exec", "proc_open", "popen",
    "eval", "assert", "include", "require", "include_once", "require_once",
]

_ASSIGN_RE = re.compile(
    r"\$([a-zA-Z_][\w]*)\s*=\s*([^;]+);", re.IGNORECASE
)

_INPUT_VAR_RE = re.compile(r"\$(?:_GET|_POST|_REQUEST|_COOKIE|_FILES|_SERVER)", re.IGNORECASE)

_DECODE_FUNC_RE = re.compile(r"(?:base64_decode|str_rot13|gzinflate|gzuncompress|gzdecode|hex2bin|strrev|urldecode)\s*\(")


def detect_data_flow(file_text):
    """
    Theo dõi luồng dữ liệu: biến xuất phát từ input người dùng
    ($_GET/$_POST...) rồi (qua giải mã) đến hàm nguy hiểm.

    Trả về list các chuỗi mô tả luồng dữ liệu nguy hiểm phát hiện được.
    """
    flows = []

    # 1. Gán biến: bao nhiêu biến "bẩn" (bắt nguồn từ input) và biến nào gọi hàm nguy hiểm
    tainted = set()   # biến bắt nguồn từ input người dùng
    encoded_to = {}   # var -> hàm giải mã đã áp (dấu vết qua decode)

    for m in _ASSIGN_RE.finditer(file_text):
        var = m.group(1).lower()
        expr = m.group(2)

        # Biến nhận trực tiếp từ input người dùng => tainted
        if _INPUT_VAR_RE.search(expr) and _DECODE_FUNC_RE.search(expr) is None:
            # không qua decode trực tiếp nhưng có thể là input thô
            tainted.add(var)
        # Biến = decode(input) => vừa tainted vừa encoded
        if _INPUT_VAR_RE.search(expr) and _DECODE_FUNC_RE.search(expr):
            tainted.add(var)
            mdec = _DECODE_FUNC_RE.search(expr)
            encoded_to[var] = mdec.group(1)
        # Biến = decode(biến khác đã tainted) => lan taint
        if _DECODE_FUNC_RE.search(expr):
            ref_vars = re.findall(r"\$([a-zA-Z_][\w]*)", expr)
            for rv in ref_vars:
                if rv.lower() in tainted:
                    tainted.add(var)
                    encoded_to[var] = encoded_to.get(rv.lower(), "decode-chain")

    # 2. Biến tainted được truyền vào hàm nguy hiểm => cảnh báo
    for func in _DANGEROUS_FUNC_LIST:
        # tìm lời gọi func($var) hoặc func(..., $var, ...)
        for m in re.finditer(r"\b" + re.escape(func) + r"\s*\(\s*\$([a-zA-Z_][\w]*)", file_text, re.IGNORECASE):
            var = m.group(1).lower()
            if var in tainted:
                trace = encoded_to.get(var, "trực tiếp từ input")
                flows.append(f"luồng dữ liệu: $_{var.upper()} (nguồn người dùng) → {func}()")

    # Bắt $var() — gọi hàm động với biến tainted
    for m in _VAR_CALL_RE.finditer(file_text):
        vcall = m.group(0)
        vname = re.search(r"\$([a-zA-Z_][\w]*)", vcall)
        if vname and vname.group(1).lower() in tainted:
            flows.append(f"gọi hàm động từ biến người dùng: {vcall.strip()}")

    # loại bỏ trùng
    seen = set()
    deduped = []
    for f in flows:
        if f not in seen:
            seen.add(f)
            deduped.append(f)
    return deduped