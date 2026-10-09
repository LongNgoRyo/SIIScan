#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YARA Engine — chạy YARA rules thật (yara-python) để phát hiện mã độc.

Thay thế/bổ sung cho `yara_style_rules.py` (bản tự viết bằng regex),
giờ dùng engine YARA chính hãng — đặc trưng chuẩn của môn Phân tích mã độc.
"""

import os

try:
    import yara
    _HAS_YARA = True
except ImportError:
    _HAS_YARA = False

# Đường dẫn thư mục chứa rules
_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")

# Cache các rule đã compile (tránh compile lại mỗi file)
_compiled_rules = None


def load_rules(rules_dir=None):
    """
    Load và compile tất cả file .yar/.yara trong thư mục rules.
    Trả về yara.Rules đã compile, hoặc None nếu không có.
    """
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    if not _HAS_YARA:
        return None

    rules_dir = rules_dir or _RULES_DIR
    if not os.path.isdir(rules_dir):
        return None

    rule_files = {}
    try:
        for fname in os.listdir(rules_dir):
            if fname.endswith((".yar", ".yara")):
                path = os.path.join(rules_dir, fname)
                with open(path, "r", encoding="utf-8") as f:
                    # namespace = tên file không đuôi
                    ns = os.path.splitext(fname)[0]
                    rule_files[ns] = f.read()
    except Exception:
        return None

    if not rule_files:
        return None

    try:
        _compiled_rules = yara.compile(sources=rule_files)
    except Exception as e:
        print(f"[YARA] Lỗi compile rules: {e}", flush=True)
        return None

    return _compiled_rules


def scan_file(file_path):
    """
    Quét một file bằng YARA rules.
    Trả về list các rule khớp [{rule, tags, meta, strings:[...]}], hoặc [].
    """
    if not _HAS_YARA:
        return []

    rules = load_rules()
    if rules is None:
        return []

    try:
        matches = rules.match(str(file_path), timeout=60)
    except yara.TimeoutError:
        return [{"rule": "(timeout)", "meta": {}, "strings": []}]
    except Exception:
        return []

    result = []
    for m in matches:
        result.append({
            "rule": m.rule,
            "namespace": m.namespace,
            "tags": list(m.tags),
            "meta": dict(m.meta) if m.meta else {},
            "strings": [{
                "identifier": s.identifier,
                "offset": s.instances[0].offset if s.instances else 0,
                "data": _safe_bytes(s.instances[0].matched_data) if s.instances else "",
            } for s in m.strings],
        })
    return result


def _safe_bytes(b):
    """Chuyển bytes an toàn sang str (dùng cho hiển thị)."""
    if isinstance(b, (bytes, bytearray)):
        return b[:120].decode("utf-8", errors="replace")
    return str(b)[:120]


def is_available():
    """Kiểm tra YARA có sẵn không."""
    return _HAS_YARA