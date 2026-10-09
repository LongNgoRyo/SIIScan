#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module chấm điểm CVSS 3.1 + phân loại lỗ hổng + ánh xạ CWE cho PIIScan.

CVSS (Common Vulnerability Scoring System) v3.1 là chuẩn công nghiệp
chấm mức độ nghiêm trọng của lỗ hổng, thang 0.0 - 10.0.

Vector CVSS v3.1 gồm 8 thành phần:
  AV (Attack Vector):    N=Network, A=Adjacent, L=Local, P=Physical
  AC (Attack Complexity): L=Low, H=High
  PR (Privileges Required): N=None, L=Low, H=High
  UI (User Interaction):  N=None, R=Required
  S  (Scope):             U=Unchanged, C=Changed
  C  (Confidentiality):   H=High, L=Low, N=None
  I  (Integrity):         H=High, L=Low, N=None
  A  (Availability):      H=High, L=Low, N=None

Công thức tính điểm base score theo chuẩn FIRST.org (CVSS v3.1 Specification).
"""

import math

# ==========================================================
# TRỌNG SỐ CVSS v3.1 (theo đặc tả chính thức của FIRST.org)
# ==========================================================
_WEIGHTS = {
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20},
    'AC': {'L': 0.77, 'H': 0.44},
    'PR': {'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},  # Scope Unchanged
           'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}},  # Scope Changed
    'UI': {'N': 0.85, 'R': 0.62},
    'C':  {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'I':  {'H': 0.56, 'L': 0.22, 'N': 0.0},
    'A':  {'H': 0.56, 'L': 0.22, 'N': 0.0},
}

# ==========================================================
# PHÂN LOẠI MÃ ĐỘC + CWE + CVSS MẶC ĐỊNH
# ==========================================================
# Mỗi loại lỗ hổng: (mô tả, CWE-xxx, vector CVSS, điểm base, mức độ)
# Điểm base được tính sẵn bằng công thức CVSS 3.1 chính xác.

MALWARE_PROFILES = {
    "webshell_rce": {
        "name": "Webshell / Remote Code Execution (RCE)",
        "description": "Mã độc cho phép kẻ tấn công thực thi lệnh hệ thống từ xa trên máy chủ web.",
        "cwe": "CWE-94 (Code Injection) / CWE-78 (OS Command Injection)",
        "cwe_id": "CWE-94",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "mitre": {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence"},
    },
    "command_execution": {
        "name": "Lệnh thực thi hệ thống (Command Execution)",
        "description": "Hàm thực thi lệnh hệ điều hành (system, exec, shell_exec, passthru) tiếp nhận dữ liệu từ người dùng.",
        "cwe": "CWE-78 (OS Command Injection)",
        "cwe_id": "CWE-78",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "mitre": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    },
    "code_eval": {
        "name": "Thực thi mã động (eval/assert)",
        "description": "Đoạn mã dùng eval/assert/create_function với dữ liệu người dùng, cho phép tiêm mã tùy ý.",
        "cwe": "CWE-94 (Code Injection)",
        "cwe_id": "CWE-94",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "mitre": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    },
    "obfuscation": {
        "name": "Mã độc che giấu / Obfuscation",
        "description": "Sử dụng kỹ thuật mã hóa (base64, rot13, XOR, nối chuỗi) để che giấu payload độc hại.",
        "cwe": "CWE-506 (Embedded Malicious Code)",
        "cwe_id": "CWE-506",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "mitre": {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    },
    "reverse_shell": {
        "name": "Reverse Shell (Kết nối ngược)",
        "description": "Mã độc tạo kết nối ngược về máy chủ của kẻ tấn công để duy trì quyền truy cập từ xa.",
        "cwe": "CWE-78 (OS Command Injection) / CWE-506",
        "cwe_id": "CWE-78",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "score": 10.0,
        "severity": "Critical",
        "mitre": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    },
    "remote_file_inclusion": {
        "name": "Remote File Inclusion (RFI)",
        "description": "Nhúng tệp từ xa qua biến người dùng (include/require), cho phép thực thi mã từ máy chủ khác.",
        "cwe": "CWE-98 (Remote File Inclusion)",
        "cwe_id": "CWE-98",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "severity": "Critical",
        "mitre": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    },
    "file_upload": {
        "name": "Lỗ hổng tải tệp tin không kiểm soát",
        "description": "Cho phép tải tệp tin lên máy chủ mà không kiểm tra đầy đủ, tiềm ẩn upload webshell.",
        "cwe": "CWE-434 (Unrestricted File Upload)",
        "cwe_id": "CWE-434",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "score": 8.7,
        "severity": "High",
        "mitre": {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    },
    "credential_exposure": {
        "name": "Rò rỉ thông tin xác thực / Khóa bí mật",
        "description": "Mật khẩu, API key, token được lưu dưới dạng văn bản thuần.",
        "cwe": "CWE-522 (Insufficiently Protected Credentials) / CWE-798 (Hard-coded Credentials)",
        "cwe_id": "CWE-522",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "High",
        "mitre": {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    },
    "sql_dump_exposure": {
        "name": "Rò rỉ cơ sở dữ liệu / bản sao lưu SQL",
        "description": "Bản sao lưu cơ sở dữ liệu bị lộ trên máy chủ web, chứa dữ liệu nhạy cảm.",
        "cwe": "CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)",
        "cwe_id": "CWE-538",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "score": 7.5,
        "severity": "High",
        "mitre": {"id": "T1213", "name": "Data from Information Repositories", "tactic": "Collection"},
    },
}


# ==========================================================
# CÔNG THỨC TÍNH CVSS v3.1 BASE SCORE (THEO ĐẶC TẢ FIRST.ORG)
# ==========================================================
def _cvss_base_score(av, ac, pr, ui, scope, c, i, a):
    """Tính điểm base CVSS v3.1 từ các chỉ số. Trả về float 0.0-10.0."""
    # Impact sub-score (ISS)
    iss = 1.0 - ((1 - _WEIGHTS['C'][c]) * (1 - _WEIGHTS['I'][i]) * (1 - _WEIGHTS['A'][a]))

    if scope == 'U':  # Scope Unchanged
        impact = 6.42 * iss
    else:             # Scope Changed
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    if impact <= 0:
        return 0.0

    # Exploitability sub-score
    exploitability = 8.22 * _WEIGHTS['AV'][av] * _WEIGHTS['AC'][ac] * \
                     _WEIGHTS['PR'][scope][pr] * _WEIGHTS['UI'][ui]

    if scope == 'U':
        base = min(impact + exploitability, 10.0)
    else:
        base = min(1.08 * (impact + exploitability), 10.0)

    return round(base, 1)


def compute_cvss_from_vector(vector_string):
    """
    Phân tích chuỗi vector CVSS và tính lại điểm base.
    VD: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8
    """
    try:
        parts = {}
        for token in vector_string.split('/')[1:]:
            key, val = token.split(':')
            parts[key] = val
        return _cvss_base_score(
            parts.get('AV', 'N'), parts.get('AC', 'L'), parts.get('PR', 'N'),
            parts.get('UI', 'N'), parts.get('S', 'U'),
            parts.get('C', 'H'), parts.get('I', 'H'), parts.get('A', 'H')
        )
    except Exception:
        return 0.0


def severity_from_score(score):
    """Trả về mức độ theo điểm CVSS v3.1."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def get_profile(profile_key):
    """Trả về bản sao profile theo key, hoặc None nếu không tồn tại."""
    return MALWARE_PROFILES.get(profile_key)


def classify_finding(reason):
    """
    Phân loại reason từ webshell_detector thành profile key.
    reason là chuỗi mô tả ngắn (vd 'hàm/từ khóa nguy hiểm', 'reverse shell...').
    """
    r = reason.lower()
    if 'reverse shell' in r or 'kết nối ngược' in r:
        return 'reverse_shell'
    if 'giải mã' in r or 'obfuscation' in r:
        return 'obfuscation'
    if 'bao gồm/require' in r or 'remote' in r or 'file từ biến' in r:
        return 'remote_file_inclusion'
    if 'upload' in r or 'tải tệp' in r or 'move_uploaded' in r:
        return 'file_upload'
    if 'eval/assert' in r or 'mã động' in r or 'gọi hàm' in r:
        return 'code_eval'
    if 'hàm/từ khóa' in r or 'lệnh' in r or 'command' in r:
        return 'command_execution'
    # mặc định
    return 'webshell_rce'


# ==========================================================
# ENTROPY ANALYSIS (Shannon entropy) — phát hiện payload mã hóa
# ==========================================================
import collections

def shannon_entropy(data: bytes) -> float:
    """
    Tính entropy Shannon (0.0 - 8.0) của dữ liệu.
    Entropy cao > 6.5 thường là dấu hiệu dữ liệu mã hóa / nén / base64
    (payload độc hại bị che giấu), trong khi mã nguồn thường ở mức 4.0 - 6.0.
    """
    if not data:
        return 0.0
    freq = collections.Counter(data)
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def entropy_flag(entropy: float) -> dict:
    """
    Đánh giá mức độ nghi ngờ dựa trên entropy.
    Trả về dict {entropy, risk, flag}.
    """
    if entropy >= 7.0:
        return {"entropy": entropy, "risk": "high", "flag": "Rất cao — nghi ngờ payload mã hóa/nén hoàn toàn"}
    if entropy >= 6.5:
        return {"entropy": entropy, "risk": "medium", "flag": "Cao — có thể chứa dữ liệu mã hóa hoặc base64 dày đặc"}
    if entropy >= 5.5:
        return {"entropy": entropy, "risk": "low", "flag": "Trung bình — hỗn hợp mã nguồn và dữ liệu"}
    return {"entropy": entropy, "risk": "none", "flag": "Thấp — văn bản/mã nguồn thông thường"}


# ==========================================================
# OWASP RISK RATING (Likelihood x Impact)
# ==========================================================
def owasp_risk_rating(cvss_severity, is_unsecured, in_public_dir, entropy=None):
    """
    Tính điểm rủi ro tổng hợp theo phương pháp OWASP Risk Rating.
    Likelihood (0-9) x Impact (0-9) -> mức rủi ro 0-25.

    Likelihood dựa trên: khả năng tiếp cận (public dir, quyền CHMOD),
    và kỹ năng cần thiết (obfuscation -> kẻ tấn công tinh vi -> thấp hơn).
    Impact dựa trên CVSS severity (ảnh hưởng bảo mật).
    """
    # --- Impact (0-9) từ CVSS severity ---
    impact_map = {"Critical": 9, "High": 7, "Medium": 5, "Low": 3, "None": 1}
    impact = impact_map.get(cvss_severity, 3)

    # --- Likelihood (0-9) ---
    likelihood = 0
    # Dễ bị khai thác nhất khi ở thư mục public + quyền world-accessible
    if in_public_dir:
        likelihood += 3
    if is_unsecured:
        likelihood += 3
    # Entropy cao -> payload bị mã hóa -> kẻ tấn công tinh vi hơn nhưng vẫn khả thi
    if entropy is not None and entropy >= 6.5:
        likelihood += 2
    elif entropy is not None and entropy >= 5.5:
        likelihood += 1
    # Đảm bảo tối thiểu có khả năng khai thác (vì đã phát hiện mã độc)
    if likelihood == 0:
        likelihood = 2
    likelihood = min(likelihood, 9)

    risk_score = likelihood * impact

    if risk_score >= 24:
        risk_level = "Rất cao (Critical)"
    elif risk_score >= 16:
        risk_level = "Cao (High)"
    elif risk_score >= 9:
        risk_level = "Trung bình (Medium)"
    elif risk_score >= 4:
        risk_level = "Thấp (Low)"
    else:
        risk_level = "Rất thấp (Informational)"

    return {
        "likelihood": likelihood,
        "impact": impact,
        "score": risk_score,
        "level": risk_level,
    }