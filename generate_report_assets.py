#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sinh các hình ảnh minh họa cho báo cáo đồ án (Word + Slide).

Tạo các sơ đồ: kiến trúc hệ thống, quy trình phân tích 6 bước,
cấu trúc PE, luồng tấn công kill chain, thang entropy, biểu đồ kết quả.
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
os.makedirs(OUT_DIR, exist_ok=True)

# Palette màu tối hiện đại
BG = "#0b0f1a"
CARD = "#111827"
BLUE = "#3b82f6"
CYAN = "#22d3ee"
GREEN = "#10b981"
RED = "#ef4444"
AMBER = "#f59e0b"
PURPLE = "#8b5cf6"
GRAY = "#64748b"
TEXT = "#e5e7eb"
MUTED = "#9ca3af"


def _box(ax, x, y, w, h, text, color, fontsize=10, text_color=TEXT, bold=True):
    box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.02",
                         linewidth=1.5, edgecolor=color, facecolor=color + "22", zorder=2)
    ax.add_patch(box)
    ax.text(x + w/2, y + h/2, text, ha="center", va="center", fontsize=fontsize,
            color=text_color, fontweight="bold" if bold else "normal", zorder=3)


def _arrow(ax, x1, y1, x2, y2, color=GRAY):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle='-|>',
                 mutation_scale=14, linewidth=1.5, color=color, zorder=1))


def fig_architecture():
    """Hình 1: Kiến trúc hệ thống (Frontend + Backend + Modules)."""
    fig, ax = plt.subplots(figsize=(10, 6.5))
    ax.set_xlim(0, 10); ax.set_ylim(0, 6.5)
    ax.axis("off")
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    ax.text(5, 6.2, "KIẾN TRÚC HỆ THỐNG MALWARE ANALYSIS PLATFORM",
            ha="center", fontsize=14, color=TEXT, fontweight="bold")

    # Frontend layer
    _box(ax, 0.4, 4.6, 9.2, 1.1, "FRONTEND WEB\n(index.html + app.js) — GitHub Pages", BLUE, 10)
    ax.text(0.6, 4.9, "Phân tích client-side\n(SHA-256, entropy, IoC, family)", fontsize=8, color=MUTED)

    # Backend layer
    _box(ax, 0.4, 2.9, 9.2, 1.1, "BACKEND API (FastAPI) — api_server.py — Render", GREEN, 10)
    ax.text(0.6, 3.2, "Nhận file upload → phân tích chuyên sâu (MD5/SHA-256, PE, YARA, entropy, IoC)", fontsize=8, color=MUTED)

    # Modules layer
    mods = [
        ("malware_analyzer.py", "PE header · hash · entropy · family", BLUE),
        ("yara_engine.py", "YARA rules detection", RED),
        ("webshell_detector.py", "Regex + data-flow + polyglot", AMBER),
        ("cvss_scoring.py", "CVSS 3.1 + CWE + MITRE", PURPLE),
    ]
    x0 = 0.4
    for i, (name, desc, c) in enumerate(mods):
        x = x0 + i * 2.35
        _box(ax, x, 1.2, 2.2, 1.0, name, c, 8.5)
        ax.text(x + 1.1, 1.35, desc, ha="center", fontsize=6.5, color=MUTED)

    # Arrows
    _arrow(ax, 5, 4.6, 5, 0.0)  # vertical spine (decorative)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "architecture.png"), dpi=150, bbox_inches="tight",
                facecolor=BG)
    plt.close(fig)


def fig_pipeline():
    """Hình 2: Quy trình phân tích 6 bước."""
    fig, ax = plt.subplots(figsize=(7, 10))
    ax.set_xlim(0, 7); ax.set_ylim(0, 10)
    ax.axis("off")
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    ax.text(3.5, 9.6, "QUY TRÌNH PHÂN TÍCH MÃ ĐỘC (6 BƯỚC)",
            ha="center", fontsize=13, color=TEXT, fontweight="bold")

    steps = [
        ("BƯỚC 1", "Nhận diện loại file", "Magic bytes / extension", BLUE),
        ("BƯỚC 2", "Băm mật mã (hash)", "MD5 · SHA-1 · SHA-256 · SHA-512", CYAN),
        ("BƯỚC 3", "Đo Entropy", "Phát hiện packed / encrypted", GREEN),
        ("BƯỚC 4", "Mổ xẻ cấu trúc", "PE header / mã nguồn", AMBER),
        ("BƯỚC 5", "Trích xuất IoC", "IP · URL · domain (C2)", RED),
        ("BƯỚC 6", "Kết luận", "Bản chất + MITRE ATT&CK", PURPLE),
    ]

    y = 9.0
    for title, lbl, desc, c in steps:
        _box(ax, 1.2, y - 0.55, 4.6, 1.0, f"{title}\n{lbl}\n({desc})", c, 9)
        y -= 1.55
    # vertical connectors
    for i in range(5):
        _arrow(ax, 3.5, 8.85 - i * 1.55, 3.5, 8.45 - i * 1.55)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "pipeline.png"), dpi=150, bbox_inches="tight",
                facecolor=BG)
    plt.close(fig)


def fig_pe_structure():
    """Hình 3: Cấu trúc PE Header."""
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.set_xlim(0, 8); ax.set_ylim(0, 6)
    ax.axis("off")
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    ax.text(4, 5.7, "CẤU TRÚC PE (PORTABLE EXECUTABLE)",
            ha="center", fontsize=13, color=TEXT, fontweight="bold")

    layers = [
        ("DOS HEADER (MZ)", "0x00 — Magic \"MZ\"", BLUE),
        ("PE SIGNATURE", "0x3C — e_lfanew", BLUE),
        ("FILE HEADER", "Machine · NumberOfSections · TimeDateStamp", CYAN),
        ("OPTIONAL HEADER", "EntryPoint · ImageBase · Subsystem", CYAN),
        ("SECTION TABLE", ".text · .data · .rsrc (mỗi section có entropy)", GREEN),
        ("IMPORT / EXPORT TABLE", "Các API nhập/xuất — phát hiện hành vi", AMBER),
    ]
    y = 5.3
    for name, desc, c in layers:
        _box(ax, 1.0, y - 0.62, 6.0, 0.75, name, c, 10)
        ax.text(4, y - 0.78, desc, ha="center", fontsize=8, color=MUTED)
        y -= 0.85
        if name != "IMPORT / EXPORT TABLE":
            _arrow(ax, 4, y + 0.13, 4, y + 0.02)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "pe_structure.png"), dpi=150, bbox_inches="tight",
                facecolor=BG)
    plt.close(fig)


def fig_kill_chain():
    """Hình 4: Luồng tấn công kill chain."""
    fig, ax = plt.subplots(figsize=(4.5, 9))
    ax.set_xlim(0, 4.5); ax.set_ylim(0, 9)
    ax.axis("off")
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    ax.text(2.25, 8.7, "KILL CHAIN", ha="center", fontsize=13, color=TEXT, fontweight="bold")

    stages = [
        ("1. Kẻ tấn công", "Gửi lệnh HTTP", GRAY),
        ("2. Server nhận input", "$_POST / $_GET", BLUE),
        ("3. Giải mã payload", "base64 / hex / gzip", AMBER),
        ("4. Thực thi lệnh", "eval / system (RCE)", RED),
        ("5. Chiếm quyền", "Backdoor / C2", PURPLE),
    ]
    y = 8.2
    for name, desc, c in stages:
        _box(ax, 0.7, y - 0.6, 3.1, 0.95, name + "\n(" + desc + ")", c, 9)
        y -= 1.5
    for i in range(4):
        _arrow(ax, 2.25, 8.1 - i * 1.5, 2.25, 7.6 - i * 1.5)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "kill_chain.png"), dpi=150, bbox_inches="tight",
                facecolor=BG)
    plt.close(fig)


def fig_entropy():
    """Hình 5: Thang entropy + bảng kết quả mẫu."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    fig.patch.set_facecolor(BG)

    # Thang entropy
    ax1.set_facecolor(BG)
    ax1.set_title("Thang Entropy Shannon", color=TEXT, fontweight="bold", fontsize=12)
    cats = ["Thấp\n(0–5.5)", "Trung bình\n(5.5–6.8)", "Cao\n(6.8–7.2)", "Rất cao\n(>7.2)"]
    vals = [1, 2, 3, 4]
    colors = [GREEN, CYAN, AMBER, RED]
    ax1.bar(cats, vals, color=colors, alpha=0.85)
    ax1.set_ylabel("Mức độ nghi ngờ", color=MUTED)
    ax1.tick_params(colors=MUTED)
    for spine in ax1.spines.values():
        spine.set_color(GRAY)

    # Kết quả mẫu
    ax2.set_facecolor(BG)
    ax2.set_title("Ví dụ entropy các mẫu", color=TEXT, fontweight="bold", fontsize=12)
    samples = ["shell.php\n(webshell)", "upx_packed.exe\n(packed)"]
    vals2 = [5.3, 7.8]
    colors2 = [GREEN, RED]
    b = ax2.bar(samples, vals2, color=colors2, alpha=0.85)
    ax2.axhline(7.0, color=RED, linestyle="--", linewidth=1, label="Ngưỡng packed (7.0)")
    ax2.set_ylabel("Entropy (bit/ký tự)", color=MUTED)
    ax2.tick_params(colors=MUTED)
    ax2.legend(facecolor=BG, labelcolor=TEXT, edgecolor=GRAY)
    for spine in ax2.spines.values():
        spine.set_color(GRAY)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "entropy.png"), dpi=150, bbox_inches="tight",
                facecolor=BG)
    plt.close(fig)


def fig_tech_stack():
    """Hình 6: Stack công nghệ."""
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_xlim(0, 10); ax.set_ylim(0, 5)
    ax.axis("off")
    fig.patch.set_facecolor(BG); ax.set_facecolor(BG)

    ax.text(5, 4.6, "STACK CÔNG NGHỆ", ha="center", fontsize=13, color=TEXT, fontweight="bold")

    tech = [
        ("Python + FastAPI", "Backend API", GREEN),
        ("pefile", "Phân tích PE header", BLUE),
        ("yara-python", "YARA rules detection", RED),
        ("math / scipy", "Shannon entropy", CYAN),
        ("Regex + python-docx/pptx", "IoC + báo cáo", AMBER),
        ("HTML/CSS/JS", "Frontend dashboard", PURPLE),
    ]
    xs = [0.5, 1.75, 3.0, 4.35, 5.7, 7.15]
    for (name, desc, c), x in zip(tech, xs):
        _box(ax, x, 1.5, 1.15, 2.2, name, c, 8)
        ax.text(x + 0.575, 1.35, desc, ha="center", fontsize=6.5, color=MUTED, va="top",
                wrap=True)

    plt.tight_layout()
    fig.savefig(os.path.join(OUT_DIR, "tech_stack.png"), dpi=150, bbox_inches="tight",
                facecolor=BG)
    plt.close(fig)


if __name__ == "__main__":
    fig_architecture()
    fig_pipeline()
    fig_pe_structure()
    fig_kill_chain()
    fig_entropy()
    fig_tech_stack()
    files = sorted(os.listdir(OUT_DIR))
    print(f"Đã tạo {len(files)} hình ảnh trong {OUT_DIR}:")
    for f in files:
        print("  -", f)