#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tạo PDF: Điểm yếu của hệ thống + lời nói với thầy (phản biện)."""

import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, HRFlowable,
                                Table, TableStyle, PageBreak)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

# Font DejaVu (hỗ trợ tiếng Việt đầy đủ) — dùng matplotlib.get_data_path() để lấy đúng đường dẫn
import matplotlib
FONT_PATH = os.path.join(matplotlib.get_data_path(), "fonts", "ttf")
pdfmetrics.registerFont(TTFont("DejaVu", os.path.join(FONT_PATH, "DejaVuSans.ttf")))
pdfmetrics.registerFont(TTFont("DejaVu-Bold", os.path.join(FONT_PATH, "DejaVuSans-Bold.ttf")))
pdfmetrics.registerFont(TTFont("DejaVu-Oblique", os.path.join(FONT_PATH, "DejaVuSans-Oblique.ttf")))

OUT = "/home/ngolong/DoAn/SIIScan-main/DIEM_YEU_VA_LOI_NOI.pdf"

# Màu
NAVY = HexColor("#1E3A8A")
BLUE = HexColor("#3B82F6")
RED = HexColor("#DC2626")
GREEN = HexColor("#059669")
GRAY = HexColor("#6B7280")
DARK = HexColor("#1F2937")

# Styles
title_st = ParagraphStyle("title", fontName="DejaVu-Bold", fontSize=20, leading=26,
                          textColor=NAVY, alignment=TA_CENTER, spaceAfter=6)
subtitle_st = ParagraphStyle("sub", fontName="DejaVu", fontSize=12, leading=16,
                             textColor=GRAY, alignment=TA_CENTER, spaceAfter=20)
h1_st = ParagraphStyle("h1", fontName="DejaVu-Bold", fontSize=15, leading=20,
                       textColor=NAVY, spaceBefore=18, spaceAfter=8)
weak_st = ParagraphStyle("weak", fontName="DejaVu-Bold", fontSize=12.5, leading=18,
                         textColor=RED, spaceBefore=14, spaceAfter=4)
lbl_st = ParagraphStyle("lbl", fontName="DejaVu-Bold", fontSize=11.5, leading=16,
                        textColor=DARK, spaceBefore=6, spaceAfter=2)
body_st = ParagraphStyle("body", fontName="DejaVu", fontSize=11, leading=17,
                         textColor=DARK, alignment=TA_JUSTIFY, spaceAfter=6)
quote_st = ParagraphStyle("quote", fontName="DejaVu-Oblique", fontSize=11, leading=17,
                          textColor=HexColor("#065F46"), leftIndent=16,
                          borderPadding=8, spaceAfter=8)
note_st = ParagraphStyle("note", fontName="DejaVu", fontSize=10.5, leading=15,
                         textColor=GRAY, spaceBefore=4, spaceAfter=4)

story = []

# ===== TIÊU ĐỀ =====
story.append(Paragraph("ĐIỂM YẾU CỦA HỆ THỐNG", title_st))
story.append(Paragraph("&amp; LỜI NÓI VỚI THẦY KHI PHẢN BIỆN", subtitle_st))
story.append(HRFlowable(width="100%", thickness=1.2, color=BLUE, spaceAfter=16))

story.append(Paragraph(
    "Tài liệu này liệt kê những hạn chế THẬT SỰ của hệ thống Malware Analysis Platform, "
    "kèm theo cách lựa lời để trả lời thầy một cách trung thực, khiêm tốn nhưng thể hiện được "
    "sự hiểu sâu. Nguyên tắc: <b>thành thật nhận khuyết điểm + biết đúng hướng khắc phục</b> "
    "là cách ghi điểm cao nhất khi bảo vệ.", body_st))
story.append(Spacer(1, 6))

# ===== BẢNG TỔNG QUAN =====
story.append(Paragraph("Bảng tổng quan 7 điểm yếu", h1_st))
tbl_data = [
    ["#", "Điểm yếu", "Mức độ", "Hướng khắc phục"],
    ["1", "Chỉ phân tích tĩnh (không động)", "Rất lớn", "Sandbox (Cuckoo/CAPE)"],
    ["2", "Dựa chữ ký → dễ bị obfuscation vượt", "Rất lớn", "Phân tích động + ML"],
    ["3", "Không bắt được mã độc mới (zero-day)", "Lớn", "Học máy"],
    ["4", "Không tự unpack mã đóng gói", "Trung bình", "Unpacker (UPX)"],
    ["5", "YARA không chạy trên host free", "Trung bình", "Deploy Docker/trả phí"],
    ["6", "Chỉ luật cứng, không học máy", "Lớn", "Tích hợp ML"],
    ["7", "Báo nhầm (false positive)", "Thường gặp", "Tinh chỉnh rule + whitelist"],
]
tbl = Table(tbl_data, colWidths=[1.0*cm, 6.2*cm, 2.6*cm, 4.6*cm])
tbl.setStyle(TableStyle([
    ("FONTNAME", (0,0), (-1,0), "DejaVu-Bold"),
    ("FONTNAME", (0,1), (-1,-1), "DejaVu"),
    ("FONTSIZE", (0,0), (-1,-1), 9.5),
    ("BACKGROUND", (0,0), (-1,0), NAVY),
    ("TEXTCOLOR", (0,0), (-1,0), HexColor("#FFFFFF")),
    ("GRID", (0,0), (-1,-1), 0.5, HexColor("#CBD5E1")),
    ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ("ROWBACKGROUNDS", (0,1), (-1,-1), [HexColor("#FFFFFF"), HexColor("#F1F5F9")]),
    ("TOPPADDING", (0,0), (-1,-1), 6),
    ("BOTTOMPADDING", (0,0), (-1,-1), 6),
]))
story.append(tbl)
story.append(Spacer(1, 12))

# ===== CÁC ĐIỂM YẾU CHI TIẾT =====
weaknesses = [
    ("ĐIỂM YẾU 1: Chỉ phân tích TĨNH, không có phân tích ĐỘNG",
     "Hệ thống chỉ &quot;đọc&quot; file, không chạy thử. Mã độc hiện đại thường tự biến đổi khi chạy "
     "(polymorphic / metamorphic) — lúc đứng yên vô hại, lúc chạy mới lộ mặt. Nên có mã độc nằm im cũng không tra ra.",
     "Dạ đúng, đây là hạn chế lớn nhất của em. Em mới làm được phân tích tĩnh. Những mã độc tự thay đổi khi chạy "
     "thì em bắt không được, vì em không cho nó chạy. Để khắc phục, hướng đi là gắn sandbox (Cuckoo/CAPE) — "
     "nhưng do thời gian có hạn nên em chưa làm được phần đó."),
    ("ĐIỂM YẾU 2: Dựa vào CHỮ KÝ → dễ bị vượt bằng obfuscation",
     "Chỉ cần xé chuỗi (&quot;sys&quot;.&quot;tem&quot;), mã hóa (base64_decode), hay làm rối mã → chữ ký không khớp → lọt lưới. "
     "Nhưng ý nghĩa độc hại vẫn y nguyên. Đây chính là điều thầy đã chỉ ra.",
     "Thầy nói rất đúng. Em dùng cơ chế chữ ký (regex + YARA), nên bản chất có thể bị qua mặt bằng obfuscation — "
     "em đã tự thử và thấy nó lọt thật. Đây là giới hạn cố hữu của mọi hệ thống dựa chữ ký. Hướng khắc phục của ngành "
     "là phân tích động (xem hành vi thật) hoặc học máy (học đặc trưng, không so chữ ký)."),
    ("ĐIỂM YẾU 3: Chỉ nhận diện MẪU ĐÃ BIẾT, không phát hiện mã độc MỚI (zero-day)",
     "YARA rules và regex do người viết &quot;đoán trước&quot; mã độc trông thế nào. Nên chỉ bắt được những gì ta đã biết. "
     "Mã độc hoàn toàn mới (chưa ai gặp) thì hệ thống không nhận ra.",
     "Dạ, hệ thống em theo trường phái nhận diện chữ ký, nên chỉ bắt được mã độc đã biết khuôn mẫu. "
     "Mã độc hoàn toàn mới thì em không phát hiện vì chưa có rule nào khớp. Muốn bắt cả mã mới phải dùng học máy "
     "hoặc phân tích hành vi — em ghi trong phần hướng phát triển."),
    ("ĐIỂM YẾU 4: Không tự UNPACK mã đã đóng gói",
     "Với file bị pack, hệ thống chỉ phát hiện &quot;entropy cao = nghi packer&quot; rồi dừng lại, không mở gói ra phân tích. "
     "Phần &quot;ruột&quot; mã độc vẫn mù mịt.",
     "Em mới dừng ở việc NHẬN RA file bị pack (qua entropy), chứ chưa unpack được. File upx_packed mà em demo, "
     "em chỉ kết luận &#39;nghi packed&#39; chứ chưa xem được bên trong. Hướng phát triển là tích hợp unpacker (UPX unpack) "
     "để lột lớp vỏ rồi phân tích tiếp."),
    ("ĐIỂM YẾU 5: YARA không chạy được trên host free",
     "Ở máy local YARA chạy ngon. Nhưng deploy lên Render (miễn phí) thì yara-python KHÔNG cài được (thiếu libyara C), "
     "nên backend trên web thực tế thiếu mất lớp YARA.",
     "Có một hạn chế về triển khai: trên môi trường web em deploy (Render free) không cài được yara-python vì cần "
     "trình biên dịch C. Nên bản web thật chỉ có pefile + hash + entropy + IoC, còn YARA chỉ chạy ở máy local. "
     "Em có ghi rõ phần này trong báo cáo."),
    ("ĐIỂM YẾU 6: Không có học máy, chỉ là luật cứng (rule-based)",
     "Toàn bộ logic là if-else + regex cố định, không có AI học từ dữ liệu. Độ thông minh = độ &quot;đoán trước&quot; của người viết rule.",
     "Em làm theo hướng luật (rule-based), không dùng học máy. Ưu điểm là dễ giải thích từng bước rõ ràng, minh bạch; "
     "nhược điểm là không tự thích nghi với biến thể mới. Nếu có thời gian, bước tiếp theo là gắn mô hình ML để tăng độ phủ."),
    ("ĐIỂM YẾU 7: Báo nhầm (false positive)",
     "Regex quá &quot;rộng&quot; có thể bắt nhầm file lành (chỉ tình cờ chứa chữ eval/password). Ví dụ file JS chứa "
     "getElementById(&#39;password&#39;) bị báo nhầm là rò rỉ mật khẩu.",
     "Dạ đúng, em có xảy ra báo nhầm khi regex không đủ chặt. Em đã hạn chế bằng cách kết hợp data-flow "
     "(chỉ báo khi dữ liệu người dùng thật sự đổ vào hàm nguy hiểm) và whitelist các chuỗi vô hại. "
     "Đánh đổi của việc &quot;bắt mạnh&quot; là dễ báo nhầm, nên em phải cân chỉnh ngưỡng liên tục."),
]

story.append(Paragraph("Chi tiết từng điểm yếu &amp; lời nói", h1_st))
for title, problem, answer in weaknesses:
    story.append(Paragraph(title, weak_st))
    story.append(Paragraph("Vấn đề:", lbl_st))
    story.append(Paragraph(problem, body_st))
    story.append(Paragraph("Trả lời thầy (lựa lời):", lbl_st))
    story.append(Paragraph(answer, quote_st))
    story.append(Spacer(1, 2))

# ===== GHI CHÚ CHIẾN LƯỢC =====
story.append(PageBreak())
story.append(Paragraph("CHIẾN LƯỢC TRẢ LỜI TỔNG QUÁT", h1_st))
story.append(Paragraph(
    "Khi thầy hỏi về điểm yếu, đừng tỏ ra bối rối hay tìm cách chối. Nguyên tắc 3 bước:", body_st))
story.append(Paragraph("1. Thừa nhận thẳng thắn: &quot;Dạ đúng, đây là hạn chế...&quot;", quote_st))
story.append(Paragraph("2. Giải thích đúng nguyên nhân kỹ thuật (cho thấy mình hiểu sâu).", quote_st))
story.append(Paragraph("3. Nêu hướng khắc phục chuẩn ngành (sandbox, unpack, ML).", quote_st))
story.append(Spacer(1, 8))
story.append(Paragraph(
    "Điểm mấu chốt: thầy KHÔNG trừ điểm vì hệ thống có khuyết điểm (đồ án sinh viên ai cũng có), "
    "mà trừ điểm khi sinh viên <b>không biết khuyết điểm của chính mình</b>. Biết và nói rõ được giới hạn "
    "chính là dấu hiệu của người hiểu đề tài sâu.", body_st))

story.append(Spacer(1, 14))
story.append(HRFlowable(width="100%", thickness=0.8, color=GRAY, spaceBefore=10))
story.append(Paragraph(
    "Ghi chú: Tài liệu này dùng để ôn tập trước buổi bảo vệ. Khi trả lời, hãy nói bằng giọng tự nhiên, "
    "không đọc thuộc lòng — điều quan trọng là nắm ý, không phải thuộc chữ.", note_st))

doc = SimpleDocTemplate(OUT, pagesize=A4,
                        leftMargin=2*cm, rightMargin=2*cm,
                        topMargin=1.8*cm, bottomMargin=1.8*cm,
                        title="Điểm yếu & lời nói với thầy")
doc.build(story)
print("Đã tạo PDF:", OUT)