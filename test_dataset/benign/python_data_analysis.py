import statistics
from collections import Counter

def phan_tich_du_lieu(diem_thi):
    diem = [d for d in diem_thi if 0 <= d <= 10]
    if not diem:
        return {}

    return {
        "trung_binh": statistics.mean(diem),
        "trung_vi": statistics.median(diem),
        "lon_nhat": max(diem),
        "nho_nhat": min(diem),
        "do_lech_chuan": statistics.stdev(diem) if len(diem) > 1 else 0,
        "phan_bo": dict(Counter(diem)),
    }

ket_qua = phan_tich_du_lieu([8.5, 7.0, 9.2, 6.5, 8.0])
print(ket_qua)
