# Cac ham tien ich an toan
def tinh_trung_binh(danh_sach):
    if not danh_sach:
        return 0
    return sum(danh_sach) / len(danh_sach)


def doc_file(duong_dan):
    with open(duong_dan, 'r', encoding='utf-8') as f:
        return f.read()


# Xu ly du lieu nguoi dung an toan
def chuan_hoa_ten(ten):
    return ten.strip().title()
