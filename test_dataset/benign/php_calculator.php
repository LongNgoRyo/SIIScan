<?php
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
