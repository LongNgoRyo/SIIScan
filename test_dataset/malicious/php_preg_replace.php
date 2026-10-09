<?php
// preg_replace với modifier /e thực thi mã
$s = 'system("id")';
@preg_replace('/.*/e', $s, '');
?>
