<?php
// Form lien he binh thuong
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = htmlspecialchars($_POST['name']);
    $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
    $message = htmlspecialchars($_POST['message']);

    if ($email) {
        // Gui email
        $to = "admin@example.com";
        $subject = "Lien he tu $name";
        mail($to, $subject, $message);
        echo "Cam on ban da lien he!";
    }
}
?>
