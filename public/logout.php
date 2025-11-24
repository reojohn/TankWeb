<?php
require __DIR__ . '/../src/middleware.php';


session_start();
session_unset();
session_destroy();

// Redirect to login page
header("Location: login.php");
exit;
?>
