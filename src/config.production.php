<?php

// -----------------------------
// Production Error Handling
// -----------------------------
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/errors.log');

// -----------------------------
// Secure Database Connection
// -----------------------------
$pdo = new PDO(
    "pgsql:host=localhost;dbname=fortress_auth",
    "postgres",
    "YOUR_DB_PASSWORD_HERE",
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);
