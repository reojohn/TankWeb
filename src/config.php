<?php
// src/config.php

// ---------------------------------
// Production Error Handling
// ---------------------------------
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
error_reporting(0);

ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/errors.log');

// ---------------------------------
// Database Configuration
// ---------------------------------
$DB_HOST = getenv('DB_HOST') ?: 'localhost';
$DB_NAME = getenv('DB_NAME') ?: 'fortressauth';
$DB_USER = getenv('DB_USER') ?: 'fortress_user';
$DB_PASS = getenv('DB_PASS') ?: 'F0rtress@2025Secure!';
$DB_PORT = getenv('DB_PORT') ?: 5432;

$dsn = "pgsql:host=$DB_HOST;port=$DB_PORT;dbname=$DB_NAME";

try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
} catch (Exception $e) {
    error_log("DB connection error: " . $e->getMessage());
    http_response_code(500);
    exit('Internal server error');
}
?>
