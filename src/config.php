<?php
// src/config.php
// ---------------------------------
// Production Error Handling
// ---------------------------------
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);



ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../logs/errors.log');

// ---------------------------------
// Database Configuration
// ---------------------------------    
$DB_HOST = getenv('DB_HOST') ?: 'dpg-d4hcbjshg0os738besfg-a.oregon-postgres.render.com';
$DB_PORT = getenv('DB_PORT') ?: 5432;
$DB_NAME = getenv('DB_NAME') ?: 'fortressauth';
$DB_USER = getenv('DB_USER') ?: 'fortress_user';
$DB_PASS = getenv('DB_PASS') ?: 'MtIsdz6tXBo9LWqLp7zY51aqfv4UYYv7';


$dsn = "pgsql:host=$DB_HOST;port=$DB_PORT;dbname=$DB_NAME;sslmode=require";

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