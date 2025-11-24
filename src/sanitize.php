<?php
// src/sanitize.php
// Escape HTML output
if (!function_exists('e')) {
    function e($str) {
        return htmlspecialchars($str, ENT_QUOTES, 'UTF-8');
    }
}

// Strict username validation — ONLY letters/numbers/underscore, 3–32 chars
function sanitize_username($u) {
    $u = trim($u);
    if (preg_match('/^[A-Za-z0-9_]{3,32}$/', $u)) {
        return $u;
    }
    return false;
}

// Strict password check — only validates type and length
function sanitize_password($p) {
    if (!is_string($p)) return false;
    if (strlen($p) < 1 || strlen($p) > 128) return false;
    return $p;
}

// Sanitize any GET/POST string
function sanitize_text($str, $max = 255) {
    return substr(trim(filter_var($str, FILTER_SANITIZE_STRING)), 0, $max);
}

// Sanitize numeric IDs
function sanitize_id($id) {
    return filter_var($id, FILTER_VALIDATE_INT);
}