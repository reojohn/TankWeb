<?php
// src/csrf.php

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

if (!function_exists('generate_csrf_token')) {
    function generate_csrf_token() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('verify_csrf_token')) {
    function verify_csrf_token($token) {
        if (empty($_SESSION['csrf_token'])) {
            return false;
        }

        $valid = hash_equals($_SESSION['csrf_token'], $token);

        if ($valid) {
            unset($_SESSION['csrf_token']);
        }

        return $valid;
    }
}
