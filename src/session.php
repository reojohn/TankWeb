
<?php
if (session_status() === PHP_SESSION_NONE) {

    // Set secure session options
    session_start([
        'cookie_lifetime' => 0,                // Session cookie lasts until browser closes
        'cookie_httponly' => true,             // JS cannot access session cookie
        'cookie_secure' => isset($_SERVER['HTTPS']), // Cookie only sent over HTTPS
        'cookie_samesite' => 'Strict',         // Prevent CSRF via cross-site requests
        'use_strict_mode' => true,             // Reject uninitialized session IDs
        'use_only_cookies' => true,            // Prevent session ID in URL
        'sid_length' => 48,                     // Longer session IDs
        'sid_bits_per_character' => 6
    ]);

}
?>
