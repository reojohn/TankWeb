<?php
// ==========================================
// SHELL / COMMAND INJECTION DETECTION
// ==========================================
function detect_shell_attack($input) {
    if (!is_string($input)) return false;
    $input = trim($input);

    $patterns = [
        '/;/',                // ;
        '/&&/',               // &&
        '/\|/',               // |
        '/\$\(/',             // $( )
        '/`.*?`/',            // backticks
        '/rm\s+-rf/i',        // rm -rf
        '/chmod/i',
        '/chown/i',
        '/wget\s+/i',
        '/curl\s+/i',
        '/eval\s*\(/i',
        '/exec\s*\(/i',
        '/system\s*\(/i',
        '/passthru\s*\(/i',
        '/popen\s*\(/i',
    ];

    foreach ($patterns as $p) {
        if (preg_match($p, $input)) return true;
    }

    return false;
}


// ==========================================
// SQL INJECTION DETECTION
// ==========================================
function detect_sqli($input) {
    if (!is_string($input)) return false;
    $i = strtolower($input);

    $patterns = [
        '/\bunion\b/',
        '/\bselect\b/',
        '/\bdrop\b/',
        '/\binsert\b/',
        '/\bdelete\b/',
        '/--/',           // SQL comment
        '/;--/',
        '/sleep\s*\(/',
        '/benchmark\s*\(/',
        '/or\s+1=1/',
        "/' or '/",       // classic login bypass
    ];

    foreach ($patterns as $p) {
        if (preg_match($p, $i)) return true;
    }

    return false;
}


// ==========================================
// XSS DETECTION
// ==========================================
function detect_xss($input) {
    if (!is_string($input)) return false;
    $i = strtolower($input);

    $patterns = [
        '/<script\b/',
        '/<\/script>/',      
        '/onerror\s*=/',     
        '/onload\s*=/',      
        '/javascript:/',
        '/document\.cookie/',
        '/<img\b/',
        '/<iframe\b/',
        '/<svg\b/',
    ];

    foreach ($patterns as $p) {
        if (preg_match($p, $i)) return true;
    }

    return false;
}


// ==========================================
// FILE INCLUSION / PATH TRAVERSAL DETECTION
// ==========================================
function detect_path_traversal($input) {
    if (!is_string($input)) return false;

    $patterns = [
        '/\.\.\//',                // ../
        '/\.\.\\\\/',              // ..\ (Windows)
        '/etc\/passwd/',           // Linux target
        '/windows[\/\\\\]system32/i', // Windows system directory (FIXED)
        '/\.phar$/i',
        '/\.phtml$/i',
    ];

    foreach ($patterns as $p) {
        if (preg_match($p, $input)) return true;
    }

    return false;
}


// ==========================================
// SUSPICIOUS USER-AGENT CHECK
// ==========================================
function detect_suspicious_ua($ua) {
    if (!is_string($ua)) return false;

    $suspicious = [
        'sqlmap',
        'acunetix',
        'nikto',
        'nmap',
        'curl',
        'wget',
        'fuzzer',
        'dirbuster',
        'scanner',
    ];

    $ua = strtolower($ua);
    foreach ($suspicious as $s) {
        if (strpos($ua, $s) !== false) return true;
    }

    return false;
}


// ==========================================
// CENTRAL SECURITY CHECKER
// ==========================================
function security_check_inputs($inputs, $userAgent = null) {
    $userAgent = $userAgent ?? ($_SERVER['HTTP_USER_AGENT'] ?? '');

    $issues = [];

    foreach ($inputs as $key => $value) {

        if (detect_shell_attack($value))         $issues[] = "shell:$key";
        if (detect_sqli($value))                 $issues[] = "sqli:$key";
        if (detect_xss($value))                  $issues[] = "xss:$key";
        if (detect_path_traversal($value))       $issues[] = "path:$key";
    }

    // Suspicious user-agent check
    if (detect_suspicious_ua($userAgent)) {
        $issues[] = "suspicious_ua";
    }

    return $issues; // empty = clean and safe
}
?>
