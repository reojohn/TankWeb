# FortressAuth

Minimal hardened PHP login application for Red/Blue Team simulation.

## Features
- Exposes only /login and /dashboard
- Prepared statements (PDO) to prevent SQLi
- Password hashing with password_hash (bcrypt)
- HTTP-only, secure cookies
- Rate-limiting (simple file-based)
- Audit logging (data/audit.log)
- Flag stored outside webroot (data/flag.txt)

## Quick local test
1. Clone repository and `cd FortressAuth`.
2. Create `data/` and `public/templates/` folders as needed.
3. Place your flag in `data/flag.txt`.
4. Import `sql/init.sql` into your local MySQL and create app DB user.
5. Set env vars locally or edit `src/config.php` for dev.
6. Serve the app for local testing:
   ```bash
   cd public
   php -S localhost:8080
   # Visit http://localhost:8080/login.php




---

### `src/config.php`
```php
<?php
// src/config.php
// Load environment variables set on host (Render) or via shell for local dev.

$DB_HOST = getenv('DB_HOST') ?: '127.0.0.1';
$DB_NAME = getenv('DB_NAME') ?: 'fortressauth';
$DB_USER = getenv('DB_USER') ?: 'fortress_user';
$DB_PASS = getenv('DB_PASS') ?: 'changeme';
$FLAG_PATH = getenv('FLAG_PATH') ?: __DIR__ . '/../data/flag.txt';

// Cookie secure setting: in local dev you may set env COOKIE_SECURE=false
$COOKIE_SECURE = (getenv('COOKIE_SECURE') === 'false') ? false : true;

$dsn = "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_EMULATE_PREPARES => false,
];

try {
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, $options);
} catch (Exception $e) {
    // Log the real error server-side
    error_log("DB connection error: " . $e->getMessage());
    // Generic message to the visitor
    http_response_code(500);
    exit('Internal server error');
}
