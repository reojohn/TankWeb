<?php

declare(strict_types=1);

// Personal ID management now lives inside the unified Current Operator page.
// Keep this legacy route as a safe redirect so old bookmarks still work.
$query = isset($_GET['reverified']) ? '?reverified=1' : '';
header('Location: /user_management.php' . $query . '#personal-id');
exit;
