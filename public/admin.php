<?php
require __DIR__ . '/../src/middleware.php';
require __DIR__ . '/../src/honeypot.php'; // Handles ban + logging
?>

<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>FortressAuth — Admin Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />

  <!-- Same CSS as real login -->
  <link rel="stylesheet" href="/css/login.css">
</head>

<body>
  <div class="card" role="main">

    <div class="logo-container">
      <img src="/images/wolf.png" alt="Wolf Logo">
    </div>

    <h2>Admin Login</h2>

    <!-- Fake error message (optional, attackers love this) -->
    <?php if (!empty($_GET['error'])): ?>
      <div class="error-message">Invalid admin credentials</div>
    <?php endif; ?>

    <form method="post" action="" autocomplete="off" novalidate>
      <!-- Fake form fields -->
      <label for="admin_user">Admin Username</label>
      <input id="admin_user" name="admin_user" type="text" required maxlength="100" placeholder="Enter admin username" />

      <label for="admin_pass">Admin Password</label>
      <input id="admin_pass" name="admin_pass" type="password" required maxlength="128" placeholder="Enter admin password" />

      <button type="submit">Login</button>
    </form>
  </div>

  <script>
  // Floating particles (copied exactly)
  for (let i = 0; i < 40; i++) {
    let p = document.createElement("div");
    p.classList.add("particle");
    p.style.left = Math.random() * 100 + "vw";
    p.style.bottom = Math.random() * -40 + "vh";
    p.style.animationDelay = Math.random() * 10 + "s";
    p.style.opacity = Math.random() * 0.5 + 0.2;
    document.body.appendChild(p);
  }
</script>

</body>
</html>
