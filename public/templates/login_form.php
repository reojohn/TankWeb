<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>FortressAuth — Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />

  <!-- External CSS (CSP safe) -->
  <link rel="stylesheet" href="/css/login.css">
</head>

<body>
  <div class="card" role="main">

    <div class="logo-container">
      <img src="/images/wolf.png" alt="Wolf Logo">
    </div>

    <h2></h2>






    <?php if (!empty($error)): ?>
     <div class="error-message <?php echo e($error_class ?? ''); ?>">
    <?php echo e($error); ?>
</div>


    <?php endif; ?>

    <form method="post" action="/login.php" autocomplete="off" novalidate>
      <input type="hidden" name="csrf_token" value="<?php echo e(generate_csrf_token()); ?>">

      <label for="username">Username</label>
      <input id="username" name="username" type="text" required maxlength="100" placeholder="Enter username" />

      <label for="password">Password</label>
      <input id="password" name="password" type="password" required maxlength="128" placeholder="Enter password" />

      <button type="submit">Login</button>
    </form>
  </div>


  <script>
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
