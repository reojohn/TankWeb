<?php

declare(strict_types=1);

require __DIR__ . '/../src/middleware.php';
require_once __DIR__ . '/../src/config.php';
require_once __DIR__ . '/../src/bruteforce.php';
require __DIR__ . '/../src/honeypot.php'; // Handles decoy logging + temporary ban.
?>
<!doctype html>
<html lang="en">
<head>
    <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
    <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">
  <meta charset="utf-8">
  <title>FortressAuth — Admin Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#10071f">
  <link rel="stylesheet" href="/css/login.css">
</head>

<body class="auth-page auth-login honeypot-login-page">
  <main class="auth-shell" role="main">
    <section class="brand-panel" aria-label="FortressAuth security overview">
      <div class="brand-glow" aria-hidden="true"></div>
      <div class="login-scan-grid" aria-hidden="true"></div>

      <!--
        This verification presentation is visual only.
        The form still posts to /admin.php, where src/honeypot.php handles
        the decoy attempt. It never invokes the real authentication flow.
      -->
      <div class="login-verification-stage" aria-live="polite" aria-atomic="true">
        <div class="login-orbit" aria-hidden="true">
          <span class="orbit-ring orbit-ring-one"></span>
          <span class="orbit-ring orbit-ring-two"></span>
          <span class="orbit-ring orbit-ring-three"></span>
          <span class="orbit-pulse orbit-pulse-one"></span>
          <span class="orbit-pulse orbit-pulse-two"></span>

          <div class="login-identity-frame" aria-hidden="true">
            <span class="identity-corner corner-tl"></span>
            <span class="identity-corner corner-tr"></span>
            <span class="identity-corner corner-bl"></span>
            <span class="identity-corner corner-br"></span>
          </div>

          <span class="login-scan-beam" aria-hidden="true"></span>

          <div class="login-orbit-core" aria-hidden="true">
            <div class="login-person-grid"></div>
            <svg class="login-person-icon" viewBox="0 0 120 120" fill="none">
              <circle cx="60" cy="38" r="20"/>
              <path d="M24 104c2.8-24.5 16.8-38 36-38s33.2 13.5 36 38"/>
              <path d="M42 68c4.8 6.4 10.8 9.7 18 9.7S73.2 74.4 78 68"/>
            </svg>
          </div>
        </div>

        <div class="login-verification-copy">
          <span class="login-verification-badge"><i></i> ACCESS VERIFICATION</span>

          <div class="login-scan-readout">
            <span>CREDENTIAL VERIFICATION</span>
            <strong id="honeypot-scan-percent">0%</strong>
          </div>

          <h2 id="honeypot-stage-title">Preparing secure sign in...</h2>
          <p id="honeypot-stage-message">Initializing the FortressAuth access workflow.</p>

          <div class="login-stage-progress" aria-hidden="true">
            <span id="honeypot-stage-progress-bar"></span>
          </div>

          <div class="login-stage-steps" aria-label="Login verification progress">
            <div class="login-stage-step" data-honeypot-step="1"><i></i><span>Initialize</span></div>
            <div class="login-stage-step" data-honeypot-step="2"><i></i><span>Credentials</span></div>
            <div class="login-stage-step" data-honeypot-step="3"><i></i><span>Defenses</span></div>
            <div class="login-stage-step" data-honeypot-step="4"><i></i><span>Verify</span></div>
          </div>

          <div class="login-stage-role">
            <span>Protected administrator access</span>
            <strong>FortressAuth verification</strong>
          </div>
        </div>
      </div>

      <div class="brand-header">
        <div class="brand-mark">
          <img src="/images/wolf.png" alt="FortressAuth">
        </div>

        <div class="brand-copy">
          <span class="eyebrow">SECURE ACCESS GATEWAY</span>
          <h1>FortressAuth</h1>
          <p>Protected administrator access with layered authentication and continuous security monitoring.</p>
        </div>
      </div>

      <div class="security-stack" aria-label="Security controls">
        <div class="security-item">
          <span class="security-icon icon-shield" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" preserveAspectRatio="xMidYMid meet">
              <path d="M12 2.8 19.2 6v5.2c0 4.35-2.7 7.65-7.2 9.8-4.5-2.15-7.2-5.45-7.2-9.8V6L12 2.8Z"/>
              <path d="m8.7 12.1 2.15 2.15 4.55-4.7"/>
            </svg>
          </span>
          <div>
            <strong>Layered authentication</strong>
            <span>Protected administrator identity verification</span>
          </div>
        </div>

        <div class="security-item">
          <span class="security-icon icon-radar" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" preserveAspectRatio="xMidYMid meet">
              <circle cx="12" cy="12" r="8.25"/>
              <path d="M12 3.75v16.5M3.75 12h16.5"/>
              <circle cx="12" cy="12" r="2.3"/>
            </svg>
          </span>
          <div>
            <strong>Threat-aware login</strong>
            <span>Security monitoring and suspicious-activity detection</span>
          </div>
        </div>

        <div class="security-item">
          <span class="security-icon icon-lock" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" preserveAspectRatio="xMidYMid meet">
              <rect x="5.25" y="10.25" width="13.5" height="9.25" rx="2.3"/>
              <path d="M8.25 10.25V7.6a3.75 3.75 0 0 1 7.5 0v2.65"/>
              <path d="M12 14.15v2.3"/>
            </svg>
          </span>
          <div>
            <strong>Protected session</strong>
            <span>Secure session controls before privileged access is granted</span>
          </div>
        </div>
      </div>

      <div class="brand-footer">
        <span class="live-dot" aria-hidden="true"></span>
        Security monitoring active
      </div>
    </section>

    <section class="auth-panel">
      <div class="auth-panel-inner">
        <div class="mobile-brand">
          <img src="/images/wolf.png" alt="FortressAuth">
          <span>FORTRESS AUTH</span>
        </div>

        <div class="auth-heading">
          <span class="step-pill">ADMINISTRATOR SIGN-IN</span>
          <h2>Welcome back</h2>
          <p>Enter your administrator credentials to continue to the protected management area.</p>
        </div>

        <?php if (!empty($_GET['error'])): ?>
          <div class="error-message" role="alert">
            <span class="alert-icon" aria-hidden="true">!</span>
            <span>Invalid username or password</span>
          </div>
        <?php endif; ?>

        <form
          class="auth-form"
          id="honeypot-login-form"
          method="post"
          action="/admin.php"
          autocomplete="off"
          novalidate
        >
          <!--
            Deliberately separate field names from the real authentication
            endpoint. src/honeypot.php reacts to the POST before this page is
            rendered again and does not authenticate these values.
          -->
          <div class="field-group">
            <label for="admin_user">Username</label>
            <div class="input-shell">
              <span class="input-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <circle cx="12" cy="8" r="3.6"/>
                  <path d="M5.2 20c.6-4.1 3-6.2 6.8-6.2s6.2 2.1 6.8 6.2"/>
                </svg>
              </span>
              <input
                id="admin_user"
                name="admin_user"
                type="text"
                required
                maxlength="100"
                placeholder="Enter username"
                autocomplete="off"
              >
            </div>
          </div>

          <div class="field-group">
            <div class="field-label-row">
              <label for="admin_pass">Password</label>
              <span class="field-note">Protected entry</span>
            </div>

            <div class="input-shell">
              <span class="input-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <rect x="5" y="10" width="14" height="10" rx="2.5"/>
                  <path d="M8.5 10V7.2a3.5 3.5 0 0 1 7 0V10"/>
                  <path d="M12 14v2"/>
                </svg>
              </span>

              <input
                id="admin_pass"
                name="admin_pass"
                type="password"
                required
                maxlength="128"
                placeholder="Enter password"
                autocomplete="off"
              >

              <button
                class="password-toggle"
                type="button"
                id="honeypot-password-toggle"
                aria-label="Show password"
                aria-pressed="false"
              >
                <svg class="eye-open" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M2.5 12s3.4-5 9.5-5 9.5 5 9.5 5-3.4 5-9.5 5-9.5-5-9.5-5z"/>
                  <circle cx="12" cy="12" r="2.6"/>
                </svg>
                <svg class="eye-closed" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M3 3l18 18"/>
                  <path d="M10.6 7.1C11 7 11.5 7 12 7c6.1 0 9.5 5 9.5 5a15.8 15.8 0 01-3.1 3.3"/>
                  <path d="M6.1 6.1C3.8 7.7 2.5 12 2.5 12s3.4 5 9.5 5c1.3 0 2.5-.2 3.5-.6"/>
                </svg>
              </button>
            </div>
          </div>

          <button class="primary-action" id="honeypot-submit" type="submit">
            <span>Continue securely</span>
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M5 12h13"/>
              <path d="M14 7l5 5-5 5"/>
            </svg>
          </button>
        </form>

        <div class="trust-row" aria-label="Login protections">
          <span><i class="trust-dot"></i> Protected entry</span>
          <span><i class="trust-dot"></i> Audit monitored</span>
          <span><i class="trust-dot"></i> Rate limited</span>
        </div>

        <p class="auth-footnote">
          Authorized access only. Suspicious activity may be recorded and blocked.
        </p>
      </div>
    </section>
  </main>

  <script src="/js/auth_motion.js"></script>
  <script src="/js/honeypot_login_ui.js"></script>
</body>
</html>
