<!doctype html>
<html lang="en">
<head>
  <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813">
  <link rel="shortcut icon" type="image/png" href="/images/wolf1.png?v=20260813">

  <meta charset="utf-8">
  <title>FortressAuth — Secure Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#10071f">

  <link rel="stylesheet" href="/css/login.css">

  <style>
    /* =========================================================
       EXISTING SECURITY ICON ALIGNMENT FIX
       ========================================================= */

    .auth-login .security-item {
      display: flex !important;
      align-items: center !important;
    }

    .auth-login .security-icon {
      flex: 0 0 auto !important;
      display: grid !important;
      place-items: center !important;
      align-self: center !important;
      padding: 0 !important;
      line-height: 0 !important;
      overflow: hidden !important;
    }

    .auth-login .security-icon svg {
      display: block !important;
      width: 25px !important;
      height: 25px !important;
      margin: 0 !important;
      padding: 0 !important;
      position: static !important;
      inset: auto !important;
      transform: none !important;
      transform-origin: center !important;
      vertical-align: middle !important;
    }


    /* =========================================================
       FORTRESS LOGIN ART
       Does NOT change auth-shell dimensions or grid sizing.
       ========================================================= */

    .auth-login .brand-panel {
      position: relative;
      overflow: hidden;
    }

    .auth-login .fortress-login-art {
      position: absolute;
      z-index: 0;

      inset: 0;

      width: 100%;
      height: 100%;

      object-fit: cover;

      /*
       * Slightly favors the upper-middle portion so the castle,
       * moon and threat icons remain visible.
       */
      object-position: 50% 42%;

      pointer-events: none;
      user-select: none;

      filter:
        brightness(0.70)
        contrast(1.08)
        saturate(0.92);

      transform: scale(1.01);
    }


    /* Purple night overlay */
    .auth-login .fortress-login-overlay {
      position: absolute;
      z-index: 1;

      inset: 0;

      pointer-events: none;

      background:
        linear-gradient(
          180deg,
          rgba(10, 4, 25, 0.05) 0%,
          rgba(14, 5, 33, 0.12) 25%,
          rgba(17, 6, 39, 0.30) 58%,
          rgba(9, 3, 22, 0.72) 100%
        ),
        linear-gradient(
          90deg,
          rgba(45, 12, 86, 0.18) 0%,
          rgba(20, 7, 42, 0.05) 50%,
          rgba(13, 4, 29, 0.30) 100%
        );
    }


    /*
     * Existing diagonal overlay from login.css.
     * Keep it above the art but below actual UI content.
     */
    .auth-login .brand-panel::after {
      z-index: 1;
    }


    /* Existing decorative glow */
    .auth-login .brand-glow {
      z-index: 2;
      opacity: 0.18;
    }


    /* Existing scan grid */
    .auth-login .login-scan-grid {
      z-index: 2;
    }


    /*
     * Main left-side UI remains above artwork.
     */
    .auth-login .brand-header,
    .auth-login .security-stack,
    .auth-login .brand-footer {
      position: relative;
      z-index: 3;
    }


    /*
     * Verification animation needs to stay above everything
     * when login is submitted.
     */
    .auth-login .login-verification-stage {
      z-index: 6;
    }


    /* =========================================================
       HEADER READABILITY
       ========================================================= */

    .auth-login .brand-header {
      text-shadow:
        0 2px 10px rgba(0, 0, 0, 0.88),
        0 0 22px rgba(0, 0, 0, 0.45);
    }

    .auth-login .brand-copy h1 {
      text-shadow:
        0 3px 12px rgba(0, 0, 0, 0.95),
        0 0 24px rgba(171, 91, 255, 0.20);
    }

    .auth-login .brand-copy p {
      color: rgba(242, 232, 255, 0.92);
      text-shadow:
        0 2px 8px rgba(0, 0, 0, 0.95);
    }

    .auth-login .eyebrow {
      text-shadow:
        0 2px 8px rgba(0, 0, 0, 0.95),
        0 0 12px rgba(188, 108, 255, 0.18);
    }


    /* =========================================================
       LOGO HOLDER
       ========================================================= */

    .auth-login .brand-mark {
      background:
        linear-gradient(
          145deg,
          rgba(17, 6, 35, 0.70),
          rgba(11, 4, 23, 0.52)
        );

      border-color: rgba(210, 161, 255, 0.20);

      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);

      box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.06),
        0 15px 35px rgba(0, 0, 0, 0.30);
    }


    /* =========================================================
       SECURITY CARDS
       ========================================================= */

    .auth-login .security-item {
      background:
        linear-gradient(
          135deg,
          rgba(28, 11, 51, 0.82),
          rgba(14, 5, 29, 0.76)
        ) !important;

      border-color: rgba(203, 151, 255, 0.18) !important;

      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);

      box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.035),
        0 8px 28px rgba(0, 0, 0, 0.20);
    }

    .auth-login .security-item:hover {
      background:
        linear-gradient(
          135deg,
          rgba(43, 17, 72, 0.87),
          rgba(23, 7, 43, 0.82)
        ) !important;

      border-color: rgba(199, 126, 255, 0.28) !important;
    }

    .auth-login .security-item strong {
      text-shadow:
        0 2px 6px rgba(0, 0, 0, 0.90);
    }

    .auth-login .security-item div > span {
      color: rgba(220, 208, 232, 0.92);
      text-shadow:
        0 2px 5px rgba(0, 0, 0, 0.88);
    }


    /* =========================================================
       FOOTER
       ========================================================= */

    .auth-login .brand-footer {
      text-shadow:
        0 2px 7px rgba(0, 0, 0, 0.95);
    }


    /* =========================================================
       DESKTOP IMAGE POSITIONING
       ========================================================= */

    @media (min-width: 901px) {
      .auth-login .fortress-login-art {
        object-position: 50% 43%;
      }
    }


    /* =========================================================
       SHORTER LAPTOP SCREENS
       Only reposition image. Do NOT resize auth-shell.
       ========================================================= */

    @media (min-width: 901px) and (max-height: 800px) {
      .auth-login .fortress-login-art {
        object-position: 50% 46%;
      }
    }


    /* =========================================================
       MOBILE
       brand-panel is already handled by login.css.
       ========================================================= */

    @media (max-width: 900px) {
      .auth-login .fortress-login-art {
        object-position: 50% 42%;
      }
    }
  </style>
</head>


<body class="auth-page auth-login">

  <main class="auth-shell" role="main">


    <!-- =======================================================
         LEFT PANEL
         ======================================================= -->

    <section
      class="brand-panel"
      aria-label="FortressAuth access overview"
    >


      <!-- =====================================================
           FORTRESS BACKGROUND ART
           File location:
           public/fortress.png

           Browser URL:
           /fortress.png
           ===================================================== -->

      <img
        class="fortress-login-art"
        src="/fortress.png?v=20260817"
        alt=""
        aria-hidden="true"
        draggable="false"
      >

      <div
        class="fortress-login-overlay"
        aria-hidden="true"
      ></div>


      <!-- EXISTING DECORATIVE ELEMENTS -->

      <div
        class="brand-glow"
        aria-hidden="true"
      ></div>

      <div
        class="login-scan-grid"
        aria-hidden="true"
      ></div>



      <!-- =====================================================
           LOGIN VERIFICATION ANIMATION
           ===================================================== -->

      <div
        class="login-verification-stage"
        aria-live="polite"
        aria-atomic="true"
      >

        <div
          class="login-orbit"
          aria-hidden="true"
        >

          <span class="orbit-ring orbit-ring-one"></span>
          <span class="orbit-ring orbit-ring-two"></span>
          <span class="orbit-ring orbit-ring-three"></span>

          <span class="orbit-pulse orbit-pulse-one"></span>
          <span class="orbit-pulse orbit-pulse-two"></span>


          <div
            class="login-identity-frame"
            aria-hidden="true"
          >
            <span class="identity-corner corner-tl"></span>
            <span class="identity-corner corner-tr"></span>
            <span class="identity-corner corner-bl"></span>
            <span class="identity-corner corner-br"></span>
          </div>


          <span
            class="login-scan-beam"
            aria-hidden="true"
          ></span>


          <div
            class="login-orbit-core"
            aria-hidden="true"
          >

            <div class="login-person-grid"></div>

            <svg
              class="login-person-icon"
              viewBox="0 0 120 120"
              fill="none"
            >
              <circle
                cx="60"
                cy="38"
                r="20"
              />

              <path
                d="M24 104c2.8-24.5 16.8-38 36-38s33.2 13.5 36 38"
              />

              <path
                d="M42 68c4.8 6.4 10.8 9.7 18 9.7S73.2 74.4 78 68"
              />
            </svg>

          </div>

        </div>


        <div class="login-verification-copy">

          <span class="login-verification-badge">
            <i></i>
            ACCESS VERIFICATION
          </span>


          <div class="login-scan-readout">
            <span>CREDENTIAL VERIFICATION</span>
            <strong id="login-scan-percent">0%</strong>
          </div>


          <h2 id="login-stage-title">
            Preparing sign in...
          </h2>


          <p id="login-stage-message">
            Preparing your access request.
          </p>


          <div
            class="login-stage-progress"
            aria-hidden="true"
          >
            <span id="login-stage-progress-bar"></span>
          </div>


          <div
            class="login-stage-steps"
            aria-label="Login verification progress"
          >

            <div
              class="login-stage-step"
              data-login-step="1"
            >
              <i></i>
              <span>Initialize</span>
            </div>


            <div
              class="login-stage-step"
              data-login-step="2"
            >
              <i></i>
              <span>Identity</span>
            </div>


            <div
              class="login-stage-step"
              data-login-step="3"
            >
              <i></i>
              <span>Review</span>
            </div>


            <div
              class="login-stage-step"
              data-login-step="4"
            >
              <i></i>
              <span>Complete</span>
            </div>

          </div>


          <div class="login-stage-role">

            <span>
              Next step
            </span>

            <strong>
              Access continuation
            </strong>

          </div>

        </div>

      </div>



      <!-- =====================================================
           BRAND HEADER
           ===================================================== -->

      <div class="brand-header">

        <div class="brand-mark">

          <img
            src="/images/wolf.png"
            alt="FortressAuth"
          >

        </div>


        <div class="brand-copy">

          <span class="eyebrow">
            SECURE ACCESS GATEWAY
          </span>

          <h1>
            FortressAuth
          </h1>

          <p>
            Restricted administrator access for approved operators.
          </p>

        </div>

      </div>



      <!-- =====================================================
           SECURITY OVERVIEW
           ===================================================== -->

      <div
        class="security-stack"
        aria-label="Access overview"
      >


        <!-- OPERATOR VERIFICATION -->

        <div class="security-item">

          <span
            class="security-icon icon-shield"
            aria-hidden="true"
          >

            <svg
              viewBox="0 0 24 24"
              fill="none"
              preserveAspectRatio="xMidYMid meet"
            >

              <path
                d="M12 2.8 19.2 6v5.2c0 4.35-2.7 7.65-7.2 9.8-4.5-2.15-7.2-5.45-7.2-9.8V6L12 2.8Z"
              />

              <path
                d="m8.7 12.1 2.15 2.15 4.55-4.7"
              />

            </svg>

          </span>


          <div>

            <strong>
              Operator verification
            </strong>

            <span>
              Confirm your identity to continue to the administrative workspace.
            </span>

          </div>

        </div>



        <!-- ADAPTIVE ACCESS -->

        <div class="security-item">

          <span
            class="security-icon icon-radar"
            aria-hidden="true"
          >

            <svg
              viewBox="0 0 24 24"
              fill="none"
              preserveAspectRatio="xMidYMid meet"
            >

              <circle
                cx="12"
                cy="12"
                r="8.25"
              />

              <path
                d="M12 3.75v16.5M3.75 12h16.5"
              />

              <circle
                cx="12"
                cy="12"
                r="2.3"
              />

            </svg>

          </span>


          <div>

            <strong>
              Adaptive access
            </strong>

            <span>
              Sign-in activity is evaluated before access is approved.
            </span>

          </div>

        </div>



        <!-- PRIVATE WORKSPACE -->

        <div class="security-item">

          <span
            class="security-icon icon-lock"
            aria-hidden="true"
          >

            <svg
              viewBox="0 0 24 24"
              fill="none"
              preserveAspectRatio="xMidYMid meet"
            >

              <rect
                x="5.25"
                y="10.25"
                width="13.5"
                height="9.25"
                rx="2.3"
              />

              <path
                d="M8.25 10.25V7.6a3.75 3.75 0 0 1 7.5 0v2.65"
              />

              <path
                d="M12 14.15v2.3"
              />

            </svg>

          </span>


          <div>

            <strong>
              Private workspace
            </strong>

            <span>
              Administrative functions remain unavailable until access is approved.
            </span>

          </div>

        </div>

      </div>



      <!-- =====================================================
           ACCESS STATUS
           ===================================================== -->

      <div class="brand-footer">

        <span
          class="live-dot"
          aria-hidden="true"
        ></span>

        Access gateway ready

      </div>

    </section>



    <!-- =======================================================
         RIGHT LOGIN PANEL
         ======================================================= -->

    <section class="auth-panel">

      <div class="auth-panel-inner">


        <div class="mobile-brand">

          <img
            src="/images/wolf.png"
            alt="FortressAuth"
          >

          <span>
            FORTRESS AUTH
          </span>

        </div>



        <div class="auth-heading">

          <span class="step-pill">
            PRIMARY SIGN-IN
          </span>

          <h2>
            Welcome back
          </h2>

          <p>
            Enter your administrator credentials to continue.
          </p>

        </div>



        <?php if (!empty($error)): ?>

          <div
            class="error-message <?php echo e($error_class ?? ''); ?>"
            role="alert"
          >

            <span
              class="alert-icon"
              aria-hidden="true"
            >
              !
            </span>

            <span>
              <?php echo e($error); ?>
            </span>

          </div>

        <?php endif; ?>



        <form
          class="auth-form"
          method="post"
          action="/login.php"
          autocomplete="off"
          novalidate
        >

          <input
            type="hidden"
            name="csrf_token"
            value="<?php echo e(generate_csrf_token()); ?>"
          >



          <!-- USERNAME -->

          <div class="field-group">

            <label for="username">
              Username
            </label>

            <div class="input-shell">

              <span
                class="input-icon"
                aria-hidden="true"
              >

                <svg viewBox="0 0 24 24">

                  <circle
                    cx="12"
                    cy="8"
                    r="3.6"
                  />

                  <path
                    d="M5.2 20c.6-4.1 3-6.2 6.8-6.2s6.2 2.1 6.8 6.2"
                  />

                </svg>

              </span>


              <input
                id="username"
                name="username"
                type="text"
                required
                maxlength="100"
                placeholder="Enter username"
                autocomplete="username"
              >

            </div>

          </div>



          <!-- PASSWORD -->

          <div class="field-group">

            <div class="field-label-row">

              <label for="password">
                Password
              </label>

              <span class="field-note">
                Private entry
              </span>

            </div>


            <div class="input-shell">

              <span
                class="input-icon"
                aria-hidden="true"
              >

                <svg viewBox="0 0 24 24">

                  <rect
                    x="5"
                    y="10"
                    width="14"
                    height="10"
                    rx="2.5"
                  />

                  <path
                    d="M8.5 10V7.2a3.5 3.5 0 0 1 7 0V10"
                  />

                  <path
                    d="M12 14v2"
                  />

                </svg>

              </span>


              <input
                id="password"
                name="password"
                type="password"
                required
                maxlength="128"
                placeholder="Enter password"
                autocomplete="current-password"
              >


              <button
                class="password-toggle"
                type="button"
                id="password-toggle"
                aria-label="Show password"
                aria-pressed="false"
              >

                <svg
                  class="eye-open"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >

                  <path
                    d="M2.5 12s3.4-5 9.5-5 9.5 5 9.5 5-3.4 5-9.5 5-9.5-5-9.5-5z"
                  />

                  <circle
                    cx="12"
                    cy="12"
                    r="2.6"
                  />

                </svg>


                <svg
                  class="eye-closed"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >

                  <path
                    d="M3 3l18 18"
                  />

                  <path
                    d="M10.6 7.1C11 7 11.5 7 12 7c6.1 0 9.5 5 9.5 5a15.8 15.8 0 01-3.1 3.3"
                  />

                  <path
                    d="M6.1 6.1C3.8 7.7 2.5 12 2.5 12s3.4 5 9.5 5c1.3 0 2.5-.2 3.5-.6"
                  />

                </svg>

              </button>

            </div>

          </div>



          <button
            class="primary-action"
            type="submit"
          >

            <span>
              Continue securely
            </span>

            <svg
              viewBox="0 0 24 24"
              aria-hidden="true"
            >

              <path
                d="M5 12h13"
              />

              <path
                d="M14 7l5 5-5 5"
              />

            </svg>

          </button>

        </form>



        <div
          class="trust-row"
          aria-label="Access status"
        >

          <span>
            <i class="trust-dot"></i>
            Authorized users only
          </span>

          <span>
            <i class="trust-dot"></i>
            Private workspace
          </span>

          <span>
            <i class="trust-dot"></i>
            Access verified
          </span>

        </div>


        <p class="auth-footnote">
          Restricted system. Continue only if you are authorized.
        </p>

      </div>

    </section>

  </main>



  <!-- =========================================================
       AI LOGIN SECURITY TOAST
       ========================================================= -->

  <aside
    class="ai-login-toast"
    id="ai-login-toast"
    role="status"
    aria-live="polite"
    aria-atomic="true"
    hidden
  >

    <button
      class="ai-login-toast-close"
      type="button"
      aria-label="Dismiss security notice"
    >
      ×
    </button>


    <div
      class="ai-login-toast-visual"
      aria-hidden="true"
    >

      <span class="ai-login-toast-glow"></span>

      <img
        src="/images/ai7.png"
        alt=""
      >

    </div>


    <div class="ai-login-toast-copy">

      <span class="ai-login-toast-kicker">
        AI DEFENSE ACTIVE
      </span>

      <strong id="ai-login-toast-title">
        Access not verified
      </strong>

      <span id="ai-login-toast-message">
        This sign-in attempt was not accepted.
      </span>

    </div>


    <div class="ai-login-toast-status">

      <span
        class="ai-login-toast-dot"
        aria-hidden="true"
      ></span>

      <span>
        Continuous assessment active
      </span>

    </div>

  </aside>


  <script src="/js/auth_motion.js"></script>
  <script src="/js/login_ui.js"></script>

</body>
</html>