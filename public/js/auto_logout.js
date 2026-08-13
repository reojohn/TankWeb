(() => {
  // Match dashboard.php's 15-minute inactivity policy instead of the legacy 5-second timer.
  const runtimePolicy = document.getElementById('fortress-security-runtime');
  const configuredIdle = Number(runtimePolicy?.dataset.sessionIdleSeconds || 0);
  const idleLimitSeconds = configuredIdle >= 300 ? configuredIdle : 15 * 60;
  let lastActivity = Date.now();
  let redirecting = false;

  const markActivity = () => {
    lastActivity = Date.now();
  };

  ['pointerdown', 'pointermove', 'keydown', 'scroll', 'touchstart'].forEach((eventName) => {
    window.addEventListener(eventName, markActivity, { passive: true });
  });

  window.setInterval(() => {
    if (redirecting) return;

    const idleSeconds = (Date.now() - lastActivity) / 1000;
    if (idleSeconds >= idleLimitSeconds) {
      redirecting = true;
      window.location.href = '/logout.php';
    }
  }, 1000);
})();
