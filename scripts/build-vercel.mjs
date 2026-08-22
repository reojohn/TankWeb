import { cp, mkdir, rm, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, '..');
const publicDir = path.join(root, 'public');
const out = path.join(root, 'vercel-dist');

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

async function copyDir(relativeSource, relativeTarget = relativeSource) {
  const source = path.join(publicDir, relativeSource);
  try {
    const info = await stat(source);
    if (info.isDirectory()) {
      await cp(source, path.join(out, relativeTarget), { recursive: true });
    }
  } catch {
    // Optional static directory not present in this build.
  }
}

// Only browser-safe static assets are published to Vercel.
// PHP, .env files, logs, templates and backend source remain on Render.
for (const dir of ['css', 'images', 'js', 'webfonts']) {
  await copyDir(dir);
}
await copyDir('app/assets');
await copyDir('app/vendor');

const rootIndex = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <meta http-equiv="refresh" content="0;url=/login.php">
  <title>FortressAuth</title>
</head>
<body>
  <script>location.replace('/login.php');</script>
  <noscript><a href="/login.php">Continue to FortressAuth</a></noscript>
</body>
</html>
`;

await writeFile(path.join(out, 'index.html'), rootIndex, 'utf8');

// Vercel owns /app as a static directory because assets/vendor are deployed
// there. This entry file therefore performs a same-origin server auth check
// against Render BEFORE loading the React shell. The PHP backend remains the
// authority; this file only decides whether it is safe to load the frontend.
await mkdir(path.join(out, 'app'), { recursive: true });

const appIndex = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="theme-color" content="#10071f" />
  <meta name="robots" content="noindex,nofollow,noarchive" />
  <link rel="icon" type="image/png" href="/images/wolf1.png?v=20260813" />
  <title>FortressAuth v3</title>
  <style>
    html,body{margin:0;min-height:100%;background:#09030f;color:#d9cdea;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    body{min-height:100vh}
    #fortress-entry{position:fixed;inset:0;display:grid;place-items:center;background:
      radial-gradient(circle at 50% 42%,rgba(136,56,214,.12),transparent 34%),#09030f}
    .entry-core{width:30px;height:30px;border-radius:50%;border:2px solid rgba(205,159,255,.18);
      border-top-color:#c58cff;animation:spin .8s linear infinite;box-shadow:0 0 24px rgba(180,92,255,.16)}
    @keyframes spin{to{transform:rotate(360deg)}}
  </style>
</head>
<body>
  <div id="fortress-entry" aria-label="Verifying protected workspace">
    <div class="entry-core"></div>
  </div>
  <div id="root"></div>
  <script>
    (async function () {
      try {
        const response = await fetch('/api/v3.php?view=bootstrap', {
          method: 'GET',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: { 'Accept': 'application/json' }
        });

        if (!response.ok) {
          location.replace('/app/index.php' + location.hash);
          return;
        }

        const payload = await response.json().catch(() => null);
        if (!payload || payload.ok !== true) {
          location.replace('/app/index.php' + location.hash);
          return;
        }

        const css = [
          '/css/all.min.css',
          '/css/dashboard.css',
          '/css/ai_threat_intelligence.css',
          '/css/vault.css',
          '/css/user_management_profile.css',
          '/css/v3-react.css'
        ];

        css.forEach((href) => {
          const link = document.createElement('link');
          link.rel = 'stylesheet';
          link.href = href;
          document.head.appendChild(link);
        });

        document.body.className = 'command-page fortress-react-v3';

        const scripts = [
          '/app/vendor/react.production.min.js',
          '/app/vendor/react-dom.production.min.js',
          '/app/vendor/remix-router.umd.min.js',
          '/app/vendor/react-router.production.min.js',
          '/app/vendor/react-router-dom.production.min.js',
          '/app/assets/v3-fast-navigation-skeleton-20260820.js?v=20260822-1124',
          '/js/dashboard.js',
          '/js/security_alerts.js',
          '/js/ai_threat_intelligence.js',
          '/js/vault.js',
          '/js/auto_logout.js'
        ];

        const loadScript = (src) => new Promise((resolve, reject) => {
          const script = document.createElement('script');
          script.src = src;
          script.onload = resolve;
          script.onerror = reject;
          document.body.appendChild(script);
        });

        for (const src of scripts) {
          await loadScript(src);
        }

        const gate = document.getElementById('fortress-entry');
        if (gate) gate.remove();
      } catch (error) {
        location.replace('/app/index.php' + location.hash);
      }
    })();
  </script>
</body>
</html>
`;

await writeFile(path.join(out, 'app', 'index.html'), appIndex, 'utf8');

await writeFile(
  path.join(out, 'VERCEL_STATIC_ONLY.txt'),
  'FortressAuth v3 static frontend output. Dynamic/security requests are reverse-proxied to Render.\n',
  'utf8',
);

console.log(`FortressAuth Vercel static output prepared at ${out}`);
