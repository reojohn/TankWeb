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

// Give the Vercel root a real filesystem entry.
// Filesystem entries take precedence over rewrites, so "/" always resolves
// and then moves to the same-origin PHP login route, which Vercel proxies
// to the authoritative Render backend.
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

await writeFile(
  path.join(out, 'VERCEL_STATIC_ONLY.txt'),
  'FortressAuth v3 static frontend output. Dynamic/security requests are reverse-proxied to Render.\n',
  'utf8',
);

console.log(`FortressAuth Vercel static output prepared at ${out}`);
