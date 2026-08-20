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

// Copy only browser-safe static assets. PHP, .env, templates, logs, source code,
// and security configuration are deliberately never included in Vercel output.
for (const dir of ['css', 'images', 'js', 'webfonts']) {
  await copyDir(dir);
}
await copyDir('app/assets');
await copyDir('app/vendor');

// /app/ itself is intentionally absent from the static filesystem. That path
// must fall through Vercel's rewrite to Render, where public/app/index.php
// performs the authoritative PHP session/MFA check before returning React HTML.
await writeFile(
  path.join(out, 'VERCEL_STATIC_ONLY.txt'),
  'FortressAuth v3 static frontend output. Dynamic/security requests are reverse-proxied to Render.\n',
  'utf8',
);

console.log(`FortressAuth Vercel static output prepared at ${out}`);
