const rawBackend = (process.env.FORTRESS_BACKEND_ORIGIN || '').trim();

if (!rawBackend) {
  throw new Error(
    'FORTRESS_BACKEND_ORIGIN is required. Set it in Vercel to your Render v3 backend origin, for example https://fortressauth-v3-backend.onrender.com',
  );
}

let backendOrigin;
try {
  const parsed = new URL(rawBackend);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('invalid backend origin');
  }
  parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  backendOrigin = parsed.toString().replace(/\/$/, '');
} catch {
  throw new Error('FORTRESS_BACKEND_ORIGIN must be a valid HTTPS origin with no query string or fragment.');
}

export default {
  installCommand: `node -e "console.log('Using committed FortressAuth v3 frontend bundle')"`,
  buildCommand: 'node scripts/build-vercel.mjs',
  outputDirectory: 'vercel-dist',

  // Vercel gives precedence to files in vercel-dist. Existing frontend assets
  // are served directly from Vercel; every missing path is then transparently
  // reverse-proxied to the authoritative PHP backend on Render.
  rewrites: [
    {
      source: '/:path*',
      destination: `${backendOrigin}/:path*`,
    },
  ],

  headers: [
    {
      source: '/(.*)',
      headers: [
        { key: 'X-Robots-Tag', value: 'noindex, nofollow, noarchive' },
      ],
    },
    {
      source: '/app/assets/(.*)',
      headers: [
        { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
      ],
    },
    {
      source: '/css/(.*)',
      headers: [
        { key: 'Cache-Control', value: 'public, max-age=0, must-revalidate' },
      ],
    },
    {
      source: '/js/(.*)',
      headers: [
        { key: 'Cache-Control', value: 'public, max-age=0, must-revalidate' },
      ],
    },
  ],
};
