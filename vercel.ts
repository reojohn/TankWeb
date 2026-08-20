export const config = {
  installCommand: `node -e "console.log('Using committed FortressAuth v3 frontend bundle')"`,
  buildCommand: 'node scripts/build-vercel.mjs',
  outputDirectory: 'vercel-dist',

  /*
   * Existing files in vercel-dist are served by Vercel first.
   * Anything that does not exist there is reverse-proxied to the
   * authoritative FortressAuth PHP backend on Render.
   */
  rewrites: [
    {
      source: '/:path*',
      destination: 'https://tankweb-v3.onrender.com/:path*',
    },
  ],

  headers: [
    {
      source: '/(.*)',
      headers: [
        {
          key: 'X-Robots-Tag',
          value: 'noindex, nofollow, noarchive',
        },
      ],
    },
    {
      source: '/app/assets/(.*)',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, max-age=31536000, immutable',
        },
      ],
    },
    {
      source: '/css/(.*)',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, max-age=0, must-revalidate',
        },
      ],
    },
    {
      source: '/js/(.*)',
      headers: [
        {
          key: 'Cache-Control',
          value: 'public, max-age=0, must-revalidate',
        },
      ],
    },
  ],
};
