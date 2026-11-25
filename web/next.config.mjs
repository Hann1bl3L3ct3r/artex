import { fileURLToPath } from "node:url";

// Static export: `NEXT_EXPORT=1 next build` emits a purely static directory at web/out that can be dropped
// straight into an nginx web root. Development (next dev) leaves the variable unset and keeps the /api proxy and HMR.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site runs on mocks, with no backend and no /api proxy.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Keep a lockfile in a parent directory from skewing root inference and asset path generation.
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // Allow dev resources (HMR) to be reached from LAN IPs; adjust as needed.
  // In dev, let any IPv4 origin reach /_next/* and HMR (so a changing LAN IP does not matter).
  // Note: Next rejects a bare "*" for safety, so use per-segment wildcards; "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images are not optimized; each route emits <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend, so no /api proxy is needed.
          images: { unoptimized: true },
        }
      : {
          // Development: proxy /api/* to the Go backend (default :8787; override with AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

export default nextConfig;
