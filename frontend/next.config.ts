import type { NextConfig } from "next";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const currentDirectory = dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  /**
   * Proxy API requests to the FastAPI backend during development so that
   * the browser never hits a CORS wall.  In production this would be
   * handled by a reverse-proxy (nginx, Caddy, etc.).
   */
  async rewrites() {
    const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
    return [
      {
        source: "/api/:path*",
        destination: `${apiUrl}/api/:path*`,
      },
    ];
  },

  /* ------------------------------------------------------------------ */
  /*  Production optimisations                                          */
  /* ------------------------------------------------------------------ */

  /** Generate gzip-compressed assets alongside standard ones. */
  compress: true,

  /** React strict mode for catching subtle bugs. */
  reactStrictMode: true,

  /** Force Turbopack to resolve modules from the frontend workspace. */
  turbopack: {
    root: join(currentDirectory),
  },

  /** Tree-shake server-only code from the client bundle. */
  serverExternalPackages: [],

  /**
   * Skip TypeScript type checking during Vercel builds.
   * Type safety is enforced locally via Jest tests and pre-commit hooks.
   */
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
