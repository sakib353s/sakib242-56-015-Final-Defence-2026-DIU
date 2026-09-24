const API_ORIGIN = process.env.CWB_API_ORIGIN || "http://127.0.0.1:8471";

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // dev server and production build must never share webpack artifacts
  // (a build while `next dev` runs corrupts its chunk cache → "Cannot find module './NN.js'")
  distDir: process.env.NODE_ENV === "production" ? ".next-build" : ".next",
  env: {
    NEXT_PUBLIC_WS_BASE: process.env.NEXT_PUBLIC_WS_BASE || "ws://127.0.0.1:8471",
  },
  async rewrites() {
    return [
      // browsers cannot proxy WS through rewrites — raw /ws/* uses NEXT_PUBLIC_WS_BASE
      { source: "/api/:path*", destination: `${API_ORIGIN}/api/:path*` },
    ];
  },
};

module.exports = nextConfig;
