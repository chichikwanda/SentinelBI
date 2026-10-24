import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server bundle: small runtime image for the single-VM deployment.
  output: "standalone",
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
