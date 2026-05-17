import type { NextConfig } from "next";
const nextConfig: NextConfig = {
  output: "standalone",
  typescript: {
    ignoreBuildErrors: true,
  },
  async redirects() {
    return [
      {
        source: "/coverage/lookalike-domains",
        destination: "/coverage/lookalike",
        permanent: true,
      },
    ];
  },
};
export default nextConfig;