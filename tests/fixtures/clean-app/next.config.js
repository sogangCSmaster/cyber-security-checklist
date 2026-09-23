/** @type {import('next').NextConfig} */
module.exports = {
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: "default-src 'self'; script-src 'self' 'nonce-{NONCE}' 'strict-dynamic' 'unsafe-inline'; object-src 'none'; base-uri 'none'" },
          { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
        ],
      },
    ];
  },
};
