import Script from "next/script";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
        <script src="https://unpkg.com/lodash@4.17.21/lodash.min.js"></script>
        <script
          src="https://cdn.jsdelivr.net/npm/dayjs@1.11.13/dayjs.min.js"
          integrity="sha384-fixturefixturefixturefixturefixturefixturefixturefixture"
          crossOrigin="anonymous"
        ></script>
        <Script src="https://js.stripe.com/v3" />
      </head>
      <body>{children}</body>
    </html>
  );
}
