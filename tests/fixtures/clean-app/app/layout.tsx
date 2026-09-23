export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <script
          src="https://cdn.jsdelivr.net/npm/dayjs@1.11.13/dayjs.min.js"
          integrity="sha384-fixturefixturefixturefixturefixturefixturefixturefixture"
          crossOrigin="anonymous"
        ></script>
      </head>
      <body>{children}</body>
    </html>
  );
}
