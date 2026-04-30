import "@/styles/globals.css";

export const metadata = {
  title: "ChainProbe — Solana Anchor smart contract security analysis",
  description: "ChainProbe — Solana Anchor smart contract security analysis",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}