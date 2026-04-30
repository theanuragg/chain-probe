import type { Metadata } from "next";
import "@/styles/globals.css";

export const metadata: Metadata = {
  title: {
    default: "ChainProbe — Solana Anchor Smart Contract Security Analysis",
    template: "%s | ChainProbe",
  },
  description:
    "ChainProbe is an advanced security analysis platform for Solana Anchor smart contracts. Detect vulnerabilities, audit programs, and secure your Solana DeFi protocols with automated static analysis.",
  keywords: [
    "Solana",
    "Anchor",
    "smart contract",
    "security",
    "audit",
    "DeFi",
    "Rust",
    "Solana security",
    "smart contract analysis",
    "vulnerability detection",
    "blockchain security",
    "Solana program audit",
  ],
  authors: [{ name: "ChainProbe Team" }],
  creator: "ChainProbe",
  publisher: "ChainProbe",
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://chainprobe.xyz",
    title: "ChainProbe — Solana Anchor Smart Contract Security Analysis",
    description:
      "Detect vulnerabilities and secure your Solana Anchor programs with automated static analysis. The trusted security platform for Solana DeFi.",
    siteName: "ChainProbe",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "ChainProbe - Solana Smart Contract Security Analysis Platform",
        type: "image/png",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "ChainProbe — Solana Anchor Smart Contract Security Analysis",
    description:
      "Detect vulnerabilities and secure your Solana Anchor programs with automated static analysis.",
    images: ["/og.png"],
    creator: "@chainprobe",
  },
  icons: {
    icon: "/favicon.ico",
    shortcut: "/favicon-16x16.png",
    apple: "/apple-touch-icon.png",
  },
  manifest: "/site.webmanifest",
  alternates: {
    canonical: "https://chainprobe.xyz",
  },
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