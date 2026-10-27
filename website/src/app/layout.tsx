import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CVE Atlas | Vulnerability intelligence",
  description: "Explore and search CVE vulnerability records.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
