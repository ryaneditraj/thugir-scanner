import type { Metadata } from "next";
import "./globals.css";
import SiteHeader from "@/components/SiteHeader";

const SITE = process.env.NEXT_PUBLIC_SITE_URL || "https://scanner.thugirlabs.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: {
    default: "Thugir Scanner — Security for AI-built apps",
    template: "%s | Thugir Scanner"
  },
  description:
    "Scan your live web app for the specific misconfigurations AI coding assistants ship by default — exposed secrets, open databases, broken access control. Every finding is backed by captured evidence before it's flagged.",
  openGraph: {
    type: "website",
    siteName: "Thugir Scanner",
    title: "Thugir Scanner — Security for AI-built apps",
    description:
      "We test for the exact mistakes AI builders leave behind, and we verify each finding with captured evidence before reporting it."
  },
  robots: { index: true, follow: true }
};

const FOOTER: Record<string, [string, string][]> = {
  Product: [
    ["What we check", "/#checks"],
    ["How findings are confirmed", "/#confirmed"],
    ["Pricing", "/#pricing"],
    ["Sample report", "/demo"],
    ["How scans work", "/how-scans-work"]
  ],
  Company: [
    ["How scans work", "/how-scans-work"],
    ["Sample finding", "/#sample"],
    ["Sign in", "/dashboard"]
  ],
  Legal: [
    ["Terms of Service", "/terms"],
    ["Privacy Policy", "/privacy"]
  ]
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link
          href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,600;12..96,700;12..96,800&family=Fraunces:ital,opsz,wght@1,9..144,400;1,9..144,500;1,9..144,600&family=Plus+Jakarta+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <div className="bg-fx" aria-hidden="true" />
        <SiteHeader />
        <main className="site-main">{children}</main>
        <footer className="site-footer">
          <div className="footer-inner">
            <div className="footer-brand">
              <a href="/" className="brand">
                Thugir<span className="mark">Scanner</span>
              </a>
              <p>
                Security for AI-built applications. We test for the exact patterns AI coding
                assistants ship by default — and confirm each one with evidence.
              </p>
              <p className="footer-fine">Built by Ryan Editraj</p>
            </div>
            <div className="footer-cols">
              {Object.entries(FOOTER).map(([heading, links]) => (
                <div key={heading} className="footer-col">
                  <h4>{heading}</h4>
                  {links.map(([label, href]) => (
                    <a key={href} href={href}>
                      {label}
                    </a>
                  ))}
                </div>
              ))}
            </div>
          </div>
          <div className="footer-bottom">
            <span>© 2026 Thugir Labs</span>
            <span>Authorized testing only · accounts logged · rate-limited</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
