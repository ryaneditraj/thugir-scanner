import type { Metadata } from "next";
import { Bricolage_Grotesque, Fraunces, IBM_Plex_Mono, Plus_Jakarta_Sans } from "next/font/google";
import "./globals.css";
import SiteHeader from "@/components/SiteHeader";

const display = Bricolage_Grotesque({
  subsets: ["latin"],
  weight: ["600", "700", "800"],
  variable: "--font-display",
  display: "swap"
});
const serif = Fraunces({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  style: ["normal", "italic"],
  variable: "--font-serif",
  display: "swap"
});
const sans = Plus_Jakarta_Sans({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  variable: "--font-body",
  display: "swap"
});
const mono = IBM_Plex_Mono({
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  variable: "--font-mono",
  display: "swap"
});

const SITE = process.env.NEXT_PUBLIC_SITE_URL || "https://scanner.thugirlabs.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE),
  title: {
    default: "Thugir Scanner — Security for AI-built apps",
    template: "%s | Thugir Scanner"
  },
  description:
    "Thugir Scanner is an evidence-backed security scanner for AI-built web apps. It checks live URLs for exposed secrets, open databases, downloadable .env and .git files, and missing security headers, and it withholds a finding unless the check captured proof.",
  keywords: [
    "AI app security scanner",
    "vibe coding security",
    "Lovable security scan",
    "Bolt.new security",
    "Supabase RLS scanner",
    "exposed API key scanner",
    "evidence-based vulnerability scanner",
    "Thugir Scanner",
    "Thugir Labs"
  ],
  openGraph: {
    type: "website",
    siteName: "Thugir Scanner",
    title: "Thugir Scanner — Security for AI-built apps",
    description:
      "Evidence-backed checks for the misconfigurations AI coding tools leave in live web apps. A finding is reported only when the scanner captured proof.",
    images: [{ url: "/og-image.png", width: 1200, height: 630, alt: "Thugir Scanner — evidence-backed security checks for AI-built apps" }]
  },
  twitter: {
    card: "summary_large_image",
    title: "Thugir Scanner — Security for AI-built apps",
    description: "Evidence-backed security checks for AI-built web apps.",
    images: ["/og-image.png"]
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
    <html lang="en" className={`${display.variable} ${serif.variable} ${sans.variable} ${mono.variable}`}>
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
