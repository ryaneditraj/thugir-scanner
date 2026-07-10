"use client";

import { usePathname } from "next/navigation";

const NAV: [string, string][] = [
  ["Overview", "/admin"],
  ["Settings", "/admin/settings"],
  ["Patterns", "/admin/patterns"],
  ["Scans", "/admin/scans"],
  ["Users", "/admin/users"],
  ["API keys", "/admin/keys"],
  ["Audit log", "/admin/audit"]
];

export default function AdminNav() {
  const pathname = usePathname();

  return (
    <nav className="admin-nav" aria-label="Admin">
      {NAV.map(([label, href]) => {
        const active = href === "/admin" ? pathname === "/admin" : pathname.startsWith(href);
        return (
          <a key={href} href={href} className={active ? "active" : undefined} aria-current={active ? "page" : undefined}>
            {label}
          </a>
        );
      })}
    </nav>
  );
}
