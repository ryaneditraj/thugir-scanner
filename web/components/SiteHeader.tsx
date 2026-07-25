"use client";

import { useEffect, useState } from "react";

const LINKS: [string, string][] = [
  ["What we check", "/#checks"],
  ["How it's confirmed", "/#confirmed"],
  ["Pricing", "/#pricing"]
];

export default function SiteHeader() {
  const [open, setOpen] = useState(false);
  const [shrink, setShrink] = useState(false);

  useEffect(() => {
    document.documentElement.classList.add("js");

    const onScroll = () => setShrink(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });

    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            e.target.classList.add("in");
            io.unobserve(e.target);
          }
        }
      },
      { rootMargin: "0px 0px -8% 0px", threshold: 0.12 }
    );
    document.querySelectorAll("[data-reveal], .casefile").forEach((el) => io.observe(el));

    return () => {
      window.removeEventListener("scroll", onScroll);
      io.disconnect();
    };
  }, []);

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <>
      <header className={`hdr${shrink ? " shrink" : ""}`}>
        <div className="hdr-inner">
          <a className="brand" href="/">
            Thugir<span className="mark">Scanner</span>
          </a>
          <nav className="nav" aria-label="Primary">
            {LINKS.map(([label, href]) => (
              <a key={href} href={href}>
                {label}
              </a>
            ))}
          </nav>
          <div className="hdr-right">
            <a className="hdr-signin" href="/dashboard">
              Account
            </a>
            <a className="btn btn-primary" href="/#scan">
              Run a free scan
            </a>
            <button
              className="nav-toggle"
              type="button"
              aria-label={open ? "Close menu" : "Open menu"}
              aria-expanded={open}
              onClick={() => setOpen((v) => !v)}
            >
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden="true">
                {open ? (
                  <path d="M4 4l10 10M14 4L4 14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                ) : (
                  <path d="M3 5h12M3 9h12M3 13h12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                )}
              </svg>
            </button>
          </div>
        </div>
      </header>
      {open && (
        <>
          <button
            type="button"
            className="mobile-menu-backdrop"
            aria-label="Close menu"
            onClick={() => setOpen(false)}
          />
          <div className="mobile-menu" role="dialog" aria-label="Mobile navigation">
            {LINKS.map(([label, href]) => (
              <a key={href} href={href} onClick={() => setOpen(false)}>
                {label}
              </a>
            ))}
            <a href="/dashboard" onClick={() => setOpen(false)}>
              Account
            </a>
            <a href="/#scan" onClick={() => setOpen(false)}>
              Run a free scan
            </a>
          </div>
        </>
      )}
    </>
  );
}
