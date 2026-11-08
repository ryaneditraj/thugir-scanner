import ScanForm from "@/components/ScanForm";
import HeroShowcase from "@/components/HeroShowcase";
import { patternsForTier, STATIC_PATTERNS } from "@/lib/patterns";
import { loadMaskedSettings } from "@/lib/settings/store";

export const dynamic = "force-dynamic";

// Consequence-first. Technical term lives in the body, not the headline.
const EXHIBITS: { ref: string; title: string; body: React.ReactNode; tag: string; tagClass: string }[] = [
  {
    ref: "EXHIBIT A",
    title: "Strangers can read your customers' private records",
    body: (
      <>Row-level security left off, or default public datastore rules, means an anonymous request to your <span className="term">Supabase</span>/<span className="term">Firebase</span> API returns other people's data — no login required.</>
    ),
    tag: "critical",
    tagClass: "critical"
  },
  {
    ref: "EXHIBIT B",
    title: "Your API keys are sitting in the browser bundle",
    body: (
      <>OpenAI, Stripe, AWS or email-provider keys shipped to the client — or a server secret given a browser-public <span className="term">VITE_/NEXT_PUBLIC_</span> prefix — can be lifted by anyone who opens devtools.</>
    ),
    tag: "critical",
    tagClass: "critical"
  },
  {
    ref: "EXHIBIT C",
    title: "Your .env and git history are downloadable",
    body: (
      <>Deploy scaffolds frequently serve <span className="term">.env</span>, <span className="term">.git/</span> and config files from the web root, handing over every secret and your full source history.</>
    ),
    tag: "critical",
    tagClass: "critical"
  },
  {
    ref: "EXHIBIT D",
    title: "Your app can be framed and clickjacked",
    body: (
      <>Missing <span className="term">Content-Security-Policy</span>, <span className="term">X-Frame-Options</span> and <span className="term">HSTS</span> headers let an attacker page embed yours and hijack clicks, or downgrade the connection.</>
    ),
    tag: "medium",
    tagClass: "medium"
  },
  {
    ref: "EXHIBIT E",
    title: "Your original source code is readable in production",
    body: (
      <>Published JavaScript <span className="term">source maps</span> reconstruct your pre-minified code, exposing internal logic and any hard-coded values to anyone viewing the page.</>
    ),
    tag: "medium",
    tagClass: "medium"
  },
  {
    ref: "EXHIBIT F",
    title: "Attackers can forge payments or reach other users' data",
    body: (
      <>Unverified payment webhooks and resources fetched by sequential ID (<span className="term">IDOR</span>) are Deep Scan checks. They run only after the domain is verified, and their evidence stays off the free response.</>
    ),
    tag: "deep scan",
    tagClass: "low"
  }
];

const PROOF: { h: string; p: React.ReactNode }[] = [
  {
    h: "We load your app like a real browser",
    p: <>We fetch the page and its same-origin scripts, fingerprint the stack (Next.js, Vite, Supabase, Firebase and others), and map the reachable surface — no agent or install on your side.</>
  },
  {
    h: "We capture the literal evidence",
    p: <>Every issue keeps its proof: the path we requested, the HTTP status, a redacted snippet of the response body, the matched secret (masked), or the actual row a database returned to an unauthenticated request.</>
  },
  {
    h: "We reject guesses",
    p: <>A finding is only reported if the check produced positive proof. An exposed <span className="term">.env</span> must return real <span className="term">KEY=VALUE</span> content — not a 200 catch-all page. Low-confidence heuristics never show as confirmed; they're filed as Deep Scan leads.</>
  },
  {
    h: "Read-only free scan; sandboxed Deep Scan",
    p: <>The free scan is a single read-only pass. Deep Scan runs multi-step authorized probing — forged test webhook events, IDOR checks — inside an isolated worker, only against domains you've verified you own.</>
  }
];

const FLOW: [string, string][] = [
  ["Enter your URL", "A bare domain is fine."],
  ["We load it like a browser", "Page + scripts + stack fingerprint."],
  ["We probe targeted checks", "The misconfigs AI builders ship."],
  ["We verify before flagging", "Positive proof, or it's not reported."],
  ["You get evidence + a fix", "Redacted proof and paste-ready remediation."]
];

const FAQ: [string, React.ReactNode][] = [
  ["Do I need an account?", "On a deployed server, yes. The free scan requires a session so the request can be rate-limited. Locally, DEV_MODE=1 skips that session and is ignored when NODE_ENV=production. There is nothing to install."],
  ["How is a finding different from an alert?", "A free-tier finding is returned only when the check captured a positive signal: a matched secret, a response, a header, or a row. Deep-tier evidence is omitted from the free JSON. It is not hidden with CSS."],
  ["Is it safe to run against production?", "The free scan is a read-only pass plus a small set of fixed-path probes, and it refuses private and metadata addresses. Scan only a host you own or are authorized to test. Active Deep Scan probing runs after domain ownership is verified."],
  ["What is the sample on /demo?", "An in-memory page with invented secrets. The detectors in this repository run against that page and the report shows their output. It does not fetch a network host, and it is not a customer result."]
];


export default async function HomePage() {
  const settings = await loadMaskedSettings();
  const price = settings.pricing;
  const libraryChecks = STATIC_PATTERNS.filter((p) => p.enabled).length;
  const freeChecks = patternsForTier("free").length;
  const deepChecks = libraryChecks - freeChecks;
  const faqLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: FAQ.filter((item): item is [string, string] => typeof item[1] === "string").map(([name, text]) => ({
      "@type": "Question",
      name,
      acceptedAnswer: { "@type": "Answer", text }
    }))
  };
  return (
    <div className="lightsite">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(faqLd) }} />
      {/* HERO — thesis + URL-first + floating product showcase */}
      <section className="hero">
        <div className="hero-inner" data-reveal>
          <span className="hero-badge">
            <span className="hb-ico" aria-hidden="true">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                <path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
                <path d="M9 12l2 2 4-4" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
            Security for AI-built apps
          </span>
          <h1>
            Proof, or it is <em>not</em> a finding.
          </h1>
          <p className="hero-sub">
            Thugir Scanner checks an AI-built web app for exposed secrets, open databases, and
            missing headers. The free tier reports a hit only when that check captured evidence.
          </p>
          <p className="hero-proof">
            {freeChecks} free-tier checks · {libraryChecks.toLocaleString("en-US")} enabled patterns · evidence stays off the free response
          </p>
          <div className="scan-wrap">
            <ScanForm />
          </div>
        </div>

        <div className="hero-stage" data-reveal>
          <HeroShowcase freeChecks={freeChecks} libraryChecks={libraryChecks} />
        </div>
      </section>

      {/* HOW FINDINGS ARE CONFIRMED — the paper trust moment */}
      <section className="section" id="confirmed">
        <div className="paper-panel" data-reveal>
          <h2>How findings are confirmed</h2>
          <p className="lead">
            The difference between an alert and a finding is evidence. Here's exactly what happens
            on every scan — and why a result you get is a result we can show.
          </p>
          <ul className="proof-list">
            {PROOF.map((x) => (
              <li key={x.h}>
                <h3>{x.h}</h3>
                <p>{x.p}</p>
              </li>
            ))}
          </ul>
        </div>
      </section>

      {/* FLOW (genuine sequence) */}
      <section className="section">
        <div className="sec-head" data-reveal>
          <h2>URL in, <em>evidence</em> out.</h2>
        </div>
        <div className="flow" data-reveal>
          {FLOW.map(([t, d], i) => (
            <div className="flow-step" key={t}>
              <div className="n">{String(i + 1).padStart(2, "0")}</div>
              <h3>{t}</h3>
              <p>{d}</p>
            </div>
          ))}
        </div>
      </section>

      {/* WHAT WE CHECK — exhibit list */}
      <section className="section" id="checks">
        <div className="sec-head" data-reveal>
          <h2>What we check — and what it costs you if we find it.</h2>
          <p className="lead">
            Each item leads with the business consequence. The technical detail is in the body, for
            the engineers who want it.
          </p>
        </div>
        <div className="exhibits" data-reveal>
          {EXHIBITS.map((e) => (
            <div className="exrow" key={e.ref}>
              <span className="ref">{e.ref}</span>
              <div>
                <h3>{e.title}</h3>
                <p>{e.body}</p>
              </div>
              <span className={`tag ${e.tagClass}`}>{e.tag}</span>
            </div>
          ))}
        </div>
      </section>

      {/* SAMPLE FINDING — fully expanded, on paper (representative) */}
      <section className="section" id="sample">
        <div className="sample">
          <div className="sample-aside" data-reveal>
            <h2>See the engine on a labeled sample.</h2>
            <p className="lead">
              <a href="/demo">/demo</a> runs the free-tier detectors against an invented page that
              never leaves the server. The report is their output: redacted secret samples and the
              headers that page did not send.
            </p>
            <p className="disclaimer">
              Synthetic fixture. Not a customer, not a benchmark, and not a scan of a live site.
              Record that page if you need a demo without pointing the scanner at someone else.
            </p>
            <a className="btn btn-primary" href="/demo">
              Open the labeled sample
            </a>
          </div>
          <ol className="demo-beats" data-reveal>
            <li>
              <span>01</span>
              <div>
                <h3>Read the banner</h3>
                <p>It says the page is synthetic before any finding does.</p>
              </div>
            </li>
            <li>
              <span>02</span>
              <div>
                <h3>Open the first hit</h3>
                <p>The evidence block is what the detector returned, redacted.</p>
              </div>
            </li>
            <li>
              <span>03</span>
              <div>
                <h3>Copy the summary</h3>
                <p>The paste starts with SYNTHETIC FIXTURE, so a caption cannot drift.</p>
              </div>
            </li>
          </ol>
        </div>
      </section>

      {/* PRICING */}
      <section className="section" id="pricing">
        <div className="sec-head" data-reveal>
          <h2>Start free. Go <em>deep</em> when you ship.</h2>
          <p className="lead">
            Prices below are the defaults in this repository. Confirm them before you quote them.
            Limits are what the code enforces.
          </p>
        </div>
        <div className="pricing" data-reveal>
          <div className="plan">
            <span className="pname">{price.free.label}</span>
            <div className="price">{price.free.price}{price.free.period && <small> {price.free.period}</small>}</div>
            <p className="pdesc">The highest-impact checks against one page.</p>
            <ul className="specs">
              <li className="inc">One page, plus up to 12 same-origin scripts</li>
              <li className="inc">{freeChecks} free-tier checks, evidence-gated</li>
              <li className="inc">Impact and fix text on unlocked findings</li>
              <li>Account required on a deployed server</li>
            </ul>
            <a className="btn btn-ghost" href="/login">Create account &amp; scan</a>
          </div>
          <div className="plan featured">
            <span className="ftag">Most thorough</span>
            <span className="pname">{price.deep.label}</span>
            <div className="price">{price.deep.price} <small>{price.deep.period}</small></div>
            <p className="pdesc">Authenticated, multi-page crawl with the full engine.</p>
            <ul className="specs">
              <li className="inc">{deepChecks} more enabled patterns than the free tier</li>
              <li className="inc">Evidence stays off the free response</li>
              <li className="inc">Worker job, after domain verification</li>
              <li className="inc">Private and metadata targets refused</li>
            </ul>
            <a className="btn btn-primary" href="/dashboard">Unlock Deep Scan</a>
          </div>
          <div className="plan">
            <span className="pname">{price.continuous.label}</span>
            <div className="price">{price.continuous.price} <small>{price.continuous.period}</small></div>
            <p className="pdesc">Scheduled re-scans so regressions don't ship silently.</p>
            <ul className="specs">
              <li className="inc">Everything in Deep Scan</li>
              <li className="inc">Re-scan on an interval you set, 1–168 hours</li>
              <li className="inc">Needs the database and cron secret configured</li>
            </ul>
            <a className="btn btn-ghost" href="/dashboard">Start continuous</a>
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section className="section">
        <div className="sec-head" data-reveal>
          <h2>What skeptical engineers ask first.</h2>
        </div>
        <div className="faq" data-reveal>
          {FAQ.map(([q, a]) => (
            <details key={q}>
              <summary>
                {q}
                <span>+</span>
              </summary>
              <div className="ans">{a}</div>
            </details>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="section cta" data-reveal>
        <h2>See what the check can <em>prove</em>.</h2>
        <p className="lead">
          Open the labeled sample, or scan a host you are allowed to test. A finding ships with its evidence.
        </p>
        <div className="cta-actions">
          <a className="btn btn-primary btn-arrow" href="/#scan">Run a free scan</a>
          <a className="btn btn-ghost" href="/#checks">See what we check</a>
        </div>
      </section>
    </div>
  );
}
