import ScanForm from "@/components/ScanForm";
import HeroShowcase from "@/components/HeroShowcase";
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
      <>Unverified payment webhooks accept forged "paid" events, and resources fetched by sequential ID without an ownership check (<span className="term">IDOR</span>) expose other accounts. Confirmed on Deep Scan.</>
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
  ["Do I need an account?", "Yes — a free account is required to run a scan, so every request is attributable and rate-limited. There's nothing to install; you scan your live URL from the browser."],
  ["How is this different from a generic scanner?", "Generic scanners run thousands of CVE checks and bury you in maybes. We target the specific misconfigurations AI coding assistants leave behind, and we confirm each one with captured evidence before it's flagged."],
  ["Is it safe to run against production?", "The free scan is read-only and single-request. Deep Scan's active probing only runs against domains you've verified you own or are authorized to test."],
  ["What do I get for free vs. Deep Scan?", "The free scan confirms the highest-impact issues on one page with full evidence and fixes. Structural checks that need authenticated or multi-step probing (IDOR, broken auth, webhook forgery) are sealed and unlock with a Deep Scan."]
];


export default async function HomePage() {
  const settings = await loadMaskedSettings();
  const price = settings.pricing;
  return (
    <div className="lightsite">
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
            Find the flaws <em>AI builders</em> ship,
            <br />
            <em>before</em> attackers do
          </h1>
          <p className="hero-sub">
            Evidence-backed vulnerability findings for vibe-coded apps — trusted proof, not noisy
            alerts, in about ten seconds.
          </p>
          <div className="scan-wrap">
            <ScanForm />
          </div>
        </div>

        <div className="hero-stage" data-reveal>
          <HeroShowcase />
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
            <h2>What one finding looks like.</h2>
            <p className="lead">
              Not a severity pill and a one-liner. Every confirmed issue ships with the captured
              evidence, the plain-English impact, the steps to reproduce, and the exact fix text.
            </p>
            <p className="disclaimer">
              Representative example for illustration — values redacted. Your report contains the
              real captured request/response from your own app.
            </p>
          </div>
          <div className="finding-doc" data-reveal>
            <div className="fd-head">
              <span className="fd-id">EXHIBIT A · CONFIRMED</span>
              <span className="tag verified">verified</span>
            </div>
            <div className="fd-body">
              <h3>Environment file reachable over HTTP</h3>
              <p>
                A production request for <code>/.env</code> returns the file's contents instead of a
                404, exposing live credentials to anyone on the internet.
              </p>

              <div className="fd-label">Evidence captured</div>
              <div className="fd-evidence">{`$ GET https://my-app.com/.env
< HTTP/2 `}<span className="ok">200</span>{`
< content-type: application/octet-stream

DATABASE_URL=postgres://`}<span className="rd">██████████</span>{`
STRIPE_SECRET_KEY=sk_live_`}<span className="rd">████████</span>{`
JWT_SECRET=`}<span className="rd">██████████</span></div>

              <div className="fd-label">Impact</div>
              <p>
                The database URL and Stripe live key grant full read/write to customer data and the
                ability to move money. Treat every value in the file as compromised.
              </p>

              <div className="fd-label">Reproduce</div>
              <ol className="fd-steps">
                <li>Open <code>https://my-app.com/.env</code> in a browser.</li>
                <li>Observe a 200 response with <code>KEY=VALUE</code> lines.</li>
              </ol>

              <div className="fd-label">Fix</div>
              <div className="fd-fix">
                Stop serving dotfiles from the web root, redeploy so <code>/.env</code> returns 404,
                then rotate <code>DATABASE_URL</code>, <code>STRIPE_SECRET_KEY</code> and{" "}
                <code>JWT_SECRET</code> — they must be considered leaked.
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* PRICING */}
      <section className="section" id="pricing">
        <div className="sec-head" data-reveal>
          <h2>Start free. Go <em>deep</em> when you ship.</h2>
          <p className="lead">Launch pricing — concrete limits per tier so you know what you're getting before you spend a minute.</p>
        </div>
        <div className="pricing" data-reveal>
          <div className="plan">
            <span className="pname">{price.free.label}</span>
            <div className="price">{price.free.price}{price.free.period && <small> {price.free.period}</small>}</div>
            <p className="pdesc">The highest-impact checks against one page.</p>
            <ul className="specs">
              <li className="inc">1 page</li>
              <li className="inc">Highest-impact, evidence-gated checks</li>
              <li className="inc">Full impact + fix text</li>
              <li className="inc">~10 second scan</li>
              <li>Free account required</li>
            </ul>
            <a className="btn btn-ghost" href="/login">Create account &amp; scan</a>
          </div>
          <div className="plan featured">
            <span className="ftag">Most thorough</span>
            <span className="pname">{price.deep.label}</span>
            <div className="price">{price.deep.price} <small>{price.deep.period}</small></div>
            <p className="pdesc">Authenticated, multi-page crawl with the full engine.</p>
            <ul className="specs">
              <li className="inc">Up to 25 pages</li>
              <li className="inc">30+ checks incl. IDOR, broken auth, webhook forgery</li>
              <li className="inc">Authenticated crawl</li>
              <li className="inc">All severities, evidence-gated</li>
              <li className="inc">Typical run: 3–8 minutes</li>
            </ul>
            <a className="btn btn-primary" href="/dashboard">Unlock Deep Scan</a>
          </div>
          <div className="plan">
            <span className="pname">{price.continuous.label}</span>
            <div className="price">{price.continuous.price} <small>{price.continuous.period}</small></div>
            <p className="pdesc">Scheduled re-scans so regressions don't ship silently.</p>
            <ul className="specs">
              <li className="inc">Everything in Deep Scan</li>
              <li className="inc">Weekly automatic re-scans</li>
              <li className="inc">Alerts on new findings</li>
              <li className="inc">History + trend tracking</li>
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
        <h2>See what your app is <em>leaking</em>.</h2>
        <p className="lead">
          One page, about ten seconds, evidence attached. Create a free account and run it.
        </p>
        <div className="cta-actions">
          <a className="btn btn-primary btn-arrow" href="/#scan">Run a free scan</a>
          <a className="btn btn-ghost" href="/#checks">See what we check</a>
        </div>
      </section>
    </div>
  );
}
