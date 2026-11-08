import type { Metadata } from "next";
import ScanResultsPanel from "@/components/scan/ScanResultsPanel";
import { runSyntheticFixtureScan } from "@/lib/demo/fixture";
import { reportMarkdown } from "@/lib/share/report-markdown";

export const metadata: Metadata = {
  title: "Labeled sample",
  description:
    "Thugir Scanner runs its free-tier detectors on an in-memory synthetic fixture. The findings are detector output, not a scan of a live site."
};

export default async function DemoPage() {
  const scan = await runSyntheticFixtureScan();
  const markdown = reportMarkdown({
    synthetic: true,
    target: scan.target,
    detectedPlatform: scan.detectedPlatform,
    findings: scan.findings
  });

  return (
    <div className="demo-wrap">
      <div className="demo-banner" data-fixture="synthetic">
        <span>Synthetic fixture — detector output, not a live scan</span>
        <a href="/#scan">Scan a host you own</a>
      </div>

      <header className="demo-header">
        <h1>The engine, on an invented page.</h1>
        <p className="lead">
          {scan.label} Stack signals from this page: {scan.signals.join(", ") || "none"}.{" "}
          {scan.freeChecks} free-tier checks are enabled. {scan.librarySize} patterns are enabled, out of{" "}
          {scan.definedPatterns} defined. The sealed count is the rest of the catalog for this signal, not
          a list of extra hits.
        </p>
      </header>

      <ScanResultsPanel
        scanId={null}
        target={scan.target}
        tierLabel="free"
        detectedPlatform={scan.detectedPlatform}
        findings={scan.findings}
        locked={scan.locked}
        shareNote={scan.label}
        summaryMarkdown={markdown}
      />

      <section className="demo-cta">
        <h2>That was the fixture. A real scan needs a host you can test.</h2>
        <p className="lead" style={{ margin: "0 auto 22px" }}>
          The copy button on this page prefixes the paste with SYNTHETIC FIXTURE.
        </p>
        <div className="cta-actions">
          <a className="btn btn-primary" href="/#scan">
            Back to the scanner
          </a>
          <a className="btn btn-ghost" href="/how-scans-work">
            How a real scan works
          </a>
        </div>
      </section>
    </div>
  );
}
