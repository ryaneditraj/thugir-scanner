import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Sample report",
  description:
    "The illustrated Deep Scan sample was removed. Use the labeled fixture, which is real detector output on an invented page.",
  alternates: { canonical: "/demo" }
};

export default function SampleReportPage() {
  return (
    <article className="doc">
      <h1>The drawn sample is gone.</h1>
      <p>
        This URL used to show a fictional Deep Scan with invented row counts. That is not something
        to put in a launch video. The labeled sample runs the free-tier detectors on an in-memory
        page and shows what they return.
      </p>
      <p>
        <Link href="/demo">Open the labeled sample</Link>
      </p>
    </article>
  );
}
