import { NextRequest, NextResponse } from "next/server";
import { authorizeCron } from "@/lib/cron/auth";
import { tickDueMonitors } from "@/lib/monitors/tick";

export const runtime = "nodejs";
export const maxDuration = 60;

// GET /api/cron/monitors — Vercel Cron (hourly) or QStash scheduled tick.
export async function GET(req: NextRequest) {
  if (!(await authorizeCron(req))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const result = await tickDueMonitors();
  return NextResponse.json({ status: "ok", ...result });
}

export async function POST(req: NextRequest) {
  const bodyText = await req.text();
  if (!(await authorizeCron(req, bodyText))) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const result = await tickDueMonitors();
  return NextResponse.json({ status: "ok", ...result });
}
