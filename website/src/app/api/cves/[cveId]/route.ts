import { NextRequest, NextResponse } from "next/server";
import { fetchCve } from "@/lib/cves";

export const runtime = "nodejs";

type RouteContext = { params: Promise<{ cveId: string }> };

export async function GET(_request: NextRequest, context: RouteContext) {
  const { cveId } = await context.params;
  if (!/^CVE-\d{4}-\d{4,}$/i.test(cveId)) {
    return NextResponse.json({ error: "Invalid CVE ID." }, { status: 400 });
  }

  try {
    const record = await fetchCve(cveId.toUpperCase());
    if (!record) {
      return NextResponse.json({ error: "CVE record not found." }, { status: 404 });
    }
    return NextResponse.json({ record });
  } catch (error) {
    console.error(`Failed to load ${cveId}:`, error);
    return NextResponse.json(
      { error: "Could not query MySQL. Check your database settings and schema." },
      { status: 500 },
    );
  }
}
