import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";
import { NextRequest, NextResponse } from "next/server";
import { fetchCvesByIds } from "@/lib/cves";

export const runtime = "nodejs";

const execFileAsync = promisify(execFile);
const projectRoot = path.resolve(process.cwd(), "..");
const searchScript = path.join(projectRoot, "NoSQL", "search_cves.py");

type SearchHit = { cve_id: string; distance: number };

export async function POST(request: NextRequest) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON." }, { status: 400 });
  }

  const query =
    typeof body === "object" && body !== null && "query" in body && typeof body.query === "string"
      ? body.query.trim().slice(0, 500)
      : "";
  if (query.length < 3) {
    return NextResponse.json({ error: "Enter at least 3 characters to search." }, { status: 400 });
  }

  try {
    const python = process.env.CHROMA_PYTHON ?? (process.platform === "win32" ? "py" : "python3");
    const { stdout } = await execFileAsync(
      python,
      [searchScript, "--json", "--limit", "20", query],
      {
        cwd: projectRoot,
        encoding: "utf8",
        timeout: 90000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
        env: { ...process.env, PYTHONUTF8: "1" },
      },
    );
    const hits = JSON.parse(stdout) as SearchHit[];
    const records = await fetchCvesByIds(hits.map((hit) => hit.cve_id));
    const byId = new Map(records.map((record) => [record.cveId, record]));
    const ranked = hits.flatMap((hit) => {
      const record = byId.get(hit.cve_id);
      return record ? [{ ...record, distance: hit.distance }] : [];
    });

    return NextResponse.json({ records: ranked });
  } catch (error) {
    console.error("Semantic CVE search failed:", error);
    return NextResponse.json(
      {
        error:
          "Semantic search is unavailable. Check that ChromaDB is installed for the configured Python and that the CVE index exists.",
      },
      { status: 503 },
    );
  }
}
