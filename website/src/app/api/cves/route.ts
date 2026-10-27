import { NextRequest, NextResponse } from "next/server";
import type { RowDataPacket } from "mysql2";
import { getPool } from "@/lib/db";
import type { CveRecord } from "@/lib/cves";

export const runtime = "nodejs";

type CveListRow = RowDataPacket & {
  cveId: string;
  cvss: number | string | null;
  published: string | null;
  description: string | null;
  type: string | null;
  vendors: string | null;
  products: string | null;
  fixDescription: string | null;
};

function parsePositiveInteger(value: string | null, fallback: number, max: number) {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? Math.min(parsed, max) : fallback;
}

function severityCondition(severity: string | null): string | null {
  switch (severity) {
    case "critical": return "c.CVSS >= 9";
    case "high": return "c.CVSS >= 7 AND c.CVSS < 9";
    case "medium": return "c.CVSS >= 4 AND c.CVSS < 7";
    case "low": return "c.CVSS < 4";
    default: return null;
  }
}

export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const query = params.get("q")?.trim().slice(0, 200) ?? "";
  const vendor = params.get("vendor")?.trim().slice(0, 200) ?? "";
  const severity = params.get("severity");
  const page = parsePositiveInteger(params.get("page"), 1, 100000);
  const pageSize = parsePositiveInteger(params.get("pageSize"), 20, 50);
  const offset = (page - 1) * pageSize;
  const conditions = ["1 = 1"];
  const values: (string | number)[] = [];

  if (query) {
    const pattern = `%${query}%`;
    conditions.push(`(
      c.CVE_ID LIKE ? OR COALESCE(c.Description, '') LIKE ?
      OR COALESCE(c.Type, '') LIKE ?
      OR EXISTS (
        SELECT 1
        FROM AFFECTED aq
        JOIN PRODUCT pq ON pq.Product_ID = aq.Product_ID
        JOIN VENDOR vq ON vq.Vendor_ID = pq.Vendor_ID
        WHERE aq.CVE_ID = c.CVE_ID AND (pq.Name LIKE ? OR vq.Name LIKE ?)
      )
    )`);
    values.push(pattern, pattern, pattern, pattern, pattern);
  }

  if (vendor) {
    conditions.push(`EXISTS (
      SELECT 1
      FROM AFFECTED av
      JOIN PRODUCT pv ON pv.Product_ID = av.Product_ID
      JOIN VENDOR vv ON vv.Vendor_ID = pv.Vendor_ID
      WHERE av.CVE_ID = c.CVE_ID AND vv.Name LIKE ?
    )`);
    values.push(`%${vendor}%`);
  }

  const scoreCondition = severityCondition(severity);
  if (scoreCondition) conditions.push(scoreCondition);
  const whereClause = conditions.join(" AND ");

  try {
    const pool = getPool();
    const [countRows] = await pool.execute<RowDataPacket[]>(
      `SELECT COUNT(*) AS total FROM CVE c WHERE ${whereClause}`,
      values,
    );
    const [rows] = await pool.execute<CveListRow[]>(
      `SELECT
         c.CVE_ID AS cveId,
         c.CVSS AS cvss,
         DATE_FORMAT(c.Date, '%Y-%m-%d') AS published,
         c.Description AS description,
         COALESCE(vc.Type, c.Type) AS type,
         GROUP_CONCAT(DISTINCT v.Name ORDER BY v.Name SEPARATOR '||') AS vendors,
         GROUP_CONCAT(DISTINCT p.Name ORDER BY p.Name SEPARATOR '||') AS products,
         MAX(patch.Fix_Desc) AS fixDescription
       FROM CVE c
       LEFT JOIN VULN_CLASS vc ON vc.Vuln_Class_ID = c.Vuln_Class_ID
       LEFT JOIN PATCH patch ON patch.CVE_ID = c.CVE_ID
       LEFT JOIN AFFECTED a ON a.CVE_ID = c.CVE_ID
       LEFT JOIN PRODUCT p ON p.Product_ID = a.Product_ID
       LEFT JOIN VENDOR v ON v.Vendor_ID = p.Vendor_ID
       WHERE ${whereClause}
       GROUP BY c.CVE_ID
       ORDER BY c.Date DESC, c.CVE_ID DESC
       LIMIT ? OFFSET ?`,
      [...values, pageSize, offset],
    );

    const records: CveRecord[] = rows.map((row) => ({
      ...row,
      cvss: row.cvss === null ? null : Number(row.cvss),
      vendors: row.vendors ? row.vendors.split("||") : [],
      products: row.products ? row.products.split("||") : [],
    }));

    return NextResponse.json({
      records,
      total: Number(countRows[0]?.total ?? 0),
      page,
      pageSize,
    });
  } catch (error) {
    console.error("Failed to query CVE list:", error);
    return NextResponse.json(
      { error: "Could not query MySQL. Check your database settings and schema." },
      { status: 500 },
    );
  }
}
