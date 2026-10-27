import type { RowDataPacket } from "mysql2";
import { getPool } from "@/lib/db";

export type CveRecord = {
  cveId: string;
  cvss: number | null;
  published: string | null;
  description: string | null;
  type: string | null;
  vendors: string[];
  products: string[];
  fixDescription: string | null;
};

type CveRow = RowDataPacket & {
  cveId: string;
  cvss: number | string | null;
  published: string | null;
  description: string | null;
  type: string | null;
  vendors: string | null;
  products: string | null;
  fixDescription: string | null;
};

const recordSelect = `
  SELECT
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
`;

function mapRow(row: CveRow): CveRecord {
  return {
    cveId: row.cveId,
    cvss: row.cvss === null ? null : Number(row.cvss),
    published: row.published,
    description: row.description,
    type: row.type,
    vendors: row.vendors ? row.vendors.split("||") : [],
    products: row.products ? row.products.split("||") : [],
    fixDescription: row.fixDescription,
  };
}

export async function fetchCvesByIds(ids: string[]): Promise<CveRecord[]> {
  if (ids.length === 0) return [];

  const pool = getPool();
  const placeholders = ids.map(() => "?").join(", ");
  const [rows] = await pool.query<CveRow[]>(
    `${recordSelect}
     WHERE c.CVE_ID IN (${placeholders})
     GROUP BY c.CVE_ID
     ORDER BY FIELD(c.CVE_ID, ${placeholders})`,
    [...ids, ...ids],
  );
  return rows.map(mapRow);
}

export async function fetchCve(cveId: string): Promise<CveRecord | null> {
  const records = await fetchCvesByIds([cveId]);
  return records[0] ?? null;
}
