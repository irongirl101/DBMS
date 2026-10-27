"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import type { CveRecord } from "@/lib/cves";

function severity(cvss: number | null) {
  if (cvss === null) return "Unknown";
  if (cvss >= 9) return "Critical";
  if (cvss >= 7) return "High";
  if (cvss >= 4) return "Medium";
  return "Low";
}

export default function CveDetailPage() {
  const params = useParams<{ cveId: string }>();
  const cveId = params.cveId;
  const [record, setRecord] = useState<CveRecord | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    fetch(`/api/cves/${encodeURIComponent(cveId)}`)
      .then(async (response) => {
        const payload = await response.json();
        if (!response.ok) throw new Error(payload.error ?? "Could not load this CVE.");
        if (active) setRecord(payload.record);
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : "Could not load this CVE.");
      });
    return () => { active = false; };
  }, [cveId]);

  return (
    <main className="detail-page">
      <header className="detail-header">
        <Link className="brand" href="/">
          <span className="brand-mark">C</span>
          <span>CVE<span className="brand-light">Atlas</span></span>
        </Link>
        <Link className="back-link" href="/">← Back to explorer</Link>
      </header>
      <section className="detail-content">
        {error ? (
          <div className="notice error-notice"><strong>Unable to load vulnerability</strong><p>{error}</p></div>
        ) : !record ? (
          <div className="notice loading-notice"><span className="spinner" /> Loading CVE details…</div>
        ) : (
          <>
            <div className="eyebrow"><span className="eyebrow-line" /> VULNERABILITY RECORD</div>
            <h1 className="detail-title">{record.cveId}</h1>
            <div className="detail-tags">
              <span className={`severity severity-${severity(record.cvss).toLowerCase()}`}><span /> {severity(record.cvss)}</span>
              <span className="detail-date">{record.published || "Date unavailable"}</span>
            </div>
            <div className="detail-grid">
              <article className="detail-card detail-description">
                <div className="detail-card-label">DESCRIPTION</div>
                <p>{record.description || "No description is available for this record."}</p>
              </article>
              <article className="detail-card">
                <div className="detail-card-label">CVSS SCORE</div>
                <div className="detail-score">{record.cvss?.toFixed(1) ?? "—"}<span> / 10</span></div>
              </article>
              <article className="detail-card">
                <div className="detail-card-label">WEAKNESS TYPE</div>
                <p>{record.type || "Not classified"}</p>
              </article>
              <article className="detail-card detail-wide">
                <div className="detail-card-label">AFFECTED VENDORS &amp; PRODUCTS</div>
                {record.vendors.length || record.products.length ? (
                  <div className="tag-list">
                    {[...record.vendors, ...record.products].map((item, index) => <span key={`${item}-${index}`}>{item}</span>)}
                  </div>
                ) : <p>No affected product information is available.</p>}
              </article>
              <article className="detail-card detail-wide">
                <div className="detail-card-label">REMEDIATION</div>
                <p>{record.fixDescription || "No patch or remediation guidance is recorded."}</p>
              </article>
            </div>
          </>
        )}
      </section>
    </main>
  );
}
