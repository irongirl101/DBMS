"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useState } from "react";
import type { CveRecord } from "@/lib/cves";

type ListResponse = {
  records: CveRecord[];
  total: number;
  page: number;
  pageSize: number;
};

type SemanticRecord = CveRecord & { distance: number };
type SearchMode = "browse" | "semantic";

const PAGE_SIZE = 20;

function formatDate(value: string | null) {
  if (!value) return "Date unavailable";
  return new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(
    new Date(`${value}T00:00:00`),
  );
}

function severity(cvss: number | null) {
  if (cvss === null) return "Unknown";
  if (cvss >= 9) return "Critical";
  if (cvss >= 7) return "High";
  if (cvss >= 4) return "Medium";
  return "Low";
}

export default function Home() {
  const [mode, setMode] = useState<SearchMode>("browse");
  const [query, setQuery] = useState("");
  const [vendor, setVendor] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [list, setList] = useState<ListResponse | null>(null);
  const [semanticRecords, setSemanticRecords] = useState<SemanticRecord[]>([]);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const loadBrowse = useCallback(async (nextPage: number) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({
        page: String(nextPage),
        pageSize: String(PAGE_SIZE),
      });
      if (query.trim()) params.set("q", query.trim());
      if (vendor.trim()) params.set("vendor", vendor.trim());
      if (severityFilter) params.set("severity", severityFilter);

      const response = await fetch(`/api/cves?${params.toString()}`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Could not load CVEs.");
      setList(payload);
      setPage(nextPage);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Could not load CVEs.");
    } finally {
      setLoading(false);
    }
  }, [query, severityFilter, vendor]);

  const loadSemantic = useCallback(async () => {
    if (!query.trim()) {
      setError("Enter a description of the vulnerability to search.");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/search/semantic", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: query.trim(), limit: PAGE_SIZE }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error ?? "Semantic search failed.");
      setSemanticRecords(payload.records);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Semantic search failed.");
    } finally {
      setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    void loadBrowse(1);
    // Load once at startup; filter values are applied only after submitting the form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (mode === "semantic") {
      void loadSemantic();
    } else {
      void loadBrowse(1);
    }
  }

  function changeMode(nextMode: SearchMode) {
    setMode(nextMode);
    setError("");
    if (nextMode === "browse") {
      void loadBrowse(1);
    } else {
      setSemanticRecords([]);
    }
  }

  const records = mode === "browse" ? list?.records ?? [] : semanticRecords;
  const total = mode === "browse" ? list?.total ?? 0 : semanticRecords.length;
  const pageCount = Math.max(1, Math.ceil((list?.total ?? 0) / PAGE_SIZE));

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <Link className="brand" href="/">
          <span className="brand-mark">C</span>
          <span>CVE<span className="brand-light">Atlas</span></span>
        </Link>
        <div className="side-label">WORKSPACE</div>
        <nav className="side-nav" aria-label="Main navigation">
          <a className="nav-item active" href="#explorer"><span>◫</span> CVE explorer</a>
          <a className="nav-item" href="#search"><span>⌕</span> Search</a>
        </nav>
        <div className="sidebar-bottom">
          <span className="status-dot" />
          <span>MySQL + ChromaDB</span>
          <span className="local-badge">LOCAL</span>
        </div>
      </aside>

      <section className="main-panel" id="explorer">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> Vulnerabilities</div>
          <div className="topbar-right"><span className="live-dot" /> Data explorer</div>
        </header>

        <div className="content">
          <section className="intro">
            <div className="eyebrow"><span className="eyebrow-line" /> THREAT INTELLIGENCE</div>
            <h1>Vulnerability <span>explorer</span></h1>
            <p>Search, investigate, and understand vulnerabilities across your software landscape.</p>
          </section>

          <section className="search-panel" id="search">
            <div className="search-tabs" role="tablist" aria-label="Search type">
              <button
                className={`search-tab ${mode === "browse" ? "selected" : ""}`}
                onClick={() => changeMode("browse")}
                role="tab"
                aria-selected={mode === "browse"}
                type="button"
              >
                <span>⌕</span> Browse &amp; filter
              </button>
              <button
                className={`search-tab ${mode === "semantic" ? "selected" : ""}`}
                onClick={() => changeMode("semantic")}
                role="tab"
                aria-selected={mode === "semantic"}
                type="button"
              >
                <span>✳</span> Semantic search <span className="ai-tag">AI</span>
              </button>
            </div>
            <form onSubmit={handleSubmit}>
              <label className="visually-hidden" htmlFor="query">
                {mode === "semantic" ? "Describe a vulnerability" : "Search CVEs"}
              </label>
              <div className="query-row">
                <div className="query-field">
                  <span className="query-icon">{mode === "semantic" ? "✳" : "⌕"}</span>
                  <input
                    id="query"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                    placeholder={
                      mode === "semantic"
                        ? "Describe what you’re looking for… e.g. authentication bypass"
                        : "Search CVE ID, description, weakness, or product…"
                    }
                  />
                </div>
                <button className="primary-button" disabled={loading} type="submit">
                  {loading ? "Searching…" : mode === "semantic" ? "Find matches" : "Search"}
                  <span>→</span>
                </button>
              </div>
              {mode === "browse" ? (
                <div className="filters">
                  <label>
                    <span>Vendor</span>
                    <input
                      value={vendor}
                      onChange={(event) => setVendor(event.target.value)}
                      placeholder="Any vendor"
                    />
                  </label>
                  <label>
                    <span>Severity</span>
                    <select
                      value={severityFilter}
                      onChange={(event) => setSeverityFilter(event.target.value)}
                    >
                      <option value="">All severities</option>
                      <option value="critical">Critical · 9.0+</option>
                      <option value="high">High · 7.0–8.9</option>
                      <option value="medium">Medium · 4.0–6.9</option>
                      <option value="low">Low · under 4.0</option>
                    </select>
                  </label>
                  <span className="filter-hint">Filters apply to the MySQL records</span>
                </div>
              ) : (
                <div className="semantic-hint">
                  <span>✦</span> Results are ranked by meaning, not just exact keyword matches.
                </div>
              )}
            </form>
          </section>

          <section className="results-section">
            <div className="results-heading">
              <div>
                <div className="section-title">{mode === "semantic" ? "Closest matches" : "CVE records"}</div>
                <div className="section-subtitle">
                  {mode === "semantic"
                    ? "Ranked by semantic similarity"
                    : "Latest records from your vulnerability database"}
                </div>
              </div>
              {!loading && !error && (
                <div className="result-count"><strong>{total.toLocaleString()}</strong> {mode === "semantic" ? "matches" : "records"}</div>
              )}
            </div>

            {error ? (
              <div className="notice error-notice">
                <span className="notice-icon">!</span>
                <div><strong>Unable to load vulnerability data</strong><p>{error}</p></div>
              </div>
            ) : loading ? (
              <div className="notice loading-notice"><span className="spinner" /> Loading vulnerability records…</div>
            ) : records.length === 0 ? (
              <div className="notice empty-notice">
                <span className="notice-icon">⌕</span>
                <div><strong>No matching CVEs</strong><p>Try a different search or relax your filters.</p></div>
              </div>
            ) : (
              <div className="cve-list">
                {records.map((record, index) => (
                  <Link
                    className="cve-card"
                    href={`/cve/${encodeURIComponent(record.cveId)}`}
                    key={record.cveId}
                  >
                    <div className="card-index">{String(index + 1).padStart(2, "0")}</div>
                    <div className="card-main">
                      <div className="card-title-row">
                        <span className="cve-id">{record.cveId}</span>
                        <span className={`severity severity-${severity(record.cvss).toLowerCase()}`}>
                          <span /> {severity(record.cvss)}
                        </span>
                      </div>
                      <p className="card-description">{record.description || "No description is available for this record."}</p>
                      <div className="card-meta">
                        <span>{formatDate(record.published)}</span>
                        {record.type && <><i /> <span>{record.type}</span></>}
                        {record.vendors.length > 0 && <><i /> <span>{record.vendors.slice(0, 2).join(", ")}</span></>}
                      </div>
                    </div>
                    <div className="card-score">
                      <span className="score-label">CVSS</span>
                      <strong className={record.cvss !== null && record.cvss >= 7 ? "score-high" : ""}>
                        {record.cvss?.toFixed(1) ?? "—"}
                      </strong>
                      {mode === "semantic" && "distance" in record && (
                        <small>#{index + 1} match</small>
                      )}
                    </div>
                    <span className="card-arrow">↗</span>
                  </Link>
                ))}
              </div>
            )}

            {mode === "browse" && !loading && !error && list && pageCount > 1 && (
              <div className="pagination">
                <button disabled={page <= 1} onClick={() => void loadBrowse(page - 1)} type="button">← Previous</button>
                <span>Page <strong>{page}</strong> of {pageCount}</span>
                <button disabled={page >= pageCount} onClick={() => void loadBrowse(page + 1)} type="button">Next →</button>
              </div>
            )}
          </section>

          <footer className="footer">
            <span>CV<span className="footer-light">E Atlas</span></span>
            <span>Structured intelligence for a safer software ecosystem</span>
            <span>MYSQL <i /> CHROMADB</span>
          </footer>
        </div>
      </section>
    </main>
  );
}
