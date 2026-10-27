# CVE Atlas website

The Next.js UI provides MySQL-backed CVE browsing, vendor and CVSS severity filters,
pagination, CVE detail pages, and natural-language semantic search via ChromaDB.
Browser requests go through server-side Next.js API routes; the browser never connects
directly to either database.

## Requirements

- Node.js 20.9 or newer
- MySQL with the project schema and CVE data loaded
- Python with ChromaDB installed and the CVE collection indexed for semantic search
- npm (included with Node.js)

## Configure

From the `website` folder in the VS Code terminal:

```powershell
Copy-Item .env.example .env.local
```

Edit `.env.local` and set your MySQL connection values. Do not commit `.env.local`.
The optional `CHROMA_PATH` should point to the same persistent index used when running
`py NoSQL\index_cves.py`. On Windows, `CHROMA_PYTHON` defaults to `py`; set it to the
Python executable that has ChromaDB installed if the Python launcher selects a
different Python installation.

Use your local credentials. Keep a real password only in `.env.local`; never put it in
`.env.example`, source code, a commit, or chat. `.env.local` is gitignored. ChromaDB
defaults to `%USERPROFILE%\.cve-management\chroma`; set `CHROMA_PATH` in `.env.local`
only if you indexed to a different directory.

## Install and run

Run npm commands from this `website` directory because `package.json` is here:

```powershell
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The CVE browser and detail pages
query MySQL through server-side API routes. Semantic search calls the local Python
search script from a server-side route; database connections and Python execution are
never exposed directly to browser code.

The UI supports keyword browsing, vendor and CVSS severity filters, pagination, CVE
details, and semantic search. If semantic search is unavailable, verify that the Chroma
index exists and that `CHROMA_PYTHON` points to the Python installation where ChromaDB
is installed. Restart the Next.js server after changing `.env.local`.

If `npm install` hangs inside a OneDrive-synced checkout, run the app from a local copy
outside OneDrive (for example `C:\DBMS\website`). Install npm packages there rather than
copying the large `node_modules` folder back into the synced checkout. Each copied
project needs its own `.env.local`.

## Setup from a local project copy

For a copy at `C:\DBMS`, open PowerShell in VS Code:

```powershell
Set-Location C:\DBMS\website
Copy-Item .env.example .env.local
```

Edit `.env.local` with your MySQL settings and then install and run:

```powershell
npm install
npm run dev
```

Open the address printed by Next.js, usually
[http://localhost:3000](http://localhost:3000). Keep the terminal open while using the
site; press **Ctrl+C** to stop the server. If `'next' is not recognized`, run
`npm install` from `website/`, not the repository root.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `npm install` says `package-lock.json` is missing | Change to the `website` directory; npm must run beside this folder's `package.json`. |
| `Failed to fetch` or `ERR_CONNECTION_REFUSED` | Start the app with `npm run dev` and keep that terminal open. |
| MySQL configuration error | Check `website/.env.local` exists and has all required `MYSQL_*` settings; restart Next.js after editing it. |
| MySQL connection/query error | Check that MySQL is running and the schema and CVE data have been loaded. |
| Semantic search unavailable | Check that `py -c "import chromadb"` succeeds, run `py NoSQL\index_cves.py`, and confirm the app uses the same `CHROMA_PATH` if customized. |

## Checks

```powershell
npm run typecheck
npm run build
```

The project-level `DDL.sql` currently includes `TRUNCATE` statements and a `DROP
DATABASE` statement. Review and remove those destructive statements before using that
file to initialize a database containing data you want to keep.