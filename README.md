# CVE Management System

A local vulnerability-management project combining a normalized MySQL database,
ChromaDB semantic search, and a Next.js web application.

## What the project does

- Loads CVE JSON files from `CVEs/` into MySQL.
- Organizes vendors, products, CVEs, weakness classes, affected-product relationships,
  and remediation notes in a relational schema.
- Builds a persistent ChromaDB index from CVE descriptions and related text.
- Provides a Next.js UI for keyword browsing, vendor and CVSS severity filters,
  pagination, CVE details, and natural-language semantic search.

## Architecture

```text
CVEs/*.json
    ├── add_values.py ───────────────> MySQL
    └── NoSQL/index_cves.py ─────────> ChromaDB

Next.js website
    ├── browse, filters, CVE details ─> MySQL (server-side)
    └── semantic query ───────────────> ChromaDB ── CVE IDs ──> MySQL details
```

MySQL is the source of truth for full CVE records and their relationships. ChromaDB is
a semantic-search index, not a replacement for MySQL or an archive of the complete
source JSON. The Next.js server mediates access; the browser never connects directly to
either database.

## Project structure

| Path | Purpose |
| --- | --- |
| `CVEs/` | Source CVE JSON documents |
| `DDL.sql` | MySQL schema definition and manual SQL examples |
| `add_values.py` | Loads CVE JSON data into MySQL |
| `NoSQL/` | ChromaDB indexing, semantic-search CLI, and tests |
| `website/` | Next.js app, API routes, and database-backed UI |
| `ER Diagram.md` | Entity-relationship diagram |
| `Schema Diagram.md` | Relational schema diagram |

## Requirements

- MySQL with the project schema and CVE data loaded.
- Python and `pip`. These steps use the regular Python installation; a virtual
  environment is not required.
- Node.js 20.9 or newer and npm.

## Database setup

Review `DDL.sql` before running it: it includes `TRUNCATE TABLE` and `DROP DATABASE`
statements that can erase data. Do not execute those statements against a database you
need to keep. Create/load the MySQL schema and data using your preferred MySQL workflow.
Review the database configuration in `add_values.py` before using the loader. Keep real
passwords in local configuration, not source code or committed files.

## ChromaDB setup

From the repository root in PowerShell:

```powershell
py -m pip install --user -r NoSQL\requirements.txt
py -c "import chromadb; print(chromadb.__version__)"
py NoSQL\index_cves.py
```

The persistent index defaults to `%USERPROFILE%\.cve-management\chroma`. Indexing uses
CVE IDs as stable record IDs, so rerunning updates existing entries. Records without
descriptions are reported and skipped. For CLI usage and tests, see
[NoSQL/README.md](NoSQL/README.md).

## Run the website

Run npm commands in the `website` directory, where its `package.json` lives. For a local
copy at `C:\DBMS`:

```powershell
Set-Location C:\DBMS\website
Copy-Item .env.example .env.local
```

Edit `.env.local` with your local MySQL settings (`MYSQL_HOST`, `MYSQL_PORT`,
`MYSQL_USER`, `MYSQL_PASSWORD`, and `MYSQL_DATABASE`). Keep actual credentials only in
`.env.local`; never add them to `.env.example`, commit them, or paste them into chat.
Then install and start the app:

```powershell
npm install
npm run dev
```

Open the local address printed by Next.js, usually
[http://localhost:3000](http://localhost:3000). Keep the terminal open while using the
site. Run npm from `website/`, not the repository root. If npm installation hangs in a
OneDrive-synced checkout, run a local copy outside OneDrive rather than copying the
large `node_modules` directory back into the synced folder. A copied project needs its
own `website/.env.local`.

For website configuration and troubleshooting, see
[website/README.md](website/README.md).

## Tests

From the repository root:

```powershell
py -m unittest discover -s NoSQL -v
```

From `website/`:

```powershell
npm run typecheck
npm run build
```

## Data model

The relational schema contains Vendor, Product, Vulnerability Class, CVE, Patch, and
Affected entities. See [ER Diagram.md](ER%20Diagram.md),
[Schema Diagram.md](Schema%20Diagram.md), and [DDL.sql](DDL.sql).

## What this project is
This project is a relational database system for managing and analyzing Common Vulnerabilities and Exposures (CVEs). It is built to store vulnerability data in a structured and meaningful way so that it can be queried, compared, and reviewed like a real security database.

At its core, the project is about turning raw vulnerability information into usable, organized records. Instead of storing everything as unstructured text, the data is broken into logical entities such as vendors, software products, weakness classes, CVEs, affected relationships, and remediation details.

## Why this project exists
Modern software systems are affected by many vulnerabilities, and teams often need to answer practical questions such as:
- Which product is affected by a given CVE?
- Which vendor is responsible for that product?
- What is the CVSS severity score?
- Which weakness category does the issue belong to?
- Is there a patch or mitigation recommendation?

This project provides a simple but realistic way to manage that information in a database, making it easier to analyze security risk and track remediation.

## Main idea behind the system
The central object in the project is the CVE record. Each vulnerability entry contains information such as:
- the CVE ID,
- publication date,
- description,
- CVSS score,
- vulnerability type,
- affected product(s),
- vendor relationship,
- and fix or mitigation information.

The design is normalized, which means the database stores each concept once and links related records together instead of duplicating data everywhere. This keeps the system cleaner and easier to maintain.

## Core database structure
The project uses a relational model with several main tables:

### Vendor
Stores the organization or company behind a product.

### Product
Stores the software product and its relationship to a vendor.

### Vulnerability Class
Stores the weakness category or classification associated with a CVE, such as a CWE type.

### CVE
Stores the vulnerability details themselves, including ID, date, description, severity, and type.

### Patch
Stores remediation or fix guidance related to a vulnerability.

### Affected
Links CVEs to the products affected by them.

This is important because a single CVE can impact multiple products, and a product may be affected by many CVEs.

## How the project works in practice
The project reads vulnerability information from JSON files and loads it into a MySQL database. Each JSON record contains structured metadata such as:
- CVE identifier
- publication date
- vendor and product details
- severity metrics
- weakness classification
- description
- remediation or solution guidance

A Python script parses these files and inserts the data into the correct tables. In this way, the project transforms raw CVE data into a queryable database that can support tracking and analysis.

## Semantic search with ChromaDB
The `NoSQL` directory contains an optional ChromaDB index for semantic search over CVE descriptions, affected products, weakness types, and remediation text. MySQL remains the source of truth for relational queries; ChromaDB returns relevant CVE IDs that an application can use to retrieve complete records from MySQL. See [NoSQL/README.md](NoSQL/README.md) for setup and usage.

## Website
The `website` directory contains a Next.js CVE explorer with MySQL-backed browsing and filters, CVE detail pages, and semantic search through the ChromaDB index. See [website/README.md](website/README.md) for configuration and startup instructions.

## What this project is trying to solve
This project reflects a real-world software security need: organizations must keep track of vulnerabilities across their products, understand their impact, and prioritize fixes. The database helps with that by making the data searchable and organized.

It is useful for:
- monitoring vulnerabilities affecting software products,
- evaluating severity and risk,
- grouping issues by weakness type,
- checking whether a patch exists,
- and preparing reports for security review or remediation planning.

## Why the database design matters
The project is designed to be practical, not just theoretical. The relational model keeps records consistent and scalable:
- vendor names are stored once,
- products are linked to their correct vendor,
- vulnerability records are separated from product mappings,
- patch information is stored independently,
- and affected relationships are maintained through a proper link table.

This improves data integrity and makes the project easier to extend later.

## What makes the project useful
The project combines three important ideas:
1. a realistic cybersecurity domain,
2. a clean relational database schema,
3. automated ingestion of CVE data from JSON files.

That combination makes it a strong example of how database design can support vulnerability management and security analysis.

## Typical use cases
A user of this system could:
- load a batch of CVE records into the database,
- look up all vulnerabilities affecting a particular product,
- filter by vendor or severity score,
- group issues by weakness type,
- review fix or mitigation information,
- and build reports for risk assessment.

## Summary
This project is a CVE management database built to model actual vulnerability information in a structured way. It helps organize security data around vendors, products, weakness classes, severity scores, and patch guidance so that the information can be queried and used in a practical security context. In short, it is a database-driven system for understanding and managing software vulnerabilities.
