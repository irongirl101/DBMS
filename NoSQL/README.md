# ChromaDB semantic search

ChromaDB provides a persistent semantic-search index for CVE documents. MySQL remains
the source of truth for structured records and relationships. ChromaDB returns relevant
CVE IDs; the Next.js server uses those IDs to fetch complete record details from MySQL.

The index stores searchable text (description, CVSS, weakness, affected products, and
remediation text when available), an embedding, and small metadata fields. It does not
replace MySQL or archive every field of the original JSON document.

The local setup uses ChromaDB's persistent Python client. Its database defaults to
`~/.cve-management/chroma`, outside the repository. Set `CHROMA_PATH` to use another
directory. The first indexing or search run may download ChromaDB's default embedding
model; both indexing and queries use that same model.

## Install without a virtual environment

From the repository root in the VS Code PowerShell terminal, install ChromaDB into your
user-level Python packages:

```powershell
py -m pip install --user -r NoSQL\requirements.txt
py -c "import chromadb; print('ChromaDB:', chromadb.__version__); import sys; print('Python:', sys.executable)"
```

In VS Code, use **Python: Select Interpreter** from the Command Palette and choose the
Python executable printed by that command. This lets Pylance and the terminal use the
same installation. Installing without a virtual environment can affect other Python
projects on this machine.

## Build or update the index

Build or update the index from the JSON files in `CVEs\`:

```powershell
py NoSQL\index_cves.py
```

The script reads JSON files from `CVEs/` and upserts records into the `cve_records`
collection using each CVE ID as a stable record ID. It reports records without
descriptions and skips them because there is no text to embed. The first run may download
ChromaDB's default embedding model; indexing and searches use that same default model.

The persistent index defaults to `%USERPROFILE%\.cve-management\chroma`, outside the
repository. To use another directory, set `CHROMA_PATH` before indexing and use the same
setting when searching:

```powershell
$env:CHROMA_PATH = "D:\data\cve-chroma"
py NoSQL\index_cves.py
```

## Search from the terminal

```powershell
py NoSQL\search_cves.py "authentication bypass in a database server"
py NoSQL\search_cves.py --limit 10 "remote code execution"
```

The website API uses JSON output:

```powershell
py NoSQL\search_cves.py --json --limit 3 "authentication bypass"
```

If the collection is missing, run the indexing command. If Python cannot import
`chromadb`, install it above and confirm that `py` launches the same Python installation.

## Website integration

The Next.js semantic-search API runs the Python script server-side; Python and ChromaDB
are not exposed to the browser. On Windows, the website defaults to `py`. Set
`CHROMA_PYTHON` in `website/.env.local` if the Python launcher does not use the
installation containing ChromaDB. Set `CHROMA_PATH` there if you use a non-default
index directory.

See [website/README.md](../website/README.md) for website setup and
[the main README](../README.md) for architecture and project setup.

## Tests

```powershell
py -m unittest discover -s NoSQL -v
```
