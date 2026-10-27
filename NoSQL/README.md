# ChromaDB semantic search

This directory adds semantic search for the project's CVE JSON dataset. MySQL remains the
source of truth for structured records and relationships; ChromaDB stores searchable CVE
text, embeddings, and a small set of metadata fields.

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

## Index and search

Build or update the index from the JSON files in `CVEs\`:

```powershell
py NoSQL\index_cves.py
```

Search in natural language:

```powershell
py NoSQL\search_cves.py "authentication bypass in a database server"
py NoSQL\search_cves.py --limit 10 "remote code execution"
```

Indexing uses CVE IDs as stable Chroma record IDs, so rerunning it updates existing
records instead of adding duplicates. Records without descriptions are reported and
skipped because there is no text to embed. Search results provide CVE IDs and descriptions;
the application can use those IDs to fetch complete records and relationships from MySQL.

To store the local index somewhere else, set the path before running either script:

```powershell
$env:CHROMA_PATH = "D:\data\cve-chroma"
```

This is a local development index, not yet a web API. For a Next.js UI, expose semantic
search through a server-side API route or a small Python service; do not connect the
browser directly to the database.

## Tests

```powershell
py -m unittest discover -s NoSQL
```
