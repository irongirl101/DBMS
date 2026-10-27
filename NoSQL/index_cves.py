"""Build or update a persistent ChromaDB index from the CVE JSON files."""

import json
import os
from pathlib import Path

from cve_documents import MissingDescriptionError, extract_cve_document

ROOT = Path(__file__).resolve().parents[1]
CVE_FOLDER = ROOT / "CVEs"
DEFAULT_CHROMA_PATH = Path.home() / ".cve-management" / "chroma"
COLLECTION_NAME = "cve_records"
BATCH_SIZE = 100


def main() -> None:
    import chromadb

    chroma_path = Path(os.environ.get("CHROMA_PATH", DEFAULT_CHROMA_PATH))
    client = chromadb.PersistentClient(path=str(chroma_path))
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    json_files = sorted(CVE_FOLDER.glob("*.json"))
    if not json_files:
        raise FileNotFoundError(f"No CVE JSON files found in {CVE_FOLDER}")

    records = []
    skipped = 0
    for filepath in json_files:
        with filepath.open("r", encoding="utf-8") as source:
            data = json.load(source)
        try:
            cve_id, document, metadata = extract_cve_document(data)
        except MissingDescriptionError as error:
            print(f"Skipping {filepath.name}: {error}")
            skipped += 1
            continue
        records.append((cve_id, document, metadata))

    if not records:
        raise ValueError("No CVE records with descriptions were found to index")

    for start in range(0, len(records), BATCH_SIZE):
        batch = records[start : start + BATCH_SIZE]
        collection.upsert(
            ids=[record[0] for record in batch],
            documents=[record[1] for record in batch],
            metadatas=[record[2] for record in batch],
        )

    print(f"Indexed {len(records)} CVEs into '{COLLECTION_NAME}'. Skipped: {skipped}.")
    print(f"ChromaDB data directory: {chroma_path}")


if __name__ == "__main__":
    main()
