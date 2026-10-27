"""Search indexed CVEs using a natural-language query."""

import argparse
import json
import os
from pathlib import Path

from index_cves import COLLECTION_NAME, DEFAULT_CHROMA_PATH


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("query", nargs="+", help="Describe the vulnerability you're looking for")
    parser.add_argument("--limit", type=int, default=5, help="Maximum number of results (default: 5)")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print results as JSON for use by the web API",
    )
    args = parser.parse_args()
    if args.limit < 1:
        parser.error("--limit must be at least 1")

    import chromadb

    chroma_path = Path(os.environ.get("CHROMA_PATH", DEFAULT_CHROMA_PATH))
    client = chromadb.PersistentClient(path=str(chroma_path))
    collection_names = {collection.name for collection in client.list_collections()}
    if COLLECTION_NAME not in collection_names:
        raise ValueError(
            f"Chroma collection '{COLLECTION_NAME}' is missing. "
            "Run 'py NoSQL\\index_cves.py' first."
        )
    collection = client.get_collection(name=COLLECTION_NAME)
    record_count = collection.count()
    if record_count == 0:
        print("[]" if args.json_output else "No indexed CVEs found.")
        return

    results = collection.query(
        query_texts=[" ".join(args.query)],
        n_results=min(args.limit, record_count),
        include=["documents", "metadatas", "distances"],
    )

    ids = results["ids"][0]
    documents = results["documents"][0]
    metadatas = results["metadatas"][0]
    distances = results["distances"][0]
    if not ids:
        print("[]" if args.json_output else "No indexed CVEs found.")
        return

    if args.json_output:
        output = []
        for cve_id, document, metadata, distance in zip(
            ids, documents, metadatas, distances
        ):
            description = next(
                (
                    line.removeprefix("Description: ")
                    for line in document.splitlines()
                    if line.startswith("Description: ")
                ),
                document,
            )
            output.append(
                {
                    "cve_id": cve_id,
                    "distance": distance,
                    "cvss": metadata.get("cvss") if metadata else None,
                    "description": description,
                }
            )
        print(json.dumps(output))
        return

    for index, (cve_id, document, metadata, distance) in enumerate(
        zip(ids, documents, metadatas, distances), start=1
    ):
        print(f"{index}. {cve_id} (distance: {distance:.4f})")
        if metadata and "cvss" in metadata:
            print(f"   CVSS: {metadata['cvss']}")
        description = next(
            (
                line.removeprefix("Description: ")
                for line in document.splitlines()
                if line.startswith("Description: ")
            ),
            document,
        )
        print(f"   {description}")


if __name__ == "__main__":
    main()
