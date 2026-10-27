"""Convert CVE JSON records into searchable text and Chroma metadata."""

from typing import Any


class MissingDescriptionError(ValueError):
    """Raised when a CVE has no text to embed for semantic search."""


def extract_cve_document(data: dict[str, Any]) -> tuple[str, str, dict[str, str | int | float]]:
    metadata = data.get("cveMetadata", {})
    cve_id = metadata.get("cveId") if isinstance(metadata, dict) else None
    if not cve_id:
        raise ValueError("record has no cveMetadata.cveId")

    cna = data.get("containers", {}).get("cna", {})
    if not isinstance(cna, dict):
        raise ValueError(f"{cve_id} has invalid containers.cna")

    descriptions = cna.get("descriptions", [])
    description = next(
        (
            item.get("value", "").strip()
            for item in descriptions
            if isinstance(item, dict) and item.get("value", "").strip()
        ),
        "",
    )
    if not description:
        raise MissingDescriptionError(f"{cve_id} has no description to index")

    fields = [f"CVE: {cve_id}", f"Description: {description}"]
    chroma_metadata: dict[str, str | int | float] = {"cve_id": cve_id}

    published = metadata.get("datePublished") if isinstance(metadata, dict) else None
    if published:
        chroma_metadata["published"] = published[:10]

    cvss = None
    for metric in cna.get("metrics", []):
        if not isinstance(metric, dict):
            continue
        for key, value in metric.items():
            if key.lower().startswith("cvss") and isinstance(value, dict):
                cvss = value.get("baseScore")
                if cvss is not None:
                    break
        if cvss is not None:
            break
    if isinstance(cvss, (int, float)):
        chroma_metadata["cvss"] = float(cvss)
        fields.append(f"CVSS: {cvss}")

    weaknesses = []
    for problem_type in cna.get("problemTypes", []):
        if not isinstance(problem_type, dict):
            continue
        for item in problem_type.get("descriptions", []):
            if isinstance(item, dict):
                weakness = item.get("cweId") or item.get("description")
                if weakness and weakness not in weaknesses:
                    weaknesses.append(weakness)
    if weaknesses:
        chroma_metadata["weakness"] = ", ".join(weaknesses)
        fields.append(f"Weakness: {', '.join(weaknesses)}")

    affected_products = []
    for affected in cna.get("affected", []):
        if not isinstance(affected, dict):
            continue
        vendor = affected.get("vendor")
        product = affected.get("product")
        if vendor or product:
            affected_products.append(" ".join(part for part in (vendor, product) if part))
    if affected_products:
        fields.append(f"Affected products: {', '.join(affected_products)}")

    solutions = [
        item.get("value", "").strip()
        for item in cna.get("solutions", [])
        if isinstance(item, dict) and item.get("value", "").strip()
    ]
    if solutions:
        fields.append(f"Remediation: {' '.join(solutions)}")

    return cve_id, "\n".join(fields), chroma_metadata
