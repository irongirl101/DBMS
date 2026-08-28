
#NOTE, PLEASE TEST THIS!!!!!

import sys
import json
from pathlib import Path
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from models import Session, Vendor, Product, ProductVendor, CVE, VulnClass, Affected


def parse_date(value: str):
    """CVE JSON dates look like '2020-01-08T18:25:12.000Z'."""
    if not value:
        return None
    try:
        return datetime.strptime(value[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def get_or_create_vendor(session, name: str) -> Vendor:
    vendor = session.query(Vendor).filter_by(Name=name).first()
    if vendor is None:
        vendor = Vendor(Name=name)
        session.add(vendor)
        session.flush()  # get Vendor_ID without committing
    return vendor


def get_or_create_product(session, name: str, version: str) -> Product:
    # One row per (Name, Ver) combination -- see schema discussion:
    # Product.Ver can't hold multiple versions, so each version is its own row.
    product = session.query(Product).filter_by(Name=name, Ver=version).first()
    if product is None:
        product = Product(Name=name, Ver=version)
        session.add(product)
        session.flush()
    return product


def load_record(session, data: dict):
    cve_id = data.get("cveMetadata", {}).get("cveId")
    if not cve_id:
        return  # skip malformed records

    cna = data.get("containers", {}).get("cna", {})

    # --- CVE core fields ---
    descriptions = cna.get("descriptions", [])
    desc_text = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"), None
    )

    problem_types = cna.get("problemTypes", [])
    type_text = None
    if problem_types:
        pt_desc = problem_types[0].get("descriptions", [])
        type_text = next(
            (d["description"] for d in pt_desc if d.get("lang") == "en"), None
        )

    # CVSS is often absent -- CVE JSON 5.0 doesn't guarantee a metrics block
    cvss_score = None
    metrics = cna.get("metrics", [])
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m:
                cvss_score = m[key].get("baseScore")
                break
        if cvss_score is not None:
            break

    date_published = parse_date(data.get("cveMetadata", {}).get("datePublished"))

    cve_row = session.query(CVE).filter_by(CVE_ID=cve_id).first()
    if cve_row is None:
        cve_row = CVE(
            CVE_ID=cve_id,
            CVSS=cvss_score,
            Date=date_published,
            Desc=desc_text,
            Type=type_text,
        )
        session.add(cve_row)
        session.flush()

    # --- Vuln_Class (one per problemType entry, mirrors "Classified as") ---
    if type_text:
        vc = VulnClass(CVE_ID=cve_id, Type=type_text, CVSS=cvss_score)
        session.add(vc)

    # --- Vendor / Product / Affected ---
    affected_entries = cna.get("affected", [])
    for entry in affected_entries:
        vendor_name = entry.get("vendor", "n/a")
        product_name = entry.get("product", "unknown")
        versions = entry.get("versions", [])

        vendor = get_or_create_vendor(session, vendor_name)

        if not versions:
            versions = [{"version": None}]

        for v in versions:
            version_val = v.get("version")
            product = get_or_create_product(session, product_name, version_val)

            # link Product <-> Vendor (skip duplicates)
            exists = (
                session.query(ProductVendor)
                .filter_by(Product_ID=product.ID, Vendor_ID=vendor.Vendor_ID)
                .first()
            )
            if not exists:
                session.add(
                    ProductVendor(Product_ID=product.ID, Vendor_ID=vendor.Vendor_ID)
                )

            # link Product <-> CVE (skip duplicates)
            exists = (
                session.query(Affected)
                .filter_by(Product_ID=product.ID, CVE_ID=cve_id)
                .first()
            )
            if not exists:
                session.add(Affected(Product_ID=product.ID, CVE_ID=cve_id))

    # NOTE: no PATCH data exists in cvelistV5 records -- PATCH table is
    # intentionally left untouched here. Populate it from a separate source.


def main(root_dir: str):
    session = Session()
    root = Path(root_dir)
    json_files = list(root.rglob("*.json"))
    print(f"Found {len(json_files)} JSON files under {root_dir}")

    loaded, failed = 0, 0
    for i, path in enumerate(json_files, 1):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            load_record(session, data)
            loaded += 1
        except Exception as e:
            failed += 1
            print(f"  [skip] {path.name}: {e}")

        # commit in batches instead of per-file
        if i % 500 == 0:
            session.commit()
            print(f"  ...committed {i}/{len(json_files)}")

    try:
        session.commit()
    except IntegrityError as e:
        session.rollback()
        print(f"Final commit failed: {e}")

    session.close()
    print(f"Done. Loaded {loaded}, failed {failed}.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 load_cves.py /path/to/cvelistV5/cves")
        sys.exit(1)
    main(sys.argv[1])
