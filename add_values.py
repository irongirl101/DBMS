"""
Load CVE JSON records into the cve_management_system MySQL database.

Setup before running:
    pip install mysql-connector-python

"""

import json
import os
import sys
import mysql.connector
from mysql.connector import Error

# ---- CONFIG: edit these ----
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'cass2601', #replace with your MySQL root password
    'database': 'cve_management_system'
}
CVE_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'CVEs')
# -----------------------------

# caches so we don't hit the DB or re-insert the same vendor/product/class repeatedly
vendor_cache = {}
product_cache = {}
vuln_class_cache = {}


def safe_get(d, *keys, default=None):
    """Walk a nested dict safely, returning default if any key is missing."""
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
        else:
            return default
    return d if d is not None else default


def parse_cve_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    cve_id = safe_get(data, 'cveMetadata', 'cveId')
    date_published = safe_get(data, 'cveMetadata', 'datePublished')
    if date_published:
        date_published = date_published[:10]  # trim to YYYY-MM-DD for MySQL DATE

    cna = safe_get(data, 'containers', 'cna', default={})

    # description
    descriptions = cna.get('descriptions', [])
    description = descriptions[0]['value'] if descriptions else None

    # CVSS base score (check v3.1, v3.0, v4.0 in that order)
    cvss = None
    for metric in cna.get('metrics', []):
        for key in metric:
            if key.lower().startswith('cvss'):
                cvss = metric[key].get('baseScore')
                break
        if cvss is not None:
            break

    # vulnerability classification (CWE)
    cwe_id = None
    problem_types = cna.get('problemTypes', [])
    if problem_types:
        pdescs = problem_types[0].get('descriptions', [])
        if pdescs:
            cwe_id = pdescs[0].get('cweId') or pdescs[0].get('description')
            if cwe_id:
                cwe_id = cwe_id[:255]

    # affected vendor/product pairs
    vendors_products = []
    for a in cna.get('affected', []):
        vendor = a.get('vendor')
        product = a.get('product')
        if vendor and product:
            vendors_products.append((vendor.strip(), product.strip()))

    # fix/patch description
    solutions = cna.get('solutions', [])
    fix_desc = solutions[0]['value'] if solutions else None

    return {
        'cve_id': cve_id,
        'date': date_published,
        'description': description,
        'cvss': cvss,
        'cwe_id': cwe_id,
        'vendors_products': vendors_products,
        'fix_desc': fix_desc,
    }


def get_or_create_vendor(cursor, name):
    if name in vendor_cache:
        return vendor_cache[name]
    cursor.execute("SELECT Vendor_ID FROM VENDOR WHERE Name = %s", (name,))
    row = cursor.fetchone()
    if row:
        vendor_cache[name] = row[0]
        return row[0]
    cursor.execute("INSERT INTO VENDOR (Name) VALUES (%s)", (name,))
    vendor_cache[name] = cursor.lastrowid
    return cursor.lastrowid


def get_or_create_product(cursor, name, vendor_id):
    cache_key = (name, vendor_id)
    if cache_key in product_cache:
        return product_cache[cache_key]
    cursor.execute(
        "SELECT Product_ID FROM PRODUCT WHERE Name = %s AND Vendor_ID = %s",
        (name, vendor_id)
    )
    row = cursor.fetchone()
    if row:
        product_cache[cache_key] = row[0]
        return row[0]
    cursor.execute(
        "INSERT INTO PRODUCT (Name, Ver, Vendor_ID) VALUES (%s, %s, %s)",
        (name, None, vendor_id)
    )
    product_cache[cache_key] = cursor.lastrowid
    return cursor.lastrowid


def get_or_create_vuln_class(cursor, cwe_id, cvss):
    if not cwe_id:
        return None
    if cwe_id in vuln_class_cache:
        return vuln_class_cache[cwe_id]
    cursor.execute("SELECT Vuln_Class_ID FROM VULN_CLASS WHERE Type = %s", (cwe_id,))
    row = cursor.fetchone()
    if row:
        vuln_class_cache[cwe_id] = row[0]
        return row[0]
    cursor.execute(
        "INSERT INTO VULN_CLASS (Type, CVSS) VALUES (%s, %s)",
        (cwe_id, cvss)
    )
    vuln_class_cache[cwe_id] = cursor.lastrowid
    return cursor.lastrowid
def main():
    if not os.path.isdir(CVE_FOLDER):
        print(f"ERROR: folder not found: {CVE_FOLDER}")
        sys.exit(1)

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
    except Error as e:
        print(f"ERROR connecting to MySQL: {e}")
        sys.exit(1)

    cursor = conn.cursor()

    json_files = [f for f in os.listdir(CVE_FOLDER) if f.endswith('.json')]
    print(f"Found {len(json_files)} JSON files in {CVE_FOLDER}")

    loaded = 0
    skipped = 0

    for filename in json_files:
        filepath = os.path.join(CVE_FOLDER, filename)
        try:
            record = parse_cve_file(filepath)

            if not record['cve_id']:
                print(f"  skip {filename}: no CVE_ID found")
                skipped += 1
                continue

            vuln_class_id = get_or_create_vuln_class(cursor, record['cwe_id'], record['cvss'])

            # insert CVE (skip if already loaded)
            cursor.execute("SELECT 1 FROM CVE WHERE CVE_ID = %s", (record['cve_id'],))
            if cursor.fetchone():
                skipped += 1
                continue

            cursor.execute(
                """INSERT INTO CVE (CVE_ID, CVSS, Date, Description, Type, Vuln_Class_ID)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (record['cve_id'], record['cvss'], record['date'],
                 record['description'], record['cwe_id'], vuln_class_id)
            )

            # insert vendor/product + AFFECTED link
            for vendor_name, product_name in record['vendors_products']:
                vendor_id = get_or_create_vendor(cursor, vendor_name)
                product_id = get_or_create_product(cursor, product_name, vendor_id)
                cursor.execute(
                    """INSERT IGNORE INTO AFFECTED (Product_ID, CVE_ID) VALUES (%s, %s)""",
                    (product_id, record['cve_id'])
                )

            # insert PATCH if there's a fix description
            if record['fix_desc']:
                cursor.execute(
                    """INSERT INTO PATCH (Patch_Fix_Date, Fix_Desc, CVE_ID)
                       VALUES (%s, %s, %s)""",
                    (None, record['fix_desc'], record['cve_id'])
                )

            conn.commit()
            loaded += 1
            if loaded % 50 == 0:
                print(f"  loaded {loaded} so far...")

        except Error as e:
            print(f"  ERROR on {filename}: {e}")
            conn.rollback()
            skipped += 1

    print(f"\nDone. Loaded: {loaded}, Skipped: {skipped}")
    cursor.close()
    conn.close()


if __name__ == '__main__':
    main()