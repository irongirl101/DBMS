# CVE Management System

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
