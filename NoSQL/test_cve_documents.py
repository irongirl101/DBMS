import unittest

from cve_documents import extract_cve_document


class ExtractCveDocumentTests(unittest.TestCase):
    def test_extracts_searchable_fields_and_metadata(self):
        data = {
            "cveMetadata": {
                "cveId": "CVE-2025-1234",
                "datePublished": "2025-04-02T10:00:00Z",
            },
            "containers": {
                "cna": {
                    "descriptions": [{"value": "An authentication bypass issue."}],
                    "metrics": [{"cvssV3_1": {"baseScore": 8.1}}],
                    "problemTypes": [
                        {"descriptions": [{"cweId": "CWE-287"}]}
                    ],
                    "affected": [{"vendor": "Example", "product": "Server"}],
                    "solutions": [{"value": "Upgrade to the fixed version."}],
                }
            },
        }

        cve_id, document, metadata = extract_cve_document(data)

        self.assertEqual(cve_id, "CVE-2025-1234")
        self.assertIn("authentication bypass", document)
        self.assertIn("Example Server", document)
        self.assertIn("Upgrade to the fixed version.", document)
        self.assertEqual(metadata["published"], "2025-04-02")
        self.assertEqual(metadata["cvss"], 8.1)
        self.assertEqual(metadata["weakness"], "CWE-287")

    def test_rejects_missing_cve_id(self):
        with self.assertRaisesRegex(ValueError, "cveMetadata.cveId"):
            extract_cve_document({"containers": {"cna": {"descriptions": [{"value": "text"}]}}})

    def test_rejects_missing_description(self):
        data = {
            "cveMetadata": {"cveId": "CVE-2025-1234"},
            "containers": {"cna": {"descriptions": []}},
        }
        with self.assertRaisesRegex(ValueError, "no description"):
            extract_cve_document(data)


if __name__ == "__main__":
    unittest.main()
