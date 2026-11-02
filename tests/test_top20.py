import unittest
import json
from pathlib import Path

class TestTop20(unittest.TestCase):
    def test_top20_projects(self):
        projects_file = Path("docs/studies/top20/projects.json")
        self.assertTrue(projects_file.exists())
        with open(projects_file) as f:
            projects = json.load(f)
        
        self.assertEqual(len(projects), 20)
        
        names = [p["name"] for p in projects]
        self.assertEqual(len(set(names)), 20)
        
        for p in projects:
            self.assertIn("top_cves", p)
            self.assertGreaterEqual(len(p["top_cves"]), 5)
            for cve in p["top_cves"]:
                self.assertIn("id", cve)
                self.assertIn("fix_sha", cve)
                self.assertTrue(bool(cve["fix_sha"]))

    def test_lessons(self):
        lessons_file = Path("docs/studies/top20/lessons.md")
        self.assertTrue(lessons_file.exists())
        content = lessons_file.read_text()
        # Verify it has citations
        self.assertIn("CVE-", content)
