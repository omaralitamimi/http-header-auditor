import unittest
from main import audit


class HeaderTests(unittest.TestCase):
    def test_reports_present_and_missing(self):
        result = audit("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\nServer: demo")
        self.assertIn("x-content-type-options", result["present"])
        self.assertEqual(result["observed_server"], "demo")
        self.assertTrue(any(item["header"] == "content-security-policy" for item in result["missing"]))


if __name__ == "__main__":
    unittest.main()
