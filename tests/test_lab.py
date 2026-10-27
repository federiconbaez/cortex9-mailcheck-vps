import ipaddress
import json
import re
import unittest

from lab import measure


class LabTest(unittest.TestCase):
    def test_lab_meets_criterion(self):
        res = measure.run_lab()
        self.assertEqual(res["total"], 12)
        self.assertGreaterEqual(res["correct"], 11, json.dumps(res["rows"], indent=1))
        self.assertEqual(res["false_ok"], 0)
        self.assertTrue(res["healthy_ok"])

    def test_lab_uses_documentation_values_only(self):
        with open("lab/cases.py", encoding="utf-8") as fh:
            src = fh.read()
        doc4 = ipaddress.ip_network("192.0.2.0/24")
        for m in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", src):
            ip = ipaddress.ip_address(m)
            self.assertTrue(ip in doc4 or ip.is_loopback, m)
        for m in re.findall(r'"(2001:db8:[0-9a-f:/]*)"', src) + re.findall(r"ip6:([0-9a-f:/]+)", src):
            self.assertTrue(ipaddress.ip_network(m, strict=False).subnet_of(ipaddress.ip_network("2001:db8::/32")), m)
        self.assertNotRegex(src, r"\b(?!2001:db8)[0-9a-f]{1,4}:[0-9a-f]{1,4}:[0-9a-f]{0,4}:")
        for host in re.findall(r"\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|test)\b", src):
            self.assertRegex(host, r"(example\.(com|net|org)|\.test|zen\.spamhaus\.org)$", host)


if __name__ == "__main__":
    unittest.main()
