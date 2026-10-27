import unittest

from mailcheck.dns import FileResolver
from mailcheck.spf import check_host


def R(records):
    return FileResolver({"records": records})


class SpfTest(unittest.TestCase):
    def test_ip4_pass_and_fail(self):
        r = R({"example.com": {"TXT": ["v=spf1 ip4:192.0.2.0/28 -all"]}})
        self.assertEqual(check_host(r, "192.0.2.10", "example.com"), "pass")
        self.assertEqual(check_host(r, "192.0.2.99", "example.com"), "fail")

    def test_softfail_and_neutral(self):
        r = R({"a.test": {"TXT": ["v=spf1 ~all"]}, "b.test": {"TXT": ["v=spf1 ip4:192.0.2.1"]}})
        self.assertEqual(check_host(r, "192.0.2.10", "a.test"), "softfail")
        self.assertEqual(check_host(r, "192.0.2.10", "b.test"), "neutral")

    def test_mx_and_a(self):
        r = R({"example.com": {"TXT": ["v=spf1 mx a:relay.example.com -all"], "MX": ["10 mail.example.com"]},
               "mail.example.com": {"A": ["192.0.2.10"]}, "relay.example.com": {"A": ["192.0.2.20"]}})
        self.assertEqual(check_host(r, "192.0.2.10", "example.com"), "pass")
        self.assertEqual(check_host(r, "192.0.2.20", "example.com"), "pass")
        self.assertEqual(check_host(r, "192.0.2.30", "example.com"), "fail")

    def test_include_and_redirect(self):
        r = R({"example.com": {"TXT": ["v=spf1 include:_spf.example.net -all"]},
               "_spf.example.net": {"TXT": ["v=spf1 ip6:2001:db8::/32 -all"]},
               "example.org": {"TXT": ["v=spf1 redirect=example.com"]}})
        self.assertEqual(check_host(r, "2001:db8::10", "example.com"), "pass")
        self.assertEqual(check_host(r, "2001:db8::10", "example.org"), "pass")
        self.assertEqual(check_host(r, "192.0.2.10", "example.com"), "fail")

    def test_include_missing_is_permerror(self):
        r = R({"example.com": {"TXT": ["v=spf1 include:nothing.example.net -all"]}})
        self.assertEqual(check_host(r, "192.0.2.10", "example.com"), "permerror")

    def test_multiple_records_permerror(self):
        r = R({"example.com": {"TXT": ["v=spf1 -all", "v=spf1 ip4:192.0.2.10 -all"]}})
        self.assertEqual(check_host(r, "192.0.2.10", "example.com"), "permerror")

    def test_lookup_limit(self):
        recs = {f"d{i}.test": {"TXT": [f"v=spf1 include:d{i+1}.test -all"]} for i in range(12)}
        recs["d12.test"] = {"TXT": ["v=spf1 ip4:192.0.2.10 -all"]}
        self.assertEqual(check_host(R(recs), "192.0.2.10", "d0.test"), "permerror")

    def test_none(self):
        self.assertEqual(check_host(R({}), "192.0.2.10", "example.com"), "none")


if __name__ == "__main__":
    unittest.main()
