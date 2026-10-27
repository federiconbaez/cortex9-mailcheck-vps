import contextlib
import io
import json
import os
import tempfile
import unittest

from lab.cases import IP4, IP6, _pem, base_zone, new_key
from mailcheck import checks
from mailcheck.cli import main as cli_main
from mailcheck.config import parse_main_cf
from mailcheck.dns import FileResolver

KEY = _pem(new_key())
OTHER = _pem(new_key())
PUB = checks.local_dkim_pub(KEY)


def ctx(zone=None, cf_extra="", **kw):
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write("x")
        cert = fh.name
    cf = parse_main_cf(f"myhostname = mail.example.com\nmydomain = example.com\n"
                       f"smtpd_tls_cert_file = {cert}\nsmtp_tls_security_level = may\n" + cf_extra)
    base = dict(main_cf=cf, resolver=FileResolver(zone or base_zone(PUB)), ipv4=IP4, ipv6=IP6,
                opendkim={"Domain": "example.com", "Selector": "mail"}, dkim_key_pem=KEY)
    base.update(kw)
    return checks.Context(**base)


class ChecksTest(unittest.TestCase):
    def test_healthy_without_probe_is_incomplete_not_ok(self):
        rep = checks.run_all(ctx())
        self.assertEqual(rep.overall, "INCOMPLETE")
        self.assertIsNone(rep.root_cause)

    def test_missing_ipv6_is_not_ok(self):
        rep = checks.run_all(ctx(ipv6=None, probe=None))
        self.assertNotEqual(rep.overall, "OK")

    def test_ipv6_disabled_in_postfix_passes(self):
        f = checks.check_ipv6(ctx(cf_extra="inet_protocols = ipv4\n", ipv6=None))
        self.assertEqual(f[0].status, "PASS")

    def test_dkim_match_and_mismatch(self):
        self.assertEqual(checks.check_dkim(ctx())[0].status, "PASS")
        bad = checks.check_dkim(ctx(dkim_key_pem=OTHER))
        self.assertEqual(bad[0].cause, "dkim_key_mismatch")
        self.assertIn(checks.local_dkim_pub(OTHER), bad[0].fix)

    def test_dkim_revoked(self):
        z = base_zone(PUB)
        z["records"]["mail._domainkey.example.com"]["TXT"] = ["v=DKIM1; k=rsa; p="]
        self.assertEqual(checks.check_dkim(ctx(zone=z))[0].cause, "dkim_key_mismatch")

    def test_dkim_unreadable_key_is_not_run(self):
        self.assertEqual(checks.check_dkim(ctx(dkim_key_pem=b"garbage"))[0].status, "NOT_RUN")

    def test_dkim_unaligned(self):
        z = base_zone(PUB)
        z["records"]["mail._domainkey.example.net"] = {"TXT": [f"v=DKIM1; p={PUB}"]}
        f = checks.check_dkim(ctx(zone=z, opendkim={"Domain": "example.net", "Selector": "mail"}))
        self.assertIn("dkim_unaligned", [x.cause for x in f])

    def test_dkim_config_missing(self):
        self.assertEqual(checks.check_dkim(ctx(opendkim=None))[0].cause, "dkim_config_missing")

    def test_dmarc_invalid(self):
        z = base_zone(PUB)
        z["records"]["_dmarc.example.com"]["TXT"] = ["v=DMARC1; rua=mailto:x@example.com"]
        self.assertEqual(checks.check_dmarc(ctx(zone=z)).cause, "dmarc_invalid")

    def test_spf_plus_all_flagged(self):
        z = base_zone(PUB)
        z["records"]["example.com"]["TXT"] = ["v=spf1 +all"]
        causes = [f.cause for f in checks.check_spf(ctx(zone=z))]
        self.assertIn("spf_too_permissive", causes)

    def test_mx_missing(self):
        z = base_zone(PUB)
        z["records"]["example.com"]["MX"] = []
        self.assertEqual(checks.check_mx(ctx(zone=z)).cause, "mx_missing")

    def test_ordering_puts_port25_and_ptr_first(self):
        z = base_zone(PUB)
        del z["ptr"][IP4]
        z["records"]["example.com"]["TXT"] = []
        rep = checks.run_all(ctx(zone=z, probe=("127.0.0.1", 1), probe_timeout=0.5))
        self.assertEqual(rep.root_cause, "port25_blocked")
        causes = [f.cause for f in rep.failures]
        self.assertLess(causes.index("ptr_missing"), causes.index("spf_missing"))

    def test_dkim_pub_cli(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k.pem")
            with open(p, "wb") as fh:
                fh.write(KEY)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(cli_main(["dkim-pub", "--key", p]), 0)
            self.assertEqual(buf.getvalue().strip(), PUB)

    def test_cli_json_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            zp, cp = os.path.join(d, "z.json"), os.path.join(d, "main.cf")
            z = base_zone(PUB)
            z["records"]["example.com"]["TXT"] = []
            with open(zp, "w") as fh:
                json.dump(z, fh)
            with open(cp, "w") as fh:
                fh.write("myhostname = mail.example.com\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = cli_main(["diagnose", "--main-cf", cp, "--zone-file", zp, "--ipv4", IP4, "--json"])
            self.assertEqual(code, 1)
            self.assertIn("spf_missing", json.loads(buf.getvalue())["ordered_causes"])


if __name__ == "__main__":
    unittest.main()
