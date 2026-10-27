import unittest

from mailcheck.config import parse_main_cf, parse_opendkim_conf


class MainCfTest(unittest.TestCase):
    def test_defaults_and_expansion(self):
        cf = parse_main_cf("""
# comment
myhostname = mail.example.com
myorigin = $mydomain
smtpd_milters = inet:localhost:8891,
    inet:localhost:11332
""")
        self.assertEqual(cf["mydomain"], "example.com")
        self.assertEqual(cf["myorigin"], "example.com")
        self.assertEqual(cf["smtp_helo_name"], "mail.example.com")
        self.assertEqual(cf["inet_protocols"], "all")
        self.assertEqual(cf["smtpd_milters"], "inet:localhost:8891, inet:localhost:11332")

    def test_braced_var(self):
        cf = parse_main_cf("myhostname = mx.example.test\nsmtp_helo_name = ${myhostname}\n")
        self.assertEqual(cf["smtp_helo_name"], "mx.example.test")

    def test_opendkim(self):
        c = parse_opendkim_conf("Domain example.com\nSelector s1 # comment\n\nKeyFile /k\n")
        self.assertEqual(c, {"Domain": "example.com", "Selector": "s1", "KeyFile": "/k"})


if __name__ == "__main__":
    unittest.main()
