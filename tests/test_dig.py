"""DigResolver argv construction. subprocess is mocked: no real query is sent."""
import unittest
from unittest import mock

from mailcheck import dns


class _Done:
    def __init__(self, stdout=""):
        self.stdout = stdout


def _resolver(**kw):
    with mock.patch.object(dns.shutil, "which", return_value="/usr/bin/dig"):
        return dns.DigResolver(**kw)


class DigArgvTest(unittest.TestCase):
    def run_query(self, method, arg, stdout="", **kw):
        r = _resolver(**kw)
        with mock.patch.object(dns.subprocess, "run", return_value=_Done(stdout)) as run:
            out = getattr(r, method)(arg)
        self.assertEqual(run.call_count, 1)
        argv = run.call_args.args[0]
        self.assertFalse(run.call_args.kwargs.get("shell", False))
        return argv, out

    def assert_name_after_q(self, argv, name, rtype):
        # the name only appears as the value of -q, at the end; everything before it
        # is the fixed option prefix, identical whatever the name is
        self.assertEqual(argv[-2:], ["-q", name], argv)
        self.assertEqual(argv[:-2], ["dig", "+short", "+time=3", "+tries=1", "-t", rtype], argv)

    def test_name_starting_with_dash_is_passed_with_q(self):
        for name in ["-f/etc/passwd", "-x", "-k/tmp/key", "-"]:
            argv, _ = self.run_query("txt", name)
            self.assert_name_after_q(argv, name, "TXT")
            self.assertNotIn("-f", argv)

    def test_name_starting_with_plus_is_passed_with_q(self):
        for name in ["+tcp", "+trace", "+short"]:
            argv, _ = self.run_query("a", name)
            # "+short" is also a real option we pass; the name must still only follow -q
            self.assert_name_after_q(argv, name, "A")

    def test_type_is_passed_with_t_and_server_with_at(self):
        argv, _ = self.run_query("mx", "example.com", stdout="10 mx.example.com.\n", server="192.0.2.53")
        self.assertEqual(argv[0], "dig")
        self.assertIn("@192.0.2.53", argv)
        self.assertEqual(argv[argv.index("-t") + 1], "MX")
        self.assertEqual(argv[-2:], ["-q", "example.com"])

    def test_ptr_uses_reverse_name_with_q(self):
        argv, out = self.run_query("ptr", "192.0.2.10", stdout="mail.example.com.\n")
        self.assertEqual(argv[-2:], ["-q", "10.2.0.192.in-addr.arpa"])
        self.assertEqual(out, ["mail.example.com"])

    def test_output_parsing_unchanged(self):
        _, out = self.run_query("txt", "example.com", stdout='"v=spf1 " "-all"\n;; comment\n')
        self.assertEqual(out, ["v=spf1 -all"])

    def test_missing_dig_raises(self):
        with mock.patch.object(dns.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError):
                dns.DigResolver()


if __name__ == "__main__":
    unittest.main()
