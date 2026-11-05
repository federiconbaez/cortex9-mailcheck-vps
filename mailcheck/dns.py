"""DNS backends.

FileResolver reads a JSON zone fixture (used by the lab and the tests: no
network). DigResolver shells out to `dig +short` and is NOT exercised by the
test suite.
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess


def reverse_name(ip: str) -> str:
    return ipaddress.ip_address(ip).reverse_pointer


class FileResolver:
    """Zone fixture format::

        {"records": {"example.com": {"MX": ["10 mail.example.com"],
                                      "TXT": ["v=spf1 ..."], "A": [...]}},
         "ptr": {"192.0.2.10": "mail.example.com"}}

    DNSBL lookups are ordinary A queries on the reversed name, so a listing
    is just an "A" record under e.g. ``10.2.0.192.zen.spamhaus.org``.
    """

    def __init__(self, data: dict):
        self.records = {k.lower().rstrip("."): v for k, v in data.get("records", {}).items()}
        self.ptrs = {str(ipaddress.ip_address(k)): v for k, v in data.get("ptr", {}).items()}
        self.queries: list[tuple[str, str]] = []

    @classmethod
    def from_file(cls, path: str) -> FileResolver:
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def _get(self, name: str, rtype: str) -> list[str]:
        name = name.lower().rstrip(".")
        self.queries.append((name, rtype))
        return list(self.records.get(name, {}).get(rtype, []))

    def txt(self, name):
        return self._get(name, "TXT")

    def a(self, name):
        return self._get(name, "A")

    def aaaa(self, name):
        return self._get(name, "AAAA")

    def mx(self, name):
        out = []
        for rec in self._get(name, "MX"):
            pref, host = rec.split()
            out.append((int(pref), host.rstrip(".").lower()))
        return sorted(out)

    def ptr(self, ip):
        self.queries.append((reverse_name(ip), "PTR"))
        host = self.ptrs.get(str(ipaddress.ip_address(ip)))
        return [host.rstrip(".").lower()] if host else []


class DigResolver:  # pragma: no cover - needs network, not run in tests
    def __init__(self, server: str | None = None, timeout: int = 3):
        if not shutil.which("dig"):
            raise RuntimeError("dig not found; install dnsutils/bind-tools")
        self.server = server
        self.timeout = timeout

    def _q(self, name, rtype):
        cmd = ["dig", "+short", f"+time={self.timeout}", "+tries=1", name, rtype]
        if self.server:
            cmd.insert(1, "@" + self.server)
        # argv list, no shell; the binary is the fixed string "dig" found via shutil.which.
        res = subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
        return [ln.strip() for ln in res.stdout.splitlines() if ln.strip() and not ln.startswith(";")]

    def txt(self, name):
        out = []
        for line in self._q(name, "TXT"):
            parts = [p for p in line.split('"') if p.strip()]
            out.append("".join(parts))
        return out

    def a(self, name):
        return self._q(name, "A")

    def aaaa(self, name):
        return self._q(name, "AAAA")

    def mx(self, name):
        out = []
        for line in self._q(name, "MX"):
            pref, host = line.split()
            out.append((int(pref), host.rstrip(".").lower()))
        return sorted(out)

    def ptr(self, ip):
        return [h.rstrip(".").lower() for h in self._q(reverse_name(ip), "PTR")]
