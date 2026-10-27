"""Parsers for Postfix main.cf and opendkim.conf (read-only)."""
from __future__ import annotations

import re

_VAR = re.compile(r"\$(\{?)([a-z_0-9]+)\}?")


def parse_main_cf(text: str) -> dict[str, str]:
    """Parse main.cf: `key = value`, continuation lines start with whitespace,
    `#` comments. `$name`/`${name}` are expanded against the same file plus
    the Postfix defaults this tool relies on."""
    raw: dict[str, str] = {}
    key = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace() and key:
            raw[key] += " " + line.strip()
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip()
        raw[key] = v.strip()

    if "myhostname" in raw and "mydomain" not in raw:
        host = raw["myhostname"]
        raw["mydomain"] = host.split(".", 1)[1] if "." in host else host
    raw.setdefault("smtp_helo_name", "$myhostname")
    raw.setdefault("inet_protocols", "all")
    raw.setdefault("myorigin", "$myhostname")

    def expand(v: str, depth=0) -> str:
        if depth > 10:
            return v
        return _VAR.sub(lambda m: expand(raw.get(m.group(2), ""), depth + 1), v)

    return {k: expand(v) for k, v in raw.items()}


def parse_opendkim_conf(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0]] = parts[1].strip()
    return out
