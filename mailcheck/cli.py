"""Command line entry point: python -m mailcheck ..."""
from __future__ import annotations

import argparse
import json
import sys

from . import checks, config, dns


def build_context(args) -> checks.Context:
    with open(args.main_cf, encoding="utf-8") as fh:
        main_cf = config.parse_main_cf(fh.read())
    opendkim = None
    if args.opendkim_conf:
        with open(args.opendkim_conf, encoding="utf-8") as fh:
            opendkim = config.parse_opendkim_conf(fh.read())
    key_path = args.dkim_key or (opendkim or {}).get("KeyFile")
    pem = None
    if key_path:
        try:
            with open(key_path, "rb") as fh:
                pem = fh.read()
        except OSError:
            pem = None
    if args.zone_file:
        resolver = dns.FileResolver.from_file(args.zone_file)
    else:
        resolver = dns.DigResolver(args.dns_server)
    probe = None
    if args.probe:
        host, _, port = args.probe.rpartition(":")
        probe = (host.strip("[]"), int(port))
    return checks.Context(main_cf=main_cf, resolver=resolver, ipv4=args.ipv4, ipv6=args.ipv6,
                          domain=args.domain, opendkim=opendkim, dkim_key_pem=pem, probe=probe,
                          probe_timeout=args.probe_timeout,
                          dnsbls=tuple(args.dnsbl) if args.dnsbl else checks.DEFAULT_DNSBLS)


def render_text(rep: checks.Report) -> str:
    lines = [f"overall: {rep.overall}"]
    if rep.failures:
        lines.append("root causes (fix in this order):")
        for i, f in enumerate(rep.failures, 1):
            lines.append(f"  {i}. [{f.cause}] {f.detail}")
            if f.fix:
                lines.append(f"     fix: {f.fix}")
    lines.append("checks:")
    for f in rep.findings:
        lines.append(f"  {f.status:8} {f.check:7} {f.detail}")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mailcheck", description="Read-only mail deliverability diagnosis")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("diagnose", help="run all checks")
    d.add_argument("--main-cf", default="/etc/postfix/main.cf")
    d.add_argument("--opendkim-conf")
    d.add_argument("--dkim-key", help="override KeyFile from opendkim.conf")
    d.add_argument("--domain", help="From domain (default: mydomain)")
    d.add_argument("--ipv4")
    d.add_argument("--ipv6")
    g = d.add_mutually_exclusive_group()
    g.add_argument("--zone-file", help="JSON zone fixture (offline)")
    g.add_argument("--dns-server", help="resolver for dig (default: system)")
    d.add_argument("--probe", help="host:port for the outbound port-25 test")
    d.add_argument("--probe-timeout", type=float, default=5.0)
    d.add_argument("--dnsbl", action="append")
    d.add_argument("--json", action="store_true")
    k = sub.add_parser("dkim-pub", help="print the DNS p= value for a DKIM private key")
    k.add_argument("--key", required=True)
    args = p.parse_args(argv)
    if args.cmd == "dkim-pub":
        with open(args.key, "rb") as fh:
            pub = checks.local_dkim_pub(fh.read())
        if not pub:
            print("cannot read key", file=sys.stderr)
            return 2
        print(pub)
        return 0
    rep = checks.run_all(build_context(args))
    print(json.dumps(rep.to_dict(), indent=2) if args.json else render_text(rep))
    return {"OK": 0, "FAIL": 1, "INCOMPLETE": 3}[rep.overall]


if __name__ == "__main__":
    sys.exit(main())
