"""Minimal SPF evaluator (RFC 7208 subset): ip4, ip6, a, mx, include,
redirect=, all with qualifiers, and the 10-DNS-lookup limit. Macros, exists:
and ptr: are not implemented and yield PERMERROR."""
from __future__ import annotations

import ipaddress

QUAL = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


class SpfError(Exception):
    pass


def get_spf_records(resolver, domain):
    return [t for t in resolver.txt(domain) if t.lower().startswith("v=spf1")]


def check_host(resolver, ip: str, domain: str, _state=None) -> str:
    state = _state if _state is not None else {"lookups": 0}
    recs = get_spf_records(resolver, domain)
    if not recs:
        return "none"
    if len(recs) > 1:
        return "permerror"
    addr = ipaddress.ip_address(ip)
    redirect = None
    terms = recs[0].split()[1:]
    try:
        for term in terms:
            if term.lower().startswith("redirect="):
                redirect = term.split("=", 1)[1]
                continue
            if "=" in term:
                continue  # unknown modifier
            q = "pass"
            if term[0] in QUAL:
                q, term = QUAL[term[0]], term[1:]
            mech, _, arg = term.partition(":")
            mech = mech.lower()
            cidr = None
            if "/" in mech:
                mech, cidr = mech.split("/", 1)
            if "/" in arg and mech in ("a", "mx"):
                arg, cidr = arg.split("/", 1)
            if mech == "all":
                return q
            if mech in ("ip4", "ip6"):
                if addr in ipaddress.ip_network(arg, strict=False):
                    return q
                continue
            if mech in ("a", "mx", "include"):
                state["lookups"] += 1
                if state["lookups"] > 10:
                    return "permerror"
            target = arg or domain
            if mech == "a":
                if _match_hosts(resolver, [target], addr, cidr):
                    return q
            elif mech == "mx":
                hosts = [h for _, h in resolver.mx(target)]
                if _match_hosts(resolver, hosts, addr, cidr):
                    return q
            elif mech == "include":
                r = check_host(resolver, ip, arg, state)
                if r == "pass":
                    return q
                if r in ("permerror", "none"):
                    return "permerror"
            else:
                return "permerror"
    except ValueError:
        return "permerror"
    if redirect:
        state["lookups"] += 1
        return check_host(resolver, ip, redirect, state)
    return "neutral"


def _match_hosts(resolver, hosts, addr, cidr):
    for h in hosts:
        ips = resolver.a(h) if addr.version == 4 else resolver.aaaa(h)
        for i in ips:
            if cidr:
                if addr in ipaddress.ip_network(f"{i}/{cidr}", strict=False):
                    return True
            elif ipaddress.ip_address(i) == addr:
                return True
    return False
