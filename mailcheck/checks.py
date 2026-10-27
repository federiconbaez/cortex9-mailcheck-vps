"""Deliverability checks. Every check is read-only: it parses local files,
asks the configured resolver, and (only if a target is given) opens one TCP
connection to test outbound port 25."""
from __future__ import annotations

import base64
import ipaddress
import os
import socket
from dataclasses import asdict, dataclass, field

from . import spf

DEFAULT_DNSBLS = ("zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org")

# Lower index = more fundamental root cause (fix this first).
CAUSE_ORDER = [
    "port25_blocked",
    "dnsbl_listed",
    "ptr_missing",
    "ptr_mismatch",
    "helo_mismatch",
    "spf_missing",
    "spf_permerror",
    "spf_ip_not_authorized",
    "dkim_config_missing",
    "dkim_record_missing",
    "dkim_key_mismatch",
    "dkim_unaligned",
    "dmarc_missing",
    "dmarc_invalid",
    "ipv6_no_ptr",
    "ipv6_spf",
    "tls_missing",
    "mx_missing",
    "spf_too_permissive",
]


@dataclass
class Finding:
    check: str
    status: str  # PASS | FAIL | WARN | NOT_RUN
    detail: str
    cause: str | None = None
    fix: str | None = None


@dataclass
class Context:
    main_cf: dict
    resolver: object
    ipv4: str | None = None
    ipv6: str | None = None
    domain: str | None = None
    opendkim: dict | None = None
    dkim_key_pem: bytes | None = None
    probe: tuple[str, int] | None = None
    probe_timeout: float = 5.0
    dnsbls: tuple = DEFAULT_DNSBLS

    @property
    def mail_domain(self) -> str:
        return (self.domain or self.main_cf.get("mydomain", "")).lower().rstrip(".")

    @property
    def hostname(self) -> str:
        return self.main_cf.get("myhostname", "").lower().rstrip(".")


@dataclass
class Report:
    findings: list = field(default_factory=list)

    @property
    def failures(self):
        f = [x for x in self.findings if x.status == "FAIL"]
        return sorted(f, key=lambda x: CAUSE_ORDER.index(x.cause) if x.cause in CAUSE_ORDER else 99)

    @property
    def root_cause(self):
        f = self.failures
        return f[0].cause if f else None

    @property
    def overall(self) -> str:
        if self.failures:
            return "FAIL"
        if any(x.status == "NOT_RUN" for x in self.findings):
            return "INCOMPLETE"  # never claim OK for something not checked
        return "OK"

    def to_dict(self):
        return {
            "overall": self.overall,
            "root_cause": self.root_cause,
            "ordered_causes": [x.cause for x in self.failures],
            "findings": [asdict(x) for x in self.findings],
        }


def check_port25(ctx: Context) -> Finding:
    if not ctx.probe:
        return Finding("port25", "NOT_RUN", "no --probe host:port given; outbound 25 not tested")
    host, port = ctx.probe
    try:
        with socket.create_connection((host, port), timeout=ctx.probe_timeout):
            pass
        return Finding("port25", "PASS", f"TCP connect to {host}:{port} succeeded")
    except OSError as e:
        return Finding(
            "port25", "FAIL", f"TCP connect to {host}:{port} failed: {e.__class__.__name__}",
            "port25_blocked",
            "Ask the VPS provider to unblock outbound TCP/25, or relay through a smarthost: "
            "postconf -e 'relayhost = [smtp.relay.example]:587'",
        )


def check_dnsbl(ctx: Context) -> list[Finding]:
    if not ctx.ipv4:
        return [Finding("dnsbl", "NOT_RUN", "no IPv4 given")]
    rev = ".".join(reversed(ctx.ipv4.split(".")))
    out = []
    for zone in ctx.dnsbls:
        hits = [a for a in ctx.resolver.a(f"{rev}.{zone}") if a.startswith("127.")]
        if hits:
            out.append(Finding("dnsbl", "FAIL", f"{ctx.ipv4} listed in {zone} ({', '.join(hits)})",
                               "dnsbl_listed", f"Follow the delisting procedure of {zone} after fixing the source of spam"))
        else:
            out.append(Finding("dnsbl", "PASS", f"{ctx.ipv4} not listed in {zone}"))
    return out


def check_ptr(ctx: Context) -> list[Finding]:
    if not ctx.ipv4:
        return [Finding("ptr", "NOT_RUN", "no IPv4 given")]
    ptrs = ctx.resolver.ptr(ctx.ipv4)
    if not ptrs:
        return [Finding("ptr", "FAIL", f"{ctx.ipv4} has no PTR record", "ptr_missing",
                        f"Set reverse DNS of {ctx.ipv4} to {ctx.hostname} in the VPS provider panel")]
    name = ptrs[0]
    fwd = ctx.resolver.a(name)
    if name != ctx.hostname or ctx.ipv4 not in fwd:
        return [Finding("ptr", "FAIL",
                        f"PTR {ctx.ipv4} -> {name}; myhostname={ctx.hostname}; A({name})={fwd}",
                        "ptr_mismatch",
                        f"Make PTR of {ctx.ipv4} = {ctx.hostname} and {ctx.hostname}. A {ctx.ipv4}")]
    return [Finding("ptr", "PASS", f"PTR {ctx.ipv4} -> {name}, forward-confirmed")]


def check_helo(ctx: Context) -> Finding:
    helo = ctx.main_cf.get("smtp_helo_name", ctx.hostname).lower().rstrip(".")
    expected = ctx.hostname
    if ctx.ipv4:
        ptrs = ctx.resolver.ptr(ctx.ipv4)
        if ptrs:
            expected = ptrs[0]
    resolves = (not ctx.ipv4) or ctx.ipv4 in ctx.resolver.a(helo)
    if helo != expected or not resolves:
        return Finding("helo", "FAIL", f"smtp_helo_name={helo}, expected {expected} (resolves to IP: {resolves})",
                       "helo_mismatch", "postconf -e 'smtp_helo_name = $myhostname'")
    return Finding("helo", "PASS", f"HELO {helo} matches PTR/hostname")


def _spf_fix(ctx):
    mech = " ".join(x for x in (f"ip4:{ctx.ipv4}" if ctx.ipv4 else "", f"ip6:{ctx.ipv6}" if ctx.ipv6 else "") if x)
    return f'{ctx.mail_domain}. TXT "v=spf1 mx {mech} -all"'


def check_spf(ctx: Context) -> list[Finding]:
    recs = spf.get_spf_records(ctx.resolver, ctx.mail_domain)
    if not recs:
        return [Finding("spf", "FAIL", f"no SPF record at {ctx.mail_domain}", "spf_missing", _spf_fix(ctx))]
    if len(recs) > 1:
        return [Finding("spf", "FAIL", f"{len(recs)} SPF records (must be exactly 1)", "spf_permerror",
                        "Merge into a single TXT: " + _spf_fix(ctx))]
    out = []
    rec = recs[0]
    if ctx.ipv4:
        r = spf.check_host(ctx.resolver, ctx.ipv4, ctx.mail_domain)
        if r == "permerror":
            out.append(Finding("spf", "FAIL", f"SPF evaluation error for '{rec}'", "spf_permerror", _spf_fix(ctx)))
        elif r != "pass":
            out.append(Finding("spf", "FAIL", f"SPF result for {ctx.ipv4} is {r} ('{rec}')",
                               "spf_ip_not_authorized", _spf_fix(ctx)))
        else:
            out.append(Finding("spf", "PASS", f"SPF pass for {ctx.ipv4}"))
    else:
        out.append(Finding("spf", "NOT_RUN", "no IPv4 given; SPF not evaluated"))
    terms = rec.lower().split()
    if "+all" in terms or "all" in terms:
        out.append(Finding("spf", "FAIL", "SPF ends in +all: anyone may send as this domain",
                           "spf_too_permissive", _spf_fix(ctx)))
    return out


def _dkim_tags(txt):
    tags = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip()] = "".join(v.split())
    return tags


def check_dkim(ctx: Context) -> list[Finding]:
    conf = ctx.opendkim or {}
    selector, ddomain = conf.get("Selector"), conf.get("Domain")
    if not selector or not ddomain:
        return [Finding("dkim", "FAIL", "OpenDKIM Selector/Domain not configured", "dkim_config_missing",
                        "Set Domain, Selector and KeyFile in /etc/opendkim.conf")]
    ddomain = ddomain.lower().rstrip(".")
    name = f"{selector}._domainkey.{ddomain}"
    recs = [t for t in ctx.resolver.txt(name) if "p=" in t]
    out = []
    if not recs:
        out.append(Finding("dkim", "FAIL", f"no DKIM TXT at {name}", "dkim_record_missing",
                           f"Publish {name}. TXT with the p= value printed by: mailcheck dkim-pub --key <KeyFile>"))
    else:
        published = _dkim_tags(recs[0]).get("p", "")
        local = local_dkim_pub(ctx.dkim_key_pem) if ctx.dkim_key_pem else None
        if local is None:
            out.append(Finding("dkim", "NOT_RUN", "local DKIM private key not readable; key match not tested"))
        elif not published:
            out.append(Finding("dkim", "FAIL", f"DKIM key at {name} is revoked (empty p=)", "dkim_key_mismatch",
                               f'{name}. TXT "v=DKIM1; k=rsa; p={local}"'))
        elif published != local:
            out.append(Finding("dkim", "FAIL", f"DNS key at {name} does not match the local private key",
                               "dkim_key_mismatch", f'{name}. TXT "v=DKIM1; k=rsa; p={local}"'))
        else:
            out.append(Finding("dkim", "PASS", f"DNS key at {name} matches local private key"))
    md = ctx.mail_domain
    if not (ddomain == md or md.endswith("." + ddomain) or ddomain.endswith("." + md)):
        out.append(Finding("dkim", "FAIL", f"DKIM d={ddomain} not aligned with From domain {md}", "dkim_unaligned",
                           f"Set 'Domain {md}' in opendkim.conf and publish its key"))
    return out


def local_dkim_pub(pem: bytes) -> str | None:
    try:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(pem, password=None)
        der = key.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        return base64.b64encode(der).decode()
    except Exception:
        return None


def check_dmarc(ctx: Context) -> Finding:
    name = f"_dmarc.{ctx.mail_domain}"
    recs = [t for t in ctx.resolver.txt(name) if t.replace(" ", "").lower().startswith("v=dmarc1")]
    if not recs:
        return Finding("dmarc", "FAIL", f"no DMARC record at {name}", "dmarc_missing",
                       f'{name}. TXT "v=DMARC1; p=none; rua=mailto:dmarc@{ctx.mail_domain}"')
    tags = _dkim_tags(recs[0])
    if tags.get("p", "").lower() not in ("none", "quarantine", "reject"):
        return Finding("dmarc", "FAIL", f"DMARC record has no valid p= tag: '{recs[0]}'", "dmarc_invalid",
                       f'{name}. TXT "v=DMARC1; p=none"')
    return Finding("dmarc", "PASS", f"DMARC p={tags['p']}")


def check_ipv6(ctx: Context) -> list[Finding]:
    protos = ctx.main_cf.get("inet_protocols", "all").replace(",", " ").split()
    uses6 = "all" in protos or "ipv6" in protos
    if not uses6:
        return [Finding("ipv6", "PASS", "inet_protocols excludes IPv6")]
    if not ctx.ipv6:
        return [Finding("ipv6", "NOT_RUN", "Postfix may send over IPv6 (inet_protocols) but no --ipv6 given")]
    out = []
    ptrs = ctx.resolver.ptr(ctx.ipv6)
    if not ptrs:
        out.append(Finding("ipv6", "FAIL", f"{ctx.ipv6} has no PTR; Postfix sends over IPv6 when the peer has AAAA",
                           "ipv6_no_ptr",
                           f"Set reverse DNS of {ctx.ipv6} to {ctx.hostname}, or postconf -e 'inet_protocols = ipv4'"))
    else:
        out.append(Finding("ipv6", "PASS", f"PTR {ctx.ipv6} -> {ptrs[0]}"))
    r = spf.check_host(ctx.resolver, ctx.ipv6, ctx.mail_domain)
    if r != "pass" and spf.get_spf_records(ctx.resolver, ctx.mail_domain):
        out.append(Finding("ipv6", "FAIL", f"SPF result for {ctx.ipv6} is {r}", "ipv6_spf", _spf_fix(ctx)))
    return out


def check_tls(ctx: Context) -> Finding:
    cf = ctx.main_cf
    cert, key = cf.get("smtpd_tls_cert_file") or cf.get("smtpd_tls_chain_files"), cf.get("smtpd_tls_key_file")
    level = cf.get("smtp_tls_security_level", "")
    problems = []
    if not cert:
        problems.append("smtpd_tls_cert_file not set")
    elif not os.path.exists(cert.split(",")[0].strip()):
        problems.append("smtpd_tls_cert_file does not exist")
    if key and not os.path.exists(key):
        problems.append("smtpd_tls_key_file does not exist")
    if level not in ("may", "encrypt", "dane", "dane-only", "verify", "secure"):
        problems.append(f"smtp_tls_security_level='{level}' (outbound STARTTLS disabled)")
    if problems:
        return Finding("tls", "FAIL", "; ".join(problems), "tls_missing",
                       "postconf -e 'smtpd_tls_cert_file = <fullchain>' 'smtpd_tls_key_file = <key>' "
                       "'smtpd_tls_security_level = may' 'smtp_tls_security_level = may'")
    return Finding("tls", "PASS", f"TLS files present, smtp_tls_security_level={level}")


def check_mx(ctx: Context) -> Finding:
    mx = ctx.resolver.mx(ctx.mail_domain)
    if not mx:
        return Finding("mx", "FAIL", f"no MX for {ctx.mail_domain}", "mx_missing",
                       f"{ctx.mail_domain}. MX 10 {ctx.hostname}.")
    return Finding("mx", "PASS", f"MX {mx[0][1]}")


def run_all(ctx: Context) -> Report:
    r = Report()
    r.findings.append(check_port25(ctx))
    r.findings += check_dnsbl(ctx)
    r.findings += check_ptr(ctx)
    r.findings.append(check_helo(ctx))
    r.findings += check_spf(ctx)
    r.findings += check_dkim(ctx)
    r.findings.append(check_dmarc(ctx))
    r.findings += check_ipv6(ctx)
    r.findings.append(check_tls(ctx))
    r.findings.append(check_mx(ctx))
    return r
