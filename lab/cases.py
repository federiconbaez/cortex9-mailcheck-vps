"""Broken-on-purpose lab: 12 single-fault configurations plus 1 healthy
control. Everything is generated into a temporary directory at run time
(keys included, so no private key is ever committed). Names and addresses are
RFC 2606 / RFC 5737 / RFC 3849 documentation values only; DNS is a JSON
fixture, so no real query leaves the machine."""
from __future__ import annotations

import copy
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mailcheck.checks import local_dkim_pub

DOMAIN = "example.com"
HOST = "mail.example.com"
IP4 = "192.0.2.10"
IP6 = "2001:db8::10"
SELECTOR = "mail"

BROKEN_CASES = {
    # name: expected root cause
    "spf_missing": "spf_missing",
    "spf_ip_not_authorized": "spf_ip_not_authorized",
    "dkim_record_missing": "dkim_record_missing",
    "dkim_key_mismatch": "dkim_key_mismatch",
    "dmarc_missing": "dmarc_missing",
    "ptr_missing": "ptr_missing",
    "ptr_mismatch": "ptr_mismatch",
    "helo_mismatch": "helo_mismatch",
    "ipv6_no_ptr": "ipv6_no_ptr",
    "port25_blocked": "port25_blocked",
    "dnsbl_listed": "dnsbl_listed",
    "tls_missing": "tls_missing",
}


def _pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def base_zone(pub: str) -> dict:
    return {
        "records": {
            DOMAIN: {"MX": [f"10 {HOST}"], "TXT": [f"v=spf1 mx ip4:{IP4} ip6:{IP6} -all"]},
            HOST: {"A": [IP4], "AAAA": [IP6]},
            f"{SELECTOR}._domainkey.{DOMAIN}": {"TXT": [f"v=DKIM1; k=rsa; p={pub}"]},
            f"_dmarc.{DOMAIN}": {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]},
        },
        "ptr": {IP4: HOST, IP6: HOST},
    }


def base_main_cf(d: str) -> dict:
    return {
        "myhostname": HOST,
        "mydomain": DOMAIN,
        "myorigin": "$mydomain",
        "inet_protocols": "all",
        "smtpd_tls_cert_file": os.path.join(d, "tls", "fullchain.pem"),
        "smtpd_tls_key_file": os.path.join(d, "tls", "privkey.pem"),
        "smtpd_tls_security_level": "may",
        "smtp_tls_security_level": "may",
        "milter_default_action": "accept",
        "smtpd_milters": "inet:localhost:8891",
        "non_smtpd_milters": "$smtpd_milters",
    }


def build_case(name: str, root: str, key_pem: bytes, other_pem: bytes, open_port: int, closed_port: int):
    """Write one case into root/name and return the argv for `mailcheck diagnose`."""
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, "tls"), exist_ok=True)
    pub = local_dkim_pub(key_pem)
    zone = base_zone(pub)
    cf = base_main_cf(d)
    probe_port = open_port
    recs = zone["records"]

    if name == "spf_missing":
        recs[DOMAIN]["TXT"] = []
    elif name == "spf_ip_not_authorized":
        # IPv4 of the server is outside the authorized range; IPv6 stays covered
        # so that this is the only fault.
        recs[DOMAIN]["TXT"] = [f"v=spf1 ip4:192.0.2.128/25 ip6:{IP6} -all"]
    elif name == "dkim_record_missing":
        del recs[f"{SELECTOR}._domainkey.{DOMAIN}"]
    elif name == "dkim_key_mismatch":
        recs[f"{SELECTOR}._domainkey.{DOMAIN}"]["TXT"] = [f"v=DKIM1; k=rsa; p={local_dkim_pub(other_pem)}"]
    elif name == "dmarc_missing":
        del recs[f"_dmarc.{DOMAIN}"]
    elif name == "ptr_missing":
        del zone["ptr"][IP4]
    elif name == "ptr_mismatch":
        zone["ptr"][IP4] = "10-2-0-192.vps.example.net"
        recs["10-2-0-192.vps.example.net"] = {"A": [IP4]}
    elif name == "helo_mismatch":
        cf["smtp_helo_name"] = "localhost.localdomain"
    elif name == "ipv6_no_ptr":
        del zone["ptr"][IP6]
    elif name == "port25_blocked":
        probe_port = closed_port
    elif name == "dnsbl_listed":
        recs[".".join(reversed(IP4.split("."))) + ".zen.spamhaus.org"] = {"A": ["127.0.0.2"]}
    elif name == "tls_missing":
        del cf["smtpd_tls_cert_file"]
        del cf["smtpd_tls_key_file"]
        cf["smtp_tls_security_level"] = "none"
    elif name != "healthy":
        raise KeyError(name)

    with open(os.path.join(d, "tls", "fullchain.pem"), "w") as fh:
        fh.write("placeholder certificate for lab, not parsed\n")
    with open(os.path.join(d, "tls", "privkey.pem"), "w") as fh:
        fh.write("placeholder\n")
    with open(os.path.join(d, "main.cf"), "w") as fh:
        fh.write("# generated lab main.cf\n")
        for k, v in cf.items():
            fh.write(f"{k} = {v}\n")
    keyfile = os.path.join(d, "dkim.private")
    with open(keyfile, "wb") as fh:
        fh.write(key_pem)
    with open(os.path.join(d, "opendkim.conf"), "w") as fh:
        fh.write(f"Domain {DOMAIN}\nSelector {SELECTOR}\nKeyFile {keyfile}\n")
    with open(os.path.join(d, "zone.json"), "w") as fh:
        json.dump(zone, fh, indent=1)
    return [
        "diagnose", "--main-cf", os.path.join(d, "main.cf"),
        "--opendkim-conf", os.path.join(d, "opendkim.conf"),
        "--zone-file", os.path.join(d, "zone.json"),
        "--ipv4", IP4, "--ipv6", IP6,
        "--probe", f"127.0.0.1:{probe_port}", "--probe-timeout", "1", "--json",
    ]
