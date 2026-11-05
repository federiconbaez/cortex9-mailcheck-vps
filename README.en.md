# mailcheck-vps (English)

*Spanish original: [README.md](README.md). If the two disagree, the Spanish README is
the reference.*

Mail deliverability diagnosis **from inside the server**, read-only: it reads
Postfix `main.cf` and `opendkim.conf`, derives the DKIM public key from the local
private key, compares it with what is published in DNS, and evaluates SPF, DMARC,
PTR/rDNS, HELO, IPv6, TLS, MX, 3 DNSBL lists and outbound port 25. It returns the
root causes **in order** (what to fix first) with the exact command or DNS record to
fix them.

> Status: **one-day MVP**. It is the core of the CLI plus a lab that tests its value.
> The full product (see "Out of scope") is estimated at about 3 person-weeks.

## Usage

```sh
pip install "cryptography>=41"
python -m mailcheck diagnose \
  --main-cf /etc/postfix/main.cf \
  --opendkim-conf /etc/opendkim.conf \
  --ipv4 192.0.2.10 --ipv6 2001:db8::10 \
  --probe mx.example.net:25          # optional: tests outbound port 25
# --zone-file zone.json  -> DNS from a file (no network)
# --dns-server <ip>      -> real DNS via `dig` (not covered by the tests)
# --json                 -> structured output

python -m mailcheck dkim-pub --key /etc/opendkim/keys/mail.private   # p= value to publish
```

Exit codes: `0` all OK, `1` failures found, `3` incomplete (something could not be
checked; nothing is ever reported OK if it was not looked at), `2` usage error.

The checks and root causes are listed, in recommended fix order, in the table of the
Spanish README (`port25_blocked`, `dnsbl_listed`, `ptr_*`, `helo_mismatch`, `spf_*`,
`dkim_*`, `dmarc_*`, `ipv6_*`, `tls_missing`, `mx_missing`, `spf_too_permissive`).

## What is tested

Measured on Linux x86_64, Python 3.13, on 2026-10-27:

```sh
python -m lab.measure
# root cause correct: 12/12; false OK: 0; healthy control OK: True; criterion met: True
```

- **Lab**: 12 configurations broken on purpose, one fault per case (`lab/cases.py`),
  plus a healthy control. Criterion fixed before running: correct root cause in
  >= 11/12 and 0 broken cases marked OK. **Result: 12/12, 0 false OK, healthy
  control = OK.** Repeated 3 times in a row with fresh DKIM keys each run: same result.
- **Tests**: `python -m tests.run` runs 27 tests (`main.cf` and `opendkim.conf`
  parsers, SPF evaluator with include/redirect/10-lookup limit, DKIM
  match/mismatch/revoked/unreadable, alignment, DMARC, cause ordering, CLI). A skipped
  test counts as a failure.
- Everything is offline: the lab DNS is a JSON file, keys are generated in a
  temporary directory on every run (no keys in the repository) and only
  documentation names and addresses are used. A test checks this on `lab/cases.py`.

## What is NOT tested (honest limits)

- **The lab was written by the same author as the tool.** Each case has a single fault
  and the tool was designed knowing those 12 faults; 12/12 shows the checks do what they
  say, not that they cover the problems of a real server. With several faults at once,
  the cause order is a heuristic (`CAUSE_ORDER` in `mailcheck/checks.py`).
- No real Postfix or OpenDKIM was started: their configuration files are parsed and
  DNS is simulated.
- **Not tested against a real server**, and the mail-tester score after applying the
  fixes was not measured (the >= 9/10 goal is pending).
- The real DNS backend (`--dns-server`, via `dig`) exists but **no test exercises it**.
- The TLS check only verifies that the files exist and the configured security level;
  it does not validate the certificate or perform STARTTLS.
- SPF: macros, `exists:` and `ptr:` are not implemented (they return `permerror`), nor
  is the "void lookups" limit.
- The public IP is passed as an argument; it is not detected automatically.

## Out of scope

Exchange / Microsoft 365 / Google Workspace; IP warming; email marketing; rspamd
(only OpenDKIM today); modifying the server (the tool is read-only and only prints the
fix commands).

## Contributing, bugs and security

- Bugs and feature requests: <https://github.com/federiconbaez/cortex9-mailcheck-vps/issues>
- How to contribute: [CONTRIBUTING.md](CONTRIBUTING.md)
- Vulnerabilities (private): [SECURITY.md](SECURITY.md)
- Changes per version: [CHANGELOG.md](CHANGELOG.md)

## License

Apache-2.0 ([LICENSE](LICENSE)).
