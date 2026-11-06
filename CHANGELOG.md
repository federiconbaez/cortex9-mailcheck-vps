# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-11-06

First tagged release. Version as declared in `pyproject.toml`.

### Added
- `python -m mailcheck diagnose`: read-only deliverability diagnosis from inside the
  server. Reads Postfix `main.cf` and `opendkim.conf`, derives the DKIM public key
  from the local private key and compares it with DNS, and checks SPF, DMARC,
  PTR/rDNS, HELO, IPv6, TLS configuration, MX, 3 DNSBLs and outbound port 25.
  Root causes are reported in a recommended fix order, with the exact fix command or
  DNS record. Text or `--json` output; exit codes 0/1/2/3.
- `python -m mailcheck dkim-pub`: prints the `p=` value to publish for a DKIM key.
- DNS from a JSON zone file (offline) or from `dig` (argv tested with mocks; no real
  queries in the tests).
- 33 tests and a lab of 12 single-fault configurations plus a healthy control.
  Results and limits are in the README.

### Project infrastructure (added before tagging)
*Added:*
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog and an English README
  (`README.en.md`).
- Ruff lint (including flake8-bandit security rules) configured in `pyproject.toml`
  and run in CI.

*Changed:*
- Removed unused imports and fixed the remaining lint findings; no behavior change
  (the tests and the 12-case lab give the same results).
- Minimum `cryptography` raised from 41 to 50.0.0, the version that fixes the most
  recent published cryptography advisory (GHSA-g6cj-pr64-35w5, checked 2026-11-06).

*Fixed:*
- `DigResolver` now passes the queried name to `dig` with `-q` and the type with
  `-t`, so a name starting with `-` or `+` can no longer be read as a `dig` option.
  Regression tests in `tests/test_dig.py` and a CI job with the real `dig`.

### Security
- No publicly known vulnerabilities (CVE/GHSA) fixed in this version. The `dig`
  argument hardening above was found during review, before any release.
