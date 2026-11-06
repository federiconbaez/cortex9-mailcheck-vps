# Security policy

## Supported versions

Only the latest commit on `main` (currently the 0.1.x line) receives security fixes.
There are no older maintained branches.

## Reporting a vulnerability

**This repository currently has no channel for reporting vulnerabilities**: the issue
tracker is disabled, GitHub private vulnerability reporting is not enabled, and the
project does not publish an email address. This is a known gap. Until a channel is
enabled:

- Please do not publish exploit details about this tool.
- A fix can be proposed as a pull request against `main` at <https://github.com/federiconbaez/cortex9-mailcheck-vps/pulls>; keep the
  description to what the change does, without exploitation steps.

This file will be updated when a reporting channel exists.

## What to expect

- No vulnerability report has been received so far.
- Confirmed vulnerabilities are fixed on `main`, released with a new version, and
  listed in the release notes in [CHANGELOG.md](CHANGELOG.md) with their CVE or GHSA
  identifier when they have one.

## Scope

mailcheck-vps is a read-only diagnostic CLI: it reads Postfix and OpenDKIM
configuration files and the local DKIM private key, queries DNS, and optionally opens
a TCP connection to port 25. It never modifies the server; it only prints suggested
commands.

Relevant issues include: leaking private key material in its output (it should only
ever print the public key), modifying files, executing commands built from
configuration or DNS data, or crashing/hanging on crafted configuration or DNS
responses. The fix commands it prints are suggestions for a human to review; review
them before running them.
