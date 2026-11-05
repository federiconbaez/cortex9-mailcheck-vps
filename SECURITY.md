# Security policy

## Supported versions

Only the latest commit on `main` (currently the 0.1.x line) receives security fixes.
There are no older maintained branches.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub private vulnerability
reporting:

- Go to <https://github.com/federiconbaez/cortex9-mailcheck-vps/security/advisories/new>
  (repository **Security** tab -> **Report a vulnerability**).
- Include the affected commit or version, steps to reproduce, and the impact you expect.

Do **not** open a public issue, pull request or discussion for a suspected
vulnerability. The report stays visible only to you and the maintainer until an
advisory is published.

## What to expect

- The maintainer aims to acknowledge every report within **14 days**.
- If the report is confirmed, the fix is developed in a private fork of the
  advisory, released, and the advisory is published with credit to the reporter
  (unless they prefer to stay anonymous).
- Release notes in [CHANGELOG.md](CHANGELOG.md) list every fixed vulnerability that
  has a CVE, GHSA or RUSTSEC identifier.

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
