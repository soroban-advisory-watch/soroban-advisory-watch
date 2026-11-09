# Security policy

## Reporting a problem in this tool

Do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting: go to the repository's **Security** tab and choose **Report a vulnerability**. Only the maintainers can see the report.

Please include:

- What you found and where (file, function, command).
- How to reproduce it, ideally with an input file.
- What an attacker could do with it.

We aim to acknowledge reports within 3 working days and to agree a fix and disclosure date with you.

## What counts

In scope:

- A crafted Wasm file, RPC response, OSV file or inventory that makes the tool crash, hang, use unbounded memory, or write outside the paths it was given.
- A bug that makes the tool report `not-matched` for a contract whose recorded version is in an affected range, or that hides a finding.
- A wrong affected range or wrong crate grouping in the bundled data.

Out of scope:

- Vulnerabilities in Soroban contracts or in `soroban-sdk` itself. Report those to the contract team, or to Stellar through [their security policy](https://github.com/stellar/rs-soroban-sdk/security/policy).
- Results that are `possible` for a contract that turns out not to be affected. That is how the tool is designed; see the [limits](https://soroban-advisory-watch.github.io/soroban-advisory-watch/limits.html).

## Audit status

This tool has not been audited. It reads untrusted Wasm and RPC data with bounded parsers (`wasmparser`, `stellar-xdr` with length limits) and does not execute contract code. Its output is a starting point for a human review, not a security assessment.

## Supported versions

Only the latest release gets fixes.
