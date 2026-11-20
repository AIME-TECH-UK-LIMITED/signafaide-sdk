# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem.

Report it privately, either through GitHub's **Report a vulnerability** button on the [Security tab](https://github.com/AIME-TECH-UK-LIMITED/signafaide-sdk/security) of this repository, or by email to [sales@signafaide.co.uk](mailto:sales@signafaide.co.uk). Include the details and a way to reproduce it.

## Response times

- We confirm we received your report within 3 working days (UK).
- We send a first assessment, including whether we treat it as a vulnerability, within 10 working days.
- For a confirmed vulnerability we aim to release a fix within 90 days of the report, keep you informed until then, and agree the disclosure date with you.

## Good-faith research

We will not take action against good-faith research that avoids other customers' data and does not disrupt the hosted service, and we will credit you if you wish once it is fixed.

The same policy is published at [signafaide.co.uk/security](https://signafaide.co.uk/security#responsible-disclosure) and in [security.txt](https://signafaide.co.uk/.well-known/security.txt).

## Scope

In scope: the SDKs (`signafaide` on npm and PyPI, `langchain-signafaide`, `signafaide-mcp`), the Rust core and verifier, the GitHub Action and the protocol in `spec/SPEC.md`.

Of particular interest:

- a verification pack that the verifier accepts although a record was changed, removed, reordered or back-dated;
- a way to make a protected tool run without the witness's ruling;
- record content, keys or session tokens leaving the machine when the documentation says they do not.

## Supported versions

Fixes go into the latest release. Please check that the problem is present in it before reporting.
