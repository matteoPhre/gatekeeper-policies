# Security Policy

## Supply-Chain Posture

This package is built to reduce supply-chain risk:

- Runtime dependencies: none.
- Package payload restricted via `files` field (`dist` only).
- TypeScript build output is the only published artifact.
- Security checks are enforced before publishing.

## Secure Release Workflow

Run the following commands before publishing:

```bash
npm ci
npm run release:check
npm run publish:npm:dry
```

Publish with provenance:

```bash
npm run publish:npm
```

`publish:npm` uses `--provenance` to generate signed build provenance metadata when supported by npm.

## Vulnerability Management

- Production-impact audit: `npm run security:audit:prod`
- Full development audit: `npm run security:audit:dev`

Development-only vulnerabilities should still be triaged and upgraded regularly, especially for build and test tooling.

## Audit Data Redaction Policy

Audit callbacks are executed in fire-and-forget mode and are failure-isolated.

- Every audit payload includes a dedicated `schemaVersion` field (separate from `policyVersion`).
- Sensitive keys in `details` are redacted before callback execution.
	- redacted key patterns include password/passphrase/secret/token/credential/plaintext/plain
- Error objects are sanitized before emission.
- Callback exceptions are swallowed to prevent policy-flow side effects.

This policy is designed to guarantee that plaintext secrets are never forwarded through audit payloads produced by the library.

## Reporting a Security Issue

Until a dedicated security contact is configured, open a private security advisory on the repository once GitHub is connected.
