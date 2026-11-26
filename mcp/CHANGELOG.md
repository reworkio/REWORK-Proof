# Changelog

Changes to `@reworkdigital.io/rework-proof-mcp`. The source syncs to GitHub on
every merge; npm only gets a change when a new version is published, so
anything under **Unreleased** is on GitHub and not yet on npm.

When you publish, move the Unreleased entries under the new version and date,
and bump `version` in both `package.json` and `server.json` (npm never
republishes a version).

## Unreleased

- **README:** the hosted-server section said "the same four tools". There are
  five since 1.4.0 added `check_rework_certificate`, so it now says "the same
  tools", with no number to go stale.
- **Package:** this changelog ships in the package from the next version on.

## 1.4.0

- Added `check_rework_certificate`: check a certificate from its ID or its
  link.

Versions before this changelog was started are described in the repository's
commit history, not here; the 1.4.0 entry above is not a complete list.
