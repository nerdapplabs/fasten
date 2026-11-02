<!--
Thanks for the PR. Answer briefly and delete sections that don't apply.
-->

### What

<!-- One or two lines describing the change as an adopter sees it. The
diff covers the implementation; this is what a future reader sees in
`git log --oneline`. -->

### Why

<!-- The motivation: bug fix, feature, or cleanup that unblocks something
else. Link the issue, spec or docs line that justifies it. -->

### Affected SDK / surface

- [ ] Python
- [ ] Go
- [ ] Node / TypeScript
- [ ] Rust
- [ ] C++14
- [ ] Spec / wire format (`spec/row-schema.json`)
- [ ] CI / release workflow
- [ ] Docs / website

### Cross-language impact

<!-- If you changed the wire shape, the public API or the catalog
contract, list the other SDKs that need a follow-up. fasten's promise is
"wire it once, read it anywhere", so we work hard to keep the SDKs from
drifting apart. Skip this section for docs, CI, or internals of a single
SDK. -->

### Tests and verification

<!-- How did you check that this works? The convention elsewhere in the
codebase is "verified in <docker image>: N passed". -->

### Breaking change?

- [ ] No, additive and backwards-compatible.
- [ ] Yes, migration path noted here. We still take breaking changes
      before 1.0 GA, but adopters upgrade on a Friday and live with it on
      Monday, so keep the scope tight and add a CHANGELOG entry.

### Checklist

- [ ] Tests added / updated and pass in the SDK's pinned Docker image
- [ ] CHANGELOG.md updated for adopter-visible changes
- [ ] Docs / per-SDK README updated if the change is user-visible
- [ ] No new dependencies (or, if added, justified in the description)
