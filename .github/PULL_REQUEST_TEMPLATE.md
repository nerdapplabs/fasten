<!--
Thanks for the PR. A few prompts to make review fast — answer briefly,
delete sections that don't apply.
-->

### What

<!-- One or two lines: the change in adopter-visible terms. The diff
covers the implementation; this is the line a future reader will see
in `git log --oneline`. -->

### Why

<!-- The motivation. Bug fix? Feature? Cleanup that unblocks something
else? Link the issue / spec / docs line that justifies it. -->

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

<!-- If you touched the wire shape, the public API, or the catalog
contract, note which other SDKs need a follow-up. fasten's promise is
"wire it once, read it anywhere"; gratuitous divergence is the thing
we try hardest to avoid. Skip this section for docs / CI / single-SDK
internals. -->

### Tests + verification

<!-- How did you check this works? "verified in <docker image> →
N passed" is the convention used elsewhere in the codebase. -->

### Breaking change?

- [ ] No — additive / backwards-compatible.
- [ ] Yes — note the migration path here. Pre-1.0 GA we still take
      breaking changes, but every adopter pulls on a Friday risking
      their Monday morning, so tight scope + a CHANGELOG entry is
      mandatory.

### Checklist

- [ ] Tests added / updated and pass in the SDK's pinned Docker image
- [ ] CHANGELOG.md updated for adopter-visible changes
- [ ] Docs / per-SDK README updated if the change is user-visible
- [ ] No new dependencies (or, if added, justified in the description)
