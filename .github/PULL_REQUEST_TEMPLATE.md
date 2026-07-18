<!--
Thanks for sending a pull request! Please fill in the sections below so
the reviewer has the context they need to land your change.
-->

## Summary

<!-- One or two sentences explaining what changed and why. -->

## Test plan

<!-- Bulleted checklist of what you ran. Examples:
- [ ] go vet ./...
- [ ] go test ./...
- [ ] golangci-lint run
- [ ] make e2e (if relevant)
- [ ] manual repro on Windows / macOS / Linux (specify)
-->

## Red line check

DIZGIN has two non-negotiable red lines (see `CLAUDE.md` and
`docs/SECURITY.md`):

- [ ] **R1 — Sensitive credential isolation:** my change does not weaken
      the DACL/deny-list DENY coverage on the sensitive credential SSOT
      (`.ssh`, cloud credentials, browser cookies, DPAPI vault, …) or
      expose those paths to the sandboxed tool.
- [ ] **R2 — Native experience:** my change does not break the
      transparent-sandbox UX for any tool.

If either box is unchecked, please explain in the summary why the
trade-off is the right call.

## Conventional commit

<!-- Pick one. See https://www.conventionalcommits.org/ -->

- [ ] `feat:` end users can do something they could not before
- [ ] `fix:` something was broken for end users and now works
- [ ] `refactor:` / `chore:` / `test:` / `docs:` / `ci:` no behaviour change
