# Notes for coding agents and reviewers

This is Jay's build of EasyTier: an upstream tag plus a small set of hardening patches. Read [JAY.md](JAY.md) first. It lists the base tag, every patch and the release log. Pull requests target the current `jay/<tag>` branch, not `main`.

## Coding rules

- Keep the change small and close to upstream code style, so the next rebase onto a new upstream tag stays easy.
- Every behaviour change is listed in `JAY.md` (patch list or release log) in the same pull request.
- Don't undo a patch listed in `JAY.md` unless the pull request says so and explains why.
- Builds use `--locked`. `cargo audit` must pass; a new entry in `.cargo/audit.toml` needs a written reason, scope and an exit condition.
- GitHub Actions stay pinned to commit hashes. Prebuilt files in `easytier/third_party` stay pinned by SHA-256.
- No telemetry, no new built-in servers or public addresses, no remote management.
- The licence is LGPL-3.0, as upstream.

## Review guidelines

### What to check

- Correctness, panics on malformed input (`unwrap`, indexing, integer overflow), async tasks that leak or never time out, and lock ordering.
- Interoperability with upstream EasyTier nodes and with older Jay builds of this fork.
- That `JAY.md` matches the change.
- Tests for new behaviour where upstream has a test module for that area.

### How to write the review

- Write review comments in Simplified Chinese (the maintainers' working language). Keep code identifiers, file names and commands as they are.
- Each finding: file and line, what goes wrong, how it is triggered, and a suggested fix. Point out missing tests for new behaviour.
- Severity:
  - **Blocking (P0/P1)**: wrong behaviour users will hit, data loss, a crash, a broken build or test, a repository rule below broken, or a change that breaks compatibility without a version bump.
  - **Medium (P2)**: an edge case that fails, a resource or thread leak, a missing timeout or limit, missing tests for new behaviour, a confusing or wrong user-facing text.
  - **Low (P3)**: naming, comments, small simplifications, style.
- Don't report pure style preferences as blocking. Don't repeat a finding that an earlier review on the same lines already made unless the new commit didn't fix it.
- Never approve, merge, close or push. Only comment.

### Security findings stay out of public comments

This repository is public. Maintainers run a separate, private security review for every pull request.

- If you see a possible security vulnerability (a way to bypass a check, read or change data you shouldn't, crash or overload a service from outside, escalate privileges, or recover a secret), **don't describe it in the review**. Write one line only: `可能有安全问题，已交给维护者私下处理。` No file, line, attack steps or impact.
- Don't write about weaknesses that aren't fixed yet, limits that can be bypassed, or how a protection could be defeated, even as a side remark or a suggestion.
- Normal hardening advice that doesn't point at an exploitable gap (for example "add a unit test for the malformed input path") is fine.

### Privacy in the pull request itself

Flag as blocking anything in the diff, the commit messages or the pull request text that contains:

- a public IP address (use `example.org`, `192.0.2.x`, `198.51.100.x`, `203.0.113.x` or `2001:db8::` in tests and docs),
- an email address, a real name, a computer user name or host name, or a machine-specific absolute path,
- a key, token, password or other secret.
