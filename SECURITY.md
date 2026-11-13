# Security policy

## Reporting a vulnerability

Please report security problems privately. Don't open a public issue, pull request or discussion with the details.

1. Open the **Security** tab of this repository and choose **Report a vulnerability**. That creates a private advisory that only the maintainers can see.
2. If that button is missing, open an issue that only asks for a private contact, with no details in it.

Include what you found, the affected version or commit, and the steps to reproduce it. We'll confirm that we received it, fix it, and then publish an advisory. Please give us a reasonable time to ship the fix before you talk about it in public.

## Supported versions

Only the latest release and the current development branch get security fixes.

## Scope

In scope:

- The Jay patches listed in `JAY.md` and anything that weakens them.
- The build and release workflow (`.github/workflows/jay-build.yml`), dependency pinning and `.cargo/audit.toml`.
- Problems in upstream EasyTier code that affect Jay's build. If the problem is also in upstream EasyTier, please report it to upstream as well, following their policy.

Out of scope:

- Third-party services and their own security (Microsoft, Mojang, Modrinth, CurseForge, download mirrors, relay nodes run by others).
- Minecraft itself, and mods or packs written by others.
- Attacks that need full control of the user's computer or account.
- Volumetric network floods; please don't test those against nodes you don't own.
- Social engineering.

## Security review

Automated and manual security reviews of pull requests are done privately. Public review comments mention at most the number of findings, never their details.
