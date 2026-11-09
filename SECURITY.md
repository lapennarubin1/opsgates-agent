# Security policy

OpsGates gives AI assistants access to servers, so we take security reports seriously.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately:

- Use GitHub's **"Report a vulnerability"** button (Security → Advisories) on this repository, or
- email the address listed at <https://opsgates.com/security>.

Include what you found, how to reproduce it and the version (`sudo opsgate help` shows it).
We aim to acknowledge reports within 3 working days and to ship a fix for confirmed issues as soon as possible.

## Scope

In scope: this agent (path confinement, secret redaction, authentication, OAuth, the installer and the systemd sandbox).
Out of scope: social engineering, denial of service by flooding, and issues that need an already-compromised server or root access.

## Supported versions

Only the latest release is supported. Update with `sudo opsgate update`.
