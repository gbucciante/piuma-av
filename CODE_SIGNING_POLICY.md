# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org)

*Firma digitale gratuita fornita da SignPath.io, certificato di SignPath Foundation.*

> **Status:** application to SignPath Foundation pending. Releases published before
> approval are unsigned.

## What is signed

Windows release packages of PiumaAV (`PiumaAV-<version>-Windows.zip`, attached to
[GitHub Releases](https://github.com/gbucciante/piuma-av/releases)). Inside the package all
PowerShell scripts in `install/windows/` are Authenticode-signed. Batch (`.bat`) and Python
(`.py`) files cannot carry an Authenticode signature; their integrity is covered by the
SHA-256 checksum published with each release.

Signed files are built exclusively from the source code in this repository by the GitHub
Actions workflow [`.github/workflows/release.yml`](.github/workflows/release.yml), using
[`tools/build_release.py`](tools/build_release.py) (deterministic packaging). The SignPath
artifact configuration is versioned in [`.signpath/`](.signpath/). Every signing request
is approved manually.

## Team roles

| Role | Members |
|---|---|
| Committers and reviewers | [gbucciante](https://github.com/gbucciante) |
| Approvers | [gbucciante](https://github.com/gbucciante) (repository owner) |

- **Committers** may change the source code directly.
- **Reviewers**: every contribution from people who are not committers (pull requests) is
  reviewed by a committer before merging, including build scripts and CI configuration.
- **Approvers**: each signing request is manually approved in SignPath before release.

All team members use multi-factor authentication on GitHub and SignPath.

## Privacy policy

See [PRIVACY.md](PRIVACY.md). In short: PiumaAV has no telemetry. It only contacts the
services listed there (signature and threat-feed updates; optional, opt-in hash lookups),
and every one of them can be disabled in the configuration file.

## System changes and uninstallation

Before changing anything, the Windows installer lists the system changes it will make
(Python and ClamAV via winget, program and data folders, scheduled tasks, a dedicated
section in the `hosts` file for the malicious-site blocklist, Windows Firewall rules in the
`PiumaAV` group, exploit-protection settings for browsers/Office/PDF readers). Everything is
reverted by `install\windows\uninstall.ps1`. Microsoft Defender hardening is never applied
automatically: it is a separate, opt-in script (`harden-defender.ps1`, with `-Audit` to
try it and `-Undo` to revert it). See [README.md](README.md).

## Reporting

Suspected misuse of the signing certificate or a signed file that does not match this
repository: open an issue at https://github.com/gbucciante/piuma-av/issues or contact
SignPath Foundation at https://signpath.org.
