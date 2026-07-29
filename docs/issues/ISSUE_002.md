# ISSUE_002 — `/usr/bin/docker` fails with "Input/output error" after enabling WSL integration

## Problem

Enabling Docker Desktop's WSL integration for `Ubuntu-24.04` did not make `docker`
usable. The binary now exists on PATH, but running it fails:

```
$ docker info
/bin/bash: line 1: /usr/bin/docker: Input/output error
```

This is worse than the previous state (ISSUE_001, `command not found`) because it
looks like the integration succeeded. Every documented workflow command
(`docker compose build`, `docker compose run --rm app pytest`, …) fails at the CLI
before ever reaching the daemon.

## Cause

The daemon is fine. Only the WSL-side CLI mount is stale.

`/usr/bin/docker` is a symlink into a read-only ISO that Docker Desktop mounts into
each integrated distro:

```
/usr/bin/docker -> /mnt/wsl/docker-desktop/cli-tools/usr/bin/docker

/isocache/entries/docker-wsl-cli.iso/13bcf80e… on /mnt/wsl/docker-desktop/cli-tools
    type iso9660 (ro,relatime,…)
```

Two timestamps give it away:

| Path | Mounted | Meaning |
|---|---|---|
| `/mnt/wsl/docker-desktop/cli-tools` | Jul 22 15:20 | ISO from an **earlier** Docker Desktop session |
| `/mnt/wsl/docker-desktop/shared-sockets/guest-services` | Jul 29 13:30 | Sockets from the **current** session |

Docker Desktop restarted (an update, or the "Apply & Restart" that enabled the
integration). The socket tmpfs was re-created, but this distro kept its old
iso9660 mount, whose backing file in `/isocache/` no longer exists. Directory
listing still works because the metadata is cached; reading the file hits the dead
loop device and returns EIO.

So it is a stale-mount problem, not a configuration problem. Re-checking the
integration toggle does not help, because the toggle is already correct.

## Solution

**Adopted: call the Windows CLI directly.** The daemon is reachable from WSL over
the same socket, so only the client binary needs replacing. Added to `~/.bashrc`:

```bash
alias docker='/mnt/c/Program\ Files/Docker/Docker/resources/bin/docker.exe'
alias docker-compose='/mnt/c/Program\ Files/Docker/Docker/resources/bin/docker.exe compose'
```

Verified: `docker info` → Server 29.6.1, `docker compose version` → v5.3.0, and the
existing `pi-detector:dev` image (9.94 GB) is intact, so nothing needs rebuilding.

**Caveat — path translation.** `docker.exe` takes Windows paths. `/mnt/d/...` is
auto-translated to `D:\...`, but pure-Linux paths (`~`, `/home/...`) are not, so
bind mounts and volume paths must live under `/mnt/`. This project sits under
`/mnt/d`, so its compose file works unchanged. A project under `$HOME` would not.

**Real fix, when convenient:** `wsl --shutdown` from PowerShell, then reopen the
terminal. That tears down every distro and remounts `cli-tools` from the current
ISO. Not done immediately because it kills all running WSL sessions, including the
one doing the work.

Worth trying first, as it is non-destructive: toggle WSL Integration off for the
distro → Apply → back on → Apply. This re-runs the integration bootstrap and may
remount the ISO without a full shutdown.

## Prevention

- **Do not read `command not found` and "Input/output error" as the same failure.**
  The first means integration is off; the second means it is on but stale. They
  have different fixes, and the second is the one that looks like success.
- After any Docker Desktop update or restart, if `docker` misbehaves in WSL, check
  the mount timestamps before touching settings:
  ```bash
  mount | grep docker-desktop
  ls -la /mnt/wsl/docker-desktop/
  ```
  A `cli-tools` mount older than `shared-sockets` means stale ISO.
- `docs/OVERVIEW.md` now documents the virtualenv path as a first-class
  alternative, so a broken Docker CLI no longer blocks the whole toolchain. The
  2026-07-28 OOD benchmark was produced entirely without Docker.
- Keep the project under `/mnt/` while the `docker.exe` alias is in use, or the
  path translation caveat above becomes a silent source of failed bind mounts.

## Related

- ISSUE_001 — the earlier state of this problem (integration off entirely) and the
  `.venv-dev` bootstrap that came out of it.
