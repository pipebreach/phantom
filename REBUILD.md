# Assisted rebuild

`phantom scan <pkg>==<version> --rebuild` builds a wheel from the package's
**published sdist** and diffs it against the **published wheel**. A finding
means the wheel contains code the sdist does not build: it was tampered after
the source was cut. This is the LiteLLM shape (clean repo and sdist, poisoned
wheel).

## This executes untrusted code

Rebuilding runs the package's own build (`setup.py`, build backend). That code
is attacker-influenced. Two protections apply, and you need both:

1. **A disposable host.** Run in a fresh Codespace or a throwaway CI runner, not
   your laptop. If the build is malicious, only the disposable environment is
   exposed.
2. **No network for the build.** phantom wraps the build subprocess in a network
   namespace with no interfaces (`unshare --net`) so a malicious build cannot
   exfiltrate. If `unshare` is unavailable, phantom warns that egress was not
   denied; treat that run as untrusted.

Do not run `--rebuild` in an environment holding secrets you care about.

## Codespaces

This repo ships a `.devcontainer` that provisions a disposable Python
environment with the common build backends pre-installed (builds run offline,
so build dependencies must be present ahead of time). Open the repo in a
Codespace and:

```bash
phantom scan somepkg==1.2.3 --rebuild
```

## Limits

- PyPI only; the sdist must be published.
- The build runs offline (`--no-isolation`), so packages needing an uncommon
  build backend not pre-installed will fail to rebuild (reported, not a false
  finding).
- Non-deterministic build output is compared with phantom's normalizers (AST
  for Python), not bit-for-bit, so formatting noise does not cause findings.
