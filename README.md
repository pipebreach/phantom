# phantom

**Detects divergence between a package's declared source and the artifact it actually publishes.**

Part of the [pipebreach] research project. `phantom` compares *what a package declares* (its source repository at the tag matching the published version) against *what it ships* (the wheel on PyPI). Any code present in the artifact that does not exist in the source is a **phantom** — flagged regardless of whether it "looks malicious".

## Threat model

An attacker compromises a package's build/publish pipeline and injects code into the distributed artifact **without touching the source repository**. Anyone auditing the code on GitHub sees nothing; anyone installing the package gets the backdoor.

Real-world incidents this class of tool catches:

- **LiteLLM (March 2026):** a three-stage payload (credential theft, Kubernetes lateral movement, RCE backdoor) injected into the PyPI wheel post-build. The repo was clean.
- **XZ Utils (CVE-2024-3094):** backdoor present in the distribution tarball but not in git.

Malware scanners (GuardDog, Semgrep rules, etc.) look for *known-bad patterns*. `phantom` is **pattern-agnostic**: it doesn't care whether injected code looks bad — only that it isn't in the source. That catches clean, obfuscated, or never-before-seen injection. Reproducible-builds infrastructure (rebuilderd) solves this for OS distros; nothing equivalent exists for language ecosystems. That's the gap.

## Quickstart

Requires Python 3.11+. Zero runtime dependencies (stdlib only, by design).

```bash
pip install phantom-scan
# or, without installing:
uvx phantom-scan scan requests==2.31.0

# Scan a single package version
phantom scan requests==2.31.0

# Machine-readable output
phantom scan requests==2.31.0 --json
phantom scan requests==2.31.0 --sarif   # for GitHub code scanning
```

What a scan does:

1. Downloads the pure-Python wheel from the PyPI JSON API.
2. Resolves the source repo from the package metadata (`project_urls`) and finds the tag matching the version (`v{ver}`, `{ver}`, `release-{ver}`).
3. Computes an **AST-normalized hash** of every `.py` file on both sides (comments/whitespace/formatting don't count) and flags every wheel file whose content exists nowhere in the source.
4. Grades each phantom by its execution vectors (subprocess, network, `exec`/`eval`, `os.environ` access). Reading data + network egress = `critical` (exfiltration shape).
5. Any `.pth` file inside a wheel is always flagged (it executes at interpreter startup).

Downloads are cached on disk (`~/.cache/phantom` by default, `--cache-dir` to override), so re-scanning the same `pkg==version` is deterministic and offline.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings (or only medium/low severity) |
| 1 | At least one **high**/**critical** finding |
| 2 | Execution error (bad arguments, network failure, package not found) |
| 3 | Out of scope: the release has no pure-Python wheel (binary wheels or sdist only) |

## GitHub Action

Package maintainers can verify their own releases right after publishing —
this catches a compromised build/publish pipeline (the LiteLLM case) even
though the repo looks clean:

```yaml
name: verify-release
on:
  workflow_run:
    workflows: [publish]        # run after your publish workflow completes
    types: [completed]

jobs:
  phantom:
    runs-on: ubuntu-latest
    permissions:
      security-events: write    # for SARIF upload
    steps:
      - uses: pipebreach/phantom@5be67a3e8c73f18273f4ee6bb944ba2dec059c59 # v0.1.0
        id: scan
        with:
          spec: mypkg==1.2.3    # e.g. derived from the release tag
      - uses: github/codeql-action/upload-sarif@411c4c9a36b3fca4d674f06b6396b2c6d23522c6 # v3.36.3
        if: always() && hashFiles('phantom-results.sarif') != ''
        with:
          sarif_file: phantom-results.sarif
```

The job fails when phantom finds a high/critical divergence. Notes:

- Scan *after* the artifact is live on PyPI (publishing and scanning in the
  same workflow can race index propagation).
- If your tags carry a `v` prefix, strip it for the spec: phantom probes tag
  conventions on the source side, but the spec version must match PyPI.
- Releases without a pure-Python wheel emit a warning instead of failing;
  set `fail-on-out-of-scope: "true"` to make them fail.

Inputs: `spec` (required), `ecosystem` (default `pypi`), `sarif-file`
(default `phantom-results.sarif`), `fail-on-out-of-scope` (default `false`).
Outputs: `exit-code`, `sarif-file`.

Scanning a whole lockfile from a consumer project (`phantom audit`) will use
the same action once M2 lands.

## Finding types

| Type | Meaning | Severity |
|------|---------|----------|
| `phantom_file` | A `.py` in the wheel whose content exists nowhere in the source | `medium`–`critical` per execution vectors |
| `suspicious_pth` | A `.pth` file shipped inside the wheel | `high`; `critical` if it has import lines |
| `no_source_declared` | No source repo in the package metadata — unverifiable by construction | `high` |
| `source_ref_not_found` | Repo declared, but no tag matches the version | `medium` |

Every finding carries a `confidence` and a `reason`: phantom prefers saying "this is phantom but might be build-generated code" (e.g. `_version.py` from setuptools-scm gets `low` confidence) over false certainty.

The `--json` output is a versioned public contract (`schema_version`); breaking changes bump the version.

## Library use

The CLI is a thin layer over the core (usable in CI, batch jobs, services):

```python
from phantom.cache import DiskCache, default_cache_dir
from phantom.core import scan
from phantom.registry import build_default_registry

registry = build_default_registry(DiskCache(default_cache_dir()))
result = scan("six", "1.16.0", registry.get("pypi"))
print(result.to_dict())
```

## Known limits (M1)

Explicitly **not supported yet** — the plugin architecture (`Ecosystem`/`Fetcher`/`SourceResolver`/`Normalizer` interfaces) is designed so these land without touching the core:

- **Compiled/binary wheels and sdist-only releases** — reported as out of scope (exit 3). Needs build-step normalizers (M3).
- **npm / JavaScript** — no minification/transpilation normalizers yet (M2/M3).
- **Phantom *spans*** — code injected *into* a file that does exist in the source. M1 only detects whole phantom files; intra-file AST diffing is M2. A modified file will still show up as a phantom (its hash won't match), but without span-level localization.
- **`phantom audit <lockfile>`** — registered but stubbed (M2).
- **Non-GitHub forges** (GitLab, Codeberg…) — M3.
- **Tag-based resolution only** — packages that publish from a commit without tagging that version yield `source_ref_not_found`.

## Development

```bash
pip install -e ".[dev]"
pytest                             # unit tests, fully offline
PHANTOM_NETWORK_TESTS=1 pytest -m network   # integration tests against real PyPI/GitHub
```

[pipebreach]: https://github.com/pipebreach
