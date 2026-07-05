# 🪤 sandtrap

**Trap the worm before it traps you.**

Sandtrap is a behavioral supply chain scanner for npm and PyPI. Instead of matching known-bad package lists (useless against hijacked *legitimate* packages — axios, Trivy, TanStack…), it downloads each dependency and inspects **what the code actually does**: install-time execution hooks, stacked obfuscation, credential-store access and exfiltration primitives — the exact tradecraft of the Shai-Hulud / Mini Shai-Hulud worm lineage and the 2025–2026 registry compromise wave.

- **Zero dependencies.** Pure Go standard library. A supply chain security tool should not have a supply chain of its own — audit the whole codebase in an afternoon.
- **Fast.** Concurrent worker pool (goroutines + channels) scans hundreds of packages in seconds.
- **CI-native.** Meaningful exit codes, `--fail-on` thresholds, JSON output, streaming progress.
- **Low noise by design.** Rules require *combined, diverse* signals; verdicts aggregate per-rule instead of double-counting. Popular benign packages scan clean.

## Install

```sh
go install github.com/sandtrap-sh/sandtrap/cmd/sandtrap@latest
# or grab a prebuilt binary from Releases
```

## Use

```sh
# scan a project (package-lock.json / yarn.lock / requirements.txt)
sandtrap scan .

# vet a single package before adding it
sandtrap check npm some-package@1.2.3
sandtrap check pypi somepkg@4.5.6

# CI gating: fail the build on HIGH or worse, machine-readable report
sandtrap scan --fail-on high --format json . > sandtrap-report.json
```

Exit codes: `0` ok · `2` risk threshold reached · `3` analysis errors (with `--fail-on-error`) · `64` usage.

## GitHub Actions

```yaml
- name: Supply chain scan
  run: |
    go install github.com/sandtrap-sh/sandtrap/cmd/sandtrap@latest
    sandtrap scan --fail-on high .
```

## What it detects

| Rule | Signal | Real-world precedent |
|---|---|---|
| `install-scripts` | npm lifecycle hooks, pipe-to-shell / inline interpreters / base64 staging in hooks | Detonation point of every Shai-Hulud wave |
| `obfuscation` | Stacked techniques: eval chains + encoded blobs + mangled identifiers + entropy | Mini Shai-Hulud's "heavily obfuscated payloads" |
| `exfiltration` | webhook.site / Discord webhooks / tunnels, raw-IP C2, fetch-and-execute, bulk `process.env` capture | April 2026 npm/PyPI/Docker Hub secret-stealing wave |
| `credential-access` | `.npmrc` / `.pypirc` / SSH keys / browser stores / cloud metadata endpoint | How the worm steals maintainer tokens to self-propagate |
| `fresh-publish` | Version published <24h/<7d ago, package <30d old | The axios compromise window was ~3 hours |

Precision is engineered in: compiler output (dart2js banners, minified bundles, inline sourcemaps), decode-without-execute data tables, npm aliases, doc IPs and test fixtures are all recognized — validated against 1,700+ packages from real production lockfiles.

## Baseline: fail only on NEW behavior

Some trusted packages legitimately trip behavioral rules (esbuild's binary-download postinstall, vue-demi's version switcher). Review them once, accept them, and future scans fail only on findings **not** in the baseline — which is precisely the signature of a hijacked release:

```sh
sandtrap scan .                    # review the findings
sandtrap scan --write-baseline .   # accept them into .sandtrap.json
sandtrap scan .                    # exit 0; a NEW behavior in any package fails again
```

`.sandtrap.json` entries pin exact versions (`npm:esbuild@0.27.4/install-scripts`), so a version bump resurfaces the finding for fresh review. Use `@*` to accept a rule for all versions of a package. Commit the file to your repo.

## How verdicts work

Each finding has a severity (INFO→CRITICAL). Per-package score aggregates the *worst finding per rule* plus a small increment for repeats — ten files with the same signal are one kind of evidence, not ten. Diverse signals across different rules escalate the verdict, mirroring human triage.

## Honest limitations (read this)

Sandtrap is static, first-pass triage — a tripwire, not a bunker:

- Determined attackers can evade static heuristics (staged payloads fetched post-install, novel encodings).
- It does not (yet) execute packages in a sandbox; see the roadmap.
- A CLEAN verdict means "no known-bad behavioral patterns", not "safe".
- Findings are leads for review, not convictions. MEDIUM ≠ malicious.

Use it alongside lockfile pinning, version cooldowns, `--ignore-scripts`, and provenance/attestation checks.

## Roadmap

- **v0.2 — diff mode:** compare a new version against the previous one; alert on *newly introduced* hooks, obfuscation or network code (catches hijacked releases of trusted packages).
- **v0.3 — sandbox execution:** run install hooks in an isolated container and observe syscalls/network.
- **v0.4 — more ecosystems & lockfiles:** pnpm-lock.yaml, poetry.lock, uv.lock; Cargo/RubyGems/Go proxy. (yarn.lock classic+berry: ✅ shipped in v0.1.1)
- **v0.5 — intel feeds:** OSV/malicious-package feeds, compromise-window lookups for incident response.
- Rule plugins, SARIF output, allow/deny policy files, offline cache.

## License

MIT
