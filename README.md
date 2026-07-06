# 🪤 sandtrap

**Trap the worm before it traps you.**

Sandtrap is a behavioral supply chain scanner for npm and PyPI. Instead of matching known-bad package lists (useless against hijacked *legitimate* packages — axios, Trivy, TanStack…), it downloads each dependency and inspects **what the code actually does**: install-time execution hooks, stacked obfuscation, credential-store access and exfiltration primitives — the exact tradecraft of the Shai-Hulud / Mini Shai-Hulud worm lineage and the 2025–2026 registry compromise wave.

- **Zero dependencies.** Pure Go standard library. A supply chain security tool should not have a supply chain of its own — audit the whole codebase in an afternoon.
- **Fast.** Concurrent worker pool (goroutines + channels) scans hundreds of packages in seconds.
- **CI-native.** Meaningful exit codes, `--fail-on` thresholds, JSON output, streaming progress.
- **Low noise by design.** Rules require *combined, diverse* signals; verdicts aggregate per-rule instead of double-counting. Popular benign packages scan clean.

## Install

```sh
go install github.com/JAugusto42/sandtrap/cmd/sandtrap@latest
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
sandtrap scan --fail-on high --format json --output sandtrap-report.json .

# SARIF for GitHub code scanning (findings appear in the Security tab)
sandtrap scan --format sarif --output sandtrap.sarif .
```

Exit codes: `0` ok · `2` risk threshold reached · `3` analysis errors (with `--fail-on-error`) · `64` usage.

## GitHub Actions

```yaml
- name: Supply chain scan
  run: |
    go install github.com/JAugusto42/sandtrap/cmd/sandtrap@latest
    sandtrap scan --fail-on high --format sarif --output sandtrap.sarif .
- name: Upload to GitHub code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sandtrap.sarif
```

## Report formats

- **text** (default) — colored terminal report for humans.
- **json** — structured report (`schema: sandtrap-report/1`): `tool`, `scan` (targets, duration, error/suppressed counts, configured gate), `summary` (by-risk histogram, worst risk), `rules` (full description + remediation + references for every rule that fired, referenced by `rule_id`), and `results` (per-package verdict, score, findings with severity, file path inside the archive, and redacted evidence excerpt). Severities and risks serialize as strings (`"CRITICAL"`), never ordinals.
- **sarif** — SARIF 2.1.0 for GitHub code scanning and compatible dashboards: one result per finding (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note), the lockfile as physical location, the exact in-archive file as logical location, and the rule catalog embedded in the driver.

Use `--output FILE` with any format; streaming progress stays on stderr so pipes and files receive only the report.

## Execution log and verbose mode

The report answers "what is the risk state of my dependencies"; the **execution log** answers "what exactly did this run do" — the artifact you attach to CI or an incident timeline. `--log FILE` writes a timestamped record of the run configuration, every package analyzed (verdict, score, files inspected, duration), every finding with evidence, every fetch error, and the final summary with exit code. `--verbose` mirrors those events to stderr live and, if no `--log` is given, defaults the file to `sandtrap.log`. Report, execution log and terminal streaming are three independent outputs:

```sh
sandtrap scan . --verbose --format json --output report.json
# → report.json (risk report) + sandtrap.log (execution record) + live progress on stderr
```

## Network resilience

Real-world scans hit flaky links. Sandtrap layers three defenses: every registry request retries up to 3× with backoff; the per-package `--timeout` budget truly bounds downloads (no global body-read timeout that kills large tarballs on slow connections); and after the main pass, an automatic **retry pass** re-fetches every transiently-failed package with reduced concurrency (4 workers, doubled timeout) before the report is produced — permanent errors (404s) are not retried. On very poor connections, additionally lower the initial pressure with `--workers 4 --timeout 3m`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full architecture walkthrough and step-by-step guides for adding lockfile formats, ecosystems, detection rules and output formats.

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
