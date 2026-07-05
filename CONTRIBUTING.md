# Contributing to Sandtrap

Thanks for your interest! This document explains how the project works end to
end, and gives step-by-step guides for the most common contributions: adding
a lockfile format, adding a registry/ecosystem, adding a detection rule, and
adding an output format.

## Project philosophy

Three principles drive every design decision. Understanding them will make
your PR review much smoother:

1. **Behavioral, not reputational.** Sandtrap never asks "is this package on
   a bad list?" — it asks "what does this code do?". The 2025–2026 attack wave
   (Shai-Hulud worm lineage, the axios and Trivy hijacks) compromised
   *legitimate, popular* packages, so any reputation- or popularity-based
   signal is structurally blind to the threat model. Rules must key on
   behavior found in the artifact itself.

2. **Precision is the product.** A security scanner that cries wolf gets
   ignored, and an ignored scanner is worse than no scanner. Every rule was
   calibrated against ~1,800 packages from real production lockfiles; PRs
   that add detection must demonstrate they do not flag popular benign
   packages (see *Testing your change* below). When in doubt, prefer a
   missed edge case over a false positive — other rules and diff mode
   provide defense in depth.

3. **Zero dependencies.** The module uses only the Go standard library. A
   supply chain security tool must not have a supply chain of its own: the
   entire codebase should be auditable in an afternoon. PRs adding external
   dependencies will be declined regardless of convenience.

## Architecture and data flow

```
cmd/sandtrap/main.go        entry point; delegates to internal/cli
internal/
├── cli/          command parsing (scan/check), flag handling, wiring
├── lockfile/     discovers and parses dependency manifests → []Package
├── analyzer/     core types + concurrent orchestration (worker pool)
├── registry/     npm/PyPI clients; download + safe in-memory extraction
├── heuristics/   detection rules + rule metadata catalog
├── baseline/     accepted-findings files (.sandtrap.json)
├── report/       terminal, JSON and SARIF renderers; exit-code policy
└── runlog/       timestamped execution log (separate from the report)
```

A scan flows like this:

1. `cli` parses flags (interleaved: they may appear before or after
   positional args) and calls `lockfile.Discover(dir)`.
2. `lockfile` parses every supported manifest into a flat, deduplicated
   `[]analyzer.Package{Ecosystem, Name, Version, Source}`.
3. `analyzer.New(rules, opts).Run(ctx, pkgs)` starts a bounded worker pool
   (goroutines + channels, default 2×CPU capped at 16). Each worker:
   a. resolves the package's `registry.Client` by ecosystem,
   b. fetches metadata + archive (`Client.Fetch` → `registry.Artifact`),
   c. runs every `Rule.Check(artifact)` and collects findings,
   d. applies the baseline suppressor, aggregates the score per rule
      (worst finding at full weight + 20% per repeat — ten files with the
      same signal are one *kind* of evidence, not ten), and derives the
      `RiskLevel` verdict.
4. Results stream back over a channel in completion order. `report.Collect`
   aggregates them, streams progress lines, and feeds the execution log.
5. The chosen renderer (`Terminal`, `JSON`, `SARIF`) writes the report;
   `report.ExitCode` implements CI gating (`--fail-on`).

Dependency arrows point one way: `cli → {analyzer, lockfile, report,
baseline, runlog}`, `analyzer → registry`, `heuristics → {analyzer,
registry}`, `report → {analyzer, heuristics, runlog}`. The analyzer defines
its own `Rule` interface (structurally identical to the heuristics') so it
never imports the heuristics package.

## Core types (internal/analyzer/types.go)

- `Package` — one dependency to analyze (`Ecosystem`, `Name`, `Version`,
  `Source` = which lockfile pulled it in).
- `Finding` — one suspicious signal: `RuleID`, `Severity` (INFO…CRITICAL),
  `Title`, `Detail` (why it matters, referencing real attack patterns),
  `File` (path inside the archive), `Evidence` (short redacted excerpt).
- `Result` — full outcome per package: findings, aggregated `Score`,
  `RiskLevel` verdict, error, timing, suppressed count.
- Severity→score weights and score→risk thresholds live here too. Change
  them only with strong justification: they encode the calibration.

## How to add support for a new lockfile format

Example: pnpm-lock.yaml. Everything happens in `internal/lockfile/`.

1. Create `pnpm.go` with `func parsePnpmLock(path string) ([]analyzer.Package, error)`.
   Study `yarn.go` — it handles the hard cases you must also handle:
   - **Aliases**: the installed name may differ from the registry name
     (`string-width-cjs` → `string-width`). Always emit the *registry* name.
   - **Non-registry entries**: workspace members, `patch:`/`link:`/git/file
     dependencies are not downloadable from the public registry — skip them.
   - **Scoped names** (`@scope/pkg`) interact badly with naive `@` splitting.
2. Register the file in `Discover`'s `candidates` slice:
   `{"pnpm-lock.yaml", parsePnpmLock}`.
3. Add table tests in `lockfile_test.go` covering: normal entries, scoped
   packages, aliases, non-registry entries, and an empty/comment-only file.
4. Update the "no supported lockfiles found" message in `internal/cli/cli.go`
   and the README's format list.

That's it — packages flow into the existing pipeline untouched.

## How to add support for a new ecosystem/registry

Example: crates.io (Rust). Touches `internal/registry/`, `internal/analyzer/`
and `internal/lockfile/`.

1. Add the ecosystem constant in `internal/analyzer/types.go`:
   `Crates Ecosystem = "crates"`.
2. Create `internal/registry/crates.go` implementing the `Client` interface:
   `Fetch(ctx, name, version) (*Artifact, error)`. Responsibilities:
   - Query the registry's metadata API with `getWithRetry` (3 attempts,
     backoff — long scans WILL hit transient network failures).
   - Fill `Metadata`: `PublishedAt`/`FirstPublishedAt` (feeds the
     fresh-publish rule), `Maintainers`, and `InstallScripts` for whatever
     the ecosystem's install-time execution mechanism is (npm hooks,
     setup.py, build.rs…). Model it as install scripts so the
     install-scripts rule treats every ecosystem uniformly.
   - Download the archive with `download()` (has size caps + retry) and
     extract with `extractTarGz`/`extractZip` (they enforce the
     anti-zip-bomb limits in `registry.go` — never bypass them).
   - Be lenient with malformed metadata: old packages publish garbage
     (see `decodeScripts` in npm.go). Never fail a whole packument because
     one field has an unexpected shape.
3. Register the client in `analyzer.New`'s client map.
4. Add a lockfile parser (Cargo.lock) per the previous section.
5. Review each heuristic for ecosystem-specific patterns worth adding
   (e.g. Rust: `build.rs` network access). File-level rules (exfiltration,
   credential-access) work on any ecosystem out of the box.

## How to add a detection rule

Rules live in `internal/heuristics/`, one file each.

1. Create the type implementing the `Rule` interface:
   ```go
   type MyRule struct{}
   func (MyRule) ID() string { return "my-rule" }
   func (MyRule) Check(a *registry.Artifact) []analyzer.Finding { ... }
   ```
2. Rules must be **stateless and safe for concurrent use** — `Check` runs
   from many goroutines simultaneously.
3. Design for precision from day one:
   - Require *combinations* of signals, not single matches. Legitimate code
     trips any one pattern; malware stacks different techniques.
   - Study the false-positive classes already engineered around in
     `obfuscation.go`: inline sourcemaps and base64 data-URIs (stripped
     before analysis), compiler banners ("Generated by dart2js"), minified
     bundles (held to the obfuscator-fingerprint bar: `_0x` mangling /
     hex-escape floods), decode-without-execute data tables, and test/docs
     paths (`adjustForTestPath` lowers severity one tier).
   - Write `Detail` text that references the real attack pattern the rule
     targets, and keep `Evidence` short and redacted (`truncate`).
4. Register the rule in `All()` (heuristics.go) **and** add its
   documentation to `Catalog()` (catalog.go): description, remediation and
   references. The catalog feeds the JSON report's `rules` section and
   SARIF's driver rules — a rule without catalog metadata is a bug.
5. Tests: add positive cases (synthetic, inert fixtures that mimic the
   *shape* of the attack — never functional malware) and negative cases
   proving popular benign patterns do not flag. See `heuristics_test.go`.

## How to add an output format

1. Create `internal/report/<format>.go` with
   `func MyFormat(w io.Writer, s *Summary, meta Meta) error`.
2. Wire it into the `switch c.format` in `internal/cli/cli.go` and document
   it in the usage string and README.
3. Schema tests in `report_test.go` — use `sampleSummary()` and assert the
   structural invariants a consumer would rely on (see the SARIF test for
   the level of rigor expected, including edge cases like "clean scan emits
   an empty array, not null").

## Testing your change

```sh
make lint          # go vet + gofmt
make test          # unit tests with -race
make build
```

For any change touching detection or registries, also validate live against
the calibration set — these are the packages that historically produced
false positives, plus known-benign controls:

```sh
./bin/sandtrap check --fail-on never npm \
  prettier@3.8.3 sass@1.98.0 vite@7.3.5 @vue/compiler-sfc@3.5.38 \
  mermaid@11.15.0 superagent@10.3.0 istanbul-reports@3.2.0 \
  vscode-uri@3.1.0 lz-string@1.5.0 webpack@5.107.2 lodash@4.17.21 \
  axios@1.6.0 speakingurl@14.0.1
```

Everything above must scan **clean** (behavioral true positives like
esbuild/vue-demi hooks are expected and documented). If your change flags
any of them, that is a regression, not a discovery.

## Code style

- Standard Go: `gofmt`, `go vet`, table tests, small focused files.
- Comments: doc comments on every exported (and significant unexported)
  type/function, plus rationale comments where behavior is non-obvious —
  especially calibration decisions in heuristics, which encode hard-won
  knowledge about real-world false positives. No step-by-step narration of
  obvious code.
- Errors: wrap with context (`fmt.Errorf("npm tarball: %w", err)`); a
  failed package must never abort the scan — it becomes a SKIP.
- All limits (archive size, file count, timeouts) are constants in
  `registry/registry.go`; new I/O paths must respect them.

## Commit and PR conventions

- Conventional commits: `feat:`, `fix:`, `perf:`, `docs:`, `test:`.
- One logical change per PR. Detection changes must include the calibration
  evidence (which packages were tested, before/after behavior).
- New rules or ecosystems: update README's detection table and roadmap.

## Roadmap (help wanted)

- **Diff mode** (`sandtrap diff npm pkg@old pkg@new`): alert on *newly
  introduced* capabilities between versions — the definitive answer to
  hijacked releases of trusted packages.
- Sandbox execution of install hooks (container + syscall/network observation).
- More lockfiles: pnpm-lock.yaml, poetry.lock, uv.lock; ecosystems: crates,
  RubyGems, Go proxy.
- OSV / malicious-package feed integration; compromise-window lookups.
- Offline/local archive cache; rule plugin loading; policy files.
