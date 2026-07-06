// Package analyzer orchestrates concurrent package analysis: a bounded worker
// pool fans out over the dependency list, each worker fetches the artifact
// from its registry and runs every heuristic, and results stream back over a
// channel as they complete.
package analyzer

import (
	"context"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/JAugusto42/sandtrap/internal/registry"
)

// Rule is re-declared here (structurally identical to heuristics.Rule) so the
// analyzer does not import the heuristics package — keeping the dependency
// arrow pointing in one direction: cli → analyzer ← heuristics.
type Rule interface {
	ID() string
	Check(a *registry.Artifact) []Finding
}

// Options tunes a scan run.
type Options struct {
	Workers        int           // 0 = auto (2×CPU, capped at 16)
	PackageTimeout time.Duration // per-package budget, 0 = 90s
	// Suppress filters findings accepted in a baseline file. Suppressed
	// findings are dropped from the verdict but counted in Result.Suppressed.
	Suppress func(Package, Finding) bool
}

// Analyzer holds the registry clients and rule set for a run.
type Analyzer struct {
	clients map[Ecosystem]registry.Client
	rules   []Rule
	opts    Options
}

// New builds an Analyzer with the given rules and default registry clients.
func New(rules []Rule, opts Options) *Analyzer {
	if opts.Workers <= 0 {
		opts.Workers = runtime.NumCPU() * 2
		if opts.Workers > 16 {
			opts.Workers = 16
		}
	}
	if opts.PackageTimeout <= 0 {
		opts.PackageTimeout = 90 * time.Second
	}
	return &Analyzer{
		clients: map[Ecosystem]registry.Client{
			NPM:  registry.NewNPM(),
			PyPI: registry.NewPyPI(),
		},
		rules: rules,
		opts:  opts,
	}
}

// Run analyzes all packages concurrently. Results are delivered on the
// returned channel in completion order and the channel is closed when every
// worker finishes. Cancel the context to abort early.
func (an *Analyzer) Run(ctx context.Context, pkgs []Package) <-chan Result {
	jobs := make(chan Package)
	results := make(chan Result, an.opts.Workers)

	var wg sync.WaitGroup
	for i := 0; i < an.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pkg := range jobs {
				select {
				case <-ctx.Done():
					return
				case results <- an.analyzeOne(ctx, pkg):
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, p := range pkgs {
			select {
			case <-ctx.Done():
				return
			case jobs <- p:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

// analyzeOne fetches one package artifact and runs every rule against it.
func (an *Analyzer) analyzeOne(ctx context.Context, pkg Package) Result {
	start := time.Now()
	res := Result{Package: pkg}

	client, ok := an.clients[pkg.Ecosystem]
	if !ok {
		res.Err = "unsupported ecosystem: " + string(pkg.Ecosystem)
		return res
	}

	pctx, cancel := context.WithTimeout(ctx, an.opts.PackageTimeout)
	defer cancel()

	art, err := client.Fetch(pctx, pkg.Name, pkg.Version)
	if err != nil {
		res.Err = err.Error()
		res.Elapsed = time.Since(start)
		res.DurationMS = res.Elapsed.Milliseconds()
		return res
	}
	res.FilesScanned = len(art.Files)

	for _, rule := range an.rules {
		res.Findings = append(res.Findings, rule.Check(art)...)
	}

	// Baseline: drop accepted findings before scoring so CI fails only on
	// NEW behavior — the signature of a hijacked release.
	if an.opts.Suppress != nil {
		kept := res.Findings[:0]
		for _, f := range res.Findings {
			if an.opts.Suppress(pkg, f) {
				res.Suppressed++
			} else {
				kept = append(kept, f)
			}
		}
		res.Findings = kept
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		return res.Findings[i].Severity > res.Findings[j].Severity
	})
	// Score per rule = worst finding at full weight + 20% for each repeat.
	// Ten files reading .netrc is the same *kind* of evidence as one — the
	// verdict should escalate through *diverse* signals, mirroring how a
	// human analyst reasons.
	perRule := map[string]int{}
	for _, f := range res.Findings {
		w := f.Severity.Score()
		if cur, seen := perRule[f.RuleID]; seen {
			perRule[f.RuleID] = cur + w/5
		} else {
			perRule[f.RuleID] = w
		}
	}
	for _, s := range perRule {
		res.Score += s
	}
	res.Risk = riskFromScore(res.Score)
	res.Elapsed = time.Since(start)
	res.DurationMS = res.Elapsed.Milliseconds()
	return res
}
