// Package cli implements the sandtrap command line interface using only the
// standard library — a supply chain security tool should have no supply
// chain of its own.
package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/JAugusto42/sandtrap/internal/analyzer"
	"github.com/JAugusto42/sandtrap/internal/baseline"
	"github.com/JAugusto42/sandtrap/internal/heuristics"
	"github.com/JAugusto42/sandtrap/internal/lockfile"
	"github.com/JAugusto42/sandtrap/internal/report"
	"github.com/JAugusto42/sandtrap/internal/runlog"
)

// Version is stamped at build time via -ldflags.
var Version = "0.1.0-dev"

const usage = `sandtrap — behavioral supply chain scanner for npm and PyPI

Usage:
  sandtrap scan [dir]                 scan lockfiles in a project directory
  sandtrap check <eco> <pkg>[@ver]    analyze a single package (eco: npm|pypi)
  sandtrap version                    print version

Flags (scan & check):
  --workers N          concurrent workers (default: 2×CPU, max 16)
  --format FMT         output format: text|json|sarif (default text)
  --output FILE        write the report to FILE instead of stdout
  --fail-on LEVEL      exit 2 at/above: critical|high|medium|low|never (default high)
  --fail-on-error      exit 3 if any package could not be analyzed
  --timeout DUR        per-package timeout (default 90s)
  --quiet              suppress streaming progress lines
  --baseline FILE      accepted-findings file (default: .sandtrap.json in scan dir)
  --verbose            detailed per-package/per-finding events on stderr (implies --log)
  --log FILE           write a timestamped execution log (default with --verbose: sandtrap.log)
  --write-baseline     accept all current findings: write them to the baseline and exit 0

Exit codes: 0 ok · 2 risk threshold reached · 3 analysis errors · 64 usage

Examples:
  sandtrap scan .
  sandtrap check npm axios@1.12.0
  sandtrap scan --format json --fail-on critical . > report.json
  sandtrap scan --write-baseline .   # review findings once, then fail only on NEW behavior
`

// Run is the real entry point; it returns the process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return 64
	}
	cmd, rest := args[0], args[1:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Println("sandtrap", Version)
		return 0
	case "help", "--help", "-h":
		fmt.Print(usage)
		return 0
	case "scan":
		return runScan(rest)
	case "check":
		return runCheck(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		return 64
	}
}

// parseInterleaved parses flags that may appear before or after positional
// arguments. Go's flag package stops at the first positional, which silently
// ignores everything in `sandtrap scan . --format json` — a footgun no CLI
// should ship with.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

type commonFlags struct {
	workers       int
	format        string
	failOn        string
	failOnError   bool
	timeout       time.Duration
	quiet         bool
	output        string
	verbose       bool
	logPath       string
	baselinePath  string
	writeBaseline bool
	// scanDir is set by runScan so execute can auto-detect .sandtrap.json.
	scanDir string
	targets []string
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.IntVar(&c.workers, "workers", 0, "")
	fs.StringVar(&c.format, "format", "text", "")
	fs.StringVar(&c.output, "output", "", "")
	fs.BoolVar(&c.verbose, "verbose", false, "")
	fs.StringVar(&c.logPath, "log", "", "")
	fs.StringVar(&c.failOn, "fail-on", "high", "")
	fs.BoolVar(&c.failOnError, "fail-on-error", false, "")
	fs.DurationVar(&c.timeout, "timeout", 90*time.Second, "")
	fs.BoolVar(&c.quiet, "quiet", false, "")
	fs.StringVar(&c.baselinePath, "baseline", "", "")
	fs.BoolVar(&c.writeBaseline, "write-baseline", false, "")
	return c
}

// signalContext cancels on Ctrl-C / SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := bindCommon(fs)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return 64
	}
	dir := "."
	if len(pos) > 0 {
		dir = pos[0]
	}

	pkgs, files, err := lockfile.Discover(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandtrap:", err)
		return 64
	}
	if len(pkgs) == 0 {
		fmt.Fprintf(os.Stderr, "sandtrap: no supported lockfiles found in %s (looked for package-lock.json, yarn.lock, requirements.txt)\n", dir)
		return 64
	}
	c.scanDir = dir
	c.targets = files
	if !c.quiet {
		fmt.Fprintf(os.Stderr, "sandtrap %s — scanning %d packages from %s\n\n",
			Version, len(pkgs), strings.Join(files, ", "))
	}
	return execute(pkgs, c)
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := bindCommon(fs)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return 64
	}
	if len(pos) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sandtrap check <npm|pypi> <package>[@version] [more packages...]")
		return 64
	}
	eco := analyzer.Ecosystem(strings.ToLower(pos[0]))
	if eco != analyzer.NPM && eco != analyzer.PyPI {
		fmt.Fprintf(os.Stderr, "sandtrap: unsupported ecosystem %q (npm|pypi)\n", pos[0])
		return 64
	}
	var pkgs []analyzer.Package
	for _, spec := range pos[1:] {
		name, ver := splitSpec(spec)
		pkgs = append(pkgs, analyzer.Package{Ecosystem: eco, Name: name, Version: ver, Source: "cli"})
	}
	return execute(pkgs, c)
}

// splitSpec parses "name@version" honoring npm scopes ("@scope/pkg@1.0.0").
func splitSpec(spec string) (name, version string) {
	at := strings.LastIndexByte(spec, '@')
	if at <= 0 { // no version, or leading @ of a scope
		return spec, "latest"
	}
	return spec[:at], spec[at+1:]
}

func execute(pkgs []analyzer.Package, c *commonFlags) int {
	failOn, err := report.ParseRisk(c.failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandtrap:", err)
		return 64
	}

	// Execution log: --log writes it; --verbose mirrors it to stderr and,
	// when no path is given, defaults the file to sandtrap.log so a verbose
	// run always leaves an execution record behind.
	if c.verbose && c.logPath == "" {
		c.logPath = "sandtrap.log"
	}
	lg, err := runlog.New(c.logPath, c.verbose)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sandtrap:", err)
		return 64
	}
	defer lg.Close()
	lg.Event("INFO", "sandtrap %s starting packages=%d targets=%v fail-on=%s format=%s workers=%d timeout=%s",
		Version, len(pkgs), c.targets, c.failOn, c.format, c.workers, c.timeout)

	// Baseline: explicit --baseline path, or .sandtrap.json in the scan dir.
	var bl *baseline.Baseline
	blPath := c.baselinePath
	if blPath == "" && c.scanDir != "" {
		if candidate := filepath.Join(c.scanDir, baseline.DefaultFile); fileExists(candidate) {
			blPath = candidate
		}
	}
	if blPath != "" && !c.writeBaseline {
		if bl, err = baseline.Load(blPath); err != nil {
			fmt.Fprintln(os.Stderr, "sandtrap:", err)
			return 64
		}
		if !c.quiet {
			fmt.Fprintf(os.Stderr, "sandtrap: using baseline %s\n", blPath)
		}
		lg.Event("INFO", "baseline loaded from %s", blPath)
	}

	ctx, cancel := signalContext()
	defer cancel()

	rules := make([]analyzer.Rule, 0)
	for _, r := range heuristics.All() {
		rules = append(rules, r)
	}
	opts := analyzer.Options{Workers: c.workers, PackageTimeout: c.timeout}
	if bl != nil {
		opts.Suppress = bl.Suppress
	}
	an := analyzer.New(rules, opts)

	quietStream := c.quiet || (c.output == "" && c.format != "text")
	scanStart := time.Now()
	summary := report.Collect(os.Stderr, an.Run(ctx, pkgs), quietStream, lg)

	// Retry pass: fetch failures on flaky links are usually transient and
	// aggravated by concurrency pressure. Re-run only the errored packages
	// with reduced parallelism and a doubled per-package budget, then merge.
	if summary.Errors > 0 && ctx.Err() == nil {
		var failed []analyzer.Package
		for _, r := range summary.Results {
			if r.Err == "" || permanentError(r.Err) {
				continue
			}
			failed = append(failed, r.Package)
		}
		if len(failed) > 0 {
			if !c.quiet {
				fmt.Fprintf(os.Stderr, "\nsandtrap: retrying %d failed package(s) with reduced concurrency...\n", len(failed))
			}
			lg.Event("INFO", "retry pass starting failed=%d workers=4 timeout=%s", len(failed), c.timeout*2)
			retryOpts := analyzer.Options{Workers: 4, PackageTimeout: c.timeout * 2}
			if bl != nil {
				retryOpts.Suppress = bl.Suppress
			}
			retried := report.Collect(os.Stderr, analyzer.New(rules, retryOpts).Run(ctx, failed), quietStream, lg)

			merged := make(map[string]analyzer.Result, len(retried.Results))
			for _, r := range retried.Results {
				merged[r.Package.String()] = r
			}
			for i, r := range summary.Results {
				if r.Err == "" {
					continue
				}
				if nr, ok := merged[r.Package.String()]; ok {
					summary.Results[i] = nr
				}
			}
			summary = report.Rebuild(summary.Results, time.Since(scanStart))
			lg.Event("INFO", "retry pass complete remaining_errors=%d", summary.Errors)
		}
	}

	if c.writeBaseline {
		out := blPath
		if out == "" {
			dir := c.scanDir
			if dir == "" {
				dir = "."
			}
			out = filepath.Join(dir, baseline.DefaultFile)
		}
		if err := baseline.Write(out, summary.Results); err != nil {
			fmt.Fprintln(os.Stderr, "sandtrap:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "sandtrap: baseline written to %s — future scans fail only on findings not accepted there\n", out)
		return 0
	}

	out := os.Stdout
	if c.output != "" {
		f, err := os.Create(c.output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sandtrap:", err)
			return 1
		}
		defer f.Close()
		out = f
	}
	meta := report.Meta{Version: Version, Targets: c.targets, FailOn: c.failOn}
	var rerr error
	switch c.format {
	case "json":
		rerr = report.JSON(out, summary, meta)
	case "sarif":
		rerr = report.SARIF(out, summary, meta)
	case "text":
		report.Terminal(out, summary)
	default:
		fmt.Fprintf(os.Stderr, "sandtrap: unknown --format %q (text|json|sarif)\n", c.format)
		return 64
	}
	if rerr != nil {
		fmt.Fprintln(os.Stderr, "sandtrap:", rerr)
		return 1
	}
	if c.output != "" && !c.quiet {
		fmt.Fprintf(os.Stderr, "sandtrap: report written to %s\n", c.output)
	}
	code := report.ExitCode(summary, failOn, c.failOnError)
	lg.Event("INFO", "scan complete scanned=%d errors=%d suppressed=%d by_risk=%v duration=%s exit=%d",
		summary.Scanned, summary.Errors, summary.Suppressed, summary.ByRisk,
		summary.Elapsed.Round(time.Millisecond), code)
	if c.logPath != "" && !c.quiet {
		fmt.Fprintf(os.Stderr, "sandtrap: execution log written to %s\n", c.logPath)
	}
	return code
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// permanentError reports fetch errors that a retry cannot fix.
func permanentError(msg string) bool {
	return strings.Contains(msg, "not found") || strings.Contains(msg, "unsupported")
}
