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

	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
	"github.com/sandtrap-sh/sandtrap/internal/baseline"
	"github.com/sandtrap-sh/sandtrap/internal/heuristics"
	"github.com/sandtrap-sh/sandtrap/internal/lockfile"
	"github.com/sandtrap-sh/sandtrap/internal/report"
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
  --format FMT         output format: text|json (default text)
  --fail-on LEVEL      exit 2 at/above: critical|high|medium|low|never (default high)
  --fail-on-error      exit 3 if any package could not be analyzed
  --timeout DUR        per-package timeout (default 90s)
  --quiet              suppress streaming progress lines
  --baseline FILE      accepted-findings file (default: .sandtrap.json in scan dir)
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

type commonFlags struct {
	workers       int
	format        string
	failOn        string
	failOnError   bool
	timeout       time.Duration
	quiet         bool
	baselinePath  string
	writeBaseline bool
	// scanDir is set by runScan so execute can auto-detect .sandtrap.json.
	scanDir string
}

func bindCommon(fs *flag.FlagSet) *commonFlags {
	c := &commonFlags{}
	fs.IntVar(&c.workers, "workers", 0, "")
	fs.StringVar(&c.format, "format", "text", "")
	fs.StringVar(&c.failOn, "fail-on", "high", "")
	fs.BoolVar(&c.failOnError, "fail-on-error", false, "")
	fs.DurationVar(&c.timeout, "timeout", 90*time.Second, "")
	fs.BoolVar(&c.quiet, "quiet", false, "")
	fs.StringVar(&c.baselinePath, "baseline", "", "")
	fs.BoolVar(&c.writeBaseline, "write-baseline", false, "")
	return c
}

// signalContext cancels on Ctrl-C / SIGTERM so a huge scan aborts cleanly.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := bindCommon(fs)
	if err := fs.Parse(args); err != nil {
		return 64
	}
	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
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
	if err := fs.Parse(args); err != nil {
		return 64
	}
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: sandtrap check <npm|pypi> <package>[@version] [more packages...]")
		return 64
	}
	eco := analyzer.Ecosystem(strings.ToLower(fs.Arg(0)))
	if eco != analyzer.NPM && eco != analyzer.PyPI {
		fmt.Fprintf(os.Stderr, "sandtrap: unsupported ecosystem %q (npm|pypi)\n", fs.Arg(0))
		return 64
	}
	var pkgs []analyzer.Package
	for _, spec := range fs.Args()[1:] {
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

	// Baseline: explicit --baseline path, or .sandtrap.json in the scan dir.
	var bl *baseline.Baseline
	blPath := c.baselinePath
	if blPath == "" && c.scanDir != "" {
		if candidate := filepath.Join(c.scanDir, baseline.DefaultFile); fileExists(candidate) {
			blPath = candidate
		}
	}
	if blPath != "" && !c.writeBaseline {
		var err error
		if bl, err = baseline.Load(blPath); err != nil {
			fmt.Fprintln(os.Stderr, "sandtrap:", err)
			return 64
		}
		if !c.quiet {
			fmt.Fprintf(os.Stderr, "sandtrap: using baseline %s\n", blPath)
		}
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

	quietStream := c.quiet || c.format == "json"
	summary := report.Collect(os.Stderr, an.Run(ctx, pkgs), quietStream)

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

	switch c.format {
	case "json":
		if err := report.JSON(os.Stdout, summary); err != nil {
			fmt.Fprintln(os.Stderr, "sandtrap:", err)
			return 1
		}
	default:
		report.Terminal(os.Stdout, summary)
	}
	return report.ExitCode(summary, failOn, c.failOnError)
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
