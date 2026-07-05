// Package report renders scan results for humans (colored terminal) and
// machines (JSON), and decides the process exit code for CI gating.
package report

import (
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/sandtrap-sh/sandtrap/internal/analyzer"
	"github.com/sandtrap-sh/sandtrap/internal/runlog"
)

var useColor = isTerminal(os.Stdout)

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func paint(code, s string) string {
	if !useColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func riskColor(r analyzer.RiskLevel) string {
	switch r {
	case analyzer.RiskCritical:
		return paint("1;97;41", " "+r.String()+" ") // white on red
	case analyzer.RiskHigh:
		return paint("1;31", r.String())
	case analyzer.RiskMedium:
		return paint("1;33", r.String())
	case analyzer.RiskLow:
		return paint("36", r.String())
	default:
		return paint("32", r.String())
	}
}

func sevColor(s analyzer.Severity) string {
	switch s {
	case analyzer.SevCritical:
		return paint("1;31", s.String())
	case analyzer.SevHigh:
		return paint("31", s.String())
	case analyzer.SevMedium:
		return paint("33", s.String())
	case analyzer.SevLow:
		return paint("36", s.String())
	default:
		return paint("2", s.String())
	}
}

// Summary aggregates a full run.
type Summary struct {
	Scanned    int               `json:"scanned"`
	Errors     int               `json:"errors"`
	Suppressed int               `json:"suppressed"`
	Elapsed    time.Duration     `json:"elapsed_ns"`
	ByRisk     map[string]int    `json:"by_risk"`
	Results    []analyzer.Result `json:"results"`
	worst      analyzer.RiskLevel
}

// Collect drains the results channel, streaming per-package lines to w as
// they arrive (quiet=false), recording every outcome to the execution log,
// and returning the aggregated summary.
func Collect(w io.Writer, ch <-chan analyzer.Result, quiet bool, lg *runlog.Logger) *Summary {
	start := time.Now()
	s := &Summary{ByRisk: map[string]int{}}
	for res := range ch {
		s.Scanned++
		if res.Err != "" {
			s.Errors++
		}
		s.ByRisk[res.Risk.String()]++
		s.Suppressed += res.Suppressed
		if res.Risk > s.worst {
			s.worst = res.Risk
		}
		s.Results = append(s.Results, res)
		if !quiet {
			streamLine(w, res)
		}
		logResult(lg, res)
	}
	s.Elapsed = time.Since(start)
	sort.SliceStable(s.Results, func(i, j int) bool {
		return s.Results[i].Risk > s.Results[j].Risk
	})
	return s
}

func streamLine(w io.Writer, res analyzer.Result) {
	if res.Err != "" {
		fmt.Fprintf(w, "  %s %s — %s\n", paint("2", "SKIP"), res.Package, paint("2", res.Err))
		return
	}
	if res.Risk == analyzer.RiskClean {
		fmt.Fprintf(w, "  %s %s\n", paint("32", "  ok"), res.Package)
		return
	}
	fmt.Fprintf(w, "  %s %s  (score %d, %d findings)\n",
		riskColor(res.Risk), res.Package, res.Score, len(res.Findings))
}

// Terminal prints the detailed human report for every non-clean package.
func Terminal(w io.Writer, s *Summary) {
	fmt.Fprintln(w)
	flagged := 0
	for _, res := range s.Results {
		if res.Risk == analyzer.RiskClean || res.Err != "" {
			continue
		}
		flagged++
		fmt.Fprintf(w, "%s %s\n", riskColor(res.Risk), paint("1", res.Package.String()))
		for _, f := range res.Findings {
			loc := ""
			if f.File != "" {
				loc = paint("2", "  ["+f.File+"]")
			}
			fmt.Fprintf(w, "  %s %s%s\n", sevColor(f.Severity), f.Title, loc)
			fmt.Fprintf(w, "     %s\n", paint("2", f.Detail))
			if f.Evidence != "" {
				fmt.Fprintf(w, "     %s %s\n", paint("2", "evidence:"), paint("2;3", f.Evidence))
			}
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%s %d packages scanned in %s — ", paint("1", "sandtrap:"),
		s.Scanned, s.Elapsed.Round(time.Millisecond))
	if flagged == 0 {
		fmt.Fprintln(w, paint("1;32", "no traps sprung ✔"))
	} else {
		fmt.Fprintf(w, "%s\n", paint("1;31", fmt.Sprintf("%d package(s) flagged", flagged)))
	}
	if s.Suppressed > 0 {
		fmt.Fprintf(w, "%s\n", paint("2", fmt.Sprintf("%d finding(s) suppressed by baseline", s.Suppressed)))
	}
	if s.Errors > 0 {
		fmt.Fprintf(w, "%s\n", paint("33", fmt.Sprintf("warning: %d package(s) could not be fetched/analyzed", s.Errors)))
	}
}

// ExitCode implements CI gating: 0 below threshold, 2 at/above it,
// 3 when analysis errors occurred and failOnError is set.
func ExitCode(s *Summary, failOn analyzer.RiskLevel, failOnError bool) int {
	if s.worst >= failOn && failOn > analyzer.RiskClean {
		return 2
	}
	if failOnError && s.Errors > 0 {
		return 3
	}
	return 0
}

// ParseRisk converts a --fail-on flag value.
func ParseRisk(s string) (analyzer.RiskLevel, error) {
	switch s {
	case "critical":
		return analyzer.RiskCritical, nil
	case "high":
		return analyzer.RiskHigh, nil
	case "medium":
		return analyzer.RiskMedium, nil
	case "low":
		return analyzer.RiskLow, nil
	case "never":
		return analyzer.RiskClean, nil
	}
	return 0, fmt.Errorf("invalid --fail-on value %q (critical|high|medium|low|never)", s)
}

// logResult records one package outcome and each of its findings.
func logResult(lg *runlog.Logger, res analyzer.Result) {
	if !lg.Enabled() {
		return
	}
	switch {
	case res.Err != "":
		lg.Event("WARN", "%s error=%q duration=%dms", res.Package, res.Err, res.DurationMS)
	default:
		lg.Event("PKG", "%s risk=%s score=%d findings=%d suppressed=%d files=%d duration=%dms",
			res.Package, res.Risk, res.Score, len(res.Findings), res.Suppressed, res.FilesScanned, res.DurationMS)
	}
	for _, f := range res.Findings {
		loc := ""
		if f.File != "" {
			loc = " file=" + f.File
		}
		lg.Event("FIND", "%s %s rule=%s title=%q%s evidence=%q",
			res.Package, f.Severity, f.RuleID, f.Title, loc, f.Evidence)
	}
}
