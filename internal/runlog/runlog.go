// Package runlog provides the execution log: a timestamped, append-style
// record of everything a run did (configuration, every package analyzed,
// every finding, errors, final summary). It is deliberately separate from the
// report — the report answers "what is the risk state of my dependencies";
// the execution log answers "what exactly did this run do", which is what
// you attach to a CI artifact or an incident timeline.
package runlog

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Logger writes execution events to an optional file and, in verbose mode,
// mirrors them to stderr. Safe for concurrent use (results arrive from the
// worker pool in completion order).
type Logger struct {
	mu      sync.Mutex
	file    io.WriteCloser
	verbose bool
	stderr  io.Writer
}

// New creates a Logger. path may be empty (no file); verbose mirrors every
// event to stderr in addition to the file.
func New(path string, verbose bool) (*Logger, error) {
	l := &Logger{verbose: verbose, stderr: os.Stderr}
	if path != "" {
		f, err := os.Create(path)
		if err != nil {
			return nil, fmt.Errorf("execution log: %w", err)
		}
		l.file = f
	}
	return l, nil
}

// Enabled reports whether the logger will record anything at all.
func (l *Logger) Enabled() bool {
	return l != nil && (l.file != nil || l.verbose)
}

// Event records one line: RFC3339 timestamp, level, formatted message.
// Levels used by sandtrap: INFO (run lifecycle), PKG (per-package outcome),
// FIND (individual finding), WARN (fetch/analysis errors).
func (l *Logger) Event(level, format string, args ...any) {
	if !l.Enabled() {
		return
	}
	line := fmt.Sprintf("%s %-4s %s\n",
		time.Now().UTC().Format("2006-01-02T15:04:05.000Z"), level, fmt.Sprintf(format, args...))
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		io.WriteString(l.file, line)
	}
	if l.verbose {
		io.WriteString(l.stderr, line)
	}
}

// Close flushes and closes the underlying file, if any.
func (l *Logger) Close() {
	if l == nil || l.file == nil {
		return
	}
	l.file.Close()
}
