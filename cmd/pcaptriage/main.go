// Command pcaptriage reads a capture file, applies deterministic TCP/IP
// heuristics, and reports what is unusual in it, ranked by likely
// significance, with frame references.
//
// The tool is advisory, not diagnostic. It does not name a root cause. It
// answers a narrower question: out of everything in this capture, what is
// worth your attention first?
//
// It makes no network calls of any kind, runs no model inference, and never
// writes to or near the input file.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Proxy-IT/pcaptriage/internal/analysis"
	"github.com/Proxy-IT/pcaptriage/internal/capture"
	"github.com/Proxy-IT/pcaptriage/internal/flow"
	"github.com/Proxy-IT/pcaptriage/internal/report"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes for the development harness.
//
// These are a convenience for driving the tool from a script while working on
// it, not a contract. There is no shipped CLI and nothing external consumes
// these values, so they may change whenever it is convenient — see BRIEF.md
// section 13, which withdrew the exit-code commitment along with the public CLI.
const (
	exitOK              = 0
	exitToolError       = 2
	exitCaptureUnusable = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is main's body, taking its arguments explicitly so the exit code
// contract can be tested.
func run(args []string) int {
	fs := flag.NewFlagSet("pcaptriage", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `pcaptriage %s — PCAP Triage, offline packet capture triage

Usage:
  pcaptriage <capture.pcap|capture.pcapng> [flags]

Reads a capture and reports what is unusual in it, ranked, with frame
references you can look up in Wireshark. Advisory only: it does not tell you
what broke.

This build implements 2 of the 15 v1 rules (R01 zero-window-stall, R04
server-response-outlier). The report says so; a clean result is not an
all-clear.

Flags:
`, version)
		fs.PrintDefaults()
	}

	jsonOut := fs.String("json", "", "write the findings JSON to this path")
	htmlOut := fs.String("html", "", "write a self-contained HTML report to this path")
	maxFlows := fs.Int("max-flows", flow.DefaultMaxFlows, "maximum concurrently tracked flows before least-recently-used eviction")

	// The documented invocation puts the capture first and the flags after it
	// — `pcaptriage capture.pcap --json findings.json` — but the flag package
	// stops parsing at the first non-flag argument. Parse repeatedly, peeling
	// off operands as they appear, so flags work on either side of the path.
	var operands []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return exitOK
			}
			return exitToolError
		}
		if fs.NArg() == 0 {
			break
		}
		operands = append(operands, fs.Arg(0))
		rest = fs.Args()[1:]
	}

	if len(operands) != 1 {
		fs.Usage()
		return exitToolError
	}
	input := operands[0]

	// The input file is evidence. Refuse anything that would write to it, or
	// alongside it under the same name, before doing any work.
	for _, out := range []string{*jsonOut, *htmlOut} {
		if out == "" {
			continue
		}
		same, err := samePath(out, input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcaptriage: %v\n", err)
			return exitToolError
		}
		if same {
			fmt.Fprintf(os.Stderr, "pcaptriage: refusing to write output over the input capture %q\n", input)
			return exitToolError
		}
	}

	res, err := analysis.Run(input, analysis.Options{MaxFlows: *maxFlows})
	if err != nil {
		var unsupported *capture.UnsupportedLinkTypeError
		switch {
		case errors.Is(err, capture.ErrUnknownFormat), errors.As(err, &unsupported), os.IsNotExist(err):
			fmt.Fprintf(os.Stderr, "pcaptriage: %v\n", err)
			return exitCaptureUnusable
		default:
			fmt.Fprintf(os.Stderr, "pcaptriage: %v\n", err)
			return exitToolError
		}
	}

	doc := report.Build(res, report.Invocation{
		Args:     args,
		Input:    input,
		MaxFlows: *maxFlows,
	}, version)

	if *htmlOut != "" {
		if err := writeFile(*htmlOut, func(w io.Writer) error { return report.WriteHTML(w, doc) }); err != nil {
			fmt.Fprintf(os.Stderr, "pcaptriage: %v\n", err)
			return exitToolError
		}
	}

	// JSON goes to stdout unless a path was given, except when only an HTML
	// report was asked for — printing the JSON alongside it would be noise.
	switch {
	case *jsonOut != "":
		if err := writeFile(*jsonOut, func(w io.Writer) error { return report.Write(w, doc) }); err != nil {
			fmt.Fprintf(os.Stderr, "pcaptriage: %v\n", err)
			return exitToolError
		}
	case *htmlOut == "":
		if err := report.Write(os.Stdout, doc); err != nil {
			fmt.Fprintf(os.Stderr, "pcaptriage: %v\n", err)
			return exitToolError
		}
	}

	return exitOK
}

// writeFile creates path and hands it to write, closing it afterwards. The
// close error is reported: a report truncated by a full disk must not look
// like a successful run.
func writeFile(path string, write func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := write(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// samePath reports whether two paths refer to the same file. It compares
// resolved absolute paths, and where the target already exists, identity as
// the OS sees it.
func samePath(a, b string) (bool, error) {
	absA, err := filepath.Abs(a)
	if err != nil {
		return false, err
	}
	absB, err := filepath.Abs(b)
	if err != nil {
		return false, err
	}
	if absA == absB {
		return true, nil
	}
	fa, errA := os.Stat(absA)
	fb, errB := os.Stat(absB)
	if errA == nil && errB == nil {
		return os.SameFile(fa, fb), nil
	}
	return false, nil
}
