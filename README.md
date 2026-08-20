# pcaptriage

Reads a capture file, applies deterministic TCP/IP heuristics, and reports what
is *unusual* in it — ranked by likely significance, with frame references you
can look up in Wireshark.

> **Work in progress.** This is an early build. **2 of the 15 v1 rules are
> implemented** (R01 `zero-window-stall`, R04 `server-response-outlier`). Every
> report says so at the top, so a clean result is not an all-clear.

## Three things worth stating up front

**No LLM.** All detection is deterministic rule-based logic. There is no model
inference and no API call anywhere in the analysis pipeline.

**Advisory, not diagnostic.** The tool surfaces what is unusual and shows its
working. It does not tell you what broke. Every finding states what was
observed, why it stood out, which frames evidence it, and what to check next —
never a cause.

**Open rules.** The detection and ranking logic is published, so you can audit
why something was surfaced and disagree with it.

It also makes **no network calls of any kind** — no update check, no telemetry,
no reverse DNS — and **never writes to or near the input file**. Because the
source is public, both are auditable claims rather than marketing ones.

## The app

The primary interface is a desktop app. Build it with:

```bash
version=$(grep -o '"productVersion": *"[^"]*"' wails.json | cut -d'"' -f4)
[ -n "$version" ] || { echo "could not read productVersion from wails.json" >&2; exit 1; }
wails build -nopackage -ldflags "-X main.version=$version"
```

The binary lands in `build/bin/`. `wails dev` runs it with live reload. The
frontend is plain HTML, CSS and JavaScript in `frontend/dist` — there is no
bundler and no `npm install` step.

**`-nopackage` is required, not optional.** The Windows icon, manifest and
version block come from `winres/winres.json`, compiled into the committed
`rsrc_windows_amd64.syso`, which Go links automatically. Wails' own packaging
writes a competing version resource that Windows can locate but cannot read
strings from, so a binary built without the flag reports an empty `ProductName`
and `FileDescription` — which is what Task Manager and SmartScreen's "unknown
publisher" prompt show a user.

**The `-ldflags` line is required too, for the same reason.** `main.go`
declares `var version = "dev"` and says so in its own comment: it is a
placeholder, stamped at build time. `wails build` does not do that stamping
for you — skip the flag and the binary is correctly iconned and versioned in
its Windows properties dialog, but reports itself as `dev` on its own About
screen and in every report it exports (`tool.version` in the JSON, the same
string in the HTML masthead). `wails.json`'s `info.productVersion` is the
source of truth for the release version everywhere it appears — `winres.json`
restates it for the Windows resource, and `TestVersionAgreesEverywhere`
(`internal/gui/winres_test.go`) holds the two in step the same way
`TestCopyrightAgreesEverywhere` holds the licence line. Bump it in one place
when cutting a release; the command above reads it fresh every time, so
nothing else needs to change to match.

`CHANGELOG.md`'s "Unreleased" section accumulates user-visible changes as they
land, so cutting a tag is a matter of retitling that section rather than
reconstructing months of history from commit messages.

`winres/winres.json`'s version fields need updating by hand alongside
`wails.json`'s (the test above says so, loudly, if they drift), then
regenerate the resources:

```bash
go generate .
```

That needs `go-winres` (`go install github.com/tc-hib/go-winres@latest`).
Nobody needs it for an ordinary build, because the `.syso` is committed.

The app is a shell around the engine: pick or drop a capture, watch it read,
read the findings. It shares every line of parsing, detection and ranking with
the development CLI below — neither reimplements any of it, which
`internal/gui/app_test.go` asserts by comparing their output.

The app can export a self-contained HTML report: one file with the stylesheet
and every chart inlined, referencing nothing external and running no script, so
it opens on a machine with no network access and can be attached to a ticket
as-is.

## The development CLI

`cmd/pcaptriage` is an in-repo harness for running fixtures and driving the
engine while working on it. It is **not an end-user product**: it is not
released, not documented for users, and carries no compatibility promises —
its flags, exit codes, and output format may change at any time, and nothing
should be built against them. It builds from source
(`go run ./cmd/pcaptriage --help`) for anyone who wants it. The engine package
is what a real CLI would be built on, should anyone want to maintain one.

## Current limitations

Beyond the thirteen unimplemented rules:

- **Ethernet link type only.** Linux cooked capture (`tcpdump -i any`) and raw
  IP captures are rejected with an explicit error rather than analysed
  incorrectly.
- **IPv4 and IPv6 are decoded; the rules are TCP-only.** UDP and ICMP are
  counted and skipped.
- **No filtering flags yet** (`--host`, `--port`, `--after`/`--before`), so
  findings carry no drill-down command.
- **No `--redact`, no `--list-checks`, no `--fail-on`.**
- The report's capture-completeness banner is **reduced**: packets, flows,
  midstream proportion and snaplen only. Snaplen truncation, offload artifacts,
  one-way flows and timestamp resolution arrive with R15.
- **No per-flow table.** The report tabulates the subjects that produced
  findings instead. A table of every flow ranked by significance needs per-flow
  state retained to the end of the run, and flow state is evictable by design.
- In the app: **no full-details view, no completeness banner, no export action**,
  and the about/help screen is a stub. The top-findings view is all there is.
- The report is **light-theme only**, with a print stylesheet. Charts are
  static server-rendered SVG; there is no zoom or hover.

## Repository layout

```
main.go               desktop app entry point (Wails requires it at the root)
wails.json            desktop app build config
frontend/dist/        the app's HTML, CSS and JS — no bundler
internal/gui/         the bound app object; a shell, no analysis logic
cmd/pcaptriage/       CLI entry point
internal/capture/     pcapgo framing plus hand-rolled Ethernet/IP/TCP decode
internal/flow/        5-tuple keying, TCP state machine, LRU flow store
internal/findings/    retained findings store, evidence and repetition capping
internal/rules/       the detection rules and the threshold table
internal/scoring/     the significance model
internal/stats/       percentiles and bounded sampling
internal/analysis/    the streaming pass that drives all of the above
internal/report/      JSON and HTML rendering, plus the embedded template,
                      stylesheet and hand-rolled SVG charts
internal/synth/       synthesised fixture builder
testdata/fixtures/    committed synthetic captures (pcap and pcapng)
testdata/golden/      committed golden reports (.json and .html)
```

### Two-tier memory

Packet-path state — per-flow TCP state, RTT sampling rings, decode buffers — is
evictable and bounded by an LRU cap. The findings store, including per-host and
per-server baselines, is retained to the end of the run, because ranking and
filtering both need the full picture. These are separate structures on purpose
and should stay that way.

## Determinism

Identical input produces byte-identical output, for the HTML as much as the
JSON. Two things make that hold, and both are asserted in tests:

- Every collection is sorted before it is emitted. Go randomises map iteration
  order, so anything assembled from a map and emitted unsorted would reorder
  between runs.
- Nothing in the report derives from the wall clock. There is deliberately no
  "generated at" field.

## Tests

```bash
go test ./...
```

Every rule has a positive fixture that must trigger it and a negative fixture
that must not, built from the false-positive traps listed under that rule in
`RULES.md`. Fixtures are synthesised byte by byte in Go — no live capture, no
network, no privileges — and committed so that a change to the builder shows up
as a diff rather than silently altering what the rule tests are testing.

To regenerate fixtures and golden files after an intended change, run the two
steps in order — the golden files are produced by reading the committed
fixtures, so the fixtures have to be written first:

```bash
go test ./internal/synth/ -update
```

```bash
go test ./internal/analysis/ -update
```

Then review the diff.

## Licence

MIT — see [LICENSE](LICENSE).
