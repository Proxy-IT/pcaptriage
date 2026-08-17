# PCAP Triage Utility — Technology Brief

**Premise:** a free, open-source desktop application that reads a capture file,
applies deterministic TCP/IP heuristics, and surfaces what is *abnormal* in the
stream — ranked by likely significance, with frame references — for someone who
does not know what to look for in Wireshark and would not know how to interpret
its output if they did. No LLM, no upload to any external service, no telemetry.

**Primary interface: a desktop GUI app.** File picker or drag-and-drop, a
plain-English ranked findings view, no terminal, no flags. This is the interface
users touch, and every design decision in this document should be evaluated
against whether it serves that user.

**Platform priority: Windows and macOS first-class; Linux best-effort.** The app
installs on any desktop-capable machine, including server VMs — a Windows Server
VM or an Ubuntu box with a desktop session is simply another install target, not
a separate mode. Windows and macOS builds are tested, signed, and release-
blocking; the Linux build ships when it works and does not gate releases.

**The engine remains a separate, reusable Go package.** Parsing, flow state, rule
detection, and JSON output have no UI dependency — see sections 1–2 and 5–10,
none of which are affected by the interface decision. The GUI (section 3) is a
shell around that engine, not a rewrite of it.

**CLI: internal development tool only, not a shipped product.** A thin command-
line wrapper around the engine remains in the repository for running fixtures,
test captures, and development workflows. It is not released, not documented for
end users, carries no compatibility promises (exit codes, flags, and JSON schema
may change freely), and imposes no feature-parity obligation on the GUI. If a
future contributor wants to maintain a public CLI, the engine package makes that
possible as their project.

**The tool is advisory, not diagnostic.** It does not claim to name the root cause.
It answers a narrower and more tractable question: *out of everything in this
capture, what is unusual and worth your attention first?* This matters more, not
less, under a GUI aimed at non-experts — wording has to carry meaning that a
technical reader could otherwise infer from context. Every finding must point at
specific frames so it can be verified in Wireshark by someone who later wants to.

**Design constraints driving every decision below:**

1. Primary use is the desktop GUI on Windows and macOS, including on server VMs
   with a desktop session. Linux is a best-effort build. There is no headless or
   terminal-based end-user mode.
2. Must not require a separate runtime, package manager, or driver install beyond
   the app bundle itself.
3. Must handle multi-GB files without exhausting RAM, with visible progress —
   a GUI that appears frozen on a large file will be read as broken.
4. Output must be reproducible — same input, byte-identical findings, whether
   triggered from the GUI or the internal dev CLI.
5. Must survive hostile input. A pcap is attacker-controlled data. This matters
   for both interfaces: a desktop app opening files from unknown sources is at
   least as exposed as a server processing a capture someone chose to run there.
6. Every finding cites frame numbers. No unverifiable claims.
7. Open source, as with Hana. Published rules are auditable rules, which is what
   makes an advisory tool trustworthy.
8. Nothing leaves the machine. No upload, no network calls of any kind.
   "Select a file" means a local file picker, not a transfer to any process
   outside the app itself.

---

## Scope boundaries

*This section precedes the numbered technology decisions because it constrains
them. It is also the basis for the README's capability section — users should be
told the limits before they rely on the output, not after.*

### In scope — detectable from an unencrypted L3/L4 view

**Connection establishment**
- SYN with no SYN/ACK (blackhole, firewall drop, dead listener)
- SYN answered by RST (port closed, service down)
- Handshake latency, and its distribution across hosts
- Repeated connection churn where a persistent connection was expected

**Loss and delivery**
- Retransmissions, classified as fast retransmit vs RTO-driven
- Duplicate ACKs and SACK blocks
- Out-of-order delivery, discriminated from genuine retransmission
- One-way loss (materially more diagnostic than symmetric loss)

**Flow control**
- Zero window events, and stall duration until window update
- Window full conditions (requires the handshake — see section 10)
- Zero window probes and persist timer behaviour

**Timing**
- Network RTT, from handshake and from ACK timing
- Server response delta: last request byte → first response byte, RTT subtracted
- Percentile distribution of response time per server and per port
- Idle gaps preceding a teardown

**Teardown**
- RST classification: mid-transfer, post-idle, in place of FIN
- Half-open and half-closed connections
- FIN sequences that never complete

**Adjacent protocols, where cleartext**
- DNS: unanswered queries, slow responses, SERVFAIL and NXDOMAIN patterns
- ICMP unreachables and fragmentation-needed, correlated to the affected flow
- TLS handshake duration, alerts, failed negotiation, and certificate validity
  from the ServerHello
- MSS and MTU mismatch signals

**Capture quality itself**
- Snaplen truncation
- Midstream flows and their proportion
- Segments above MTU indicating TSO/LRO on-host capture artifacts
- Timestamp resolution and multi-interface merge issues

### Out of scope — cannot be detected, by nature

State these plainly. A user who believes the tool checked something it cannot
check is worse off than one who was told the boundary.

- **Anything inside encrypted payload.** HTTP status codes, query text,
  application errors over TLS. Timing is visible; content is not.
- **QUIC and HTTP/3 internals.** UDP 443 transport headers are largely encrypted.
  Volume, timing, and connection-level behaviour only. This limitation grows over
  time and should be stated prominently.
- **Where a packet was lost.** A retransmission proves a segment was not
  acknowledged. It does not indicate which hop dropped it. One vantage point
  cannot localise loss along a path.
- **Root cause.** The tool observes symptoms. Zero window strongly suggests a
  receiver not draining its buffer, but cannot confirm CPU, disk, memory, or
  application-thread starvation on that host.
- **Anything absent from the capture.** Wrong interface, over-narrow filter, or a
  fault outside the capture window. The tool cannot know what it did not see.
- **Layer 1 and 2 faults.** CRC errors, duplex mismatch, cabling, optics. These
  live in NIC and switch counters, not in a capture.
- **Radio-layer wireless problems**, unless the capture was taken in monitor mode.
- **Application logic errors** that produce valid, timely TCP.
- **Whether the observed performance is acceptable.** The tool has no SLA context.
  It reports outliers relative to the capture, not verdicts against a target.

### Out of scope — by choice, not inability

These are deliberately ceded to existing tools. Each one is a place where scope
would otherwise expand indefinitely.

| Excluded | Owned by |
|---|---|
| Live capture | `tcpdump` / `dumpcap` — also avoids needing elevated privileges |
| Full protocol dissection | Wireshark. The tool points *into* Wireshark, not around it |
| Malware and intrusion detection | Zeek, Suricata |
| File and credential extraction | NetworkMiner, A-Packets |
| Capture editing and anonymisation | TraceWrangler, `editcap` |
| Long-term capture indexing | Arkime |
| Capture merging and splitting | `mergecap`, `editcap` |

**Declining live capture is the single most valuable scope decision.** It removes
the need for raw socket privileges, driver dependencies (`libpcap`, Npcap), and
platform-specific capture code, which collectively account for most of the
complexity in tools of this kind. It also keeps the app's permission footprint
minimal on a workstation, and makes any server-side use easier to justify.

### v1 rule budget

Cap the initial release at roughly **fifteen rules**, chosen for coverage of the
common cases rather than completeness. The rules table is never finished — there
is always another heuristic worth adding — and that is exactly why the ceiling
must be set before implementation rather than during it.

Deferred to v2 and beyond: application-layer HTTP analysis on cleartext ports,
ARP and duplicate-address anomalies, IPv6-specific conditions, multicast, VoIP
and RTP jitter analysis, and per-protocol rule packs.

### Self-reporting capability

The tool should be able to state its own coverage — `--list-checks` enumerating
every rule, and a report section listing the checks that ran, the checks that were
skipped, and why. This is the same mechanism as the `unavailable` tagging in
section 10, applied at the level of the tool rather than the individual finding,
and it is what keeps the boundary honest as the rules grow.

---

## 1. Language and runtime

### Go — recommended

**Pros**
- `pcapgo` reads pcap and pcapng in pure Go. No cgo, no libpcap, no Npcap.
- True static binaries, cross-compiled from one machine to Linux/macOS/Windows,
  amd64 and arm64, from a single `GOOS=... go build`.
- `embed` puts the HTML template, CSS, and rules table inside the binary.
- Memory-safe against malformed input — a bad length field panics recoverably
  rather than corrupting the heap.
- Consistent with the Go probe work already underway, so the heuristics engine
  can be lifted into that codebase later without a rewrite.

**Cons**
- Parsing throughput is maybe 30–50% below equivalent Rust if written naively.
  Mostly recoverable by avoiding gopacket's decode path in the hot loop.
- GC pressure if you allocate per packet. Requires deliberate buffer reuse.
- Binary size ~8–15 MB. Not a problem here, but it isn't tiny.

### Rust

**Pros**
- Fastest realistic option. `etherparse` decodes L2–L4 with zero allocation.
- No GC, fully predictable memory profile on huge captures.
- Strong story for parsing untrusted input.

**Cons**
- Slower to write, especially the report/template layer.
- Cross-compilation is workable (`cargo-zigbuild`) but fiddlier than Go's.
- Only worth it if throughput becomes the actual product differentiator. It won't
  be at v1 — correctness of the heuristics will be.

### C / C++ with libpcap

**Pros**
- Maximum performance, direct access to the reference implementation.

**Cons**
- Memory safety on adversarial input is a genuine liability, not a theoretical one.
- Requires libpcap/Npcap present on the target. Breaks constraint 2 immediately.
- Build and distribution burden across three platforms is disproportionate.

### Python (Scapy / dpkt)

**Pros**
- Fastest possible path to prototyping heuristics. Scapy is excellent for
  interrogating a capture interactively while you work out detection rules.

**Cons**
- Scapy is roughly two orders of magnitude too slow for multi-GB files.
  dpkt is much faster but still not close.
- PyInstaller "single binary" is a 40 MB self-extracting archive with startup lag
  and antivirus false positives.

**Verdict:** use Python to *design* the rules against sample captures.
Ship in Go.

---

## 2. Capture file parsing

### `pcapgo` reader + hand-rolled L2–L4 decode — recommended

Use gopacket's `pcapgo` for file framing (both pcap and pcapng), then decode
Ethernet/VLAN/IP/TCP headers by hand into a reusable struct.

**Pros**
- Pure Go, no cgo, so cross-compilation stays trivial.
- Handles pcapng's block structure, multiple interfaces, and timestamp resolution,
  which are annoying to get right yourself.
- Hand-rolled decode avoids gopacket's per-packet allocations in the hot loop.

**Cons**
- You own the header parsing bugs. Mitigate with a fuzz corpus.
- No dissectors above L4 — fine, since encryption limits you there anyway.

### Full gopacket decode

**Pros** — less code, wide protocol coverage, well-tested.
**Cons** — allocation-heavy; noticeably slower on large files. Reasonable for v1
if you want to ship sooner, with the hand-rolled path as an optimisation later.

### Shelling out to `tshark`

**Pros** — inherits every Wireshark dissector and its analysis flags for free.
**Cons** — destroys the single-binary promise, which is the entire differentiator.
Also slow, and output format drifts between Wireshark versions. Rejected.

---

## 3. Output and interface

### Desktop GUI app (Wails) — recommended, primary interface

Wails wraps the existing Go engine directly — the same parsing, flow state, rule
detection, and JSON output already built, with no rewrite. The frontend is
HTML/CSS/JS rendered in the OS's native webview (WebView2 on Windows, WebKit on
macOS/Linux), which means the report wording and layout work already done for the
HTML report carries over into the app UI rather than being replaced by it.

**Pros**
- Reuses the Go engine as-is; the GUI is a shell, not a second implementation.
- Native webview rather than a bundled Chromium runtime (unlike Electron) — a
  meaningfully smaller, more native-feeling app per OS.
- HTML/CSS gives real design control for a non-expert-facing UI: drag-and-drop
  zones, card layouts, color and iconography conveying significance without
  requiring the reader to interpret a number. This is harder to achieve well in
  a native Go widget toolkit like Fyne.
- File picker and drag-and-drop are natural in this model; no terminal is ever
  shown to the user.

**Cons**
- Real UI surface to build and maintain — the engine alone was a far smaller
  deliverable.
- Cross-platform packaging and code signing (macOS notarization, Windows
  authenticode) become a first-order cost rather than an optional extra — see
  section 6. The bar is high because users expect an app to look and feel
  finished in a way a command-line binary never had to.
- One more moving part in CI: three OS builds instead of cross-compiled binaries
  from one Go toolchain.

**Interaction model**

1. **First launch is a normal application home screen, not a blank drop zone.**
   App name and a one-line description of what it does. The primary action —
   drag-and-drop zone or file-picker button — is the visual focus, but it sits
   alongside brief instructional copy ("Drop a .pcap or .pcapng file here, or
   click to browse — we'll look for common problems and explain what we find")
   and a short line setting expectations for the advisory posture ("This tool
   highlights unusual activity — it doesn't diagnose the cause"). Normal
   application chrome — menu bar or equivalent, an about/help entry — rather
   than a single-purpose screen with nothing else on it. The goal is a user who
   has never seen the app before knowing what to do and roughly what they'll get,
   without needing this document.
2. Visible progress during parsing. Large captures take real time; a window that
   appears frozen will be read as broken, not as working — see constraint 3.
3. Lands on a **top-findings view**: cards, not a table, each one in RULES.md's
   plain-English wording, ordered by significance. This is the default and, for
   most users, the entire interaction.
4. A secondary, clearly secondary, "full details" view holding the complete
   findings list, per-flow table, and completeness banner — for anyone who wants
   to go further, not required to reach a conclusion.

**Report structure** (applies to both the GUI's built-in view and any exported
HTML — see below):

1. Capture completeness banner (see section 10), translated into plain language
   for the GUI's default view — technical detail like "18 of 42 flows began
   before capture start" moves to the full-details view; the top-level view
   states in plain terms what's affected and why.
2. **Top findings** — five to ten most significant anomalies, each with frame
   references and a "what to check next" line.
3. Full findings list, grouped by category, ranked within each — full-details view.
4. Per-flow table, sortable by significance — full-details view.
5. Explicit list of checks that could not be performed, and why — surfaced
   plainly in both views, since a false all-clear is the worst failure mode
   regardless of which view produced it (see section 9).

**Export.** The app can write a self-contained HTML report — useful for
attaching to a ticket or emailing to a vendor — as an export action from within
the GUI, not the primary way results are consumed.

### CLI — internal development tool, not shipped

A thin wrapper around the engine, retained in the repo for fixture runs, netem
capture testing, and development workflows. Not released, not documented for end
users, no compatibility contract — exit codes, flags, and output schema may
change freely. It exists because the engine needs a harness, not because
terminal analysis is a supported product. **One engine, all consumers** still
applies: the dev CLI calls the same package the GUI does, and the end-to-end
test asserting identical findings across both entry points remains the
enforcement mechanism for engine/UI separation.

### TUI (Bubble Tea)

No longer worth building. It solved for SSH-only terminal access, which is no
longer a supported end-user mode at all. Dropped rather than deferred.

### Local web server on 127.0.0.1

**Cons remain from the original analysis** — a listening port raises firewall and
policy questions, and it isn't needed: Wails' webview renders local HTML without
opening a network port at all. Rejected for the same reason as before, now more
clearly avoidable.

---

## 4. Charts inside the app and exported reports

| Option | Pros | Cons |
|---|---|---|
| Server-rendered SVG (hand-rolled or go-echarts) | No JS, tiny, prints cleanly, works air-gapped | Static; no zoom or hover |
| uPlot inlined (~40 KB) | Interactive zoom on time series, very fast with 100k+ points | Adds JS; must be inlined, never CDN |
| Chart.js / Plotly | Rich, familiar | 200 KB–3 MB inlined; overkill |

**Recommendation:** SVG for the summary charts, uPlot inlined only for the
throughput-and-events timeline where zooming genuinely helps.

---

## 5. State handling

### Streaming single pass with an in-memory flow map — recommended

Key on the 5-tuple, hold per-flow TCP state, accumulate findings, LRU-evict flows
above a configurable cap.

**Pros** — flat memory regardless of file size; no temp files; no dependencies.
**Cons** — one pass only, so anything needing global context must be accumulated
deliberately rather than queried afterwards.

### Two-tier memory model — separate the packet path from the findings store

Presentation-layer filtering (section 8) and impact ranking (section 7) both
require that findings be held until the end of the run rather than emitted as they
are detected. You cannot rank against a population you haven't finished counting,
and you cannot filter a report you have already written.

This produces two distinct memory tiers with different characteristics, and they
should be separated in the code from the first commit:

| Tier | Contents | Lifetime | Bound |
|---|---|---|---|
| **Packet path** | Per-flow TCP state, reusable decode buffers, running aggregates | Evictable; discarded once a flow closes or ages out | LRU cap on concurrent flows |
| **Findings store** | Detected anomalies, frame references, per-host and per-path baselines | Held to end of run | Cap on findings per rule per flow |

The tiers differ by orders of magnitude — findings are vastly fewer than packets,
so retaining them is cheap even on very large captures. The risk is not total
volume but **pathological repetition**: a flow retransmitting fifty thousand times
should produce one finding with a count and a representative frame list, not fifty
thousand findings. Cap per rule per flow, retain the first and worst few frame
references, and record the total.

Keeping these separate also leaves the door open for the SQLite option below, or
for a future interactive viewer, without disturbing the packet path.

### SQLite intermediate store

**Pros** — re-query without re-parsing; useful if you later want interactive drill-down.
**Cons** — cgo unless you use `modernc.org/sqlite` (pure Go, materially slower),
plus disk writes on a production server you may not be welcome to make.
Premature at v1.

---

## 6. Distribution

**Tier 1 — Windows and macOS: signed, notarized app installers.** A signed
`.msi` or `.exe` for Windows; a notarized `.dmg`/`.app` for macOS. These are the
release-blocking builds. Notarisation and Authenticode signing are the primary
distribution cost of the project — an unsigned app triggering Gatekeeper or
SmartScreen warnings is exactly the friction that loses the non-expert user this
tool is built for. Budget for signing early, not as a late-stage detail.

**Tier 2 — Linux: best-effort.** Wails produces the build nearly for free, so
ship it, but it does not gate releases and gets one packaging format (whichever
proves least friction — likely AppImage or a plain tarball), not three. Note
Wails on Linux depends on WebKit2GTK as a system library — the one platform
where "no install footprint beyond the app" is slightly compromised; state it in
the install notes rather than papering over it.

**Not distributed: CLI binaries.** The dev CLI stays in the repo and builds from
source for anyone who wants it, but there are no CLI releases, checksums,
Homebrew/Scoop manifests, or Docker images to maintain. This removes the exit-
code contract, `--fail-on`, and JSON schema stability obligations that shipped
CLI consumers would have created — the JSON format is now internal and may
change freely (see section 13).

GitHub Releases as the distribution point. Updates are manual — no auto-update
mechanism, keeping the no-network-calls claim absolute rather than
exception-laden.

---

## 7. Findings ranking — the core problem

Detection is the easy half. Every heuristic listed in this brief is documented in
Wireshark's source and in tcptrace, and could be reimplemented in a weekend. What
is not solved anywhere is **ordering**.

A busy capture contains thousands of technically-abnormal events, and most are
noise. A 0.3% retransmit rate is a healthy internet path. A single four-second
zero-window stall is the outage. Both are "abnormal"; only one matters. If a
trivial finding outranks a real one, the user stops reading and the tool has
failed even though its detection was perfect.

### Score on impact, not on event count

Contributing factors, roughly in order of weight:

- **Time lost.** Seconds of stall attributable to the condition. A zero window
  held for four seconds outranks two hundred retransmits costing 40 ms total.
- **Scope.** One flow, one host, one subnet, or everything. Broad usually means
  infrastructure; narrow usually means endpoint.
- **Deviation from the rest of the capture** (see below).
- **Directionality.** One-way loss is far more diagnostic than symmetric loss.
- **Proximity to failure.** Events immediately preceding a RST or a timeout
  outrank the same events occurring during steady state.

### Comparative baselines within the capture

Most of what makes something genuinely *interesting* is that it differs from its
peers in the same file. One server slow while forty are fast. One flow
retransmitting while its neighbours across the same path do not. Loss present in
one direction only.

This is cheap to compute in the existing single pass — hold per-host and per-path
aggregates alongside per-flow state — and it has a significant secondary benefit:
**it requires no external reference data and no labelled corpus.** The capture is
compared against itself. Absolute thresholds, which would otherwise have to be
guessed and would be wrong across different environments, become a fallback rather
than the primary mechanism.

### Presentation follows ranking

Lead with the top five to ten. Full list below, always available, never first.
Each finding states what was observed, why it stood out, which frames to look at,
and what to check next — in that order. Never a causal claim.

**Wording discipline.** The difference between the advisory posture and an
unsupportable verdict is entirely in the language:

> **Avoid:** "Your application server is slow."
>
> **Prefer:** "Server 10.2.2.7:443 responded at p95 in 1.8s while the other 41
> servers in this capture are under 40ms. payload → first response byte, network
> RTT subtracted. Frames 8821, 9104, 9330. Check application or backend
> dependency latency on that host."

The second is verifiable, falsifiable, and leaves the conclusion to the user.

---

## 8. Filtering and scoping the analysis

Core functionality, not a convenience. Users frequently arrive already knowing
which conversation matters — "it's between the app server and the database" — and
a busy capture makes that conversation impossible to find manually.

### Filter at the presentation layer by default

**Parse everything. Build baselines from everything. Filter only what is shown.**

This preserves the comparative ranking described in section 7, which is the
mechanism that makes findings meaningful. If the parse is filtered to A↔B, the
peer group is gone, and the tool can report that server A responded in 1.8s but
not that this is 45× the median of the other 41 servers in the same file. The
second statement is the one worth reading.

Presentation-layer filtering keeps both: the user sees only the A↔B conversation,
but each finding retains its context against the full population.

Implementation consequence: findings must be accumulated and held to the end of the
run rather than streamed out as detected. See the two-tier memory model in
section 5.

### Parse-time prefiltering as an explicit escape hatch

`--prefilter` applies the filter during the parse for genuinely oversized files
where the full pass is impractical.

When used, the report must state that **baselines are drawn from the filtered
subset only**, and comparative findings must be downgraded or suppressed
accordingly. Silently narrowing the baseline produces confident nonsense — every
flow looks normal when compared only against flows exhibiting the same fault.

### Bidirectional by default

A literal one-way source→destination match is a serious footgun. Matching data
segments without their ACKs collapses TCP state tracking and produces a report
claiming catastrophic loss that does not exist.

- `--host A --host B` means the **conversation**, both directions. This is the
  default and the documented path.
- `--src` and `--dst` remain available as explicit directional overrides, and must
  emit a warning describing what one-way filtering breaks.

### Syntax — deliberately not BPF or Wireshark display filters

Both are large grammars to implement, and both defeat the premise. The target user
is someone who does not know Wireshark; requiring `ip.addr==10.1.1.5 && tcp.port==443`
to operate the tool that exists because they don't know Wireshark is self-defeating.

Plain flags cover the realistic cases:

```
--host 10.1.1.5 --host 10.2.2.7    # conversation, either direction
--port 443
--proto tcp|udp|icmp
--after 14:02:00 --before 14:04:00 # time window
--exclude-host 10.0.0.9            # drop known-noisy hosts
--top 20                           # limit findings shown
```

Multiple `--host` flags scope to traffic between those hosts. Combining classes
(host and port and time) is an intersection.

### Time windowing is often the stronger filter

Users typically know *when* something broke more reliably than they know which
hosts were involved. Time bounds also cut a capture down far more aggressively
than host filters in most incident scenarios. Treat `--after` / `--before` as
first-class rather than secondary, and accept both absolute timestamps and offsets
from capture start.

### The report emits its own drill-down commands

Each finding carries the exact invocation needed to narrow to it:

> Worst flow: 10.1.1.5 ↔ 10.2.2.7 — 4.2s cumulative stall
> Drill down: `pcaptriage capture.pcap --host 10.1.1.5 --host 10.2.2.7`

This resolves the common case where the user does not yet know what to filter on:
run unfiltered, read the top findings, copy the command. It also teaches the filter
syntax without documentation, and reinforces the advisory posture — the tool
proposes where to look, the user decides whether to follow.

### Filter state in the completeness banner

Every report states packets present, packets analysed, and the filter applied.

Same reasoning as the `unavailable` findings in section 10: a report that appears
clean because the filter excluded the problem is the dangerous failure mode. If a
filter is active, say so at the top, in the same place the user is told about
capture completeness.

---

## 9. Correctness risks worth designing around now

These are the things that make the tool point in the wrong direction. An advisory
tool survives being incomplete far better than it survives being misleading —
a finding that sends someone to investigate the wrong system costs more than a
finding that was never raised.

- **Missing SYN.** Without the handshake you don't know the window scale factor,
  so window sizing figures are meaningless. This is the common case rather than
  the exception — see section 10, which treats it as a first-class design problem.
- **TSO/LRO artifacts.** Captures taken on an endpoint show 64 KB "packets" that
  never existed on the wire. Detect segments above MTU and annotate accordingly.
- **Reordering misread as loss.** Sub-3 ms retransmit deltas with sane IP ID
  ordering are almost always reordering. Getting this wrong means blaming the
  network for a NIC offload setting.
- **Truncated snaplen.** `tcpdump -s 96` silently breaks payload analysis.
  Check `capinfos`-equivalent metadata and warn.
- **Clock issues in pcapng.** Multiple interfaces with differing timestamp
  resolution will corrupt delta calculations if merged carelessly.
- **Hostile input.** Fuzz the header parsers. Malformed captures are a real
  attack surface for anything running on a server.

---

## 10. Midstream capture handling

In datacenter environments midstream is the **majority case**, not an edge case.
Connection pools, VPN tunnels, replication links, and long-lived database sessions
have typically been established for days or weeks. Their handshakes will never
appear in a capture taken during an incident. A tool that declines to analyse
these flows is useless precisely where it is most needed.

### What actually breaks

TCP window scaling is negotiated once, in the SYN and SYN/ACK options, as a shift
value of 0–14. The raw 16-bit window field in every subsequent segment must be
multiplied by 2^shift. Absent the handshake, a raw window of 501 could mean
501 bytes or 8.2 MB — a factor of 16,384.

**Unavailable without the handshake:**
- Receive window sizing in absolute bytes
- Window-full detection
- "Throughput limited by receive window" conclusions
- Bandwidth-delay product comparisons
- Baseline handshake RTT (SYN → SYN/ACK)

**Unaffected — the majority of the product:**
- **Zero window.** Zero multiplied by any scale factor is still zero. The headline
  detection, including duration until window update, works fully midstream.
- Retransmissions, fast retransmits, RTO-driven retransmits
- Duplicate ACKs, SACK blocks, out-of-order detection
- RSTs and connection teardown analysis
- **Server response delta.** Pure timing across data and ACK frames. The
  "is it us or them" answer survives completely intact.

### Per-flow capture completeness state

Track completeness per flow, never globally. A single capture routinely contains
both established and newly opened connections, and the newly opened ones are often
the ones reproducing the fault.

| State | Condition | Consequence |
|---|---|---|
| `COMPLETE` | SYN and SYN/ACK both observed | Full analysis, all findings confirmed |
| `PARTIAL` | One SYN observed | That side's shift is known, but scaling activates only if *both* peers sent the option — so it cannot be confirmed active |
| `MIDSTREAM` | Neither observed | Window sizing unavailable; all other analysis proceeds |

### Evidence quality tagging

Every emitted finding carries a quality tag:

- `confirmed` — derived from directly observed protocol state
- `inferred` — derived from a defensible deduction, with the basis stated
- `unavailable` — the check could not be performed, with the reason stated

**The `unavailable` findings must be rendered in the report, not silently dropped.**
This is the single most important control in this section. A report that looks
clean because half the checks never ran will close a ticket on a fault that is
still live. Explicit wording, e.g.:

> Not assessed: receive window sizing. 18 of 42 flows began before capture start,
> so the window scale factor is unknown. Zero-window detection was performed and
> is unaffected.

### Window scale inference

If bytes in flight on a flow exceed the raw advertised window, scaling must be
active, and the ratio yields a lower bound on the shift value. Refine the bound
as the capture progresses.

Wireshark does not do this. It is a genuine differentiator and worth building.
It must be tagged `inferred`, must show its working, and must never feed a
confident verdict on its own.

### Operator controls

```
--midstream=annotate    # default: analyse everything, tag what is uncertain
--midstream=strict      # suppress all findings that depend on absent state
--midstream=permissive  # include inferred window scale in sizing analysis
--assume-window-scale N # operator asserts a known environment default
```

### Capture completeness banner

Every report opens with a completeness summary: flow counts by state, capture
start and end, snaplen, and whether truncation was detected.

Where a large proportion of flows are midstream and the fault is reproducible,
the most valuable output the tool can produce is a recommendation to restart the
capture before reproducing. Prompting a better capture beats extracting marginal
inferences from a poor one.

---

## 11. Privacy and data handling

This section exists because section 3 recommends emailing the report to a vendor
or attaching it to a ticket, and the report is derived from data that is frequently
sensitive. That recommendation is only safe with the controls below.

### What a report actually contains

Internal IP addressing and subnet structure. Hostnames from cleartext DNS queries.
TLS SNI values, which reveal which services a host talks to. Certificate subjects
and issuers. Port numbers and service inventory. Timing patterns that can imply
business process. Collectively this is a reasonable map of internal infrastructure.

A user pasting that into a vendor ticket is disclosing more than they intend.

### Controls

- **No payload bytes in the report, ever.** v1 emits frame numbers only. This
  makes the report safe *by construction* against credential and PII leakage
  rather than by filtering, which is the far weaker guarantee. Any future feature
  proposing to include payload should be rejected on this basis.
- **`--redact` mode.** Deterministic pseudonymisation: IP addresses mapped to
  stable placeholders (`host-01`, `host-02`) consistently within the run, so
  findings still correlate and the report remains readable. Hostnames and SNI
  stripped. Structure and timing preserved, since that is what the vendor needs.
- **A disclosure note in every unredacted report**, stating plainly what it
  contains and that `--redact` exists. Users cannot make a judgement about
  sharing if they do not know what they are holding.

### Read-only, and no network

- The tool **never writes to or near the input file**. Captures are frequently
  incident evidence and occasionally subject to legal hold.
- The tool **makes no network calls of any kind**. No update check, no telemetry,
  no crash reporting.
- **Reverse DNS enrichment is the trap here.** Resolving IPs to hostnames would
  materially improve report readability, and it would send internal addresses to
  a resolver, break the air-gap guarantee, and alter behaviour between runs.
  Excluded in v1. If ever added, it must be opt-in, off by default, and
  prominently flagged in the report when used.

Because the source is published, "makes no network calls" is an auditable claim
rather than a marketing one. That is worth more than the feature it costs.

---

## 12. Validation and test strategy

The hardest unsolved problem in this project is not technical. It is that **no
public corpus of labelled network performance pathologies exists.** Available
capture repositories are overwhelmingly security-oriented — malware traffic, CTF
artifacts, protocol samples. Almost nothing is labelled "this is a slow consumer
causing zero-window stalls."

Without ground truth, the rules encode textbook assumptions and ship as confident
guesses. Four complementary approaches, in order of cost.

### Synthesised captures — the primary mechanism

Write pcap files programmatically in Go tests, crafting TCP state directly rather
than capturing from a live stack. No network involved, no privileges, fully
deterministic, small enough to commit to the repository.

Every rule gets a **positive fixture** that must trigger it and a **negative
fixture** that must not — the false-positive traps in `RULES.md` are the source
material for the second set. A zero-window stall, a reordering pattern that must
not be reported as loss, a PMTU blackhole with ICMP filtered: all constructible
byte by byte.

This directly answers the corpus problem for detection correctness. It does not
validate *thresholds*, because synthetic timing is whatever you make it.

### Lab injection with `tc netem`

Real stacks, real timing, real congestion behaviour. Inject loss, latency,
reordering, and rate limits between two hosts and capture the result. Slower to
produce and not committable, but it exercises TCP dynamics that hand-built
fixtures cannot reproduce faithfully — congestion window behaviour in particular.

This is where threshold calibration actually happens.

### Real captures from users

The existing Hana audience is a genuine advantage here that most people attempting
this project do not have. Soliciting sanitised captures with a description of the
known fault builds the corpus nobody else has.

Note the dependency: this is only practical once `--redact` from section 11 exists.
Nobody sends a stranger an unsanitised capture of their production network. Build
the redaction tooling before asking.

### Regression and fuzzing

- **Golden-file testing** on the findings JSON. Any change to wording, thresholds,
  or ranking surfaces as a reviewable diff rather than a silent behavioural shift.
- **Fuzzing the parsers** against malformed input, per constraint 5. Go's native
  fuzzing, seeded from real capture files. A pcap is attacker-controlled data and
  the tool is proposed for production servers.

### Performance targets

Currently unstated, which means regression is undetectable. Proposed starting
targets, benchmarked in CI:

| Metric | Target |
|---|---|
| Throughput | ≥ 500 MB/min, single core, commodity hardware |
| Memory ceiling | Configurable; default 512 MB, never unbounded |
| Largest supported capture | 10 GB within the memory ceiling |
| Startup to first output | < 1s for captures under 100 MB |

---

## 13. Reproducibility, versioning, and automation

Constraint 4 requires byte-identical output for identical input. That needs
enforcing deliberately.

### Determinism

**Go map iteration order is randomised by design.** Any findings list, flow table,
or per-host aggregate assembled from a map and emitted without sorting will
reorder between runs on the same file. This is the single most likely way
constraint 4 gets violated, and it will not be caught by casual testing. Sort
explicitly before emit, everywhere, and assert it in the golden-file tests.

### Version stamping

Report headers carry **tool version and ruleset version separately.** Thresholds
and wording will change far more often than the code does, and a user comparing a
report from last month against one from today needs to distinguish "the network
changed" from "the tool changed." Record the full invocation too, including any
filters applied.

### Timestamps and timezone

The user's immediate next step after reading the report is correlating findings
against application logs. That makes timezone handling more consequential than it
appears. State the timezone explicitly in the report, offer `--tz`, and show both
capture-relative offsets and absolute times. Defaulting silently to UTC while the
user's logs are in local time turns a five-minute correlation into an hour.

### Exit codes and automation

Removed as a product commitment. The dev CLI has whatever exit behavior is
convenient for development; nothing external depends on it. If a shipped CLI
ever returns as a contributor-maintained project, an exit-code contract becomes
that project's concern.

### JSON format

Internal, not an API. With no shipped CLI there are no external consumers, so
the findings JSON is a format shared between the engine, the GUI, the export
action, and the golden-file tests — versioned in git like any other internal
interface, changeable freely. The explicit "Save analysis / export JSON" action
in the GUI shares this format; a note in the exported file stating that the
schema is not a stability contract costs one line and prevents accidental
dependence.

---

## 14. Licensing and contribution model

Open source, consistent with Hana, and deliberately non-commercial — this is a
free tool, not a lead-in to a paid product. That decision, made separately from
the GUI pivot, simplifies what follows.

### Licence choice

**MIT — decided.** Apache 2.0 was equally reasonable; neither was
load-bearing.

The earlier recommendation for Apache 2.0 was based on an intent to reuse the
heuristics engine in a commercial monitoring product, which is no longer the
plan. Its patent grant costs nothing to include and would still have been a
fine default, but with the commercial-reuse plan gone this was a preference
rather than a strategic decision, and MIT was chosen for being the shorter and
more widely recognised of the two.

The licence text lives in `LICENSE`, copyright Proxy-IT. The same line is
carried in the app's binary metadata (`wails.json` and `winres/winres.json`),
which is the place it most easily goes stale.

### Copyright ownership

A DCO (Developer Certificate of Origin) on contributions is still worth having —
it's low overhead and keeps provenance clean regardless of commercial intent. A
CLA and the relicensing-freedom argument for one are no longer necessary; that
argument depended on the commercial-reuse plan that's no longer in effect.

### Rule contributions

Published rules invite contributed rules. This is the growth mechanism — and the
scope-creep vector, given the fifteen-rule ceiling exists precisely because the
rules table has no natural stopping point.

Require every rule contribution to include:

1. A positive test fixture that triggers it
2. A negative fixture that must not trigger it
3. False-positive analysis, in the format used in `RULES.md`
4. A proposed base weight with justification relative to existing rules

That bar is high enough to preserve quality and self-selects for contributors who
understand the advisory posture. It also means each accepted rule arrives with the
test coverage that section 12 requires.

The fifteen-rule ceiling applies to v1 only. Growth after that should be driven by
real captures showing real gaps, not by comprehensiveness for its own sake — and,
per the free-and-simple positioning, against adding capability that makes the tool
harder to understand in one sitting.

---

## Summary recommendation

| Layer | Choice |
|---|---|
| Language | Go |
| File parsing | `pcapgo` framing, hand-rolled L2–L4 decode |
| Analysis | Single streaming pass; two-tier memory — evictable flow state, retained findings store |
| Rules | Static condition → observation → why it stood out → frames → next check |
| Ranking | Impact-weighted, using within-capture comparative baselines |
| Filtering | Presentation-layer by default, bidirectional, plain flags not BPF |
| Capture completeness | Per-flow state tracking; findings tagged confirmed / inferred / unavailable |
| Output | Desktop GUI (Wails), top findings first; internal dev CLI, same engine |
| Charts | Server-rendered SVG, uPlot inlined for the timeline only |
| Licensing | MIT — non-commercial, chosen from the two the brief sanctioned |
| Distribution | Signed installers, Windows + macOS release-blocking; Linux best-effort; no CLI releases |
| Privacy | No payload in reports; `--redact` mode; zero network calls |
| Validation | Synthesised fixtures per rule, `tc netem` for threshold calibration |

Three things belong in the README explicitly.

**No LLM.** Deterministic, offline, nothing leaves the host. This is a positioning
advantage against every upload-based analyser currently in this space, and it is
the reason the tool can be used on captures that legally cannot be sent anywhere.

**Advisory, not diagnostic.** The tool surfaces what is unusual and shows its
working. It does not tell you what broke. Stating this plainly sets the right
expectation and is also the honest description of what the heuristics can support.

**Open rules.** Because the detection and ranking logic is published, any user can
audit why something was surfaced and disagree with it. That auditability is what
earns trust for a tool whose entire output is a set of judgement calls — and it is
precisely what the LLM-based alternatives cannot offer.
