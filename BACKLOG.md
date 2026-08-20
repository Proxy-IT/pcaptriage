# Backlog — prioritized work queue

**Status:** items in the "Prioritized queue" section are agreed direction, ordered
for implementation. Items under "Discussed, not yet queued" and below remain
parking-lot — do not implement those without discussion. Each queued item still
needs its session brief; this file sets order and intent, not full specs.

The ordering principle: correctness before coverage, architecture before features
that depend on it, and "can the user act on what the tool already says" before
teaching the tool to say more.

---

# Prioritized queue

## P1. State architecture foundation — do this first

**Why first:** several later items (labels, recent files, sessions, persist
behavior) share one root — the app currently has no concept of state that
outlives a single capture view. This is one narrow architectural decision, made
once, that unblocks all of them without building any of them. Retrofitting it
later means rework; doing it now is a small refactor.

**Agreed approach:**

Three distinct state objects, treated differently:

1. **App preferences** (timezone, redaction default, recent-files on/off) —
   single human-readable JSON file in the OS-standard config dir
   (`os.UserConfigDir()`: `~/.config/pcaptriage/`, `%AppData%`,
   `~/Library/Application Support`). No database.
2. **User-entered labels** (IP → friendly name, e.g. "10.2.2.7 = DB server") —
   same config file or sibling JSON. Keyed by IP, global per machine, not per
   capture. This is the user's own knowledge, not capture-derived data.
3. **Analysis results** — **never persisted automatically.** The capture file is
   the persistence; the engine is deterministic (constraint 4), so reopening a
   file re-parses and is guaranteed byte-identical. "Save analysis…" exists as
   an explicit export action (the JSON already emitted), never an automatic
   cache. Automatic caching of derived capture data is §11 territory and stays
   out by default.

**In-memory model:** the GUI's state becomes **a list of open analyses with an
active index, not a single current analysis** — even while the UI renders only
one. This is the cheap-now/expensive-later decision: it's the difference between
multi-capture tabs being a v2 feature versus a v2 rewrite.

**Explicitly not building:** SQLite, cache directories, auto-save, per-capture
workspaces. Each is a plausible next step; each fails the free-and-simple test
until real usage demands it.

**Privacy payoff:** the data story becomes one sentence — "the only things this
app writes to disk are your settings and your labels, in one readable file" —
which is itself the content for the first-run privacy moment (P8).

**Scope for the session:** refactor GUI state to list-of-analyses; add config
read/write with timezone as the first preference. Narrowest version that locks
the architecture. Labels UI and recent files land later as pure feature work.

## P2. B1 — R15 kernel capture drops (correctness fix)

**Why now:** this is the tool being *wrong*, not incomplete. If the capture host
dropped packets (recorded in pcapng's Interface Statistics Block; reported by
tcpdump on exit), R05/R06/R08 confidently report wire loss that never happened,
with frame references. §9 names this as the expensive failure mode. Extension to
R15, not a new rule — no ceiling impact. Small, contained, high value.

## P3. A8 — Clean-capture state

**Why this order:** the most load-bearing UI gap. An empty findings list
currently reads as either "nothing wrong" or "tool didn't work" — the user can't
tell which, and this user especially can't. Needs an explicit statement: nothing
significant found, what was checked, what couldn't be checked and why. The last
part is the §9 false-all-clear guard applied to the GUI's most dangerous screen.
Depends on nothing; blocks nothing; every real-world clean capture hits it.

## P3.5 Export coverage parity + design token unification

**Done 2026-08-17, commit 92ee198.** Coverage moved into the report document
(schema 4) so exports and the in-app clean screen render the same struct; the
P3 banned-phrase test now runs against the export rendering. Tokens: colors,
fonts, type base and radii extracted to one file both surfaces consume;
spacing deliberately not tokenized — the two surfaces are a document and an
application and legitimately space themselves differently, so a shared spacing
scale would have unified values that weren't drifting.

**Added after the P1–P3 session.** The clean-capture screen now shows "what
could not be checked" in-app, but the exported HTML report does not carry
coverage data at all — findings can render with no gaps section. The export is
the artifact most likely to be read by someone with zero context (attached to a
ticket, forwarded to a vendor), so it has the same §9 false-all-clear exposure
the clean screen just fixed, in the surface with the least surrounding context.

Bring coverage (checks run, checks unavailable and why, completeness counters)
into the exported HTML and JSON. The always-zero `MinorObservations` field ships
in the same structure for the same reason it exists in-app.

**Do the design-token unification in the same session** (the long-standing
review item): both tasks touch the report template, and the tokens item has
been waiting for exactly this — extract shared tokens (colors, spacing, type
scale) into one source both the GUI stylesheet and the report template consume.

## P4. A4 — Evidence quality badges + severity vocabulary

**Done 2026-08-17, commits 0f741f7 (severity + badges) and 6059357 (guide +
About).** Thresholds [chosen]: Significant ≥ 40, Worth noting ≥ 15,
informational below — anchored on RULES.md's own R06 language (its healthy
fast-retransmit example scores 18.1 and the spec calls it "worth noting").
Green clean banner requires strong coverage (no gaps and complete rule set),
so today it is always neutral. No display floor introduced, per the note below.

Two related card-level signals, distinct and both needed:
- **Evidence quality** (`confirmed` / `inferred` / `unavailable`) — already in
  RULES.md, currently internal. Says *how sure*.
- **Severity vocabulary** ("significant / worth noting / informational") — says
  *how much it matters*. Ranking gives order but not calibration; three findings
  could be three curiosities or three fires.

Do together because they're the same rendering surface and conflating them would
be a design error — design the two-badge layout once.

**Note from the P3 session:** there is currently no display floor — rules
suppress their own trivia at detection time and everything emitted is shown.
P4's severity work is where a floor would be calibrated if one is ever wanted;
`MinorObservations` (always zero today) is the seam left for it. Don't introduce
a floor casually as a side effect of badge work — it's a §9-relevant decision.

## Fixture realism is a separate review axis from fixture correctness

**Three instances by the end of Batch 3, two mechanisms. Recorded because a
fixture that passes its assertion can still misrepresent the condition it
names, and nothing in the suite is looking for that.**

A synthesized fixture drifts toward whatever makes its assertion pass, not
toward what the wire actually looks like. Every simplification is individually
reasonable at the time; the drift only shows up when something else forces a
second look. All three instances below were found while doing something else
entirely.

- **R13's positive had no peer flows.** One connection failing on size, in a
  file containing nothing else. It exercised the detection perfectly and
  demonstrated nothing, because a single flow failing on size is ambiguous —
  the comparison that makes the finding diagnostic had no population to draw
  on. Found only when the scoring ceiling forced a peer comparison.
- **R13's positive backed off at 300ms.** Real TCP RTO starts near a second
  and doubles, so the fixture was modelling a blackhole that resolved in three
  seconds — faster than any real one. The condition's entire cost is the time
  a transfer spends going nowhere, and the fixture had quietly made that cost
  small. Found while fixing the first instance.
- **Three R09 fixtures send 6–16KB segments on synthetic Ethernet** (detail
  below). Found while measuring segment sizes for R13's offload gate.

The common shape: **the fixture tests the detection while stripping away the
context that makes the condition meaningful.** Correctness and realism are
different questions, and the suite only asks the first.

**What catches this and what does not.** The tshark oracle catches
protocol-level disagreement — it will say if a segment is not a
retransmission, or a handshake is malformed. It has nothing to say about
timing plausibility, topology, or whether a capture contains the traffic that
would surround the condition in the wild. Those are the ones that got through.

**Checklist item when writing a fixture:** having made it trigger the rule,
ask separately whether a real capture of this condition would look like this.
Would it arrive alone in the file, or beside working traffic? Are the
intervals ones a real stack produces? Are the sizes ones a real link carries?
A fixture that answers no to any of these still passes its test and still
misrepresents what the rule is for.

### The R09 instance, in detail

**Found 2026-08-20 while measuring for Batch 3's R13 gate. Real, not blocking.**

`r09-reset-mid-transfer` (16,000-byte segments), `r09-clean-close` (8,000) and
`r09-uniform-reset` (6,000) send payloads far larger than any Ethernet link
carries. They were authored for byte volume — "a substantial download" — with
segment size chosen for convenience rather than realism.

Nothing currently misreports because of it: those flows use plain `Handshake`,
which advertises no MSS, and the offload detection added for R13 compares
against the negotiated maximum and declines to speak without one. So they
produce no false offload notice.

It is still worth fixing, for a reason beyond tidiness: **a real capture
containing 16KB segments on Ethernet is a capture showing TSO artifacts.**
These fixtures are, unintentionally, modelling exactly the condition R13
degrades for — so anything derived from segment size in them is measuring
something no wire ever carried.

The fix is to give them realistic segments and a handshake that negotiates an
MSS, then regenerate. Not free: R09's own figures — bytes in flight at the
reset, the "averaging 1KB transferred" style wording — are computed from those
sizes, so its three goldens and any test asserting those numbers move with
them. Worth doing when R09 is next touched rather than as isolated churn.

## Filter affordances on titles — two known inconsistencies

**Noted 2026-08-20 during the filterability session. Ruled leave-as-is;
recorded so they are not rediscovered, and to be revisited once all fifteen
rules exist.**

Clicking an endpoint in a finding's title scopes the view to it. Which
endpoints are clickable falls out of how each rule authors its title, and two
consequences follow:

1. **Flow findings make only one of their two endpoints clickable.** R01's
   title names `10.2.2.7:5432` while its subject is the flow
   `10.1.1.5:44210 <-> 10.2.2.7:5432`. Both are subjects and both *match* a
   filter correctly; only the named one can be clicked. R05 and R08 differ
   again — their titles name both hosts but without ports, so both are
   clickable as bare hosts.
2. **The same visual token means different things on different cards.** R01's
   title carries `host:port` and R09's carries a bare `host` (its subject is
   `10.2.2.9:5432` but the authored title drops the port). Clicking them
   produces filters of different granularity from what looks like the same
   kind of thing.

Left alone deliberately. Titles are authored per-rule in RULES.md and the
wording is spec — R09 dropping the port is a wording decision, not an
oversight. Making every subject endpoint clickable would mean either composing
titles mechanically, losing the authored wording, or adding clickable tokens
outside the title, which is chrome the brief explicitly resists.

The second one is the one to watch: an affordance whose meaning varies by card
erodes trust quietly rather than failing visibly. It does not warrant
restructuring while four rules are unbuilt and Part 3's typed input is about to
make any endpoint filterable regardless of what a title happens to name.
**Revisit when all fifteen rules exist and the full set of title shapes is
visible** — Batch 3 will add more, and the right fix (if any) depends on the
whole set rather than on today's ten.

## Typed filter input — time windows, and why they are not built

**Specified in the filterability session's Part 3b. Host, port and
conversation terms are built; time windows are not.**

The intended behaviour: `after 63s`, `before 66s`, `63s-66s`, in
capture-relative seconds matching Wireshark's default time column, composing
with host and port terms as an intersection. A finding matches when **any of
its cited frames** falls inside the window.

What blocks it is that the data is not there to do it correctly. A finding's
cited frames and its retained packet rows are different sets: R04 cites eight
representative frames and retains header snapshots for two of them. The GUI's
only source of frame times is that packet evidence, so a window filter built on
it would match on two frames and silently ignore six — a reader narrowing to
the window containing the other six would watch a genuine finding disappear.
That is a false negative inside a filter, which is the failure mode this tool's
whole posture is against.

Doing it properly means carrying cited-frame times out to the GUI. The
`Evidence` collector already holds a time per retained occurrence, so a
`FrameTimes()` accessor mirroring `Frames()` is straightforward — but only four
of the ten built rules produce their frame list through `Evidence.Frames()`.
The other six assemble it locally, and each would need its times threaded
alongside. That is engine work across every rule, in a session whose governing
constraint is that filtering is presentation-only, so it was stopped rather
than half-done: partial support that works for four rules and silently
under-matches for six is worse than none.

Cheap and worth doing when picked up: the new field belongs on the GUI binding's
`AnalysisResult`, not on `report.Finding`. The evidence array is already
GUI-only, so adding times there leaves the JSON and HTML goldens byte-identical
and keeps a presentation concern out of the report schema.

## Filtered export — designed, deliberately not built

**Specified in the filterability session and deferred there. Blocked on a GUI
export action existing at all, which today it does not.**

Presentation-layer filtering now exists in the app: clicking the hosts and
ports a finding names scopes the view, and a chip bar carries a mandatory
"Showing N of M" for as long as any filter is active. **The export is always
the complete, unfiltered report**, and that is the deliberate position rather
than an unfinished one. An export is the artifact a stranger reads with no
context and no chip bar; a silently-filtered one is the false-all-clear risk in
its worst form, because nothing on the page would admit the subset.

What a filtered export needs before it can exist, from BRIEF §8's filter-state
requirement:

- A **loud provenance banner** in the document itself, stating the filter that
  produced it, in the same place the reader is told about capture completeness.
  §8 puts this beside the coverage gaps for the same reason: a report that
  looks clean because the filter excluded the problem fails identically to one
  that looks clean because a check never ran.
- The banner in the **JSON as well as the HTML**, since the JSON is the machine
  artifact and a consumer cannot see a visual banner.
- A decision about **comparative wording**, which is the sharp edge. Findings
  say things like "the other 8 servers in this capture are under 40ms" —
  measured against the full population, correct in a full report, and
  potentially confusing in a filtered one where those 8 servers do not appear.
  The wording is right and must not change; the banner has to carry the
  explanation.

**Sequencing:** there is no export action in the GUI at all yet — export lives
only in the dev CLI's `-html`/`-json` flags, which are not a shipped product.
When a GUI export is built, it inherits the session's rule immediately: if a
filter is active, say plainly at the action that the export contains the
complete report. That note has no home until the action exists.

## P5. A5 — Redaction as a visible control

Visible toggle at export/share time, one-line statement of what the report
contains, **default to redacted on share/copy actions** with unredacted as
deliberate opt-out. The GUI's target user is the person most likely to paste an
unredacted report into a vendor ticket. Requires the redaction engine work
(deterministic pseudonymization per §11) — this item pulls that forward from
CLI-flag status to core feature.

**Sequencing note:** gates the "solicit real captures from the audience" corpus
plan — nobody sends unsanitized production captures. Finishing this unlocks that.

## P6. A3 — Bundled demo capture

"See an example" on the home screen loading a known fixture with known findings.
Lets a user judge the tool before trusting it with production data. Fixtures
already exist; mostly wiring. Doubles as a smoke test. Cheap, high trust value.

## P7. A7 + A2 — Ticket summary and frame-reference bridging

Done together — both are "help the user hand findings to the next person":
- **A7:** "Copy summary for a ticket" — plain-text paste (top findings, frame
  refs, tool version). The user's real next action is telling someone else.
- **A2:** frame references explained — minimum: one line saying what frame
  numbers are for (the person they escalate to). Optional stretch: detect
  Wireshark, offer "Open in Wireshark at frame N" (`wireshark -g`). Stretch is
  genuinely optional; don't let it expand the session.

## P8. First-run privacy moment + A9 small items

**Partial (2026-08-17, commit 6059357):** the privacy story landed on the About
page — no longer invisible, but still only where a user goes looking for it.
P8's remaining scope is the first-run moment itself plus the A9 small items
below.

- One screen, shown once: everything stays on this machine, no upload, no
  telemetry. Content is P1's one-sentence data story — now written, on the
  About page. The no-network posture is the strongest differentiator; the
  first-run moment puts it in front of every user instead of only the ones who
  open About.
- A9 batch: friendly rejection of unsupported types, transparent `.gz` handling,
  size/time expectation before run ("2.3 GB — this may take a few minutes"),
  timezone as visible control (reads P1's preference).
- **Cancel button** for in-flight analysis — a progress bar without abort feels
  broken on a 10 GB mistake.

## P9. A6 — Inline term explanations

**Absorbed 2026-08-17 (commit 6059357):** the guide pages replace tooltips —
each finding card links to its rule's plain-language page, which covers the
terms in context. Revisit only if the pages prove too heavy for quick lookups;
don't build a second explanation layer alongside them without that evidence.

Tooltips/expandable definitions on terms (zero window, retransmission, RTT, p95,
SYN). Layered on top of RULES.md wording, which stays verbatim. Progressive
disclosure. Placed after P3–P7 because it improves comprehension of cards the
earlier items make trustworthy and actionable.

## P10. "What did you check?" screen

**Absorbed 2026-08-17 (commit 6059357):** the registry-driven guide index is
the checks screen — one entry per built check with its authored one-liner,
unbuilt checks disclosed by count rather than named (naming them would need a
hand-maintained list that could drift from RULES.md; the registry is the single
source of truth). Reached from Help and from every guide page.

The fifteen rules in plain language, in-app — makes the published-rules trust
argument (§14) visible instead of living in a repo the user never visits.
Natural home is the About/Help area stubbed in the first GUI session.

**Note:** `--list-checks` is referenced in BRIEF.md's scope boundaries and
RULES.md's handoff notes but has never been built. The GUI half of P10 is
closed by the guide; the dev-CLI `--list-checks` references remain open.

## P10.5. R15's remaining conditions — snaplen truncation, TSO, timestamp/multi-interface

**Added 2026-08-17, during Batch 1 Part 2b.** RULES.md's R15 condition list is
snaplen truncation, midstream proportion, TSO/LRO segment-size artifacts,
one-way flows, timestamp resolution, and multi-interface merges. Part 2b
formalized R15 as a real rule (registered, owns its own reporting) but only for
what the engine already tracked: midstream, one-way, and capture-host drops.
Snaplen is read and shown as a raw banner value but was never turned into a
completeness gap; TSO/LRO and timestamp/multi-interface have no tracking at
all — not even the raw facts exist yet, only `Packet.Truncated` at the decode
layer with nothing aggregated from it.

The session brief's language ("consolidate snaplen, midstream, TSO, one-way,
timestamp handling, and kernel drops under R15") assumed all six already
existed to move; only three did. Flagged and resolved for that session by
formalizing the built subset and writing R15's Summary to state only what it
covers — GUIDE-CONTENT-BATCH1.md's R15 page describes an "oversized packets"
notice this build cannot yet produce, so the same caveat applies there.

This item is the actual detection work: aggregate `Packet.Truncated` into a
snaplen-truncation gap, add TSO/LRO segment-size tracking (RULES.md's example:
"segments up to 24KB observed"), and timestamp-resolution / multi-interface
merge reporting. New fixtures per condition, wording per RULES.md's R15
example, golden diffs called out rather than nil (this is new detection, not
a move).

## P11. C2 — Idle-then-fail (firewall session reaping)

First new detection after the UI run, because R05 currently gets this case
*wrong* (reports "sustained loss on the path" when a firewall reaped the
session). Consumer rule reading R05 output plus idle duration — same shape as
R08, not a new detector. Needs full RULES.md spec first (condition, weight,
wording, degradation, traps) — spec in conversation, then implement.

## P12. C1 — Throughput / BDP limit

"Why do I only get 30 Mbps on a gigabit link" — among the most common capture
questions. Clean signature (in-flight pinned at advertised window, window never
grows, throughput ≈ window ÷ RTT). Distinct from R01. Unavailable midstream;
degrades per §10. Needs full spec first. Ceiling question (see D) must be
resolved before this and P13 land.

## P13. C3 — Delayed ACK / Nagle interaction

40ms/200ms clustered-gap signature. Prevents R04 from blaming a server for a
stack interaction. Valuable precisely because the plain-English explanation is
something this audience cannot produce themselves. Needs full spec first.

---

# Discussed, not yet queued

Parking lot. Do not implement without discussion.

## Multi-capture UX (beyond P1's architecture)
P1 makes the state model a list; actual tabs/session-list UI, and any
cross-capture intelligence (e.g. same flow seen from both sides feeding R08), is
deliberately deferred. The architecture decision is made; the features wait for
real demand.

## Progressive results during parse
Findings streaming in as flows close, rather than appearing at 100%. Engaging
and functional on multi-GB files, but ranking needs the full population, so this
is real engine design work. **One decision worth making early though:** whether
the findings store API is observable mid-run or only at completion — cheap to
decide now, expensive to retrofit. Flag for the P1 session as a design note, not
a feature.

## Recent files
Standard chrome, genuinely useful, but paths/names can be sensitive
(`\\legal-hold\incident-.../`). Needs clear-history and an off switch (the
preference lands in P1). UI deferred.

## Host labels UI
Storage lands in P1; the entry/edit UI and rendering-alongside-IPs is deferred
feature work. High value for readability ("user thinks 'the file server', tool
says 10.2.2.7") — likely early post-P13 candidate.

## Persist/save-analysis UX
P1 sets the policy (never automatic; explicit export only). Any richer
"save/restore session" concept stays out per free-and-simple.

## Partial-results strategy for corrupt captures
The 60%-readable-then-corrupt case. Options: fail entirely, or analyze the
readable portion behind a loud banner. Leaning toward the second — the readable
part may hold the answer and this user can't re-take the capture — but it has a
§9 false-confidence angle and needs a real decision, not a default.

## Bridging summary line above cards
"3 findings, one involving several seconds of delay" — acknowledges the user's
actual question ("is this why it's slow?") without a causal claim. Wording needs
care to stay advisory; discuss before speccing.

## Accessibility pass
Keyboard nav, contrast, screen-reader labels on cards. Should become a standing
test criterion rather than a one-off item — raise during any card-rendering
session (P3/P4) rather than as separate work.

## Window-size test criterion
Realistic viewport is a docked window on a laptop at 125% scaling, not a
full-screen monitor. Same treatment: standing criterion, raise during card work.

## Significance is invariant to occurrence count

**Noted 2026-08-18, during Batch 2 Part 1's R03 weight review. Not queued —
recorded so it is not rediscovered.**

`significance = base_weight × impact × scope × deviation` has no term for how
many times a condition occurred. `impact` is log-scaled *seconds of stall*, so
for any rule whose condition costs no measurable time, forty-seven occurrences
score exactly what two do.

R03 is where this surfaced: a refusal arrives instantly by definition — that
is precisely what distinguishes it from R02's silence — so its impact factor
is pinned at the 1.0 floor and only `scope` can move it. A host refusing 400
connection attempts and a host refusing 2 rank identically. The same shape
applies to any future count-driven, time-free rule.

Deliberately not fixed as part of the weight change, because it is a scoring
model question and not a weight question: no choice of base weight makes a
rule's score respond to its own occurrence count. Options if it is ever worth
addressing — a count term, or letting rules supply their own impact
derivation rather than always seconds — both change ranking across every rule
at once, which is exactly the kind of change that wants its own session and
its own before/after evidence.

Worth revisiting when a count-heavy rule first shares a capture with other
findings and ordering is genuinely exercised. Today no fixture puts R03
alongside anything else, so the effect is unobservable.

**Now a two-time occurrence, within a single batch.** R09 hit the same wall
later in Batch 2: it set no impact at all, so a genuine mid-transfer abort
could never rise above informational however many connections it interrupted,
and the rule's own uniformity downgrade was invisible because both fixtures
bottomed out at the floor together. It was fixed locally by charging the
transfer time thrown away — a real seconds-denominated cost that a reset does
have, once you look for it.

Twice in one batch is enough to stop treating this as incidental. **Checklist
item for R11, R12 and R13, which are still ahead:** before writing a rule's
fixtures, ask what its seconds-denominated impact actually is. If the honest
answer is "none", that is a design signal, not a detail to leave at the
default — the rule will be pinned to informational regardless of how many
occurrences it finds or how bad they are, and any severity distinction the
rule tries to draw internally will be invisible. Decide deliberately whether
that is correct (it was for R03) or whether there is a real cost being
overlooked (there was for R09). Check it during implementation, not after the
severity table comes out flat.

**Now a three-time occurrence, and the third has a different mechanism.**

R13 hit the same wall in Batch 3 by a route the checklist above does not
catch. It *has* an honest seconds denominator — a hung transfer stalls for a
measurable time — and it was assessed as fine at Checkpoint 0 on exactly that
basis. It was not fine. With `ScopeFlow` (0.8) and no peer group (deviation
1.0), `7 × Impact × 0.8 × 1.0` **tops out at 28.0**, below the significant
floor of 40. Measured:

| stall | significance |
|---|---|
| 3s | 12.3 informational |
| 30s | 22.3 worth noting |
| 600s | 28.0 worth noting |

A ten-minute hang scored the same as a two-minute one, and neither could reach
significant at any duration. The denominator was present and working; the
other two factors pinned the ceiling below the floor.

**The checklist is therefore wrong as written, and is corrected here: check
all four factors, not just the denominator.** For each rule ask what its
plausible range is on every axis —

- **impact** — is there a seconds-denominated cost, and does it scale with the
  condition's size?
- **scope** — can this condition ever affect more than one flow, and does the
  rule notice when it does?
- **deviation** — is there a population to compare against, or is this pinned
  at 1.0 forever?
- **base weight** — and then, given the achievable product of the other three,
  what severity band can this rule actually reach?

The last question is the one that would have caught R13: multiply the
best-case factors together and compare against the floors. A rule that cannot
reach the band its condition deserves is misconfigured regardless of how
sensible each factor looks alone.

**Part 4 item:** R03 and R09's accepted ceilings were reasoned about on the
impact axis only, using the "confirms what the application already told the
user" argument. That argument is sound for R03 and does not obviously extend
to R09, and neither was checked against scope and deviation. Re-examine both
once all fifteen rules exist and the full severity table can be read at once.

## Tests that pass while asserting nothing

**Noted 2026-08-20, during the evidence-quality session. Not queued — recorded
so the pattern is not rediscovered, and because it is now guarded.**

Four separate instances turned up inside one session. Each looked different,
each was green, and none of them measured the thing its name claimed:

- **The escaping match.** Compared two strings that were both empty, so the
  comparison held for a reason unrelated to escaping.
- **The emphasis round-trip.** Reconstructed its expected value using the same
  parser it was testing, so empty runs rebuilt the correct source string and
  42 genuinely broken `**bold**` spans passed. Live in the shipped alpha.
- **The inlined-stylesheet match.** Asserted a CSS class appeared in an
  exported report. The report inlines its whole stylesheet, so the class
  matched its own rule definition rather than any finding card.
- **The vacuous loop.** `TestR04MidstreamRTTIsInferred` iterated R04 findings
  in a fixture whose R04 findings are all confirmed. The loop body never ran,
  for the degradation the app demonstrates most.

The common failure is that a test's *subject* can vanish while its assertions
stay valid, and an assertion over nothing is indistinguishable in CI from an
assertion that held. Green means "found no counterexample", which is not the
same as "checked".

Only the fourth shape is mechanically detectable, and it is now linted:
`TestNoTestAssertsOnlyInsideAnUncheckedLoop` (`internal/analysis/
empty_assertion_test.go`) parses the repo's own test files and fails any test
whose assertions all sit inside a range loop with nothing establishing the loop
runs. Writing it surfaced nine further instances, all fixed — including
`TestPaletteMeetsContrastThresholds`, which would have verified no contrast
ratio at all on an empty pair list while reading exactly like a full
accessibility pass.

**Checklist item when writing any test:** ask what makes it fail. If the answer
depends on a collection being non-empty, a regex matching, or a fixture still
producing a particular finding, assert that premise separately — the lint only
catches the loop shape, and three of the four instances above were other
shapes. The general discipline the lint cannot enforce: prove a new test fails
against the bug it targets before trusting that it passes.

## D. Ceiling pressure (decision needed before P12/P13)
If the fifteen-rule ceiling holds and C-items are adopted, something gives.
**R03 (`syn-rejected`) is the weakest current rule** — connection refused is
something the user's application already told them; the tool adds confirmation,
not information. Demoting or dropping it buys room. Decide when P11 is specced.

---

# Considered and not recommended

Recorded so they don't get re-proposed.

- **Duplicate IP / ARP conflicts** — needs correctly-positioned L2 capture;
  increasingly rare in switched networks
- **Bufferbloat via RTT-under-load** — detectable, hard to word without a verdict
- **Ephemeral port exhaustion** — real but narrow; R14 gets close
- **IP fragmentation loss** — mostly folds into R13
- **Client-side think time** — "your own client is slow" is rarely actionable
  from a capture
- **Reverse DNS enrichment** — would improve readability and would break the
  no-network guarantee; host labels (P1/parking lot) are the offline answer

---

# Known review items (not proposals)

- **Design token duplication** — resolved by P3.5 (2026-08-17, commit 92ee198):
  one token file, a byte-equality test between the two copies, and a test that
  neither consumer stylesheet declares a custom property or restates a token
  colour as a literal. No longer held together by review.
- **Screenshot/visual verification gap** — computer-use tooling can't resolve a
  freshly built exe; current coverage is `-preview` HTML render plus end-to-end
  tests, which misses the Wails IPC layer and native menu. Owner verification
  (running the app directly) remains the check for those.
