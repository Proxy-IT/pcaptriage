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
