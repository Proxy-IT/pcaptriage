# Engineering notes

Three failure patterns this codebase produced more than once, written down so
the next occurrence is recognised rather than rediscovered. Each cost real time
to find, and each was found by accident rather than by a test firing.

They are kept together because they share a shape: **a check that looks like it
is working, and is not.** A test that passes without asserting anything, a
fixture that triggers a rule while misrepresenting the condition, a scoring
factor that is correct in isolation and wrong in combination. None of them fail
loudly. All of them require someone to notice.

Where a guard exists it is named. Where none does — because the pattern is not
mechanically detectable — the entry says so and gives the question to ask
instead.

---

## Tests that pass while asserting nothing

**Found four times in one session, September 2026. Now partly guarded by a
lint; the rest is a habit that has to be kept.**

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


---

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


## Significance is invariant to occurrence count

**First noticed during R03's weight review, then twice more. The third
occurrence corrected the checklist below, which had been asking the wrong
question.**

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

Twice in one batch is enough to stop treating this as incidental. **Checklist item when adding a rule:** before writing its
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

**Re-examined once all fifteen rules existed.** R03's ceiling is correct: it
has no seconds denominator by design, its base weight was set knowing that, and
it lands where its own reasoning says. R09 turned out fine for a different
reason — it gained a real denominator earlier, charging the transfer time an
abort throws away, so it reaches the top band on its own merits. The concern
logged against it had not survived the change that fixed it, which is its own
small lesson: a concern recorded against an earlier state of the code does not
automatically still apply.

**The distinction that review established, and the most useful thing here:** a
low ceiling is a *defect* when it suppresses harm that has already happened,
and *correct* when the condition genuinely has no measured cost yet. Both
present identically as "this rule cannot reach the top band". Only one of them
is wrong.

