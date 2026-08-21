# Detection Rules — v1 Specification

Fifteen rules. This is the scope ceiling for v1, set deliberately before
implementation. Additions go to the deferred list at the end, not into this table.

Every rule in this document is advisory. It states what was observed, why it stood
out, which frames evidence it, and what to check next. No rule asserts a root
cause.

---

## Scoring model

Each finding receives a significance score used only for **ordering**. It is not
a severity rating and is never shown as a number to the user — it decides what
appears in the top findings and in what order.

```
significance = base_weight × impact × scope × deviation
```

| Factor | Range | Derivation |
|---|---|---|
| `base_weight` | 1–10 | Fixed per rule, below |
| `impact` | 1.0–5.0 | log-scaled seconds of measurable stall or delay attributable to the condition |
| `scope` | 0.8–2.0 | 1 flow = 0.8, 1 host = 1.2, multiple hosts = 1.6, capture-wide = 2.0 |
| `deviation` | 0.5–3.0 | ratio to the population median for the same metric in this capture; 1.0 when no peer group exists |

**Proximity bonus:** ×1.5 when the condition occurs within 2 seconds of a RST,
a connection timeout, or the end of a flow that transferred no data.

**Deviation is the differentiator.** A condition present uniformly across every
flow in the capture is background, not a finding. A condition isolated to one host
while forty peers are clean is the thing worth reading first. Where no peer group
exists — a capture containing a single conversation — `deviation` is fixed at 1.0
and the report says comparative ranking was unavailable.

### Threshold calibration warning

Every absolute threshold below is a **starting point requiring calibration against
real captures**, not a validated constant. Environments differ by orders of
magnitude: 200 ms RTT is catastrophic in a datacenter and normal on satellite.
Prefer the comparative path wherever both are available. Absolute thresholds are
the fallback for when the capture contains no usable peer group.

### Evidence quality

Every finding carries `confirmed`, `inferred`, or `unavailable`, per section 10 of
the technology brief. Rules that degrade are marked below.

### Repetition capping

Maximum one finding per rule per flow. Retain the first occurrence, the worst
occurrence, and up to eight representative frame numbers. Record the total count.
Fifty thousand retransmissions on one flow is one finding with a count of 50,000,
never fifty thousand findings.

---

## The rules

---

### R01 · `zero-window-stall`

**Base weight:** 9

**Condition**
A peer advertises a window of 0 having previously advertised non-zero, and the
sender is blocked from transmitting new data until a window update arrives.
Measure the interval from the zero-window advertisement to the window update, or
to the end of the flow if no update arrives.

Report on **cumulative and maximum stall duration**, not event count. Suppress
below 100 ms cumulative.

**Why this is R01**
It is the highest-value finding in the tool and it works fully on midstream
captures, because zero multiplied by any window scale factor is still zero.

**Report wording**

> **Receiver stopped accepting data — 10.2.2.7:5432**
> Advertised a zero receive window 6 times, stalling the sender for 4.2s total
> (longest single stall 2.9s). The other 12 hosts in this capture show no zero
> window events.
> Frames 8821, 8834, 9104, 9330
> **Check next:** the receiving application on 10.2.2.7 — a zero window means the
> application is not reading from its socket buffer fast enough. Look at CPU,
> blocked threads, or a downstream dependency on that host.

**Degradation:** none. Fully available midstream.

**False positive traps**
- Deliberate application-level flow control (some protocols pace this way).
- Sub-50 ms zero windows during normal operation are common and meaningless.
  Duration is the signal, not occurrence.

---

### R02 · `syn-unanswered`

**Base weight:** 9

**Condition**
A SYN with no SYN/ACK and no RST within the flow's observation window. Count
retry SYNs — the retry pattern (typically 1s, 2s, 4s, 8s) confirms the client
kept trying rather than giving up.

**Report wording**

> **Connection attempts received no response — 10.1.1.5 → 10.4.4.9:8443**
> 4 SYN attempts over 15s, no SYN/ACK and no RST returned. The client retried
> with standard backoff. Other services on 10.4.4.9 responded normally.
> Frames 221, 224, 231, 248
> **Check next:** a silent drop, not a closed port — a closed port returns RST.
> Look at firewall or security group rules on the path, or whether the listener
> is bound to a different interface.

**Degradation:** none.

**False positive traps**
- Asymmetric routing means the SYN/ACK may exist but traverse a path this capture
  point cannot see. State this possibility in the wording when the capture shows
  other evidence of asymmetry.
- Captures that end mid-handshake. Suppress for SYNs within 2s of capture end.

---

### R03 · `syn-rejected`

**Base weight:** 4 — revised down from 7; see the addendum entry for the
evidence.

**Condition**
SYN answered by RST rather than SYN/ACK.

**Report wording**

> **Connections actively refused — 10.4.4.9:8443**
> 47 connection attempts from 3 clients answered with RST. The host is reachable
> and responding; nothing is listening on that port.
> Frames 118, 122, 139
> **Check next:** whether the service is running and bound to the expected port
> and address. Distinct from R02 — the host itself is up and answering.

**Degradation:** none.

**False positive traps**
- A middlebox may forge RST on a client's behalf. TTL inconsistency between the
  RST and the peer's other packets is a strong hint. Flag when TTL differs by
  more than 2 from the same peer's established traffic.

---

### R04 · `server-response-outlier`

**Base weight:** 8

**Condition**
Per server:port, compute application response time as (last request byte →
first response byte) − network RTT. Report p50, p95, max. Flag where p95 exceeds
the capture-wide population median by ≥5×, or exceeds 1s absolute where no peer
group exists.

**This is the "is it us or them" rule** and the primary reason the tool exists.

**Report wording**

> **One server much slower to respond than its peers — 10.2.2.7:443**
> Responded in 1.8s at p95 (max 4.1s) while the other 41 servers in this capture
> are under 40ms at p95. Measured from last request byte to first response byte,
> with network round-trip time subtracted — so this is time spent on the server,
> not on the network.
> Frames 8821, 9104, 9330
> **Check next:** application or backend dependency latency on 10.2.2.7. The
> network path to this host looks comparable to its peers.

**Degradation:** RTT subtraction is `inferred` on midstream flows, since the
handshake baseline is unavailable — fall back to minimum observed ACK RTT and
say so.

**False positive traps**
- Pipelined or multiplexed protocols break the request/response pairing. Restrict
  v1 to flows where request and response alternate cleanly; skip and report as
  `unavailable` otherwise.
- Long-polling and server-sent events look identical to a slow server. Exclude
  flows where the client sent no data before a long gap.

---

### R05 · `rto-retransmission`

**Base weight:** 7

**Condition**
Retransmission occurring after a timeout rather than triggered by duplicate ACKs.
Identify by the gap preceding it approximating an RTO interval and by absence of
≥3 preceding dup ACKs. Exponential backoff across successive attempts confirms.

Score on **time lost to the stall**, not on count. An RTO costs hundreds of
milliseconds; a fast retransmit costs one RTT.

**Report wording**

> **Timeout-driven retransmissions — 10.1.1.5 → 10.3.3.2**
> 34 segments retransmitted after timeout, costing 6.1s of transfer time. Retry
> intervals doubled each attempt, indicating the sender received no acknowledgement
> at all rather than recovering quickly. Retransmission rate on this path is 4.2%
> against a capture-wide median of 0.1%.
> Frames 4412, 4498, 4620
> **Check next:** sustained loss on the path between these hosts. This is more
> disruptive than the fast-retransmit pattern in R06 — the sender stalled waiting
> for a timer rather than recovering from duplicate ACKs.

**Degradation:** none.

**False positive traps**
- Must run after R07 (out-of-order) has had the chance to reclassify. Order matters.

---

### R06 · `fast-retransmission`

**Base weight:** 4

**Condition**
Retransmission preceded by ≥3 duplicate ACKs. Report rate against the capture
population median.

Deliberately lower-weighted than R05. Fast retransmit is TCP working correctly.
A 0.3% rate is a healthy internet path and must not outrank a real stall.

**Report wording**

> **Packet loss with fast recovery — 10.1.1.5 ↔ 10.3.3.2**
> 210 segments recovered via fast retransmit (0.9% of segments on this path,
> against a capture median of 0.1%). Recovery was quick in each case; total time
> cost approximately 340ms.
> Frames 3301, 3340, 3388
> **Check next:** low-level loss on this path. Worth noting but unlikely to be the
> cause of a user-visible problem on its own.

**Degradation:** none.

---

### R07 · `out-of-order-not-loss`

**Base weight:** 5 · **Runs before R05 and R06**

**Condition**
Segments arriving with sequence numbers below the highest seen, but where the
inter-arrival delta is under 3 ms and IP ID ordering remains sane. Reclassify as
reordering rather than retransmission, and **suppress the corresponding R05/R06
findings** for those segments.

**This rule exists to prevent other rules being wrong.** Misreading reordering as
loss sends someone to investigate the network for what is a NIC offload or
multipath setting.

**Report wording**

> **Out-of-order delivery, not packet loss — 10.1.1.5 ↔ 10.3.3.2**
> 156 segments arrived out of sequence with sub-millisecond gaps and consistent
> IP ID ordering. These were not retransmissions and no data was lost. Without
> this reclassification they would appear as a 2.1% loss rate.
> Frames 5501, 5502, 5504
> **Check next:** usually multipath routing, LACP hashing, or receive-side scaling
> on the capture host. Not a fault in itself, but it can degrade TCP throughput.

**Degradation:** IP ID heuristic is `inferred` on IPv6, which has no IP ID field —
fall back to timing alone and lower confidence.

---

### R08 · `asymmetric-loss`

**Base weight:** 8

**Condition**
Retransmission rate in one direction exceeding the reverse direction by ≥5× on
the same flow, with a minimum of 20 retransmissions to qualify.

Directionality is disproportionately diagnostic and cheap to compute once both
directions are already tracked.

**Report wording**

> **Loss in one direction only — 10.1.1.5 → 10.3.3.2**
> 4.1% of segments retransmitted client-to-server, against 0.05% server-to-client
> on the same connection. Loss is not symmetric.
> Frames 6612, 6690, 6744
> **Check next:** something specific to the forward path — asymmetric routing, a
> congested uplink, or a policer applied in one direction. Symmetric loss would
> point at the shared path instead.

**Degradation:** none, but requires both directions present in the capture.
Report `unavailable` where only one direction was captured, and say so — this is
a common consequence of one-way SPAN configuration.

---

### R09 · `reset-mid-transfer`

**Base weight:** 7

**Condition**
RST sent on a flow with data in flight or within 1 s of a data segment, as
distinct from RST after a long idle period (which is R14 territory) or RST in
place of a clean FIN at end of transfer.

**Report wording**

> **Connections reset during active transfer — 10.2.2.7 → 10.1.1.5**
> 12 connections terminated by RST while data was still in flight, averaging 340KB
> transferred before the reset. The remaining 380 connections in this capture
> closed normally with FIN.
> Frames 7701, 7823, 7960
> **Check next:** an application-side abort, a resource limit, or a stateful device
> on the path dropping the session. The TTL on these resets matches the peer's
> other traffic, so they appear to originate from the host rather than a middlebox.

**Degradation:** none.

**False positive traps**
- Some applications legitimately RST instead of FIN to avoid TIME_WAIT. If a host
  resets *every* connection this way, it is a pattern, not a fault — detect
  uniformity and downgrade to informational.

---

### R10 · `rtt-outlier`

**Base weight:** 6

**Condition**
Per host or subnet, network RTT (handshake, or minimum observed ACK RTT midstream)
exceeding the capture-wide median by ≥4×.

**Report wording**

> **Higher network latency to one host — 10.7.7.3**
> Round-trip time of 180ms against a capture median of 8ms across 43 hosts. The
> elevated latency is consistent across all 22 connections to this host rather
> than intermittent.
> Frames 1201, 1340, 1502
> **Check next:** the network path to 10.7.7.3 — routing, physical distance, or a
> congested link. Consistent rather than variable latency usually indicates path
> length rather than congestion.

**Degradation:** `inferred` midstream — minimum observed ACK RTT is an
approximation of handshake RTT and can overestimate.

---

### R11 · `dns-failure`

**Base weight:** 8

**Condition**
On cleartext port 53: queries with no response within 2 s, responses with SERVFAIL
or NXDOMAIN, or response times exceeding 500 ms.

Weighted high because DNS is a frequent cause of "the application is slow" and is
almost always overlooked by someone unfamiliar with captures.

**Report wording**

> **DNS queries failing or slow — resolver 10.0.0.53**
> 18 queries received no response within 2s, and 6 returned SERVFAIL. Successful
> queries to the same resolver averaged 640ms. Application connections to the
> affected names were delayed correspondingly.
> Frames 92, 118, 204
> **Check next:** resolver health and reachability. DNS delay of this magnitude
> will present to users as general application slowness, and often gets attributed
> to the application instead.

**Degradation:** DNS over TLS or HTTPS is invisible. State `unavailable` where
port 853 or DoH-shaped traffic is observed.

---

### R12 · `tls-handshake-failure`

**Base weight:** 6

**Condition**
TLS handshakes that fail to complete, fatal alerts, negotiation failures, and
handshake duration exceeding 1 s. Read certificate validity dates from the
ServerHello where visible and flag expiry within 30 days or already elapsed.

**Report wording**

> **TLS handshakes failing — 10.2.2.7:443**
> 23 handshakes terminated by fatal alert (handshake_failure) before completion.
> Successful handshakes to the same host took 1.4s at p95 against a capture median
> of 90ms. The presented certificate expires in 4 days.
> Frames 3401, 3455, 3502
> **Check next:** certificate validity and cipher suite compatibility between these
> clients and the server. The certificate expiry is worth resolving regardless of
> whether it caused these particular failures.

**Degradation:** TLS 1.3 encrypts most of the handshake after ServerHello.
Certificate inspection is `unavailable` for 1.3 — say so rather than silently
skipping.

---

### R13 · `pmtu-blackhole`

**Base weight:** 7

**Condition**
Two signals, either independently: ICMP fragmentation-needed messages correlated
to a flow, or repeated retransmission of segments above a certain size while
smaller segments on the same flow succeed.

The second signal catches the harder and more common case where ICMP is filtered
and the blackhole is silent.

**Report wording**

> **Large packets failing while small packets succeed — 10.1.1.5 ↔ 10.9.9.4**
> Segments above 1400 bytes were retransmitted repeatedly and never acknowledged,
> while segments below that size were delivered normally. No ICMP
> fragmentation-needed messages were seen, which is consistent with ICMP being
> filtered somewhere on the path.
> Frames 2201, 2245, 2290
> **Check next:** MTU along the path, particularly any tunnel or VPN segment. This
> pattern often presents as "the connection works but transfers hang."

**Degradation:** unreliable on captures showing TSO/LRO artifacts, since apparent
segment size is not wire segment size. Downgrade to `inferred` when R15 has
flagged offload artifacts.

---

### R14 · `connection-churn`

**Base weight:** 5

**Condition**
More than 50 connections to the same server:port within the capture, with a median
lifetime under 1 s, where the same client is reconnecting repeatedly.

**Report wording**

> **Rapid connection cycling — 10.1.1.5 → 10.2.2.7:5432**
> 412 connections opened and closed in 90s, median lifetime 210ms. Each connection
> completed a full handshake and teardown, adding roughly 12ms of setup overhead
> per request.
> Frames 5001, 5040, 5088
> **Check next:** connection pooling configuration on the client, or an idle
> timeout closing pooled connections sooner than expected. Functionally working,
> but the handshake overhead is measurable at this rate.

**Degradation:** requires handshakes, so `unavailable` for flows already
established at capture start. Report the proportion excluded.

---

### R15 · `capture-quality` — meta-rule

**Base weight:** n/a — always runs, always reported in the completeness banner
rather than in the ranked findings.

**Condition**
Detect and report: snaplen truncation, proportion of midstream flows, segments
exceeding MTU (TSO/LRO on-host capture artifacts), one-way-only flows, timestamp
resolution and multi-interface merges, and capture start/end relative to the
observed traffic.

**Purpose**
This rule exists so the tool cannot produce a false all-clear. It also gates
other rules: it downgrades R13 on offload artifacts, marks R08 unavailable on
one-way captures, and supplies the midstream proportion driving R04, R10, and R14
degradation.

**Report wording**

> **Capture completeness**
> 1.2M packets, 42 flows. 18 of 42 flows (43%) began before the capture started —
> receive window sizing was not assessed for those. Zero-window detection is
> unaffected and was performed on all flows.
> Snaplen 262144 (untruncated). Segments up to 24KB observed, indicating capture
> was taken on an endpoint with offload enabled; wire segment sizes differ.
> 3 flows captured in one direction only — loss direction analysis unavailable
> for those.
> **Suggestion:** if the fault is reproducible, a capture taken at a network tap
> with `-s 0` and started before the connections open would allow the full rule
> set to run.

---

## Rule interaction order

Order matters in three places. Everything else is independent.

1. **R15** runs first and gates degradation flags for R04, R08, R10, R13, R14.
2. **R07** runs before R05 and R06, and suppresses their findings for reclassified
   segments.
3. **R08** consumes R05 and R06 output, so it runs after both.

---

## Deferred — not v1

Explicitly out of scope for the initial release. Each is a reasonable rule; none
is worth delaying v1 for.

- Cleartext HTTP status code and latency analysis
- ARP anomalies, duplicate address detection, gratuitous ARP conflicts
- IPv6-specific conditions (RA anomalies, extension header issues)
- Multicast and IGMP
- VoIP and RTP jitter, MOS estimation
- TCP window-full and bandwidth-delay product analysis
- SACK-derived loss reconstruction
- Nagle and delayed-ACK interaction
- Per-protocol rule packs (SMB, database wire protocols, Kafka)
- QUIC connection-level behaviour, to the limited extent it is observable

---

## Implementation handoff notes

For whoever implements this:

- Each rule is an independent detector consuming per-flow state and emitting zero
  or one finding per flow, subject to the repetition cap.
- The wording above is the specification, not a suggestion. The observation → why
  it stood out → frames → check next structure is what keeps the tool advisory
  rather than diagnostic, and it should not be paraphrased into verdict language
  during implementation.
- Thresholds belong in a single table, not scattered through detector code. They
  will be recalibrated repeatedly against real captures.
- Every rule needs a test capture, real or synthesised, that triggers it and one
  that should not trigger it. The false-positive traps above are the second set.
- `--list-checks` enumerates all fifteen with their current thresholds.


---

## Implementation addendum

Clarifications and thresholds established during implementation. The rules above
remain the spec; this section records how ambiguities were resolved so they are
not rediscovered. (The repo copy of this file may carry earlier addendum entries
from the R01/R04 session — merge, don't replace, if so.)

### R15: kernel capture drops (added in the P2 session)

R15's condition list now includes capture-host packet drops:

- **pcapng:** read from the Interface Statistics Block via pcapgo's
  `NgReaderOptions.StatisticsCallback`, with `NgNoValue64` distinguishing
  "option absent" from "zero drops". Multiple interfaces are keyed separately.
- **Classic pcap:** has no drop field. Reported as `unavailable` with wording
  that states the format cannot say either way and suggests pcapng re-capture —
  never treated as zero drops.
- **pcapng without an ISB:** a third distinct state, also not zero.
- **Threshold:** `R15KernelDropRatio = 0.001` (0.1% of packets read + dropped),
  [chosen]. Rationale: it is the order of magnitude the loss rules operate at —
  R06's own example contrasts 0.9% against a 0.1% capture median — so below it
  capture loss cannot plausibly account for a rate a rule would flag.
- **Gating:** when drops exceed the threshold, R05/R06/R08 findings are
  downgraded to `inferred` with a basis sentence scoped to the capture host
  ("some apparent loss may be capture loss rather than loss on the network").
  The clean-drops note is deliberately scoped to the host itself and must not
  claim anything about taps or SPAN ports upstream — a test forbids the
  stronger phrasing.

### Clean-capture and empty-capture semantics (added in the P3 session)

- A capture that parses but contains no findings renders an explicit coverage
  statement, never an empty list. Wording is calibrated, not celebratory; a
  test bans "healthy", "all clear", "your network", "nothing is wrong".
- A capture with packets but no TCP conversations is a third state, reported as
  the absence of anything to assess — not as a clean result.
- Zero packets or an unparseable file is an **error**, never a result. An
  absence of data must never render as an absence of problems.
- There is no display floor: rules suppress their own trivia at detection time
  (e.g. R01's 100 ms cumulative), and every emitted finding is shown. If a
  floor is ever introduced, it is a severity-calibration decision (BACKLOG P4),
  not a rendering convenience.

### Severity mapping and coverage strength (added in the P4/P3.5 session)

- **Severity is presentation-only**, derived from the existing significance
  score at render time: `Significant ≥ 40`, `Worth noting ≥ 15`, informational
  below, [chosen]. Anchored on this document's own language rather than picked
  to make fixtures look varied: R06's healthy fast-retransmit contrast scores
  18.1 and R06's wording calls that "worth noting", so the significant floor
  sits above it; a mid-weight rule with about a second lost and clear isolation
  scores just over 40. The mapping changes nothing about ranking, finding
  content, or JSON beyond the added `severity`/`severity_label` fields, and the
  word always renders beside the colour.
- **Green for a clean result requires strong coverage**: no coverage gaps on
  the capture *and* the complete rule set built, [chosen] — so at the current
  build state every clean result renders neutral, which is the intended
  outcome. Colour must not say what the clean-wording ban forbids the words
  from saying. Error states (empty, unparseable, no-TCP) never carry severity
  colours at all.
- Per the standing constraint recorded above: **no display floor exists and
  the severity work did not introduce one** — severity labels map onto existing
  scores without changing what is shown.

### R03 base weight: 7 → 4 (revised in the Batch 2 Part 1 session)

Proposed with evidence and applied at review, the same way any threshold
change here is meant to move. The suspicion was that R03 is over-weighted
because a refusal mostly corroborates what the connecting application already
reported in its own error message. Measuring it changed the reasoning:

R03's scoring inputs are `impact = 1.0` (a refusal costs no measurable time —
that is exactly what separates it from R02's silence), `deviation = 1.0` (no
peer group; there is no population to compare a refusal against), and
`scope = 0.8` for the ordinary case of one refusing endpoint. Significance is
therefore just `weight × 0.8`:

| Base weight | Significance | Severity |
|---|---|---|
| 7 (previous) | 5.60 | informational |
| 6 | 4.80 | informational |
| 5 | 4.00 | informational |
| **4 (applied)** | **3.20** | **informational** |
| 3 | 2.40 | informational |

**The severity a reader sees is unchanged.** It is informational at every
weight in that range, and even at multi-host scope the old weight of 7 reached
only 11.20 — still under the worth-noting floor of 15. The scoring model was
already suppressing R03 in practice; the weight was never what held it down.

So the change is **ordering-only**, and that is the ground it stands on. Base
weight feeds significance, significance orders findings, and ordering answers
"what should the reader look at first". A finding that restates the error
message the application already showed earns less of the reader's attention
than one telling them something new — which is what the guide content says of
this pair: R03 is corroboration, R02 is the more useful of the two.

The obvious objection, stated rather than glossed: 4 puts R03 level with R06,
and R06 frequently reports TCP working correctly where R03 reports a genuine
failure to connect. That objection is about severity-of-condition; base weight
is about marginal information. On the axis that actually governs ordering,
parity is right — and the severity table above shows nothing about how bad the
condition looks to a reader changes either way.

**Known limitation, deliberately not fixed here:** R03's significance is
invariant to attempt count. Forty-seven refusals score exactly the same as
two, because the model's impact factor measures seconds lost and a refusal
loses none. That is a scoring-model question rather than a weight question —
recorded in BACKLOG rather than resolved by picking a different number.

---

### Batch 3 — R10's impact denominator

**Added 2026-08-20, Batch 3 Checkpoint 0.**

R10 as specified had no seconds denominator, which under
`significance = base × impact × scope × deviation` pins a rule to whatever
`base × scope × deviation` gives regardless of how much traffic the condition
touched. Measured on this rule's own specification example — 180ms against an
8ms median, one host, 22 connections — that is `6 × 1.0 × 1.2 × 3.0 = 21.6`,
**worth noting**, and it is the same 21.6 whether the host was contacted twice
or twenty-two thousand times.

**The denominator now used:** the excess round-trip time over the capture-wide
median, accumulated across the connections that paid it.

    time_lost = (host_median_rtt − capture_median_rtt) × flows_to_that_host

Elevated latency is not lost time the way a stall is — nothing is stopped. But
it is paid again on every round trip, so the honest magnitude is the excess
multiplied by how often the path was actually traversed. This is the same
construction R04 already uses for server response time, where impact is the
excess over what the population manages across every exchange.

**Before and after, on the specification's own example:**

| | impact factor | significance | severity |
|---|---|---|---|
| no denominator | 1.00 | 21.6 | worth noting |
| accumulated excess (22 connections) | 2.36 | 50.9 | **significant** |

And the volume responsiveness that is the point of the change:

| connections | time lost | significance | severity |
|---|---|---|---|
| 2 | 0.34s | 27.1 | worth noting |
| 6 | 1.04s | 35.0 | worth noting |
| 22 | 3.78s | 50.9 | significant |
| 220 | 37.8s | 90.3 | significant |

A host that is far away and rarely contacted is a fact about the network. The
same host carrying the bulk of a capture's conversations is a finding. The
model could not previously tell those apart.

### Batch 3 — R13's offload gate, resolved

**Added 2026-08-20, Batch 3 Checkpoint 0.**

R13's degradation as specified reads "downgrade to `inferred` when R15 has
flagged offload artifacts". R15 was formalised for midstream, one-way and
capture-host drops only; TSO/LRO had no tracking of any kind, so the gate had
nothing to gate on. R13's second signal is entirely "large segments
retransmitted while small ones succeed", which is precisely what offload
corrupts, so shipping without the gate was not acceptable.

**Resolution: the detection was built, comparing against the connection's own
negotiated MSS rather than against an assumed link MTU.**

A flow records the smaller of the two advertised maximum segment sizes and the
largest payload observed. A segment larger than that negotiated maximum cannot
have crossed the wire in that shape — the peer said it would not accept more —
so the capture was taken before the sending interface split it.

The comparative form was chosen over a constant on measurement, not
preference. Against a 1460-byte constant, three committed fixtures trip the
detection and six golden files change. Against each connection's own
negotiation, none do, because those fixtures negotiate no MSS at all. **Where
no maximum was negotiated the check declines to speak**, rather than
substituting a guess about the link — which also means it needs no chosen
threshold.

The consequence is a blind spot worth stating: a midstream flow carries no
handshake and therefore no negotiation, so offload on such a flow is not
detected. Midstream is already an R15 condition reported in its own right, so
the reader is not left without a signal.

### Batch 3 — per-host grouping for R10, a deliberate narrowing

**Added 2026-08-20.**

R10's condition offers "per host or subnet". **Only per-host is built.**

This is a narrowing rather than an omission. The rule's own report wording is
per host ("Higher network latency to one host — 10.7.7.3"), and its check-next
line sends the reader to the path to a single address. Subnet grouping would
additionally require a definition of "subnet" that a capture cannot supply: a
packet carries addresses, never the prefix length its network was configured
with, so any grouping would rest on an assumed mask — /24 by habit — which is
an assumption about the reader's network rather than an observation of it.

That is the same reasoning the offload gate above rests on, applied to a
different quantity: compare against what the capture observed, and decline to
speak where it observed nothing.

### Batch 3 — thresholds introduced

**Added 2026-08-20.** Provenance marked as in `internal/rules/thresholds.go`.

| threshold | value | provenance |
|---|---|---|
| `R10PeerRatio` | 4.0 | **[RULES.md]** — "exceeding the capture-wide median by ≥4×" |
| `R10MinFlows` | 3 | [chosen] — the fewest samples that can show whether latency is steady or variable, which is a distinction the finding reports. Two samples have a spread but no shape. |
| `R10MinPeerHosts` | 2 | [chosen] — mirrors `R04MinPeerGroup`; the smallest number that permits a comparison at all. |
| `R10SteadyDispersion` | 0.5 | [chosen] — the spread between a host's slowest and fastest round trip, over its median, below which latency is called steady. The specification says "consistent rather than intermittent" without a figure. Set so the stronger claim (distance rather than congestion) needs the tighter evidence. |
| `R13MinLargeRetransmits` | 3 | [chosen] — the specification says "repeated" without a figure. Three separates a pattern from a coincidence. |
| `R13MinSmallDelivered` | 3 | [chosen] — the small side is the control in "large fails while small succeeds", so it needs enough successes to be a control rather than an anecdote. |

### Batch 3 — R13's ICMP sentence, a spec-vs-build divergence

**Added 2026-08-20. Resolves when the ICMP surface lands; not a permanent
wording change.**

R13's specified wording includes:

> No ICMP fragmentation-needed messages were seen, which is consistent with
> ICMP being filtered somewhere on the path.

This build does not decode ICMP at all — the decoder stops at any protocol
that is not TCP — so that sentence would imply a search that never ran. An
absence reported by something that never looked is not evidence of absence,
and the reader would take it as one.

**The build says instead:**

> This build does not examine ICMP, so whether the network reported the size
> limit back to the sender is unknown.

The specification's two variants — "saw ICMP" versus "silent pattern only" —
therefore collapse to one until ICMP decoding exists. When it does, both
variants become expressible and the specified wording is the correct one:
having looked and found nothing genuinely is consistent with ICMP being
filtered, which is exactly what makes the sentence worth saying.

The same reasoning governs the observation's size phrasing. The specification
writes "Segments above 1400 bytes were retransmitted ... while segments below
that size were delivered normally", which names one boundary. The build names
both observed sizes instead — the size that failed and the size that
succeeded — because where the real limit sits between them is precisely what
the capture cannot say.

### Batch 3 — R13's peer comparison, and a second use of the deviation field

**Added 2026-08-20, after the Part 1b review.**

R13 as first built could not reach `significant` at any stall duration. With
`ScopeFlow` (0.8) and no peer group (deviation 1.0), `7 × Impact × 0.8 × 1.0`
tops out at **28.0** against a floor of 40 — so a ten-minute hang and a
two-minute one scored alike, and neither could reach the band the condition
deserves. The impact denominator was present and correct; the other two
factors pinned the ceiling below the floor. See the BACKLOG entry on
invariant significance, where this is the third occurrence and the one that
corrected the checklist.

**The comparison added:** how many times larger the segment size other flows
deliver is than the size this flow manages.

    ratio = median(largest delivered size, across flows that delivered anything)
            ÷ largest delivered size on this flow

| stall | before | after (peers 1400 vs flow 300) |
|---|---|---|
| 3s | 12.3 informational | 37.0 worth noting |
| 10s | 17.3 worth noting | **51.8 significant** |
| 30s | 22.3 worth noting | **66.9 significant** |
| ceiling | **28.0** | **84.0** |

It stays proportionate rather than simply moving everything up. A milder
deficit — peers at 1400, this flow managing 900 — needs 120s to reach
significant. Several flows to the same host raise the scope band and reach it
from 3s. **With no peer group the ratio stays 1.0 and the finding scores
exactly what it did before any comparison existed**, which is the property
that makes the change safe: it can add signal where a comparison exists and
can never manufacture one where it does not.

**The population is filtered to flows that delivered something.** A flow that
delivered nothing has not demonstrated what the path carries, and letting it
contribute would drag the median down — a capture full of broken connections
could otherwise make a broken connection look ordinary. The finding states the
filter in its own wording ("Other connections in this capture that delivered
data carried segments of N bytes") rather than saying "other flows" and
leaving the reader to assume it meant all of them.

**A departure worth naming: R13 uses `Value` and `PopulationMedian`
differently from R04.** `Deviation` assumes higher is worse. R13's anomaly is
a *shortfall* — this path carries less than its peers — so the raw metric
moves the wrong way, and comparing it directly would score a badly broken flow
as unremarkable. R13 therefore passes the ratio itself as `Value` against a
`PopulationMedian` of 1.0, which is what a flow keeping up with its peers
scores.

If a third rule ever needs this shape, that is the signal to give the scoring
model an explicit direction rather than encoding the inversion per rule. Two
is not yet that signal.

### Batch 3 — R11 and R12 wording divergences

**Added 2026-08-20, Part 2. Four departures from the specified wording, each
because the specification claims something this build cannot.**

**1. "at the median" rather than "averaged" (R11).** The spec says successful
queries "averaged 640ms". The build reports the median. A mean is pulled by
one outlier, and these samples are small — a resolver with six successful
lookups and one pathological one would be described by its worst case. The
spec's phrasing was written before the sample sizes were known.

**2. "at the median" rather than "at p95" (R12).** Same reasoning. With six
successful handshakes, p95 by nearest rank *is* the maximum, so the figure
would be labelled a percentile while being a single observation.

**3. R11 omits "Application connections to the affected names were delayed
correspondingly."** The rule does not correlate lookups to the connections
that follow them — it reads DNS and nothing else. The sentence is almost
certainly true and the tool has no evidence for it, which is exactly the
category the advisory posture exists to keep out. Stating a consequence it did
not observe would be the tool taking credit for an inference it never made.

**4. R12 says "expires 4 days after the capture ended" rather than "expires in
4 days".** "In 4 days" is relative to now; a capture is read weeks after it was
taken, and a certificate that had four days left when the traffic was recorded
may have expired long before anyone reads the report. Naming the reference
point is the difference between a fact and a stale one.

### Batch 3 — DoH, and reporting a detection that cannot be complete

R11's unavailable note says DNS over HTTPS "cannot be distinguished from
ordinary web traffic here at all, so this count is a floor rather than a
total."

DNS over TLS is recognisable by port and is counted. DoH is HTTPS to a web
port and is not distinguishable from any other HTTPS. Reporting only the DoT
count without that sentence would imply the tool had accounted for encrypted
resolution, when it has accounted for the half it can see.

The same discipline as R13's ICMP substitution: where a detection is
structurally incomplete, the report says so at the point of reporting rather
than leaving the reader to discover the gap.

### Batch 3 — data minimisation in the new decode surface

The decoder's payload guarantee weakened in Part 2, from *never reads payload*
to *extracts only named scalars* (see the package doc and
`internal/capture/allowlist_test.go`). One consequence runs the other way and
is worth recording.

**R11 does not parse the DNS question section at all.** The rule reports how
many lookups failed, went unanswered, or ran slow — never which names. So the
name is never read, never stored, and never emitted, and that is a property of
the parser rather than a filtering step applied afterwards.

The same holds for R12: no certificate subject, no issuer, no server name, no
key material. Only an expiry date, as a Unix second.

So the surface that weakened the guarantee's *basis* narrowed what the tool
looks at. A capture's most identifying content — the names someone looked up
and the sites they connected to — is precisely what these rules decline to
read, and the allowlist is what keeps that true as the rules change.
