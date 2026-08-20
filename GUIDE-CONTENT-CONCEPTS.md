# Guide content — Concepts

Same spec status as prior GUIDE-CONTENT files: implement verbatim, propose
changes rather than edit. The two-register rule from the original document
governs this prose as well.

**Structural note.** These are *concept* pages, not rule pages. They are not
registry-derived, they have no rule ID, and they do not appear in the "what
this build looks for" list on the home screen or in the built/planned counts.
They belong in a separate "Concepts" section of the guide index, listed below
the checks. See the session brief for the mechanism.

---

## Guide page: How sure the tool is — confirmed and inferred

### One-line summary
Every finding carries a badge saying how solid the evidence behind it is.
Confirmed means the capture directly showed it. Inferred means the tool had
to work around something the capture didn't contain.

### These answer a different question than severity
Findings carry two badges, and they are not degrees of the same thing.

**Severity** — significant, worth noting, informational — answers *how much
this matters*. It is about the size of the problem.

**Evidence quality** — confirmed or inferred — answers *how sure the tool
is*. It is about the quality of the recording.

A finding can be significant and inferred at the same time: a serious
problem, measured through an approximation. That combination is not a
contradiction, and it is common in captures that started while connections
were already open. It means: this looks important, and you should confirm
the numbers before acting on them as precise.

### What confirmed means
The capture contained everything the check needed. The measurement comes
from data that is directly in the file, not reconstructed around a gap.

Confirmed is not a promise that the tool's reading is the only possible
explanation — every check has limits, described on its own guide page. It
means the evidence this particular check relies on was all present.

### What inferred means
Something the check would normally use was missing from the capture, so the
tool substituted the best available approximation and continued, rather than
staying silent.

The most common cause by far is a capture that started after a connection
was already open. Connections announce important details when they first
establish — how the two sides will measure available space, and a clean
baseline for how long the network takes to carry a packet. A capture that
missed the opening never saw those, so any check that depends on them has to
approximate or skip.

Other causes include address formats that don't carry a field the check
normally reads, and captures where the recording machine's own limitations
affect what a measurement can mean.

**Every inferred finding says what was missing and what was substituted.**
That explanation is on the finding itself, so you never have to guess which
part of it is approximate.

### What to do differently with each
- **Confirmed:** read the numbers as measured. They came from the file.
- **Inferred:** read the direction as reliable and the exact figure as
  approximate. If a decision depends on the precise number rather than on
  the pattern, the finding will usually name the way the approximation can
  be wrong — whether it tends to overstate or understate — so you know which
  way to lean.

The tool marks findings inferred rather than hiding them because a
qualified answer is more useful than none. The alternative — reporting only
what a perfect capture supports — would stay silent on most real captures,
which almost always begin partway through something.

### Getting confirmed findings instead
If a finding matters and it's marked inferred, and the problem can be
reproduced, a fresh capture usually resolves it: start recording before
reproducing the fault, so the connections open inside the capture rather
than before it. The capture-quality notes at the top of the report say
whether that applies to this file.

---

## Guide page: What the tool ranks first — severity

### One-line summary
Findings are ordered by how much they appear to matter, not by when they
happened. The badge on each one names the band it fell into.

### The three bands
- **Significant** — measurable time lost, or a condition that could
  plausibly explain something a person noticed. Start here.
- **Worth noting** — real, and not nothing, but unlikely to be the headline
  on its own. Often useful as supporting context for a significant finding.
- **Informational** — background, patterns, and conditions that are not
  faults. Present because leaving them out would be a different kind of
  dishonesty, not because they need action.

### How the ordering is decided
Four things feed it: how much time was measurably lost, how widely the
condition spread (one connection, one host, or everything), how far it
stands out from the rest of the same capture, and whether it happened right
before something failed.

The third of those matters most and is worth understanding. The tool
compares a capture against **itself** rather than against fixed thresholds.
One server slow while forty are fast is interesting. Forty servers all
equally slow is a different situation, and usually a less interesting one
for a tool like this, because there is no outlier to point at. This is also
why the same measurement can rank differently in two different captures —
what counts as unusual depends on what else was in the file.

### What severity is not
- **Not a judgment about your network.** The bands describe how much a
  finding stands out in this capture, not whether performance is acceptable.
  The tool has no idea what you expect.
- **Not a diagnosis.** A significant finding is a place to look first, not a
  cause. Every finding names what to check next for that reason.
- **Not the same as confidence.** How much something matters and how sure
  the tool is are separate, and each has its own badge.

### Reading a report by severity
Start at the top and read down until the findings stop being relevant to
what you came for. The ordering exists so a capture with hundreds of
observations still has a first page worth reading. If nothing significant
appears, that is stated plainly rather than left as an empty space — though
it is a statement about what was checked, never a clean bill of health.
