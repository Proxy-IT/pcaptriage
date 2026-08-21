# Changelog

User-visible changes only. Internal refactors, test work and documentation are
in the git history; this file is what someone upgrading would notice.

The release version itself lives in `wails.json`'s `info.productVersion` — see
README's release section for what to bump when cutting a tag.

## Unreleased

### Fixed

- **Captures that declare no snap length now open.** A classic pcap stores the
  snap length as a plain uint32, so "no truncation limit" has to be written as
  zero — which is what several capture appliances emit. It was being read as a
  literal zero-byte ceiling, so every packet in the file looked oversized and
  the whole capture was refused with *"capture length exceeds snap length"*.
  These files open and analyse normally now. The report says the snap length is
  not declared rather than repeating a substituted figure, matching how a
  pcapng that omits the field has always been handled.

## v0.2.0-alpha — 2026-08-20

Everything below is new since `v0.1.0-alpha`.

### The v1 rule set is complete

**All fifteen checks are now built.** The four that landed in this batch:

- **R10 · rtt-outlier** — one host reached over a much longer path than every
  other host in the capture. Reports whether the latency was steady or
  variable, since that separates distance from congestion.
- **R11 · dns-failure** — name lookups that went unanswered, came back as
  errors, or ran slow. A lookup happens before the connection it enables, so a
  slow one delays everything behind it and is very often blamed on the
  application instead.
- **R12 · tls-handshake-failure** — encrypted connections that failed to
  negotiate, took an unusually long time, or presented a certificate close to
  expiry.
- **R13 · pmtu-blackhole** — large packets repeatedly failing while small ones
  on the same connection succeed. The signature of a size limit on the path
  that nothing is reporting back to the sender.

The report no longer says "Partial build". It now names the fifteen and states
plainly that anything outside them was not examined — a complete rule set is
not complete coverage, and the sentence says so.

R11 and R12 are the first checks that read above TCP. Two consequences worth
knowing:

- **Encrypted traffic is reported as unreadable rather than as clean.** DNS
  over TLS and TLS 1.3 both hide what these checks would otherwise read, and
  both now produce an explicit "not assessed" note. An absence of certificate
  findings is not a statement that the certificates are valid.
- **Neither check reads names.** R11 reports how many lookups failed, never
  which ones; R12 reads a certificate expiry date and no subject, issuer or
  server name.

### Also in this release

- **Captures with nothing in them are no longer presented as well covered.**
  Completing the rule set made the positive green treatment reachable for the
  first time, and a capture containing no conversations would have qualified
  for it.
- **A capture of only name lookups is described correctly.** It used to be told
  that every check looks at TCP and none had anything to examine, which stopped
  being true when R11 arrived.

### Fixed

- **Bold text in guide pages now renders bold.** The guide's markdown parser
  handled `*emphasis*` but not `**bold**`, so 42 spans across the three guide
  content documents rendered as plain text with their markers stripped. Those
  spans are the answer-first lead-ins the guide's structure depends on —
  "**What it is.**", "**What it usually means.**" — so every affected page read
  as an undifferentiated wall of prose. Shipped in `v0.1.0-alpha`; fixed in the
  parser rather than by rewriting the documents, since the documents use
  standard Markdown and the next one written from habit would reintroduce it.

### Changed

- **The guide index leads with Concepts, then Checks.** Concepts explain the
  vocabulary every check entry uses, so a reader meeting "inferred" for the
  first time halfway down the checks list had already scrolled past the page
  defining it. Both sections now carry their own heading; previously the checks
  list was unlabelled, being the page's only section.

### Added

- **A Concepts section in the guide**, with two pages: *How sure the tool is —
  confirmed and inferred*, and *What the tool ranks first — severity*. They
  explain the two badges every finding carries.
- **Both badges on a finding card are now links** to the concept page that
  explains the question that badge answers. Returning lands back on the exact
  finding, at the scroll position it was left at.
- **Inferred findings state why, labelled.** The reason for the downgrade now
  renders directly under the badge as "Marked inferred because: …", instead of
  as an unlabelled paragraph after the check-next line where it read as a
  general caveat. Confirmed findings show nothing there — the absence is the
  signal. The exported HTML carries the same treatment, plus a one-line
  explanation of the two badges, since an export reader has no badge to click.
