# Changelog

User-visible changes only. Internal refactors, test work and documentation are
in the git history; this file is what someone upgrading would notice.

The release version itself lives in `wails.json`'s `info.productVersion` — see
README's release section for what to bump when cutting a tag.

## Unreleased

Changes on `main` since `v0.1.0-alpha`, for whenever the next tag is cut.

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
