package gui

import (
	"regexp"
	"strings"
	"testing"
)

// TestTypedAndClickedFiltersShareOneMechanism is Part 3's central requirement.
//
// Typed input and clicked input produce identical state because they are the
// same state: the parser turns text into terms and hands each to
// addFilterTerm, which is the function an endpoint click calls. Two paths that
// each maintained their own notion of a term would eventually disagree about
// what one means — whether :5432 from a click is the same thing as :5432
// typed — and the chip bar would be showing one of two answers.
func TestTypedAndClickedFiltersShareOneMechanism(t *testing.T) {
	js := readFrontend(t, "app.js")

	typed := extractFunction(t, js, "applyTypedFilter")
	if !strings.Contains(typed, "addFilterTerm") {
		t.Fatal("the typed path does not go through addFilterTerm, so typed and clicked filters " +
			"are two mechanisms rather than two entrances to one")
	}
	// And it keeps no state of its own.
	for _, own := range []string{"typedTerms", "textFilter", "filterText ="} {
		if strings.Contains(typed, own) {
			t.Errorf("applyTypedFilter maintains %q; there is one filterTerms list and both "+
				"entrances write to it", own)
		}
	}
	// The click path goes through the same door.
	click := extractFunction(t, js, "endpointControl")
	if !strings.Contains(click, "addFilterTerm") {
		t.Error("the click path no longer goes through addFilterTerm")
	}
	// And the repaint is driven from addFilterTerm, so neither entrance can
	// change the terms without the view following.
	add := extractFunction(t, js, "addFilterTerm")
	if !strings.Contains(add, "repaintFindings()") {
		t.Error("addFilterTerm does not repaint, so one entrance could leave the view stale")
	}
}

// TestTypedFilterAcceptsTheDocumentedForms covers 3a's accepted vocabulary.
//
// Each form is one a reader can read straight off a finding card, which is the
// point: the field is for saying what a card already showed them, not for
// composing a query.
func TestTypedFilterAcceptsTheDocumentedForms(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "parseFilterInput")

	// Whitespace-separated tokens — a conversation is two hosts, not an
	// operator between them.
	if !regexp.MustCompile(`split\(/\\s\+/\)`).MatchString(fn) {
		t.Error("input is not split on whitespace, so a conversation cannot be typed as two hosts")
	}
	// The bare :port form, which no click can produce.
	if !regexp.MustCompile(`tok\.charAt\(0\) === ":"`).MatchString(fn) {
		t.Error("a bare :port is not recognised; that form exists only for typed input, since a " +
			"card always names a host alongside its port")
	}
	// Host and host:port go through the same endpoint parser the subject uses,
	// so a typed address is read exactly as a clicked one is.
	if !strings.Contains(fn, "parseEndpoint(tok)") {
		t.Error("typed hosts are not parsed by the same endpoint parser the subjects use")
	}

	// No grammar. BRIEF section 8 rejects BPF and display-filter syntax
	// because requiring Wireshark's language to operate the tool that exists
	// for people who do not know Wireshark defeats the premise.
	//
	// Checked as vocabulary the parser compares against, not as characters in
	// the source: "&&" and "!==" appear in any JavaScript and say nothing
	// about the language this field accepts.
	for _, word := range []string{
		`"and"`, `"or"`, `"not"`, `"ip.addr"`, `"tcp.port"`, `"host"`, `"port"`, `"src"`, `"dst"`,
	} {
		if strings.Contains(fn, word) {
			t.Errorf("the parser compares against the keyword %s; there are no operators and no "+
				"display-filter grammar in this field", word)
		}
	}
	// Nor any state carried between tokens, which is what an operator would
	// need: each token is converted on its own.
	if regexp.MustCompile(`switch\s*\(\s*tok`).MatchString(fn) {
		t.Error("the parser branches on token text, which is the shape a keyword grammar takes")
	}
}

// TestUnreadableInputIsExplainedNotSwallowed is 3a's error rule.
//
// A token the parser cannot read must produce a hint naming it. The failure
// this prevents is worse than an error message: a silently-dropped token means
// the reader believes they filtered on something they did not, and the screen
// they are reading is scoped differently from the one in their head.
func TestUnreadableInputIsExplainedNotSwallowed(t *testing.T) {
	js := readFrontend(t, "app.js")
	html := readFrontend(t, "index.html")

	if !strings.Contains(html, `id="filter-input-hint"`) {
		t.Fatal("there is no element for the unreadable-input hint")
	}

	parse := extractFunction(t, js, "parseFilterInput")
	if !strings.Contains(parse, "rejected") {
		t.Fatal("the parser does not report what it could not read")
	}

	apply := extractFunction(t, js, "applyTypedFilter")
	if !regexp.MustCompile(`rejected\.length > 0`).MatchString(apply) {
		t.Error("nothing acts on the rejected tokens, so unreadable input would be a silent no-op")
	}
	// The hint names the tokens and shows the forms that work.
	if !strings.Contains(apply, "parsed.rejected.join(") {
		t.Error("the hint does not name the tokens it could not read")
	}
	for _, example := range []string{"10.41.2.16", ":5432"} {
		if !strings.Contains(apply, example) {
			t.Errorf("the hint does not show %q as an example of what works", example)
		}
	}
	// And it is cleared once the input is readable, or it becomes a permanent
	// complaint about a mistake already corrected.
	if !strings.Contains(apply, "hint.hidden = true") {
		t.Error("the hint is never cleared")
	}
}

// TestHostShapeCheckDoesNotValidateAgainstTheCapture guards a subtle way the
// filtered-empty state could be stolen.
//
// A host that is absent from the capture is a legitimate filter — it is
// precisely the case the filtered-empty screen was designed for, and the one
// the brief's own example uses. If the input rejected addresses it could not
// find, that screen would be unreachable again and the reader would get a
// "no such host" hint instead of being told how many findings the capture
// holds.
func TestHostShapeCheckDoesNotValidateAgainstTheCapture(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "looksLikeHost")

	for _, forbidden := range []string{"currentResult", "findings", "report", "findingEndpoints"} {
		if strings.Contains(fn, forbidden) {
			t.Errorf("looksLikeHost consults %q; an address absent from the capture is a valid "+
				"filter and must reach the filtered-empty state rather than be refused", forbidden)
		}
	}
	apply := extractFunction(t, js, "applyTypedFilter")
	if strings.Contains(apply, "currentResult") {
		t.Error("applyTypedFilter checks typed terms against the loaded capture; filtering to a " +
			"host that is not present is the filtered-empty state, not an input error")
	}
}

// TestFilterAffordanceIsAlwaysPresent is 3a's "a control that only sometimes
// exists is a control nobody learns".
//
// The chip bar is conditional because it reports state. This is not: it is the
// way in, and a way in that appears only once you have already found another
// way in is not a way in.
func TestFilterAffordanceIsAlwaysPresent(t *testing.T) {
	html := readFrontend(t, "index.html")

	btn := regexp.MustCompile(`<button[^>]*id="btn-filter"[^>]*>`).FindString(html)
	if btn == "" {
		t.Fatal("there is no filter affordance beside the findings header")
	}
	if strings.Contains(btn, "hidden") {
		t.Error("the filter affordance is hidden by default; it must be permanently present")
	}
	if !strings.Contains(btn, "aria-expanded") || !strings.Contains(btn, "aria-controls") {
		t.Error("the filter affordance does not describe its disclosure relationship, so its " +
			"state is invisible to assistive technology")
	}

	js := readFrontend(t, "app.js")
	if !regexp.MustCompile(`\$\("btn-filter"\)\.addEventListener`).MatchString(js) {
		t.Error("the filter affordance is not wired")
	}
	// Enter applies. A field that requires a separate button click is one
	// people type into and then wait at.
	if !regexp.MustCompile(`e\.key === "Enter"`).MatchString(js) {
		t.Error("Enter does not apply the typed filter")
	}
}

// TestPortOnlyTermsMatchAnyHost covers the one term shape typing adds.
//
// A card always names a host alongside its port, so :5432 cannot be clicked
// into existence. It matters because a reader often knows the service and not
// the address — "what is wrong with the database" is a port question.
func TestPortOnlyTermsMatchAnyHost(t *testing.T) {
	js := readFrontend(t, "app.js")

	match := extractFunction(t, js, "findingMatches")
	if !regexp.MustCompile(`if \(t\.host && e\.host !== t\.host\) return false;`).MatchString(match) {
		t.Error("a term with no host is not matched against every host; a bare :port would match " +
			"nothing or everything rather than that port wherever it appears")
	}

	key := extractFunction(t, js, "termKey")
	if !regexp.MustCompile(`if \(!t\.host\) return ":" \+ t\.port;`).MatchString(key) {
		t.Error("a port-only term has no distinct key, so its chip would be unlabelled or collide " +
			"with a host term")
	}

	add := extractFunction(t, js, "addFilterTerm")
	if !regexp.MustCompile(`!term\.host && !term\.port`).MatchString(add) {
		t.Error("addFilterTerm still requires a host, so port-only terms would be discarded " +
			"before reaching the filter")
	}
}

// TestTypedFilterStateResetsOnANewCapture extends the Part 2 reset to the
// field and its hint.
//
// A leftover "could not read foo" over a capture that was never asked about
// foo is a message with no referent, and a leftover open field implies a
// filter that is not there.
func TestTypedFilterStateResetsOnANewCapture(t *testing.T) {
	js := readFrontend(t, "app.js")
	fn := extractFunction(t, js, "analyze")

	for _, reset := range []string{`$("filter-input").value = ""`, `$("filter-input-hint").hidden = true`} {
		if !strings.Contains(fn, reset) {
			t.Errorf("analyze() does not reset %s", reset)
		}
	}
}
