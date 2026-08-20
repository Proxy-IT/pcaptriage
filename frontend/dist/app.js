// pcaptriage desktop frontend.
//
// This file renders; it does not analyse. Every number and every sentence it
// displays comes from the Go engine through window.go.gui.App — the same engine
// and the same report document the CLI writes as JSON.
//
// Everything that originates in a capture file is inserted with textContent,
// never innerHTML. A capture is attacker-controlled data and its addresses and
// ports reach the finding wording, so the DOM is built node by node rather than
// by string concatenation.

(function () {
  "use strict";

  var VIEWS = ["home", "loading", "findings", "guide", "guide-index", "about", "error"];
  var info = null;
  var busy = false;

  // Where a secondary view was opened from, and how to put the reader back
  // exactly where they were.
  //
  // Returning to the top of the results list would make the guide expensive to
  // consult: a reader six cards down has to find their place again, so they
  // learn not to click. The scroll position is part of the answer.
  //
  // A stack rather than a single slot. One slot was enough while each view
  // painted its own back label at open time, because a stale label on a view
  // nobody was looking at did no harm. The bar's single shared control is
  // repainted on every show(), so a one-hop-deep memory would have the reader
  // land back on the guide page under a "← Guide" button pointing at itself.
  var backStack = [];

  function backTop() {
    return backStack.length ? backStack[backStack.length - 1] : null;
  }

  function $(id) { return document.getElementById(id); }

  // NAV_FOR maps a view to the top-bar link that represents it. Loading,
  // findings and error are absent on purpose: no bar link leads to them, so
  // none should light up while they are showing — an active state that did
  // not correspond to a destination would be decoration rather than an answer
  // to "where am I".
  var NAV_FOR = {
    home: "nav-home",
    guide: "nav-guide",
    "guide-index": "nav-guide",
    about: "nav-about"
  };
  var NAV_LINKS = ["nav-home", "nav-guide", "nav-about"];

  // The views that can be arrived at from somewhere else and returned from.
  // Findings is absent: it is a root, reached by opening a capture rather than
  // by navigating, and "← Home" from it would undo the reader's work.
  var BACK_VIEWS = { guide: true, "guide-index": true, about: true };

  // show reveals one view. Pass keepScroll to leave the scroll position alone,
  // which is how a lossless return works.
  function show(name, keepScroll) {
    VIEWS.forEach(function (v) {
      $("view-" + v).hidden = v !== name;
    });
    // Driven from show() rather than from each call site, so a view can never
    // be revealed without the bar agreeing about where the reader is.
    NAV_LINKS.forEach(function (id) {
      var link = $(id);
      if (NAV_FOR[name] === id) {
        link.classList.add("active");
        link.setAttribute("aria-current", "page");
      } else {
        link.classList.remove("active");
        link.removeAttribute("aria-current");
      }
    });
    // The contextual return is painted here, from one place, for the same
    // reason the active state is: a view must not be able to appear wearing
    // another view's way back.
    var back = $("nav-back");
    var to = BACK_VIEWS[name] ? backTop() : null;
    if (to) {
      back.textContent = "← " + to.label;
      back.hidden = false;
    } else {
      back.textContent = "";
      back.hidden = true;
    }
    if (!keepScroll) window.scrollTo(0, 0);
  }

  // rememberReturn records the current place before a secondary view opens.
  function rememberReturn(view, label) {
    backStack.push({ view: view, scrollY: window.scrollY, label: label || "Back" });
  }

  // goHome is the bar's escape hatch: it goes to a root, so the trail of
  // secondary views the reader took to get here is spent, not suspended.
  function goHome() {
    backStack = [];
    show("home");
  }

  function goBack() {
    var to = backStack.pop();
    if (!to) { show("home"); return; }
    show(to.view, true);
    // Restore after the view is visible; a hidden element has no scroll height.
    window.scrollTo(0, to.scrollY);
  }

  function currentView() {
    for (var i = 0; i < VIEWS.length; i++) {
      if (!$("view-" + VIEWS[i]).hidden) return VIEWS[i];
    }
    return "home";
  }

  function labelFor(view) {
    return { home: "Home", findings: "Findings", guide: "Guide", "guide-index": "All checks", about: "About" }[view] || "Back";
  }

  // applyTheme sets or clears data-theme on the root element from the
  // resolved preference. "system" asks for nothing here — it is the one
  // value tokens.css answers on its own, through
  // @media (prefers-color-scheme: dark), so leaving the attribute unset is
  // the correct behaviour for it, not a missing case. "light" and "dark" each
  // set the attribute their own selector in tokens.css keys on.
  //
  // Called once Info() resolves, which is after first paint — a reader whose
  // explicit choice disagrees with their OS sees one brief flash of the
  // wrong theme before this runs. Real now that the About page's control can
  // set an explicit choice, but still small: Info() is a same-process Wails
  // IPC call, not a network round trip, so the window is on the order of the
  // time it takes the Go side to read a JSON file plus one message hop.
  // Worth revisiting only if it turns out to be noticeable in practice.
  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
      document.documentElement.setAttribute("data-theme", theme);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }

  // ---------------------------------------------------------------- helpers

  function el(tag, className, text) {
    var n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function formatCount(n) {
    return (n || 0).toLocaleString("en-US");
  }

  function formatBytes(n) {
    if (!n || n < 0) return "";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    var v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? v : v.toFixed(1)) + " " + units[i];
  }

  // ---------------------------------------------------------------- home

  function renderHome(i, idx) {
    $("app-name").textContent = i.name;
    $("app-tagline").textContent = i.tagline;
    $("app-instruction").textContent = i.instruction;
    $("app-posture").textContent = i.posture;
    $("results-posture").textContent = i.posture;

    // A preference that silently failed to apply is something the user finds
    // out about much later, and then stops trusting the rest.
    var notice = $("prefs-notice");
    if (i.preferences_notice) {
      notice.textContent = i.preferences_notice;
      notice.hidden = false;
    } else {
      notice.textContent = "";
      notice.hidden = true;
    }

    // The same rows the guide index shows, rendered by the same function, so
    // a reader can open any check from here and the two screens cannot come
    // to disagree about what this build looks for.
    renderCheckList($("checks-list"), idx.entries, "home", "Home");

    var made = (i.implemented_checks || []).length;
    // Stated before the run rather than after it. A user who is told up front
    // that two checks of fifteen exist reads a quiet result correctly; one who
    // is told afterwards has already drawn a conclusion.
    $("checks-caveat").textContent =
      made + " of " + i.total_v1_rules + " planned checks are built so far. " +
      "A result with nothing in it means these checks found nothing — not that " +
      "the capture is healthy.";

    $("about-version").textContent = i.version;
    $("about-ruleset").textContent = i.ruleset_version;
    $("about-schema").textContent = i.schema_version;
  }

  // ---------------------------------------------------------------- loading

  function resetProgress(fileName) {
    $("loading-file").textContent = fileName || "";
    $("progress-bar").classList.add("indeterminate");
    $("progress-fill").style.width = "";
    $("progress-bar").removeAttribute("aria-valuenow");
    $("loading-status").textContent = "Opening the file…";
  }

  function onProgress(p) {
    if (!p) return;

    var bar = $("progress-bar");
    var known = p.TotalBytes > 0;

    if (known) {
      var pct = p.Done ? 100 : Math.min(100, (p.BytesRead / p.TotalBytes) * 100);
      bar.classList.remove("indeterminate");
      $("progress-fill").style.width = pct.toFixed(1) + "%";
      bar.setAttribute("aria-valuenow", Math.round(pct));
      $("loading-status").textContent =
        Math.round(pct) + "% · " + formatCount(p.PacketsRead) + " packets read";
    } else {
      bar.classList.add("indeterminate");
      $("loading-status").textContent = formatCount(p.PacketsRead) + " packets read";
    }

    if (p.Done) {
      $("loading-status").textContent =
        "Read " + formatCount(p.PacketsRead) + " packets — working out what stood out…";
    }
  }

  // ---------------------------------------------------------------- findings

  // findingCard renders one finding in the structure every rule in RULES.md
  // uses: what was observed, the frames that evidence it, what to check next.
  // The wording arrives from the engine already written and is never edited,
  // reflowed or summarised here.
  function findingCard(f) {
    var sev = f.severity || "informational";
    var card = el("article", "finding sev-" + sev);

    var head = el("div", "finding-head");
    head.appendChild(el("span", "finding-rank", "#" + f.rank));
    head.appendChild(el("h3", null, f.title));
    head.appendChild(el("span", "tag tag-rule", f.rule_id));
    // Severity carries the colour and always its word with it; quality sits
    // beside it, colourless, answering a different question.
    head.appendChild(el("span", "tag tag-sev tag-sev-" + sev, f.severity_label || ""));
    head.appendChild(el("span", "tag tag-" + (f.quality || "confirmed"), f.quality || ""));
    card.appendChild(head);

    card.appendChild(el("p", "observation", f.observation));

    var frames = el("p", "frames");
    var list = (f.frames || []).join(", ");
    frames.appendChild(document.createTextNode("Frames " + (list || "—")));
    if (f.total_count > (f.frames || []).length) {
      frames.appendChild(document.createTextNode(" "));
      frames.appendChild(el(
        "span", "of",
        "(" + (f.frames || []).length + " shown of " + formatCount(f.total_count) + " occurrences)"
      ));
    }
    card.appendChild(frames);

    var next = el("p", "next");
    var label = el("b", null, "Check next:");
    next.appendChild(label);
    next.appendChild(document.createTextNode(" " + f.check_next));
    card.appendChild(next);

    if (f.quality_basis) card.appendChild(el("p", "basis", f.quality_basis));

    // The link out to the explanation. Placed after "check next", so the card
    // still reads top to bottom on its own and the guide is an offer rather
    // than a prerequisite. Rendered only when the page exists.
    if (guideAvailable[f.rule_id]) {
      var more = el("p", "guide-link-row");
      var link = el("button", "linkish");
      link.type = "button";
      link.textContent = "What does " + f.rule_id + " mean?";
      link.addEventListener("click", function () {
        rememberReturn("findings", "Findings");
        openGuide(f.rule_id, f);
      });
      more.appendChild(link);
      card.appendChild(more);
    }

    var packets = evidenceFor(f);
    if (packets.length > 0) card.appendChild(packetDisclosure(f, packets));

    return card;
  }

  // ------------------------------------------------------------ guide

  // renderRuns turns authored inline runs into DOM nodes.
  //
  // Built node by node with textContent rather than assembled as markup: the
  // prose is trusted, but the same helper renders finding context alongside it,
  // and that comes out of a capture.
  function appendRuns(parent, runs) {
    (runs || []).forEach(function (r) {
      if (r.strong) {
        parent.appendChild(el("strong", null, r.text));
        return;
      }
      if (r.emphasis) {
        parent.appendChild(el("em", null, r.text));
        return;
      }
      parent.appendChild(document.createTextNode(r.text));
    });
  }

  function renderBlocks(into, blocks) {
    (blocks || []).forEach(function (b) {
      if (b.kind === "bullets") {
        var ul = el("ul", "prose-list");
        (b.items || []).forEach(function (item) {
          var li = el("li");
          appendRuns(li, item);
          ul.appendChild(li);
        });
        into.appendChild(ul);
        return;
      }
      var p = el("p", "prose-p");
      appendRuns(p, b.runs);
      into.appendChild(p);
    });
  }

  // openGuide shows a rule's guide page.
  //
  // finding is the card the reader clicked from, or null when they arrived from
  // the index. Its presence decides two things: whether the context block
  // appears (a reader browsing from Help has no specific case to be reminded
  // of), and, on a page shared by several rules, whether the page scrolls to
  // that rule's own section. Arriving from the index always lands at the top —
  // the reader asked "what does this tool check", not about one specific rule
  // — so the scroll only happens when a finding named which rule brought them
  // here.
  function openGuide(ruleID, finding) {
    window.go.gui.App.GuidePage(ruleID)
      .then(function (page) {
        $("guide-rule-id").textContent = (page.rule_ids || [ruleID]).join(" · ");
        $("guide-title").textContent = page.title;

        var ctx = $("guide-context");
        if (finding) {
          $("guide-context-title").textContent = finding.title;
          $("guide-context-observation").textContent = finding.observation;
          $("guide-context-frames").textContent =
            "Frames " + ((finding.frames || []).join(", ") || "—");
          ctx.hidden = false;
        } else {
          ctx.hidden = true;
        }

        var body = $("guide-body");
        body.textContent = "";
        var landingSection = null;
        (page.sections || []).forEach(function (s) {
          var sec = el("section", "guide-section");
          if (s.anchor) sec.id = "guide-anchor-" + s.anchor.toLowerCase();
          sec.appendChild(el("h3", null, s.heading));
          renderBlocks(sec, s.blocks);
          body.appendChild(sec);
          if (finding && s.anchor && s.anchor.toLowerCase() === ruleID.toLowerCase()) {
            landingSection = sec;
          }
        });

        show("guide");
        // A hidden element has no scroll position to land on, so this runs
        // only once the view above has made the page visible — the same
        // reason goBack() restores its scroll position after show(), not
        // before.
        if (landingSection) {
          landingSection.scrollIntoView();
        }
      })
      .catch(function (err) { fail(String(err && err.message ? err.message : err)); });
  }

  // openConcept shows a concept page — the guide's other section. Reached
  // from the index today; from a badge once Part 2 wires that in.
  //
  // No finding parameter, unlike openGuide: a concept page is never landed on
  // with a specific finding's context — arrival is always index-style, and
  // stays that way even from a badge (session brief Part 2). No anchor or
  // landing-section logic either, since concept pages carry no anchors —
  // reusing view-guide's markup, not its scrolling behaviour.
  function openConcept(slug) {
    window.go.gui.App.GuideConcept(slug)
      .then(function (page) {
        $("guide-rule-id").textContent = "Concept";
        $("guide-title").textContent = page.title;
        $("guide-context").hidden = true;

        var body = $("guide-body");
        body.textContent = "";
        (page.sections || []).forEach(function (s) {
          var sec = el("section", "guide-section");
          sec.appendChild(el("h3", null, s.heading));
          renderBlocks(sec, s.blocks);
          body.appendChild(sec);
        });

        show("guide");
      })
      .catch(function (err) { fail(String(err && err.message ? err.message : err)); });
  }

  // renderCheckList fills a list element with one row per guide page.
  //
  // The home screen's "what this build looks for" and the guide index are the
  // same question asked in two places, so they are one function reading one
  // source rather than two renderings that would eventually disagree — the
  // same reason neither of them keeps its own list of what the tool checks.
  // It also means every row on the home screen is a working link for exactly
  // the reason the index's rows are, rather than by a parallel mechanism that
  // would need its own proof.
  //
  // fromView and fromLabel are where a click should return to, which is the
  // only thing that differs between the two call sites.
  function renderCheckList(list, entries, fromView, fromLabel) {
    list.textContent = "";
    (entries || []).forEach(function (e) {
          var li = el("li", "index-entry");
          var btn = el("button", "index-link");
          btn.type = "button";
          var ids = (e.rule_ids && e.rule_ids.length ? e.rule_ids : [e.rule_id]).join(" · ");
          btn.appendChild(el("span", "check-name", ids + " · " + e.name));
          if (e.has_page) {
            btn.addEventListener("click", function () {
              rememberReturn(fromView, fromLabel);
              // Arrival from a list always lands at the page top, even for a
              // page that serves several rules — the reader asked "what does
              // this tool check" generally, not about any one of them. The
              // null is what withholds the finding-context block, since no
              // finding sent them here.
              openGuide(e.rule_id, null);
            });
          } else {
            btn.disabled = true;
            // The disabled state alone — dimmed, default cursor, a duller
            // border — reads as "still loading" or "same as the others" at a
            // glance, not as "this one doesn't do anything." A row that looks
            // interactive but silently isn't is worse than one that's plainly
            // marked, so the difference is said in words too, the same reason
            // severity and evidence quality are never colour alone.
            btn.appendChild(el("span", "tag tag-unavailable index-tag", "No guide yet"));
          }
          btn.appendChild(el("span", "check-summary", e.summary));

          // A page serving several rules lists them, so the row says what it
          // actually covers without the reader opening it first — one row
          // standing in for four checks must not read as "four checks
          // collapsed into one and now invisible."
          if (e.members && e.members.length) {
            var covers = el("ul", "index-members");
            e.members.forEach(function (m) {
              var mli = el("li", "index-member");
              mli.appendChild(el("span", "check-name", m.rule_id + " · " + m.name));
              mli.appendChild(el("span", "check-summary", m.summary));
              covers.appendChild(mli);
            });
            btn.appendChild(covers);
          }

          li.appendChild(btn);
          list.appendChild(li);
    });
  }

  // renderConceptList fills a list element with one row per concept page —
  // the guide index's second section.
  //
  // Not renderCheckList reused with an optional-fields branch: a concept has
  // no rule_id, no built/has_page gate (a concept that parsed exists — there
  // is no "not built yet" state for prose), and never groups members. Two
  // small functions cost less than teaching one function two unrelated row
  // shapes would, the same judgment the Go side makes about Concept vs Page.
  function renderConceptList(list, entries, fromView, fromLabel) {
    list.textContent = "";
    (entries || []).forEach(function (e) {
      var li = el("li", "index-entry");
      var btn = el("button", "index-link");
      btn.type = "button";
      btn.appendChild(el("span", "check-name", e.title));
      btn.appendChild(el("span", "check-summary", e.summary));
      btn.addEventListener("click", function () {
        rememberReturn(fromView, fromLabel);
        openConcept(e.slug);
      });
      li.appendChild(btn);
      list.appendChild(li);
    });
  }

  function openGuideIndex() {
    window.go.gui.App.Guide()
      .then(function (idx) {
        renderCheckList($("guide-index-list"), idx.entries, "guide-index", "All checks");
        $("guide-index-planned").textContent = idx.planned_note || "";
        renderConceptList($("guide-concepts-list"), idx.concepts, "guide-index", "All checks");
        show("guide-index");
      })
      .catch(function (err) { fail(String(err && err.message ? err.message : err)); });
  }

  // goToGuideIndex and goToAbout are the two destinations reachable from both
  // the top bar and the native Help menu. They record where the reader was
  // first, unless they are already there — asking for the screen you are on
  // must not overwrite the way back with itself.
  function goToGuideIndex() {
    var here = currentView();
    if (here !== "guide-index") rememberReturn(here, labelFor(here));
    openGuideIndex();
  }

  function goToAbout() {
    var here = currentView();
    if (here !== "about") rememberReturn(here, labelFor(here));
    openAbout();
  }

  function openAbout() {
    // Both, before the page shows: the theme row needs the saved preference
    // at the same moment everything else on the page needs the build facts,
    // and there is no reason to paint the row twice.
    Promise.all([window.go.gui.App.About(), window.go.gui.App.Preferences()])
      .then(function (results) {
        var a = results[0], prefs = results[1];

        $("about-name").textContent = "About " + a.name;
        $("about-tagline").textContent = a.tagline;

        var what = $("about-what");
        what.textContent = "";
        (a.what || []).forEach(function (s) { what.appendChild(el("p", "prose-p", s)); });

        var priv = $("about-privacy");
        priv.textContent = "";
        (a.privacy || []).forEach(function (s) { priv.appendChild(el("p", "prose-p", s)); });

        $("about-posture").textContent = a.posture;
        $("about-coverage").textContent = a.coverage;
        $("about-opensource").textContent = a.open_source;
        $("about-version").textContent = a.version;
        $("about-ruleset").textContent = a.ruleset_version;
        $("about-schema").textContent = a.schema_version;

        $("about-attribution").textContent = a.attribution + " — ";
        var link = $("btn-about-link");
        link.textContent = a.attribution_url;
        link.onclick = function () {
          // Handed to the operating system, never fetched here. The paragraph
          // above this line promises no network calls.
          window.go.gui.App.OpenExternal(a.attribution_url);
        };

        wireThemeControl(prefs);

        show("about");
      })
      .catch(function (err) { fail(String(err && err.message ? err.message : err)); });
  }

  // wireThemeControl connects the appearance select to SavePreferences.
  //
  // Reads and writes the whole Preferences object rather than just the theme
  // field — SavePreferences takes the full set, and a save that only knew
  // about theme would silently clear whatever timezone preference existed.
  // current is kept up to date after each successful save, both so a second
  // change in the same visit starts from what is actually on disk and so a
  // failed save has the right value to revert the visible control to.
  function wireThemeControl(prefs) {
    var current = prefs;
    var select = $("about-theme");
    var notice = $("about-theme-notice");

    select.value = current.theme || "light";
    notice.hidden = true;

    select.onchange = function () {
      var chosen = select.value;
      var next = { schema: current.schema, timezone: current.timezone, theme: chosen };

      window.go.gui.App.SavePreferences(next)
        .then(function () {
          current = next;
          notice.hidden = true;
          // Applied immediately — a preference that only takes effect after a
          // restart is a preference that looks broken for however long the
          // reader keeps using the screen they just changed it on.
          applyTheme(chosen);
        })
        .catch(function (err) {
          notice.textContent = "Could not save the theme: " + String(err && err.message ? err.message : err);
          notice.hidden = false;
          select.value = current.theme || "light";
        });
    };
  }

  // ------------------------------------------------------------ clean state

  // renderCleanState builds the screen a healthy capture lands on.
  //
  // Everything is visible at once by design. The list of what could not be
  // checked is the reason this screen exists — a reader who has just been told
  // nothing was found is exactly the reader least likely to go looking for the
  // caveats, so the caveats are put in front of them rather than behind a
  // toggle.
  function renderCleanState(doc) {
    // Coverage rides inside the report document — the same struct the exported
    // HTML and JSON carry, so this screen and an export cannot disagree.
    var cov = doc.coverage || {};

    $("clean-statement").textContent = cov.statement || "Nothing was found";
    $("clean-qualifier").textContent = cov.qualifier || "";

    // Green only when the coverage earns it. Today it never does — not all
    // fifteen checks are built — so this stays neutral, which is the intended
    // outcome rather than an oversight.
    var headline = document.querySelector(".clean-headline");
    if (cov.coverage_strong) {
      headline.classList.add("coverage-strong");
    } else {
      headline.classList.remove("coverage-strong");
    }

    // What ran comes from the document's checks list — the coverage does not
    // carry a second copy of it, so the two cannot disagree.
    var checked = $("clean-checked");
    checked.textContent = "";
    (doc.checks || []).forEach(function (c) {
      var li = el("li");
      li.appendChild(el("span", "check-name", c.id + " · " + c.name));
      li.appendChild(el("span", "check-summary", c.summary));
      checked.appendChild(li);
    });

    var unbuilt = $("clean-unbuilt");
    if (cov.unbuilt_checks > 0) {
      unbuilt.textContent = cov.unbuilt_checks +
        " further checks are planned but not built yet, so nothing they would cover was examined.";
      unbuilt.hidden = false;
    } else {
      unbuilt.textContent = "";
      unbuilt.hidden = true;
    }

    var gaps = $("clean-gaps");
    gaps.textContent = "";
    if ((cov.not_checked || []).length === 0) {
      var none = el("p", "clean-nogaps",
        "Every check that is built ran to completion on this capture. " +
        "Nothing was skipped for want of information in the file.");
      gaps.appendChild(none);
    } else {
      cov.not_checked.forEach(function (g) {
        var box = el("div", "note unavailable");
        if (g.rule_id) box.appendChild(el("span", "who", g.rule_id + " · not assessed"));
        box.appendChild(document.createTextNode(g.text));
        gaps.appendChild(box);
      });
    }

    var minor = $("clean-minor");
    if (cov.minor_observations > 0) {
      minor.textContent = cov.minor_observations +
        " minor observation(s) were recorded but are not shown here, being below the threshold for the main list.";
      minor.hidden = false;
    } else {
      minor.textContent = "";
      minor.hidden = true;
    }
  }

  // ------------------------------------------------------------ packet view

  var evidence = [];

  function evidenceFor(f) {
    for (var i = 0; i < evidence.length; i++) {
      if (evidence[i].rule_id === f.rule_id && evidence[i].subject === f.subject) {
        return evidence[i].packets || [];
      }
    }
    return [];
  }

  function formatRelTime(s) {
    return (s || 0).toFixed(6);
  }

  // packetDisclosure builds the collapsed "show the packets" section.
  //
  // <details> is native: it opens and closes with no JavaScript, keeps working
  // with the keyboard, and is searchable by the browser's find. The rows are
  // laid out the way Wireshark's packet list is, so a reader who opens the
  // capture recognises the same lines.
  function packetDisclosure(f, packets) {
    var flagged = packets.filter(function (p) { return p.role === "flagged"; }).length;

    var wrap = document.createElement("details");
    wrap.className = "packets";

    var sum = document.createElement("summary");
    sum.textContent = flagged === packets.length
      ? "Show the " + packets.length + " packets this is based on"
      : "Show the packets — " + flagged + " flagged, " +
        (packets.length - flagged) + " for context";
    wrap.appendChild(sum);

    var scroller = el("div", "packets-scroll");
    var table = document.createElement("table");
    table.className = "packet-table";

    var thead = document.createElement("thead");
    var hrow = document.createElement("tr");
    ["No.", "Time", "Source", "Destination", "Proto", "Len", "Info"].forEach(function (h) {
      hrow.appendChild(el("th", null, h));
    });
    thead.appendChild(hrow);
    table.appendChild(thead);

    var tbody = document.createElement("tbody");
    packets.forEach(function (p) {
      var tr = document.createElement("tr");
      tr.className = p.role === "flagged" ? "pk-flagged" : "pk-context";

      tr.appendChild(el("td", "pk-no", String(p.frame)));
      tr.appendChild(el("td", "pk-time", formatRelTime(p.rel_seconds)));
      tr.appendChild(el("td", "pk-addr", p.src));
      tr.appendChild(el("td", "pk-addr", p.dst));
      tr.appendChild(el("td", "pk-proto", p.protocol));
      tr.appendChild(el("td", "pk-len", String(p.length)));
      tr.appendChild(el("td", "pk-info", p.info));
      tbody.appendChild(tr);

      // The note is what turns a packet list into an explanation. It sits on
      // its own row so the columns above stay aligned with Wireshark's.
      if (p.note) {
        var nr = document.createElement("tr");
        nr.className = "pk-note-row" + (p.role === "flagged" ? " pk-flagged" : "");
        var pad = document.createElement("td");
        pad.className = "pk-no";
        nr.appendChild(pad);
        var note = el("td", "pk-note", p.note);
        note.colSpan = 6;
        nr.appendChild(note);
        tbody.appendChild(nr);
      }
    });
    table.appendChild(tbody);
    scroller.appendChild(table);
    wrap.appendChild(scroller);

    var hint = el("p", "packets-hint");
    hint.appendChild(document.createTextNode(
      "Times are seconds from the start of the capture, matching Wireshark's default column. " +
      "To find these in Wireshark, open the same file and use Go → Go to Packet, or filter with "
    ));
    hint.appendChild(el("code", null, "frame.number in {" +
      packets.map(function (p) { return p.frame; }).join(" ") + "}"));
    hint.appendChild(document.createTextNode("."));
    wrap.appendChild(hint);

    return wrap;
  }

  function renderFindings(result) {
    var doc = result.report;
    var findings = doc.findings || [];
    var notes = doc.notes || [];

    evidence = result.evidence || [];

    $("results-file").textContent =
      result.file_name + " · " + formatBytes(result.file_size) +
      " · " + formatCount(doc.capture.packets_read) + " packets, " +
      formatCount(doc.capture.tcp_flows) + " TCP flows";

    // On the clean screen the section heading stays purely factual: the
    // calibrated statement below it is the message, and a heading that also
    // pronounced on the result would be a second, blunter verdict above it.
    $("results-title").textContent =
      findings.length > 0 ? "Top findings" : "Analysis complete";

    var list = $("findings-list");
    list.textContent = "";

    if (findings.length === 0) {
      renderCleanState(doc);
      $("clean-state").hidden = false;
    } else {
      $("clean-state").hidden = true;
    }

    if (findings.length === 0) {
      // The clean state above carries the whole message; an empty list beneath
      // it would only restate it.
    } else {
      // Already ranked by significance in the engine. Order is the only place
      // significance is expressed; it is never shown as a number.
      findings.forEach(function (f) { list.appendChild(findingCard(f)); });
    }

    var notesSection = $("notes-section");
    var notesList = $("notes-list");
    notesList.textContent = "";
    // When the clean state is showing, it already lists the gaps in a form
    // built for being read first. Repeating them underneath would bury the
    // point rather than reinforce it.
    if (findings.length === 0) {
      notesSection.hidden = true;
    } else if (notes.length > 0) {
      notes.forEach(function (n) {
        var box = el("div", "note" + (n.kind === "unavailable" ? " unavailable" : ""));
        box.appendChild(el("span", "who",
          (n.rule_id ? n.rule_id : "this run") +
          (n.kind === "unavailable" ? " · not assessed" : " · note")));
        box.appendChild(document.createTextNode(n.text));
        notesList.appendChild(box);
      });
      notesSection.hidden = false;
    } else {
      notesSection.hidden = true;
    }

    $("build-note-text").textContent = doc.tool.build;
  }

  // ---------------------------------------------------------------- flow

  function fail(message) {
    $("error-message").textContent = message;
    show("error");
  }

  function analyze(path) {
    if (!path || busy) return;
    busy = true;

    resetProgress(path.replace(/^.*[\\/]/, ""));
    show("loading");

    window.go.gui.App.Analyze(path)
      .then(function (result) {
        renderFindings(result);
        show("findings");
      })
      .catch(function (err) {
        fail(String(err && err.message ? err.message : err));
      })
      .finally(function () { busy = false; });
  }

  function pickFile() {
    if (busy) return;
    window.go.gui.App.ChooseFile()
      .then(function (path) { if (path) analyze(path); })
      .catch(function (err) {
        fail(String(err && err.message ? err.message : err));
      });
  }

  // ---------------------------------------------------------------- wiring

  function wire() {
    $("dropzone").addEventListener("click", pickFile);
    $("btn-another").addEventListener("click", function () { show("home"); pickFile(); });
    $("btn-error-back").addEventListener("click", function () { show("home"); });

    // The contextual return stays, and lives in the bar. "← {label}" undoes
    // exactly one hop and restores the scroll position the reader left, which
    // is a different and more precise job than the bar's Home — a reader six
    // cards down who clicked a guide link wants their card back, not the drop
    // zone. One control rather than one per view: it used to sit in each
    // view's header, where the sticky bar scrolled over it and swallowed the
    // click while it still looked pressable.
    $("nav-back").addEventListener("click", goBack);

    // The persistent bar. Every screen has these three, which is what stops
    // the next screen needing its own one-off way out.
    $("nav-home").addEventListener("click", goHome);
    $("nav-guide").addEventListener("click", goToGuideIndex);
    $("nav-about").addEventListener("click", goToAbout);

    // R15 renders in the banner, never as a card, so its guide entry has no
    // per-finding link to hang off of. One link covers it, from wherever its
    // notices appear — the clean-capture gaps column and the full findings
    // view's "what wasn't checked" section — rather than one per notice,
    // since every R15 notice leads to the same page regardless of which one
    // was clicked.
    var openR15Guide = function () {
      rememberReturn(currentView(), labelFor(currentView()));
      openGuide("R15", null);
    };
    $("btn-clean-gaps-guide").addEventListener("click", openR15Guide);
    $("btn-notes-guide").addEventListener("click", openR15Guide);

    // Drag feedback only. The path itself arrives from the Go side, because a
    // webview's drop event exposes file contents but not a usable filesystem
    // path.
    var depth = 0;
    window.addEventListener("dragenter", function (e) {
      e.preventDefault();
      depth++;
      if (!busy) document.body.classList.add("dragging");
    });
    window.addEventListener("dragover", function (e) { e.preventDefault(); });
    window.addEventListener("dragleave", function (e) {
      e.preventDefault();
      depth = Math.max(0, depth - 1);
      if (depth === 0) document.body.classList.remove("dragging");
    });
    window.addEventListener("drop", function (e) {
      e.preventDefault();
      depth = 0;
      document.body.classList.remove("dragging");
    });

    window.runtime.EventsOn("analysis:progress", onProgress);
    window.runtime.EventsOn("file:dropped", function (path) { analyze(path); });
    // The native Help menu and the top bar are two ways to ask for the same
    // screen, so they call the same function rather than each remembering
    // separately where the reader should return to.
    window.runtime.EventsOn("nav:about", goToAbout);
    window.runtime.EventsOn("nav:guide", goToGuideIndex);
    window.runtime.EventsOn("nav:open", function () { pickFile(); });
  }

  // guideAvailable maps rule IDs to whether a guide page exists for them.
  // Loaded once at startup: a card's "What does RXX mean?" link renders only
  // when the page does, so a built rule whose guide prose has not been
  // authored yet never shows a link that goes nowhere. The index handles the
  // same state with a disabled entry.
  var guideAvailable = {};

  function start() {
    // Both, before anything renders. The home screen's checks list is built
    // from the guide index now, so a race between these two would decide
    // whether the first screen the user sees lists what the tool checks.
    //
    // A failure of either is fatal rather than degraded, deliberately: the
    // guide content is embedded and parsed at startup, so a failure here is a
    // build defect, and a home screen quietly missing its list of checks
    // would be a worse outcome than an error that says so.
    Promise.all([window.go.gui.App.Info(), window.go.gui.App.Guide()])
      .then(function (results) {
        info = results[0];
        var idx = results[1];

        applyTheme(info.theme);

        (idx.entries || []).forEach(function (e) {
          if (!e.has_page) return;
          // A page serving several rules groups them into one index entry
          // (e.rule_id is only the first); every rule it actually covers —
          // the entry itself and each of its members — needs its own card
          // link to work, or a finding for any rule but the first silently
          // gets no "What does this mean?" link at all.
          guideAvailable[e.rule_id] = true;
          (e.members || []).forEach(function (m) { guideAvailable[m.rule_id] = true; });
        });

        renderHome(info, idx);
        wire();
        show("home");
      })
      .catch(function (err) {
        fail("The application could not start: " + String(err && err.message ? err.message : err));
      });
  }

  // Wails installs its bindings before firing this.
  window.addEventListener("DOMContentLoaded", function () {
    if (window.go && window.go.gui) {
      start();
    } else {
      window.addEventListener("wails:ready", start, { once: true });
    }
  });
})();
