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
  var returnTo = { view: "home", scrollY: 0, label: "Back" };

  function $(id) { return document.getElementById(id); }

  // show reveals one view. Pass keepScroll to leave the scroll position alone,
  // which is how a lossless return works.
  function show(name, keepScroll) {
    VIEWS.forEach(function (v) {
      $("view-" + v).hidden = v !== name;
    });
    if (!keepScroll) window.scrollTo(0, 0);
  }

  // rememberReturn records the current place before a secondary view opens.
  function rememberReturn(view, label) {
    returnTo = { view: view, scrollY: window.scrollY, label: label || "Back" };
  }

  function goBack() {
    show(returnTo.view, true);
    // Restore after the view is visible; a hidden element has no scroll height.
    window.scrollTo(0, returnTo.scrollY);
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

  function renderHome(i) {
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

    var list = $("checks-list");
    list.textContent = "";
    (i.implemented_checks || []).forEach(function (c) {
      var li = el("li");
      li.appendChild(el("span", "check-name", c.id + " · " + c.name));
      li.appendChild(el("span", "check-summary", c.summary));
      list.appendChild(li);
    });

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
    // than a prerequisite.
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
  // the index. Its presence is what decides whether the context block appears —
  // a reader browsing from Help has no specific case to be reminded of.
  function openGuide(ruleID, finding) {
    window.go.gui.App.GuidePage(ruleID)
      .then(function (page) {
        $("guide-rule-id").textContent = page.rule_id;
        $("guide-title").textContent = page.title;
        $("btn-guide-back").textContent = "← " + returnTo.label;

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

  function openGuideIndex() {
    window.go.gui.App.Guide()
      .then(function (idx) {
        $("btn-index-back").textContent = "← " + returnTo.label;

        var list = $("guide-index-list");
        list.textContent = "";
        (idx.entries || []).forEach(function (e) {
          var li = el("li", "index-entry");
          var btn = el("button", "index-link");
          btn.type = "button";
          btn.appendChild(el("span", "check-name", e.rule_id + " · " + e.name));
          btn.appendChild(el("span", "check-summary", e.summary));
          if (e.has_page) {
            btn.addEventListener("click", function () {
              rememberReturn("guide-index", "All checks");
              openGuide(e.rule_id, null);
            });
          } else {
            btn.disabled = true;
          }
          li.appendChild(btn);
          list.appendChild(li);
        });

        $("guide-index-planned").textContent = idx.planned_note || "";
        show("guide-index");
      })
      .catch(function (err) { fail(String(err && err.message ? err.message : err)); });
  }

  function openAbout() {
    window.go.gui.App.About()
      .then(function (a) {
        $("about-name").textContent = "About " + a.name;
        $("about-tagline").textContent = a.tagline;
        $("btn-about-back").textContent = "← " + returnTo.label;

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

        show("about");
      })
      .catch(function (err) { fail(String(err && err.message ? err.message : err)); });
  }

  // ------------------------------------------------------------ clean state

  // renderCleanState builds the screen a healthy capture lands on.
  //
  // Everything is visible at once by design. The list of what could not be
  // checked is the reason this screen exists — a reader who has just been told
  // nothing was found is exactly the reader least likely to go looking for the
  // caveats, so the caveats are put in front of them rather than behind a
  // toggle.
  function renderCleanState(cov) {
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

    var checked = $("clean-checked");
    checked.textContent = "";
    (cov.checked || []).forEach(function (c) {
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
      renderCleanState(result.coverage || {});
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

    $("btn-guide-back").addEventListener("click", goBack);
    $("btn-index-back").addEventListener("click", goBack);
    $("btn-about-back").addEventListener("click", goBack);
    $("btn-guide-index").addEventListener("click", function () {
      rememberReturn("guide", "Guide");
      openGuideIndex();
    });
    $("btn-about-index").addEventListener("click", function () {
      rememberReturn("about", "About");
      openGuideIndex();
    });

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
    window.runtime.EventsOn("nav:about", function () {
      var here = currentView();
      if (here !== "about") rememberReturn(here, labelFor(here));
      openAbout();
    });
    window.runtime.EventsOn("nav:guide", function () {
      var here = currentView();
      if (here !== "guide-index") rememberReturn(here, labelFor(here));
      openGuideIndex();
    });
    window.runtime.EventsOn("nav:open", function () { pickFile(); });
  }

  function start() {
    window.go.gui.App.Info()
      .then(function (i) {
        info = i;
        renderHome(i);
        wire();
        show("home");
      })
      .catch(function (err) {
        fail("The application could not start: " + String(err));
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
