"use strict";
// tarpit-honeypot UI enhancement layer.
//
// Self-contained, dependency-free, served from the binary (no CDN — the
// sensor host is a target). It is a small attribute-driven micro-framework:
// progressive enhancement only, so the views still work with JS disabled.
//
//   - live auto-refresh: takes over from the no-JS <meta refresh> with a
//     visibility-aware, pausable refresh + countdown.
//   - sortable tables: click a data-table header to sort client-side
//     (skips server-sorted and chart tables).
//   - table filter: tables marked data-filter get a row filter box.
//   - svg bars/graph: [data-graph] containers render a node-link graph from
//     their JSON; otherwise the server-rendered CSS bars are left as-is.
//
// CSP: loaded as an external file under script-src 'self'; no inline script,
// no eval.
(function () {
  // Mark the document as JS-enabled the moment the script executes, so CSS
  // can reveal JS-only affordances and an operator can see at a glance that
  // the packaged JS loaded.
  document.documentElement.classList.add("js");

  function ready(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  // ---- smart, flicker-free refresh --------------------------------------
  // Instead of window.location.reload() (which white-flashes and re-runs every
  // asset), we (1) ask /api/heartbeat for a cheap freshness token and SKIP
  // entirely when nothing changed, and (2) when it did change, fetch the page
  // and swap only #pgcontent in place — no navigation, no flash, scroll kept —
  // then re-run the content enhancers + re-render any new charts.
  // morph updates `from` to match `to` in place, recursing node-by-node so that
  // only the parts that actually changed are rewritten. Unchanged subtrees keep
  // their exact DOM nodes (no repaint); an already-rendered chart whose data is
  // unchanged is skipped entirely (no re-render flash); the input the operator
  // is editing is never clobbered.
  function morphAttrs(from, to) {
    var ta = to.attributes, i, a;
    for (i = 0; i < ta.length; i++) {
      a = ta[i];
      if (from.getAttribute(a.name) !== a.value) from.setAttribute(a.name, a.value);
    }
    var fa = from.attributes;
    for (i = fa.length - 1; i >= 0; i--) {
      if (!to.hasAttribute(fa[i].name)) from.removeAttribute(fa[i].name);
    }
  }
  function morph(from, to) {
    if (from.nodeType !== to.nodeType || from.nodeName !== to.nodeName) {
      from.parentNode.replaceChild(to.cloneNode(true), from);
      return;
    }
    // Text / comment: update the value only when it differs.
    if (from.nodeType === 3 || from.nodeType === 8) {
      if (from.nodeValue !== to.nodeValue) from.nodeValue = to.nodeValue;
      return;
    }
    if (from.nodeType !== 1) return;
    // Rendered chart: if the payload is unchanged, leave the live SVG untouched;
    // only replace (for re-render) when the data actually changed.
    if (from.getAttribute("data-chart") != null) {
      if (from.getAttribute("data-chart-b64") === to.getAttribute("data-chart-b64")) return;
      from.parentNode.replaceChild(to.cloneNode(true), from);
      return;
    }
    // Don't overwrite a field the operator is currently editing.
    if (from === document.activeElement &&
      (from.tagName === "INPUT" || from.tagName === "TEXTAREA" || from.tagName === "SELECT")) {
      return;
    }
    morphAttrs(from, to);
    // Children: snapshot both lists, morph the common prefix, then append new /
    // drop surplus — so inserting one row touches one row, not the whole table.
    var fc = Array.prototype.slice.call(from.childNodes);
    var tc = Array.prototype.slice.call(to.childNodes);
    var n = Math.min(fc.length, tc.length), i;
    for (i = 0; i < n; i++) morph(fc[i], tc[i]);
    for (i = n; i < tc.length; i++) from.appendChild(tc[i].cloneNode(true));
    for (i = fc.length - 1; i >= n; i--) from.removeChild(fc[i]);
  }

  var lastToken = null;
  function smartRefresh(done) {
    fetch("/api/heartbeat", { headers: { "Accept": "application/json" } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) {
        var token = j ? (j.count + ":" + (j.last || "")) : null;
        if (token !== null && token === lastToken) { done(); return; } // unchanged → skip
        return fetch(location.href, { headers: { "X-Requested-With": "fetch" } })
          .then(function (r) { return r.text(); })
          .then(function (html) {
            var doc = new DOMParser().parseFromString(html, "text/html");
            var fresh = doc.getElementById("pgcontent");
            var cur = document.getElementById("pgcontent");
            if (fresh && cur) {
              // Diff the new content into the live DOM, touching only the nodes
              // that actually changed — unchanged tables, rows and (crucially)
              // already-rendered chart SVGs are left in place, so there is no
              // whole-page repaint "blink". Falls back to a plain swap if the
              // morph ever throws.
              try { morph(cur, fresh); }
              catch (e) { cur.innerHTML = fresh.innerHTML; }
              runContentEnhancers();
              if (window.TarpitCharts && window.TarpitCharts.auto) {
                try { window.TarpitCharts.auto(cur); } catch (e) { /* ignore */ }
              }
            }
            if (token !== null) lastToken = token;
            done();
          });
      })
      .catch(function () { done(); }); // network hiccup: wait for the next tick
  }

  // ---- live auto-refresh -------------------------------------------------
  // Inserts a visible, ticking "live" pill into the nav (unmistakable proof
  // the packaged JS is running) and takes over from the no-JS <meta refresh>
  // with a pausable, tab-visibility-aware countdown.
  function setupRefresh() {
    var pill = document.createElement("span");
    pill.id = "live-pill";
    var btn = document.createElement("button");
    btn.type = "button";
    btn.id = "live-toggle";
    var status = document.createElement("span");
    status.id = "live-status";
    pill.appendChild(status);
    pill.appendChild(document.createTextNode(" "));
    pill.appendChild(btn);
    var nav = document.querySelector("nav");
    if (nav) nav.appendChild(pill);
    else document.body.insertBefore(pill, document.body.firstChild);

    var meta = document.querySelector('meta[http-equiv="refresh"]');
    var secs = meta ? parseInt(meta.getAttribute("content"), 10) : 0;
    if (meta) meta.parentNode.removeChild(meta); // JS takes over the refresh

    if (!secs || secs < 1) {
      status.textContent = "● JS active";
      btn.style.display = "none";
      return;
    }
    // Remember the pause choice across reloads too (another "setting" the
    // refresh must not silently reset).
    var pauseKey = "thlive:paused";
    var stored; try { stored = localStorage.getItem(pauseKey); } catch (e) { stored = null; }
    var paused = stored === "1", remaining = secs;
    function render() {
      btn.textContent = paused ? "resume" : "pause";
      status.textContent = paused ? "❙❙ live paused" : ("● live · refresh " + remaining + "s");
    }
    btn.addEventListener("click", function () {
      paused = !paused;
      if (!paused) remaining = secs;
      try { localStorage.setItem(pauseKey, paused ? "1" : "0"); } catch (e) { /* ignore */ }
      render();
    });
    var busy = false;
    setInterval(function () {
      if (paused || document.hidden) { render(); return; }
      if (busy) return;
      if (--remaining > 0) { render(); return; }
      busy = true;
      status.textContent = "● live · updating…";
      smartRefresh(function () { busy = false; remaining = secs; render(); });
    }, 1000);
    render();
  }

  // ---- sortable data tables ---------------------------------------------
  // Sort choices PERSIST across the auto-refresh reload (and revisits): when a
  // header is clicked we save {col,dir} in localStorage keyed by the page +
  // table, and re-apply it on load. So a timer refresh never resets the
  // operator's chosen column/order.
  function tableKey(t, idx) {
    if (t.id) return t.id;
    // Derive a stable key from the header labels so it survives reloads.
    var hs = [];
    Array.prototype.forEach.call(t.querySelectorAll("tr:first-child th"), function (h) {
      hs.push((h.textContent || "").trim().slice(0, 12));
    });
    return "t" + idx + ":" + hs.join("|");
  }
  function sortStoreKey(t, idx) { return "thsort:" + location.pathname + "#" + tableKey(t, idx); }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* private mode */ } }

  function applySort(t, headerRow, ths, col, dir, persist) {
    sortTable(t, headerRow, col, dir);
    Array.prototype.forEach.call(ths, function (o) {
      o.removeAttribute("data-arrow");
      o.removeAttribute("data-dir");
    });
    if (ths[col]) {
      ths[col].setAttribute("data-dir", dir === 1 ? "1" : "-1");
      ths[col].setAttribute("data-arrow", dir === 1 ? "▲" : "▼");
    }
    if (persist) lsSet(sortStoreKey(t, t._sortIdx), col + "," + dir);
  }

  function setupSort() {
    var tables = document.querySelectorAll("table");
    Array.prototype.forEach.call(tables, function (t, tIdx) {
      if (t.classList.contains("chart")) return;          // CSS bar charts
      var headerRow = t.querySelector("tr");
      if (!headerRow) return;
      var ths = headerRow.querySelectorAll("th");
      if (!ths.length) return;
      if (headerRow.querySelector("th a")) return;        // server-sorted
      t._sortIdx = tIdx;
      Array.prototype.forEach.call(ths, function (th, idx) {
        th.classList.add("sortable");
        th.addEventListener("click", function () {
          var dir = th.getAttribute("data-dir") === "1" ? -1 : 1;
          applySort(t, headerRow, ths, idx, dir, true);
        });
      });
      // Restore a previously chosen sort for this table.
      var saved = lsGet(sortStoreKey(t, tIdx));
      if (saved) {
        var parts = saved.split(",");
        var col = parseInt(parts[0], 10), dir = parseInt(parts[1], 10) === -1 ? -1 : 1;
        if (col >= 0 && col < ths.length) applySort(t, headerRow, ths, col, dir, false);
      }
    });
  }
  function sortTable(table, headerRow, col, dir) {
    var rows = Array.prototype.filter.call(table.rows, function (r) {
      return r !== headerRow && r.cells.length > col;
    });
    rows.sort(function (a, b) {
      var x = cellVal(a.cells[col]), y = cellVal(b.cells[col]);
      if (typeof x === "number" && typeof y === "number") return (x - y) * dir;
      return String(x).localeCompare(String(y)) * dir;
    });
    var parent = rows.length ? rows[0].parentNode : table;
    rows.forEach(function (r) { parent.appendChild(r); });
  }
  function cellVal(td) {
    var s = (td.textContent || "").trim();
    if (/^[-\d.,\s]+$/.test(s) && /\d/.test(s)) {
      var n = parseFloat(s.replace(/[,\s]/g, ""));
      if (!isNaN(n)) return n;
    }
    return s.toLowerCase();
  }

  // ---- client-side row filter -------------------------------------------
  function setupFilter() {
    var tables = document.querySelectorAll("table[data-filter]");
    Array.prototype.forEach.call(tables, function (t) {
      var box = document.createElement("input");
      box.type = "text";
      box.placeholder = "filter rows…";
      box.className = "tablefilter";
      t.parentNode.insertBefore(box, t);
      var headerRow = t.querySelector("tr");
      box.addEventListener("input", function () {
        var q = box.value.toLowerCase();
        Array.prototype.forEach.call(t.rows, function (r) {
          if (r === headerRow) return;
          r.style.display = r.textContent.toLowerCase().indexOf(q) >= 0 ? "" : "none";
        });
      });
    });
  }

  // ---- node-link graph (correlation pivots) -----------------------------
  // A [data-graph] element whose textContent is JSON {nodes:[{id,label,group}],
  // edges:[{from,to}]} is rendered as an SVG radial node-link graph. Pure
  // client-side; no external graph library.
  function setupGraphs() {
    // Inline JSON in textContent.
    Array.prototype.forEach.call(document.querySelectorAll("[data-graph]"), function (el) {
      var data;
      try { data = JSON.parse(el.textContent); } catch (e) { return; }
      drawInto(el, data);
    });
    // Base64-encoded JSON in a data attribute (HTML-escaping-safe).
    Array.prototype.forEach.call(document.querySelectorAll("[data-graph-b64]"), function (el) {
      var data;
      try { data = JSON.parse(decodeURIComponent(escape(window.atob(el.getAttribute("data-graph-b64"))))); }
      catch (e) { return; }
      drawInto(el, data);
    });
  }
  function drawInto(el, data) {
    if (!data || !data.nodes || !data.nodes.length) return;
    el.textContent = "";
    el.appendChild(renderGraph(data));
  }
  function svg(tag, attrs) {
    var e = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (var k in attrs) if (attrs.hasOwnProperty(k)) e.setAttribute(k, attrs[k]);
    return e;
  }
  function renderGraph(data) {
    var W = 720, H = Math.max(260, 60 + data.nodes.length * 26);
    var root = svg("svg", { viewBox: "0 0 " + W + " " + H, class: "graph", width: "100%" });
    // Lay nodes out in columns by group order (a simple layered layout).
    var groups = [];
    data.nodes.forEach(function (n) { if (groups.indexOf(n.group) < 0) groups.push(n.group); });
    var colX = {}, colCount = {}, colIndex = {};
    groups.forEach(function (g, i) { colX[g] = 80 + i * ((W - 160) / Math.max(1, groups.length - 1 || 1)); colCount[g] = 0; });
    data.nodes.forEach(function (n) { colCount[n.group]++; });
    var pos = {};
    data.nodes.forEach(function (n) {
      colIndex[n.group] = (colIndex[n.group] || 0);
      var c = colCount[n.group];
      var y = H * (colIndex[n.group] + 1) / (c + 1);
      pos[n.id] = { x: colX[n.group], y: y };
      colIndex[n.group]++;
    });
    (data.edges || []).forEach(function (ed) {
      var a = pos[ed.from], b = pos[ed.to];
      if (!a || !b) return;
      root.appendChild(svg("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge" }));
    });
    data.nodes.forEach(function (n) {
      var p = pos[n.id];
      var g = svg("g", {});
      g.appendChild(svg("circle", { cx: p.x, cy: p.y, r: 5, class: "node node-" + (n.group || "") }));
      var label = svg("text", { x: p.x + 9, y: p.y + 4, class: "nlabel" });
      label.textContent = n.label || n.id;
      g.appendChild(label);
      root.appendChild(g);
    });
    return root;
  }

  // ---- toggleable widgets ------------------------------------------------
  // Each chart figure becomes a show/hide widget; the choice persists in
  // localStorage per page + chart so an operator can curate which views a
  // page shows. State is a class on the figure (CSS hides the contents), so
  // it works regardless of whether charts.js has rendered yet.
  function setupWidgets() {
    var figs = document.querySelectorAll("figure[data-chart]");
    Array.prototype.forEach.call(figs, function (fig, i) {
      var name = fig.getAttribute("data-chart-title") || ("widget-" + i);
      var key = "tcw:" + location.pathname + ":" + name;
      var hidden = false;
      try { hidden = localStorage.getItem(key) === "1"; } catch (e) { /* private mode */ }
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "widget-toggle";
      function apply() {
        fig.classList.toggle("widget-hidden", hidden);
        btn.textContent = hidden ? "show" : "hide";
        btn.setAttribute("aria-expanded", hidden ? "false" : "true");
      }
      btn.addEventListener("click", function (e) {
        e.stopPropagation(); // don't trigger chart zoom
        hidden = !hidden;
        try { localStorage.setItem(key, hidden ? "1" : "0"); } catch (e) { /* ignore */ }
        apply();
      });
      fig.insertBefore(btn, fig.firstChild);
      apply();
    });
  }

  // ---- tooltip help ------------------------------------------------------
  // Any element with data-help gets a small "?" affordance whose native title
  // shows the help text on hover/focus (CSP-safe; no custom tooltip layer).
  function setupHelp() {
    Array.prototype.forEach.call(document.querySelectorAll("[data-help]"), function (el) {
      if (el.querySelector(".help")) return;
      var q = document.createElement("span");
      q.className = "help";
      q.textContent = "?";
      q.tabIndex = 0;
      q.setAttribute("role", "note");
      q.title = el.getAttribute("data-help");
      el.appendChild(document.createTextNode(" "));
      el.appendChild(q);
    });
  }

  // ---- attack-timeline order toggle -------------------------------------
  // The server renders each source's events newest-first; this button flips
  // every timeline table to oldest-first (and back), and the choice persists
  // across the auto-refresh reload.
  function setupTimelineOrder() {
    var btn = document.getElementById("tl-order");
    if (!btn) return;
    var key = "tltimeorder";
    var desired = lsGet(key) === "old" ? "old" : "new"; // server order = "new"
    function reverseTable(t) {
      var rows = Array.prototype.slice.call(t.rows);
      var parent = rows.length ? rows[0].parentNode : t;
      for (var i = rows.length - 1; i >= 0; i--) parent.appendChild(rows[i]);
    }
    function apply() {
      Array.prototype.forEach.call(document.querySelectorAll("table.tl-events"), function (t) {
        var cur = t.getAttribute("data-order") || "new"; // as rendered
        if (cur !== desired) { reverseTable(t); t.setAttribute("data-order", desired); }
      });
      btn.textContent = desired === "new" ? "order: newest first" : "order: oldest first";
    }
    btn.addEventListener("click", function () {
      desired = desired === "new" ? "old" : "new";
      lsSet(key, desired);
      apply();
    });
    apply();
  }

  // ---- rows-per-page (client-side display cap) --------------------------
  // Every data list gets a "Rows" <select> (10/25/50/100/All) capping how many
  // rows show at once. Implemented as a CSS class on the table (.rpp-N hides
  // rows past N via :nth-child), so it composes with client-side sort — which
  // just reorders the same rows — and survives the auto-refresh reload via a
  // per-page+table localStorage key. Progressive enhancement: JS off => the
  // server-rendered full list shows.
  var RPP_OPTS = [10, 25, 50, 100];
  var RPP_DEFAULT = "25";
  function setupRowsPerPage() {
    Array.prototype.forEach.call(document.querySelectorAll("table"), function (t, idx) {
      if (t.classList.contains("chart")) return;        // CSS bar charts
      if (t.classList.contains("tl-events")) return;     // per-source timeline tables
      var headerRow = t.querySelector("tr");
      if (!headerRow || !headerRow.querySelector("th")) return;
      var body = t.tBodies[0] || t;
      var dataRows = body.rows.length - 1;               // minus the header row
      if (dataRows <= RPP_OPTS[0] + 1) return;           // too small to paginate

      // A "server-backed" table (the /events + /search listings) is capped by
      // the server's ?limit=, so its Rows control must RE-QUERY the server —
      // a pure CSS cap can never reveal rows the server didn't send. Other
      // tables stay a client-side display cap.
      var serverBacked = t.hasAttribute("data-rows-server");

      var key = "throws:" + location.pathname + "#" + tableKey(t, idx);
      var saved = lsGet(key);
      var cur = (saved === "all" || RPP_OPTS.indexOf(parseInt(saved, 10)) >= 0) ? saved : RPP_DEFAULT;
      if (serverBacked) {
        // Reflect the live server limit, not a stored display pref.
        var lp = new URLSearchParams(location.search).get("limit");
        cur = (lp === "all" || lp === "0") ? "all" : (lp || String(dataRows));
      }

      var wrap = document.createElement("div");
      wrap.className = "rowsctl";
      var lab = document.createElement("label");
      lab.textContent = "Rows ";
      var sel = document.createElement("select");
      RPP_OPTS.forEach(function (n) {
        var o = document.createElement("option");
        o.value = String(n); o.textContent = String(n);
        sel.appendChild(o);
      });
      var oAll = document.createElement("option");
      oAll.value = "all"; oAll.textContent = "All";
      sel.appendChild(oAll);
      // If the active server limit isn't one of the presets, surface it so the
      // dropdown shows the truth ("showing 320 of 320").
      if (serverBacked && cur !== "all" && RPP_OPTS.indexOf(parseInt(cur, 10)) < 0) {
        var oCur = document.createElement("option");
        oCur.value = cur; oCur.textContent = cur;
        sel.appendChild(oCur);
      }
      sel.value = cur;
      lab.appendChild(sel);
      var count = document.createElement("span");
      count.className = "rowsctl-count";
      wrap.appendChild(lab);
      wrap.appendChild(count);
      t.parentNode.insertBefore(wrap, t);

      if (serverBacked) {
        count.textContent = " showing " + dataRows;
        sel.addEventListener("change", function () {
          var u = new URL(location.href);
          u.searchParams.set("limit", sel.value); // "all" or a number
          location.assign(u.toString());
        });
        return;
      }

      function apply() {
        RPP_OPTS.forEach(function (n) { t.classList.remove("rpp-" + n); });
        if (sel.value !== "all") t.classList.add("rpp-" + sel.value);
        var shown = sel.value === "all" ? dataRows : Math.min(dataRows, parseInt(sel.value, 10));
        count.textContent = " showing " + shown + " of " + dataRows;
      }
      sel.addEventListener("change", function () { lsSet(key, sel.value); apply(); });
      apply();
    });
  }

  // ---- external-link guard ----------------------------------------------
  // Any click on a link that leaves this sensor (a different host, http/https)
  // pops a confirm() naming the destination, so an operator never silently
  // hands a request off to attack.mitre.org / nvd / cve.org / a map-tiles host.
  // Capture phase + CSP-safe (addEventListener, no inline handler).
  function setupExternalLinkGuard() {
    document.addEventListener("click", function (e) {
      var a = e.target && e.target.closest && e.target.closest("a[href]");
      if (!a) return;
      var href = a.getAttribute("href");
      if (!href || href.charAt(0) === "#") return;
      var u;
      try { u = new URL(href, location.href); } catch (_) { return; }
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      if (u.host === location.host) return; // internal — let it through
      if (!window.confirm("You are about to LEAVE this sensor and open an external site:\n\n" + u.href + "\n\nContinue?")) {
        e.preventDefault();
        e.stopPropagation();
      }
    }, true);
  }

  // Config-page YAML live search — a named enhancer so it re-binds after an
  // in-place refresh swap (its elements are replaced on each update).
  function setupConfigSearch() {
    var input = document.getElementById("config-q");
    var box = document.querySelector(".config-yaml");
    if (!input || !box) return;
    var linesOnly = document.querySelector(".config-search-toggle input");
    var raw = box.textContent; // snapshot plain text (no inherited <mark> tags)
    function esc(s) {
      return s.replace(/[&<>"']/g, function (c) {
        return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
      });
    }
    function render() {
      var q = input.value;
      if (!q) { box.innerHTML = esc(raw); return; }
      var needle = q.toLowerCase(), only = !!(linesOnly && linesOnly.checked), out = [];
      var lines = raw.split("\n");
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i], low = line.toLowerCase(), pos = low.indexOf(needle);
        if (pos < 0) { if (!only) out.push(esc(line)); continue; }
        var cursor = 0, buf = "";
        while (pos >= 0) {
          buf += esc(line.slice(cursor, pos));
          buf += "<mark>" + esc(line.slice(pos, pos + q.length)) + "</mark>";
          cursor = pos + q.length;
          if (cursor >= line.length) break;
          pos = low.indexOf(needle, cursor);
        }
        if (cursor < line.length) buf += esc(line.slice(cursor));
        out.push(buf);
      }
      box.innerHTML = out.join("\n");
    }
    input.addEventListener("input", render);
    if (linesOnly) linesOnly.addEventListener("change", render);
  }

  // Range persistence: keep the chosen time window (24h / 7d / …) when the user
  // moves between pages. The active range is remembered (localStorage) and
  // appended to every nav link, so switching pages keeps the same window. The
  // param-less "24h" chip resets it. Pure presentation — no-JS users just don't
  // get cross-page persistence.
  var RANGE_KEY = "tarpit.range";
  function rangeOfHref(href) {
    var m = /[?&]range=([^&]+)/.exec(href || "");
    return m ? decodeURIComponent(m[1]) : "24h";
  }
  function setupRangePersist() {
    var params = new URLSearchParams(location.search);
    var urlRange = params.get("range");
    if (urlRange) lsSet(RANGE_KEY, urlRange);
    // Record explicit range-selector clicks (including the param-less 24h chip).
    Array.prototype.forEach.call(document.querySelectorAll(".rangesel a"), function (a) {
      a.addEventListener("click", function () { lsSet(RANGE_KEY, rangeOfHref(a.getAttribute("href"))); });
    });
    var active = urlRange || lsGet(RANGE_KEY) || "24h";
    if (!active || active === "24h") return;
    Array.prototype.forEach.call(document.querySelectorAll("nav a"), function (a) {
      var href = a.getAttribute("href");
      if (!href || href.charAt(0) !== "/" || /[?&]range=/.test(href)) return;
      a.setAttribute("href", href + (href.indexOf("?") >= 0 ? "&" : "?") + "range=" + encodeURIComponent(active));
    });
  }

  // Copy-to-clipboard buttons. Any <button class="copybtn"> copies the text of
  // its data-copy attribute, or (default) the textContent of its previous
  // element sibling — used next to displayed base64 / payload strings.
  function copyText(text, btn) {
    var done = function (ok) {
      if (!ok) return;
      var prev = btn.textContent;
      btn.classList.add("copied");
      btn.textContent = "✓ copied";
      setTimeout(function () { btn.classList.remove("copied"); btn.textContent = prev; }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(fallbackCopy(text)); });
    } else {
      done(fallbackCopy(text));
    }
  }
  function fallbackCopy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.focus(); ta.select();
      var ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (e) { return false; }
  }
  function setupCopyButtons() {
    Array.prototype.forEach.call(document.querySelectorAll("button.copybtn"), function (btn) {
      if (btn.dataset.copyWired) return;
      btn.dataset.copyWired = "1";
      btn.addEventListener("click", function () {
        var text = btn.getAttribute("data-copy");
        if (text == null) {
          var src = btn.previousElementSibling;
          text = src ? (src.textContent || "") : "";
        }
        copyText(text.trim(), btn);
      });
    });
  }

  // Enhancers that inject controls into / operate on the page CONTENT. Re-run
  // after each in-place refresh swap (the once-only ones — refresh + the
  // document-level external-link guard — are not in this list).
  // ---- live service pulse (summary board) --------------------------------
  // On each refresh, diff every service card's packet counter against the
  // previous snapshot (per page, in sessionStorage). A counter that rose pulses
  // (flash x3 via .svc-flash); a service that went from 0 to active glows green
  // (.svc-new). The first snapshot of a session is a silent baseline, so a fresh
  // page load doesn't light up everything. Works for both the JS in-place swap
  // (this re-runs after it) and the no-JS <meta refresh> (full reload; the
  // sessionStorage snapshot persists).
  function setupServicePulse() {
    var cards = document.querySelectorAll(".pcard[data-svc]");
    if (!cards.length) return;
    var key = "thsvc:" + location.pathname;
    var prev = null;
    try {
      var raw = sessionStorage.getItem(key);
      if (raw) prev = JSON.parse(raw);
    } catch (e) { /* storage blocked: degrade to no-pulse */ }
    var cur = {};
    Array.prototype.forEach.call(cards, function (card) {
      var svc = card.getAttribute("data-svc");
      var hits = parseInt(card.getAttribute("data-hits") || "0", 10) || 0;
      cur[svc] = hits;
      if (!prev) return; // baseline snapshot only
      var old = prev[svc] || 0;
      if (hits > old) {
        pulse(card, "svc-flash");             // counter rose → flash x3
        if (old === 0) pulse(card, "svc-new"); // 0 → active → temporary green
      }
    });
    try { sessionStorage.setItem(key, JSON.stringify(cur)); } catch (e) { /* ignore */ }
  }

  // pulse (re)starts a one-shot animation class and removes it when the
  // animation ends, so the same card can pulse again on the next change.
  function pulse(el, cls) {
    el.classList.remove(cls);
    void el.offsetWidth; // force reflow so re-adding restarts the animation
    el.classList.add(cls);
    el.addEventListener("animationend", function h(ev) {
      if (ev.target === el) {
        el.classList.remove(cls);
        el.removeEventListener("animationend", h);
      }
    });
  }

  var contentEnhancers = [setupSort, setupFilter, setupRowsPerPage, setupGraphs, setupWidgets, setupHelp, setupTimelineOrder, setupConfigSearch, setupRangePersist, setupCopyButtons, setupServicePulse];
  function runContentEnhancers() {
    contentEnhancers.forEach(function (fn) { try { fn(); } catch (e) { /* never break the page */ } });
  }

  ready(function () {
    runContentEnhancers();
    try { setupExternalLinkGuard(); } catch (e) { /* ignore */ }
    try { setupRefresh(); } catch (e) { /* ignore */ }
  });
})();
