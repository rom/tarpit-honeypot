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
    setInterval(function () {
      if (paused || document.hidden) { render(); return; }
      if (--remaining <= 0) { window.location.reload(); return; }
      render();
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

  ready(function () {
    [setupRefresh, setupSort, setupFilter, setupGraphs, setupWidgets, setupHelp, setupTimelineOrder].forEach(function (fn) {
      try { fn(); } catch (e) { /* never break the page */ }
    });
  });
})();

// Config-page YAML search — live (type-as-you-go) over the already-rendered
// body. The no-JS path still works via the GET form: when this script runs
// it captures the original YAML text and re-renders the box on every input
// event, so the user sees matches highlighted without a full page reload.
(function () {
  var input = document.getElementById("config-q");
  var box = document.querySelector(".config-yaml");
  if (!input || !box) return;
  var linesOnly = document.querySelector(".config-search-toggle input");

  // Snapshot the YAML once as plain text so we can re-render cleanly after
  // any prior filter pass (otherwise we'd inherit our own <mark> tags).
  var raw = box.textContent;

  function esc(s) {
    return s.replace(/[&<>"']/g, function (c) {
      return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c];
    });
  }

  function render() {
    var q = input.value;
    if (!q) { box.innerHTML = esc(raw); return; }
    var needle = q.toLowerCase();
    var only = !!(linesOnly && linesOnly.checked);
    var out = [];
    var lines = raw.split("\n");
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var low = line.toLowerCase();
      var pos = low.indexOf(needle);
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
})();
