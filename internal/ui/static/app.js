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
    var paused = false, remaining = secs;
    function render() {
      btn.textContent = paused ? "resume" : "pause";
      status.textContent = paused ? "❙❙ live paused" : ("● live · refresh " + remaining + "s");
    }
    btn.addEventListener("click", function () {
      paused = !paused;
      if (!paused) remaining = secs;
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
  function setupSort() {
    var tables = document.querySelectorAll("table");
    Array.prototype.forEach.call(tables, function (t) {
      if (t.classList.contains("chart")) return;          // CSS bar charts
      var headerRow = t.querySelector("tr");
      if (!headerRow) return;
      var ths = headerRow.querySelectorAll("th");
      if (!ths.length) return;
      if (headerRow.querySelector("th a")) return;        // server-sorted
      Array.prototype.forEach.call(ths, function (th, idx) {
        th.classList.add("sortable");
        th.addEventListener("click", function () {
          var dir = th.getAttribute("data-dir") === "1" ? -1 : 1;
          sortTable(t, headerRow, idx, dir);
          Array.prototype.forEach.call(ths, function (o) {
            o.removeAttribute("data-arrow");
            o.removeAttribute("data-dir");
          });
          th.setAttribute("data-dir", dir === 1 ? "1" : "-1");
          th.setAttribute("data-arrow", dir === 1 ? "▲" : "▼");
        });
      });
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

  ready(function () {
    [setupRefresh, setupSort, setupFilter, setupGraphs].forEach(function (fn) {
      try { fn(); } catch (e) { /* never break the page */ }
    });
  });
})();
