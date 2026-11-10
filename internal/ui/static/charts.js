"use strict";
// tarpit-honeypot charting library (charts.js).
//
// Self-contained, dependency-free, SVG-based, served from the binary (no CDN —
// the sensor host is a target; assets load same-origin under CSP script-src
// 'self'; no inline script, no eval). Companion to app.js.
//
// Two ways to use it:
//
//   1. Declarative (progressive enhancement). Put a container in the page:
//        <figure data-chart="bar" data-chart-b64="<base64 JSON>">fallback</figure>
//      or with inline JSON in textContent:
//        <figure data-chart="pie">{ "slices": [...] }</figure>
//      charts.js renders it on load; the fallback (a table/note) shows with JS
//      off. data-chart-title sets a heading.
//
//   2. Programmatic:
//        TarpitCharts.render(el, "line", data);
//        var svg = TarpitCharts.charts.heatmap(data);
//
// Chart types & their JSON shapes are documented at each renderer below:
//   bar, hbar, pie, histogram, scatter, line, area, heatmap, topology,
//   network, sankey, timeline, sourcemap, sessionreplay, creds.
window.TarpitCharts = (function () {
  var NS = "http://www.w3.org/2000/svg";
  // Read palette / ramp / severity colors from CSS variables on <html> so the
  // active theme drives them. theme.js runs synchronously before this script,
  // so the theme class and its overrides are already in effect.
  function cssvar(name, fallback) {
    try {
      var v = getComputedStyle(document.documentElement).getPropertyValue(name);
      v = v && v.trim();
      return v || fallback;
    } catch (e) { return fallback; }
  }
  // Categorical palette (color-blind-friendly-ish, dark enough on white).
  var PALETTE = [
    cssvar("--palette-1", "#4a6fa5"), cssvar("--palette-2", "#b35900"),
    cssvar("--palette-3", "#2a9d4a"), cssvar("--palette-4", "#9c4f96"),
    cssvar("--palette-5", "#c0506a"), cssvar("--palette-6", "#1a8f9c"),
    cssvar("--palette-7", "#b08a00"), cssvar("--palette-8", "#6a6f7a"),
    cssvar("--palette-9", "#7a5cc0"), cssvar("--palette-10", "#3a7d3a")
  ];
  // Sequential ramp for heatmaps (low -> high).
  var RAMP = [
    cssvar("--ramp-0", "#f7fbff"), cssvar("--ramp-1", "#dbe9f6"),
    cssvar("--ramp-2", "#b3d3ea"), cssvar("--ramp-3", "#7fb0d6"),
    cssvar("--ramp-4", "#4a86bd"), cssvar("--ramp-5", "#2a5f9e"),
    cssvar("--ramp-6", "#143e7a")
  ];
  var SEV = {
    low:      cssvar("--bar-default",  "#6b8fb5"),
    medium:   cssvar("--bar-medium",   "#d59a3a"),
    high:     cssvar("--bar-high",     "#c0506a"),
    critical: cssvar("--bar-critical", "#b00020")
  };
  var HEATMAP_ZERO = cssvar("--heatmap-zero", "#f4f6f9");

  function el(tag, attrs, kids) {
    var e = document.createElementNS(NS, tag);
    if (attrs) for (var k in attrs) if (attrs.hasOwnProperty(k) && attrs[k] != null) e.setAttribute(k, attrs[k]);
    if (kids) (Array.isArray(kids) ? kids : [kids]).forEach(function (c) {
      if (c != null) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
    });
    return e;
  }
  function text(x, y, s, cls, attrs) {
    var a = { x: x, y: y, class: cls || "c-lbl" };
    if (attrs) for (var k in attrs) a[k] = attrs[k];
    var t = el("text", a); t.textContent = s == null ? "" : String(s); return t;
  }
  function title(node, s) { if (s != null) node.appendChild(el("title", {}, String(s))); return node; }
  function color(i, explicit) { return explicit || PALETTE[i % PALETTE.length]; }
  function num(v) { v = +v; return isFinite(v) ? v : 0; }
  function fmt(v) {
    v = +v;
    if (!isFinite(v)) return "0";
    if (Math.abs(v) >= 1e9) return (v / 1e9).toFixed(1) + "G";
    if (Math.abs(v) >= 1e6) return (v / 1e6).toFixed(1) + "M";
    if (Math.abs(v) >= 1e3) return (v / 1e3).toFixed(1) + "k";
    return (Math.round(v * 100) / 100).toString();
  }
  function maxOf(arr, f) { var m = 0; arr.forEach(function (d) { var v = f(d); if (v > m) m = v; }); return m; }
  function svgRoot(w, h, cls) {
    return el("svg", { viewBox: "0 0 " + w + " " + h, class: "tc " + (cls || ""), width: "100%", preserveAspectRatio: "xMidYMid meet", role: "img" });
  }
  function legend(items) {
    var box = document.createElement("div");
    box.className = "tc-legend";
    items.forEach(function (it) {
      var s = document.createElement("span");
      s.className = "tc-leg";
      var sw = document.createElement("i"); sw.style.background = it.color; sw.className = "tc-sw";
      s.appendChild(sw); s.appendChild(document.createTextNode(" " + it.label));
      box.appendChild(s);
    });
    return box;
  }
  // Build a "nice" axis max (1/2/5 * 10^n) above v.
  function niceMax(v) {
    if (v <= 0) return 1;
    var exp = Math.floor(Math.log(v) / Math.LN10), base = v / Math.pow(10, exp);
    var step = base <= 1 ? 1 : base <= 2 ? 2 : base <= 5 ? 5 : 10;
    return step * Math.pow(10, exp);
  }

  var charts = {};

  // bar (vertical): { series:[{label,value,color?,sev?}], ymax? }
  charts.bar = function (d) {
    var s = d.series || [], W = 720, H = 300, P = { l: 44, r: 12, t: 14, b: 64 };
    var max = niceMax(d.ymax || maxOf(s, function (x) { return num(x.value); }) || 1);
    var iw = W - P.l - P.r, ih = H - P.t - P.b, bw = iw / Math.max(1, s.length);
    var root = svgRoot(W, H, "tc-bar");
    for (var g = 0; g <= 4; g++) {
      var gy = P.t + ih * g / 4;
      root.appendChild(el("line", { x1: P.l, y1: gy, x2: W - P.r, y2: gy, class: "tc-grid" }));
      root.appendChild(text(P.l - 6, gy + 4, fmt(max * (4 - g) / 4), "tc-ax", { "text-anchor": "end" }));
    }
    s.forEach(function (x, i) {
      var v = num(x.value), bh = ih * v / max, bx = P.l + i * bw + bw * 0.15, by = P.t + ih - bh;
      var r = el("rect", { x: bx, y: by, width: bw * 0.7, height: Math.max(0, bh), class: "tc-barrect", fill: x.sev ? SEV[x.sev] : color(i, x.color) });
      title(r, (x.label || "") + ": " + fmt(v)); root.appendChild(r);
      root.appendChild(text(bx + bw * 0.35, P.t + ih + 14, x.label, "tc-ax", { "text-anchor": "end", transform: "rotate(-35 " + (bx + bw * 0.35) + " " + (P.t + ih + 14) + ")" }));
    });
    return root;
  };

  // hbar (horizontal): { series:[{label,value,color?,sev?}] }
  charts.hbar = function (d) {
    var s = d.series || [], W = 720, rowH = 24, P = { l: 150, r: 80, t: 8, b: 8 };
    var H = P.t + P.b + s.length * rowH || 60;
    var max = niceMax(d.xmax || maxOf(s, function (x) { return num(x.value); }) || 1);
    var sum = s.reduce(function (a, x) { return a + num(x.value); }, 0) || 1;
    var iw = W - P.l - P.r, root = svgRoot(W, H, "tc-hbar");
    s.forEach(function (x, i) {
      var v = num(x.value), y = P.t + i * rowH, bw = iw * v / max;
      var pctTxt = (v * 100 / sum).toFixed(v * 100 / sum < 10 ? 1 : 0) + "%";
      root.appendChild(text(P.l - 8, y + rowH * 0.65, x.label, "tc-ax", { "text-anchor": "end" }));
      var r = el("rect", { x: P.l, y: y + 3, width: Math.max(1, bw), height: rowH - 8, class: "tc-barrect", fill: x.sev ? SEV[x.sev] : color(i, x.color) });
      title(r, (x.label || "") + ": " + fmt(v) + " (" + pctTxt + ")"); root.appendChild(r);
      root.appendChild(text(P.l + bw + 5, y + rowH * 0.65, fmt(v) + " · " + pctTxt, "tc-val"));
    });
    return root;
  };

  // pie / donut: { slices:[{label,value,color?}], donut? }
  charts.pie = function (d) {
    var s = (d.slices || []).filter(function (x) { return num(x.value) > 0; });
    // Wider viewBox + a legend moved left of the right edge so long labels
    // (e.g. "critical (1234)") render fully instead of clipping at the border.
    var W = 470, H = 300, cx = 150, cy = 150, R = 120, r0 = d.donut ? 56 : 0;
    var total = s.reduce(function (a, x) { return a + num(x.value); }, 0) || 1;
    var root = svgRoot(W, H, "tc-pie"), ang = -Math.PI / 2;
    s.forEach(function (x, i) {
      var frac = num(x.value) / total, a2 = ang + frac * 2 * Math.PI, big = frac > 0.5 ? 1 : 0;
      var p = el("path", {
        d: arc(cx, cy, R, r0, ang, a2, big), fill: color(i, x.color), class: "tc-slice"
      });
      title(p, x.label + ": " + fmt(x.value) + " (" + (frac * 100).toFixed(1) + "%)");
      root.appendChild(p); ang = a2;
    });
    var lx = 286, ly = 40;
    s.forEach(function (x, i) {
      var p = (num(x.value) * 100 / total);
      var pctTxt = p.toFixed(p < 10 ? 1 : 0) + "%";
      root.appendChild(el("rect", { x: lx, y: ly + i * 20 - 9, width: 11, height: 11, fill: color(i, x.color) }));
      root.appendChild(text(lx + 16, ly + i * 20, (x.label || "") + " — " + fmt(x.value) + " (" + pctTxt + ")", "tc-ax"));
    });
    return root;
  };
  function arc(cx, cy, R, r0, a1, a2, big) {
    var x1 = cx + R * Math.cos(a1), y1 = cy + R * Math.sin(a1), x2 = cx + R * Math.cos(a2), y2 = cy + R * Math.sin(a2);
    if (r0 <= 0) return "M" + cx + "," + cy + " L" + x1 + "," + y1 + " A" + R + "," + R + " 0 " + big + " 1 " + x2 + "," + y2 + " Z";
    var X1 = cx + r0 * Math.cos(a2), Y1 = cy + r0 * Math.sin(a2), X2 = cx + r0 * Math.cos(a1), Y2 = cy + r0 * Math.sin(a1);
    return "M" + x1 + "," + y1 + " A" + R + "," + R + " 0 " + big + " 1 " + x2 + "," + y2 +
      " L" + X1 + "," + Y1 + " A" + r0 + "," + r0 + " 0 " + big + " 0 " + X2 + "," + Y2 + " Z";
  }

  // histogram: { bins:[{x0,x1,count}] } or { values:[..], bins?:N }
  charts.histogram = function (d) {
    var bins = d.bins;
    if (!bins && d.values) bins = bucketize(d.values, d.bins || 20);
    bins = bins || [];
    var W = 720, H = 280, P = { l: 44, r: 12, t: 12, b: 40 };
    var max = niceMax(maxOf(bins, function (b) { return num(b.count); }) || 1);
    var iw = W - P.l - P.r, ih = H - P.t - P.b, bw = iw / Math.max(1, bins.length), root = svgRoot(W, H, "tc-hist");
    for (var g = 0; g <= 4; g++) { var gy = P.t + ih * g / 4; root.appendChild(el("line", { x1: P.l, y1: gy, x2: W - P.r, y2: gy, class: "tc-grid" })); root.appendChild(text(P.l - 6, gy + 4, fmt(max * (4 - g) / 4), "tc-ax", { "text-anchor": "end" })); }
    bins.forEach(function (b, i) {
      var bh = ih * num(b.count) / max, x = P.l + i * bw;
      var r = el("rect", { x: x + 1, y: P.t + ih - bh, width: Math.max(1, bw - 2), height: Math.max(0, bh), class: "tc-barrect", fill: PALETTE[0] });
      title(r, "[" + fmt(b.x0) + ", " + fmt(b.x1) + "): " + b.count); root.appendChild(r);
      if (i % Math.ceil(bins.length / 10) === 0) root.appendChild(text(x, P.t + ih + 14, fmt(b.x0), "tc-ax"));
    });
    return root;
  };
  function bucketize(vals, n) {
    vals = vals.map(num); var lo = Math.min.apply(null, vals), hi = Math.max.apply(null, vals);
    if (lo === hi) hi = lo + 1; var w = (hi - lo) / n, out = [];
    for (var i = 0; i < n; i++) out.push({ x0: lo + i * w, x1: lo + (i + 1) * w, count: 0 });
    vals.forEach(function (v) { var k = Math.min(n - 1, Math.floor((v - lo) / w)); out[k].count++; });
    return out;
  }

  // scatter: { points:[{x,y,r?,label?,group?}], xlabel?, ylabel? }
  charts.scatter = function (d) {
    var pts = d.points || [], W = 720, H = 360, P = { l: 50, r: 14, t: 14, b: 40 };
    var xmax = niceMax(maxOf(pts, function (p) { return num(p.x); }) || 1), ymax = niceMax(maxOf(pts, function (p) { return num(p.y); }) || 1);
    var iw = W - P.l - P.r, ih = H - P.t - P.b, root = svgRoot(W, H, "tc-scatter");
    var groups = []; pts.forEach(function (p) { if (p.group != null && groups.indexOf(p.group) < 0) groups.push(p.group); });
    for (var g = 0; g <= 4; g++) {
      var gy = P.t + ih * g / 4; root.appendChild(el("line", { x1: P.l, y1: gy, x2: W - P.r, y2: gy, class: "tc-grid" }));
      root.appendChild(text(P.l - 6, gy + 4, fmt(ymax * (4 - g) / 4), "tc-ax", { "text-anchor": "end" }));
      var gx = P.l + iw * g / 4; root.appendChild(text(gx, P.t + ih + 16, fmt(xmax * g / 4), "tc-ax"));
    }
    pts.forEach(function (p) {
      var cx = P.l + iw * num(p.x) / xmax, cy = P.t + ih - ih * num(p.y) / ymax;
      var c = el("circle", { cx: cx, cy: cy, r: p.r ? Math.max(2, num(p.r)) : 4, class: "tc-pt", fill: color(groups.indexOf(p.group) < 0 ? 0 : groups.indexOf(p.group), p.color), "fill-opacity": 0.7 });
      title(c, (p.label ? p.label + " " : "") + "(" + fmt(p.x) + ", " + fmt(p.y) + ")"); root.appendChild(c);
    });
    if (d.xlabel) root.appendChild(text(P.l + iw / 2, H - 4, d.xlabel, "tc-axt"));
    if (d.ylabel) root.appendChild(text(14, P.t + ih / 2, d.ylabel, "tc-axt", { transform: "rotate(-90 14 " + (P.t + ih / 2) + ")" }));
    return root;
  };

  // line / timeseries: { series:[{name,color?,points:[{x,y}]}], xType?:"time" }
  charts.line = function (d) {
    var series = d.series || [], W = 720, H = 320, P = { l: 52, r: 14, t: 14, b: 46 };
    var all = []; series.forEach(function (s) { (s.points || []).forEach(function (p) { all.push(p); }); });
    if (!all.length) return svgRoot(W, H, "tc-line");
    var xs = all.map(function (p) { return num(p.x); }), xmin = Math.min.apply(null, xs), xmax = Math.max.apply(null, xs);
    if (xmin === xmax) xmax = xmin + 1;
    var ymax = niceMax(maxOf(all, function (p) { return num(p.y); }) || 1);
    var iw = W - P.l - P.r, ih = H - P.t - P.b, root = svgRoot(W, H, "tc-line");
    for (var g = 0; g <= 4; g++) { var gy = P.t + ih * g / 4; root.appendChild(el("line", { x1: P.l, y1: gy, x2: W - P.r, y2: gy, class: "tc-grid" })); root.appendChild(text(P.l - 6, gy + 4, fmt(ymax * (4 - g) / 4), "tc-ax", { "text-anchor": "end" })); }
    for (var t = 0; t <= 5; t++) { var xx = xmin + (xmax - xmin) * t / 5, px = P.l + iw * t / 5; root.appendChild(text(px, P.t + ih + 16, d.xType === "time" ? tlabel(xx) : fmt(xx), "tc-ax", { "text-anchor": "middle" })); }
    function X(v) { return P.l + iw * (num(v) - xmin) / (xmax - xmin); }
    function Y(v) { return P.t + ih - ih * num(v) / ymax; }
    series.forEach(function (s, i) {
      var pts = (s.points || []).slice().sort(function (a, b) { return num(a.x) - num(b.x); });
      var dpath = pts.map(function (p, j) { return (j ? "L" : "M") + X(p.x).toFixed(1) + "," + Y(p.y).toFixed(1); }).join(" ");
      root.appendChild(el("path", { d: dpath, fill: "none", stroke: color(i, s.color), "stroke-width": 2, class: "tc-pl" }));
      pts.forEach(function (p) { title(el("circle", { cx: X(p.x), cy: Y(p.y), r: 2.5, fill: color(i, s.color) }), s.name + ": " + fmt(p.y)); });
    });
    if (series.length > 1 || series[0].name) wrapLegend(root, series.map(function (s, i) { return { label: s.name || ("series " + (i + 1)), color: color(i, s.color) }; }));
    return root;
  };
  function tlabel(ms) { var dt = new Date(ms); return (dt.getMonth() + 1) + "/" + dt.getDate() + " " + ("0" + dt.getHours()).slice(-2) + ":00"; }

  // area (stacked): { x:[..], series:[{name,values:[..],color?}] }
  charts.area = function (d) {
    var xs = (d.x || []).map(num), series = d.series || [], W = 720, H = 320, P = { l: 52, r: 14, t: 14, b: 46 };
    if (!xs.length) return svgRoot(W, H, "tc-area");
    var totals = xs.map(function (_, i) { return series.reduce(function (a, s) { return a + num((s.values || [])[i]); }, 0); });
    var ymax = niceMax(Math.max.apply(null, totals) || 1);
    var iw = W - P.l - P.r, ih = H - P.t - P.b, root = svgRoot(W, H, "tc-area");
    function X(i) { return P.l + iw * i / Math.max(1, xs.length - 1); }
    function Y(v) { return P.t + ih - ih * v / ymax; }
    for (var g = 0; g <= 4; g++) { var gy = P.t + ih * g / 4; root.appendChild(el("line", { x1: P.l, y1: gy, x2: W - P.r, y2: gy, class: "tc-grid" })); root.appendChild(text(P.l - 6, gy + 4, fmt(ymax * (4 - g) / 4), "tc-ax", { "text-anchor": "end" })); }
    var base = xs.map(function () { return 0; });
    series.forEach(function (s, si) {
      var top = base.map(function (b, i) { return b + num((s.values || [])[i]); });
      var up = xs.map(function (_, i) { return (i ? "L" : "M") + X(i).toFixed(1) + "," + Y(top[i]).toFixed(1); }).join(" ");
      var down = ""; for (var i = xs.length - 1; i >= 0; i--) down += " L" + X(i).toFixed(1) + "," + Y(base[i]).toFixed(1);
      root.appendChild(el("path", { d: up + down + " Z", fill: color(si, s.color), "fill-opacity": 0.78, stroke: color(si, s.color), class: "tc-areapath" }));
      base = top;
    });
    for (var t = 0; t <= 5; t++) { var idx = Math.round((xs.length - 1) * t / 5); root.appendChild(text(X(idx), P.t + ih + 16, d.xType === "time" ? tlabel(xs[idx]) : fmt(xs[idx]), "tc-ax", { "text-anchor": "middle" })); }
    wrapLegend(root, series.map(function (s, i) { return { label: s.name || ("series " + (i + 1)), color: color(i, s.color) }; }));
    return root;
  };

  // heatmap: { rows:[..], cols:[..], cells:[[v,..],..], max?, unit? }
  charts.heatmap = function (d) {
    var rows = d.rows || [], cols = d.cols || [], cells = d.cells || [];
    var cw = 38, ch = 24, P = { l: 130, t: 70, r: 60, b: 8 };
    var W = P.l + cols.length * cw + P.r, H = P.t + rows.length * ch + P.b;
    var max = d.max || maxOf(cells, function (row) { return maxOf(row || [], function (v) { return num(v); }); }) || 1;
    var root = svgRoot(W, H, "tc-heat");
    cols.forEach(function (c, j) { root.appendChild(text(P.l + j * cw + cw / 2, P.t - 6, c, "tc-ax", { "text-anchor": "start", transform: "rotate(-45 " + (P.l + j * cw + cw / 2) + " " + (P.t - 6) + ")" })); });
    rows.forEach(function (rlab, i) {
      root.appendChild(text(P.l - 6, P.t + i * ch + ch * 0.65, rlab, "tc-ax", { "text-anchor": "end" }));
      (cells[i] || []).forEach(function (v, j) {
        var t = max ? num(v) / max : 0, fillc = num(v) === 0 ? HEATMAP_ZERO : RAMP[Math.min(RAMP.length - 1, Math.floor(t * (RAMP.length - 1) + 0.001))];
        var r = el("rect", { x: P.l + j * cw, y: P.t + i * ch, width: cw - 1.5, height: ch - 1.5, fill: fillc, class: "tc-cell" });
        title(r, rlab + " · " + (cols[j] || "") + ": " + fmt(v) + (d.unit ? " " + d.unit : "")); root.appendChild(r);
        if (num(v) > 0 && cw >= 30) root.appendChild(text(P.l + j * cw + cw / 2 - 0.75, P.t + i * ch + ch * 0.62, fmt(v), t > 0.6 ? "tc-cellv hi" : "tc-cellv", { "text-anchor": "middle" }));
      });
    });
    return root;
  };

  // topology: layered node-link (honeynet). { nodes:[{id,label,group,kind?}], edges:[{from,to,label?}] }
  charts.topology = function (d) {
    var nodes = d.nodes || [], edges = d.edges || [];
    var groups = []; nodes.forEach(function (n) { if (groups.indexOf(n.group) < 0) groups.push(n.group); });
    var W = 760, H = Math.max(220, 60 + Math.ceil(nodes.length / Math.max(1, groups.length)) * 46);
    var root = svgRoot(W, H, "tc-topo"), colX = {}, byGroup = {};
    groups.forEach(function (g, i) { colX[g] = 90 + i * ((W - 180) / Math.max(1, groups.length - 1 || 1)); byGroup[g] = []; });
    nodes.forEach(function (n) { byGroup[n.group].push(n); });
    var pos = {};
    groups.forEach(function (g) { byGroup[g].forEach(function (n, i) { pos[n.id] = { x: colX[g], y: H * (i + 1) / (byGroup[g].length + 1) }; }); });
    edges.forEach(function (e) { var a = pos[e.from], b = pos[e.to]; if (a && b) { root.appendChild(el("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "tc-edge" })); } });
    groups.forEach(function (g) { root.appendChild(text(colX[g], 18, g, "tc-grouphdr", { "text-anchor": "middle" })); });
    nodes.forEach(function (n) {
      var p = pos[n.id], g = el("g", {});
      g.appendChild(title(el("circle", { cx: p.x, cy: p.y, r: 7, class: "tc-node k-" + (n.kind || "host") }), (n.label || n.id) + (n.os ? " · " + n.os : "")));
      g.appendChild(text(p.x + 11, p.y + 4, n.label || n.id, "tc-nlabel"));
      root.appendChild(g);
    });
    return root;
  };

  // network: circular force-free node-link. { nodes:[{id,label,group?,weight?}], edges:[{from,to,weight?}] }
  charts.network = function (d) {
    var nodes = d.nodes || [], edges = d.edges || [], W = 640, H = 520, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 60;
    var root = svgRoot(W, H, "tc-net"), pos = {}, n = nodes.length || 1;
    nodes.forEach(function (nd, i) { var a = 2 * Math.PI * i / n - Math.PI / 2; pos[nd.id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) }; });
    edges.forEach(function (e) { var a = pos[e.from], b = pos[e.to]; if (a && b) root.appendChild(title(el("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "tc-edge", "stroke-width": Math.max(1, Math.min(6, num(e.weight) || 1)) }), e.label)); });
    var groups = []; nodes.forEach(function (nd) { if (nd.group != null && groups.indexOf(nd.group) < 0) groups.push(nd.group); });
    nodes.forEach(function (nd) {
      var p = pos[nd.id], r = Math.max(4, Math.min(16, 4 + (num(nd.weight) || 0)));
      root.appendChild(title(el("circle", { cx: p.x, cy: p.y, r: r, class: "tc-node", fill: color(groups.indexOf(nd.group) < 0 ? 0 : groups.indexOf(nd.group)) }), (nd.label || nd.id) + (nd.weight ? " (" + fmt(nd.weight) + ")" : "")));
      root.appendChild(text(p.x, p.y - r - 3, nd.label || nd.id, "tc-nlabel", { "text-anchor": "middle" }));
    });
    return root;
  };

  // shared: bipartite "shared-infrastructure" graph. The left column is the
  // source IPs; the right column is the pivot entities (fingerprints, ASNs,
  // tools, creds, domains, …) they have IN COMMON. Only shared hubs are sent,
  // so every edge is correlation evidence rather than noise, and a barycentre
  // ordering keeps the crossings down so clusters read at a glance.
  //   { sources:[{id,label,sev,count}], hubs:[{id,label,kind,count}],
  //     edges:[{from,to}] }
  var SHARED_KINDS = ["fp", "pubkey", "asn", "tool", "cred", "domain", "ua", "malware"];
  function kindColor(k) { var i = SHARED_KINDS.indexOf(k); return color(i < 0 ? 7 : i); }
  charts.shared = function (d) {
    var sources = (d.sources || []).slice(), hubs = (d.hubs || []).slice(), edges = d.edges || [];
    if (!sources.length || !hubs.length) return svgRoot(720, 60, "tc-shared");
    var si = {}, hi = {};
    sources.forEach(function (s, i) { si[s.id] = i; });
    hubs.forEach(function (h, i) { hi[h.id] = i; });
    var adjS = sources.map(function () { return []; }), adjH = hubs.map(function () { return []; });
    edges.forEach(function (e) { var a = si[e.from], b = hi[e.to]; if (a != null && b != null) { adjS[a].push(b); adjH[b].push(a); } });
    function mean(a) { if (!a.length) return 1e9; var s = 0; a.forEach(function (v) { s += v; }); return s / a.length; }
    // Barycentre passes: order each side by the mean position of its neighbours
    // on the other side. Two rounds is plenty for the bounded node count.
    var sOrd = sources.map(function (_, i) { return i; }), hOrd = hubs.map(function (_, i) { return i; });
    for (var pass = 0; pass < 2; pass++) {
      var sRank = {}; sOrd.forEach(function (idx, r) { sRank[idx] = r; });
      hOrd.sort(function (a, b) { return mean(adjH[a].map(function (x) { return sRank[x]; })) - mean(adjH[b].map(function (x) { return sRank[x]; })); });
      var hRank = {}; hOrd.forEach(function (idx, r) { hRank[idx] = r; });
      sOrd.sort(function (a, b) { return mean(adjS[a].map(function (x) { return hRank[x]; })) - mean(adjS[b].map(function (x) { return hRank[x]; })); });
    }
    var W = 760, P = { t: 28, b: 16 }, rowH = 30;
    var rows = Math.max(sOrd.length, hOrd.length), H = P.t + P.b + Math.max(1, rows) * rowH;
    var lx = 140, rx = W - 150, sy = {}, hy = {};
    sOrd.forEach(function (idx, r) { sy[idx] = P.t + (r + 0.5) * ((H - P.t - P.b) / sOrd.length); });
    hOrd.forEach(function (idx, r) { hy[idx] = P.t + (r + 0.5) * ((H - P.t - P.b) / hOrd.length); });
    var root = svgRoot(W, H, "tc-shared");
    root.appendChild(text(lx, 16, "source IPs", "tc-grouphdr", { "text-anchor": "end" }));
    root.appendChild(text(rx, 16, "shared infrastructure", "tc-grouphdr", { "text-anchor": "start" }));
    edges.forEach(function (e) {
      var a = si[e.from], b = hi[e.to]; if (a == null || b == null) return;
      var x1 = lx, y1 = sy[a], x2 = rx, y2 = hy[b], mx = (x1 + x2) / 2;
      root.appendChild(el("path", { d: "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2, fill: "none", class: "tc-edge", stroke: kindColor(hubs[b].kind), "stroke-opacity": 0.35 }));
    });
    sources.forEach(function (s, i) {
      var y = sy[i]; if (y == null) return;
      root.appendChild(title(el("circle", { cx: lx, cy: y, r: 5, class: "tc-node", fill: SEV[s.sev] || PALETTE[7] }), (s.label || s.id) + (s.count ? " · " + fmt(s.count) + " events" : "")));
      root.appendChild(text(lx - 9, y + 4, s.label || s.id, "tc-nlabel", { "text-anchor": "end" }));
    });
    hubs.forEach(function (h, i) {
      var y = hy[i]; if (y == null) return;
      var r = Math.max(4, Math.min(13, 3 + (num(h.count) || 1) * 1.5));
      root.appendChild(title(el("circle", { cx: rx, cy: y, r: r, class: "tc-node", fill: kindColor(h.kind) }), (h.label || h.id) + " · shared by " + fmt(h.count) + " IPs"));
      root.appendChild(text(rx + r + 5, y + 4, h.label || h.id, "tc-nlabel", { "text-anchor": "start" }));
    });
    var kinds = []; hubs.forEach(function (h) { if (kinds.indexOf(h.kind) < 0) kinds.push(h.kind); });
    root._legend = kinds.map(function (k) { return { label: k, color: kindColor(k) }; });
    return root;
  };

  // force: force-directed node-link clustering. Same data as `network`
  // ({ nodes:[{id,label,group?,kind?}], edges:[{from,to}] }) but laid out by a
  // small Fruchterman-Reingold simulation so nodes sharing edges (e.g. source
  // IPs under one ASN / fingerprint) pull into visible clusters. Pure vanilla
  // JS, no libraries; O(n^2) repulsion is fine for the bounded node count.
  charts.force = function (d) {
    var nodes = (d.nodes || []).slice(), edges = d.edges || [], W = 720, H = 560;
    var idx = {};
    nodes.forEach(function (nd, i) {
      idx[nd.id] = i;
      nd.x = W / 2 + (Math.random() - 0.5) * W * 0.6;
      nd.y = H / 2 + (Math.random() - 0.5) * H * 0.6;
    });
    var links = edges.map(function (e) { return { s: idx[e.from], t: idx[e.to] }; })
      .filter(function (l) { return l.s != null && l.t != null; });
    var n = nodes.length || 1, k = Math.sqrt((W * H) / n) * 0.8, iters = 300;
    for (var step = 0; step < iters; step++) {
      var temp = 14 * (1 - step / iters) + 0.5;
      for (var i = 0; i < n; i++) { nodes[i].fx = 0; nodes[i].fy = 0; }
      for (i = 0; i < n; i++) {
        for (var j = i + 1; j < n; j++) {
          var a = nodes[i], b = nodes[j], dx = a.x - b.x, dy = a.y - b.y, dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
          var rep = (k * k) / dist, rx = dx / dist * rep, ry = dy / dist * rep;
          a.fx += rx; a.fy += ry; b.fx -= rx; b.fy -= ry;
        }
      }
      links.forEach(function (l) {
        var a = nodes[l.s], b = nodes[l.t], dx = a.x - b.x, dy = a.y - b.y, dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
        var att = (dist * dist) / k, fx = dx / dist * att, fy = dy / dist * att;
        a.fx -= fx; a.fy -= fy; b.fx += fx; b.fy += fy;
      });
      nodes.forEach(function (a) {
        a.fx += (W / 2 - a.x) * 0.02; a.fy += (H / 2 - a.y) * 0.02; // gentle gravity
        var disp = Math.sqrt(a.fx * a.fx + a.fy * a.fy) || 0.01;
        a.x += a.fx / disp * Math.min(disp, temp);
        a.y += a.fy / disp * Math.min(disp, temp);
        a.x = Math.max(18, Math.min(W - 18, a.x));
        a.y = Math.max(18, Math.min(H - 18, a.y));
      });
    }
    var root = svgRoot(W, H, "tc-force"), groups = [];
    nodes.forEach(function (nd) { if (nd.group != null && groups.indexOf(nd.group) < 0) groups.push(nd.group); });
    links.forEach(function (l) { var a = nodes[l.s], b = nodes[l.t]; root.appendChild(el("line", { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "tc-edge" })); });
    nodes.forEach(function (nd) {
      var hubN = nd.kind && nd.kind !== "source", r = hubN ? 9 : 5;
      if (nd.size && nd.size > 0) { r = Math.max(3, Math.min(22, nd.size)); } // explicit size (e.g. centrality)
      root.appendChild(title(el("circle", { cx: nd.x, cy: nd.y, r: r, class: "tc-node", fill: color(groups.indexOf(nd.group) < 0 ? 0 : groups.indexOf(nd.group)) }), (nd.label || nd.id) + (nd.kind ? " [" + nd.kind + "]" : "")));
      if (hubN) root.appendChild(text(nd.x, nd.y - r - 3, nd.label || nd.id, "tc-nlabel", { "text-anchor": "middle" }));
    });
    return root;
  };

  // sankey / flow: { nodes:[{id,label}], links:[{source,target,value}] }
  charts.sankey = function (d) {
    var nodes = d.nodes || [], links = d.links || [], W = 760, P = { t: 20, b: 20 };
    var idx = {}; nodes.forEach(function (nd, i) { idx[nd.id] = i; });
    var layer;
    // Prefer explicit per-node columns (node.layer) — the kill-chain journey
    // pins these so a looping path can't collapse the layout. Otherwise infer
    // columns by longest-path from sources (a DAG-ish flow).
    if (nodes.length && nodes.every(function (n) { return typeof n.layer === "number"; })) {
      var minLayer = Math.min.apply(null, nodes.map(function (n) { return n.layer; }));
      layer = nodes.map(function (n) { return n.layer - minLayer; }); // dense, 0-based
    } else {
      layer = nodes.map(function () { return 0; });
      var changed = true, guard = 0;
      while (changed && guard++ < 50) { changed = false; links.forEach(function (l) { if (idx[l.target] != null && idx[l.source] != null && layer[idx[l.target]] < layer[idx[l.source]] + 1) { layer[idx[l.target]] = layer[idx[l.source]] + 1; changed = true; } }); }
    }
    var maxL = Math.max.apply(null, layer.concat([0])), byL = {};
    nodes.forEach(function (nd, i) { (byL[layer[i]] = byL[layer[i]] || []).push(i); });
    var inSum = nodes.map(function () { return 0; }), outSum = nodes.map(function () { return 0; });
    links.forEach(function (l) { outSum[idx[l.source]] += num(l.value); inSum[idx[l.target]] += num(l.value); });
    var val = nodes.map(function (_, i) { return Math.max(inSum[i], outSum[i], 1); });
    var colMax = 0; for (var L in byL) colMax = Math.max(colMax, byL[L].reduce(function (a, i) { return a + val[i]; }, 0));
    var H = Math.max(200, 40 + colMax * 0.55), root = svgRoot(W, H, "tc-sankey");
    var nx = {}, ny = {}, nh = {}, scale = (H - P.t - P.b) / (colMax || 1) * 0.82;
    for (var Lk in byL) {
      var lx = 40 + (+Lk) * ((W - 120) / Math.max(1, maxL)), y = P.t;
      byL[Lk].forEach(function (i) { var h = Math.max(3, val[i] * scale); nx[i] = lx; ny[i] = y; nh[i] = h; y += h + 14; });
    }
    var outAcc = nodes.map(function () { return 0; }), inAcc = nodes.map(function () { return 0; });
    links.forEach(function (l, k) {
      var s = idx[l.source], t = idx[l.target]; if (s == null || t == null) return;
      var h = val[s] ? num(l.value) * scale : 3;
      var y1 = ny[s] + outAcc[s] + h / 2, y2 = ny[t] + inAcc[t] + h / 2; outAcc[s] += h; inAcc[t] += h;
      var x1 = nx[s] + 14, x2 = nx[t], mx = (x1 + x2) / 2;
      root.appendChild(title(el("path", { d: "M" + x1 + "," + y1 + " C" + mx + "," + y1 + " " + mx + "," + y2 + " " + x2 + "," + y2, fill: "none", stroke: color(s), "stroke-width": Math.max(1, h), "stroke-opacity": 0.4, class: "tc-flow" }), (lbl(s)) + " → " + lbl(t) + ": " + fmt(l.value)));
    });
    nodes.forEach(function (nd, i) {
      root.appendChild(title(el("rect", { x: nx[i], y: ny[i], width: 14, height: nh[i], fill: color(i), class: "tc-snode" }), lbl(i) + ": " + fmt(val[i])));
      root.appendChild(text(nx[i] + ((+layer[i]) < maxL / 2 ? 18 : -4), ny[i] + nh[i] / 2 + 4, nd.label || nd.id, "tc-ax", { "text-anchor": (+layer[i]) < maxL / 2 ? "start" : "end" }));
    });
    function lbl(i) { return nodes[i] ? (nodes[i].label || nodes[i].id) : "?"; }
    return root;
  };

  // timeline (attack timeline): { events:[{t,label,lane?,sev?}], lanes?:[..], start?, end? }
  charts.timeline = function (d) {
    var evs = (d.events || []).map(function (e) { return { t: num(e.t), label: e.label, lane: e.lane || "", sev: e.sev }; });
    if (!evs.length) return svgRoot(720, 80, "tc-timeline");
    var lanes = d.lanes || []; evs.forEach(function (e) { if (lanes.indexOf(e.lane) < 0) lanes.push(e.lane); });
    var ts = evs.map(function (e) { return e.t; }), t0 = d.start != null ? num(d.start) : Math.min.apply(null, ts), t1 = d.end != null ? num(d.end) : Math.max.apply(null, ts);
    if (t0 === t1) t1 = t0 + 1;
    var laneH = 30, P = { l: 150, r: 20, t: 28, b: 26 }, W = 760, H = P.t + P.b + lanes.length * laneH;
    var iw = W - P.l - P.r, root = svgRoot(W, H, "tc-timeline");
    for (var g = 0; g <= 6; g++) { var gx = P.l + iw * g / 6, tt = t0 + (t1 - t0) * g / 6; root.appendChild(el("line", { x1: gx, y1: P.t - 4, x2: gx, y2: H - P.b, class: "tc-grid" })); root.appendChild(text(gx, H - 8, tlabel(tt), "tc-ax", { "text-anchor": "middle" })); }
    lanes.forEach(function (ln, i) {
      var y = P.t + i * laneH; root.appendChild(text(P.l - 8, y + laneH * 0.6, ln || "(event)", "tc-ax", { "text-anchor": "end" }));
      root.appendChild(el("line", { x1: P.l, y1: y + laneH / 2, x2: W - P.r, y2: y + laneH / 2, class: "tc-lane" }));
    });
    evs.forEach(function (e) {
      var x = P.l + iw * (e.t - t0) / (t1 - t0), y = P.t + lanes.indexOf(e.lane) * laneH + laneH / 2;
      root.appendChild(title(el("circle", { cx: x, cy: y, r: 5, class: "tc-tev", fill: e.sev ? SEV[e.sev] : PALETTE[0] }), tlabel(e.t) + " · " + (e.label || "")));
    });
    return root;
  };

  // WORLD is a coarse equirectangular set of continent/landmass outlines as
  // [lon,lat] polygons. It gives the source map a recognizable geography with
  // zero configuration; an operator-supplied ui.map_tiles_url raster replaces
  // it when set. Low fidelity on purpose — it's a backdrop, not a survey.
  var WORLD = [
    // North America incl. Mexico (Gulf, Yucatán, Baja, isthmus to Panama) + Alaska.
    [[-168,66],[-163,71],[-156,71],[-130,70],[-110,68],[-95,73],[-85,73],[-80,68],[-78,62],[-70,62],[-64,60],[-60,55],[-56,52],[-60,47],[-66,44],[-70,43],[-74,40],[-76,37],[-81,31],[-80,25],[-81,29],[-84,30],[-88,30],[-94,29],[-97,28],[-97,22],[-95,18],[-91,18],[-88,21],[-87,16],[-83,9],[-78,8],[-83,11],[-87,13],[-95,16],[-103,18],[-106,21],[-110,23],[-110,27],[-114,28],[-114,31],[-117,33],[-122,37],[-124,42],[-124,48],[-130,54],[-135,57],[-145,60],[-150,59],[-158,57],[-165,60]],
    // Greenland
    [[-45,60],[-42,66],[-22,70],[-18,75],[-22,80],[-35,83],[-50,82],[-58,76],[-53,68],[-48,62]],
    // South America
    [[-78,8],[-72,11],[-62,10],[-52,5],[-50,0],[-44,-3],[-38,-5],[-35,-8],[-39,-14],[-43,-23],[-48,-25],[-54,-34],[-58,-35],[-62,-41],[-65,-45],[-69,-52],[-75,-52],[-74,-46],[-73,-40],[-71,-33],[-70,-23],[-70,-18],[-77,-12],[-81,-6],[-81,-2],[-80,2]],
    // Africa
    [[-17,15],[-16,21],[-13,28],[-9,30],[0,36],[10,37],[11,33],[20,32],[25,32],[32,31],[34,28],[37,22],[40,15],[43,11],[51,12],[48,5],[42,-1],[40,-10],[35,-18],[33,-26],[27,-34],[20,-35],[15,-28],[13,-17],[9,-1],[9,4],[3,6],[-7,4],[-12,8],[-16,12]],
    // Eurasia: Iberia -> France -> Scandinavia (Norway/North Cape/Baltic) ->
    // Arctic Russia -> Far East -> China -> SE Asia -> India -> Arabia -> Anatolia.
    [[-9,36],[-9,43],[-2,44],[0,47],[-5,48],[2,51],[8,54],[8,57],[5,58],[5,62],[10,64],[15,68],[20,70],[26,71],[28,70],[24,65],[20,63],[19,60],[23,60],[28,60],[30,60],[29,64],[34,66],[40,66],[50,68],[60,69],[68,73],[78,73],[100,77],[140,73],[170,68],[178,66],[165,61],[160,56],[155,52],[145,47],[140,46],[135,44],[130,42],[127,39],[122,40],[121,33],[118,24],[110,21],[105,10],[103,1],[100,6],[99,12],[98,16],[95,16],[90,21],[88,22],[83,18],[80,8],[77,8],[73,16],[70,21],[66,25],[60,25],[57,25],[50,28],[48,30],[40,30],[36,36],[31,31],[35,36],[26,40],[27,37],[24,40],[20,40],[18,42],[15,37],[8,38],[0,40],[-6,37]],
    // Australia
    [[113,-22],[114,-34],[123,-34],[131,-31],[138,-35],[147,-38],[153,-28],[146,-18],[142,-11],[136,-12],[130,-12],[123,-17],[114,-22]],
    // Madagascar
    [[43,-12],[50,-15],[47,-25],[44,-22]],
    // Japan
    [[130,31],[136,34],[141,40],[143,43],[140,38],[136,35],[132,33]],
    // Korea
    [[126,34],[126,38],[129,38],[129,35]],
    // New Zealand
    [[167,-46],[171,-44],[174,-41],[176,-39],[171,-43]],
    // British Isles
    [[-6,50],[-3,53],[-5,58],[-8,57],[-10,52]],
    // Iceland
    [[-24,65],[-18,66],[-14,65],[-20,64]],
    // Italy
    [[8,44],[13,46],[18,40],[16,38],[12,38],[10,42]],
    // Sumatra / Java (Indonesia)
    [[95,5],[104,-2],[114,-8],[106,-7],[100,0]],
    // Borneo
    [[109,2],[117,4],[118,-2],[110,-4]],
    // Cuba
    [[-84,22],[-78,23],[-74,20],[-80,20]],
    // Sri Lanka
    [[80,9],[82,7],[81,6],[80,8]]
  ];

  // sourcemap (attack source map): { points:[{lat,lon,count,label?,sev?}] } on an equirectangular graticule.
  charts.sourcemap = function (d) {
    var pts = d.points || [], W = 720, H = 360, P = { l: 8, r: 8, t: 8, b: 8 };
    var iw = W - P.l - P.r, ih = H - P.t - P.b, root = svgRoot(W, H, "tc-map");
    root.appendChild(el("rect", { x: P.l, y: P.t, width: iw, height: ih, class: "tc-ocean" }));
    function proj(lat, lon) { return { x: P.l + iw * (num(lon) + 180) / 360, y: P.t + ih * (90 - num(lat)) / 180 }; }
    // Optional equirectangular (plate-carrée) world-map backdrop. The operator
    // configures ui.map_tiles_url (a full-world image); the projection below
    // matches it exactly (lon -180..180 -> x, lat 90..-90 -> y). Self-hosted
    // under /static is recommended; an external URL is CSP-allowed server-side.
    // With no raster configured we draw the built-in WORLD continent vector so
    // the map reads as geography rather than a bare grid.
    var tilesMeta = document.querySelector('meta[name="tarpit-map-tiles"]');
    var tilesURL = tilesMeta && tilesMeta.getAttribute("content");
    if (tilesURL) {
      var img = el("image", { x: P.l, y: P.t, width: iw, height: ih, preserveAspectRatio: "none", class: "tc-mapimg" });
      img.setAttribute("href", tilesURL);
      img.setAttributeNS("http://www.w3.org/1999/xlink", "href", tilesURL); // older renderers
      root.appendChild(img);
    } else {
      WORLD.forEach(function (poly) {
        var dd = poly.map(function (c, i) { var xy = proj(c[1], c[0]); return (i ? "L" : "M") + xy.x.toFixed(1) + " " + xy.y.toFixed(1); }).join(" ") + "Z";
        root.appendChild(el("path", { d: dd, class: "tc-land" }));
      });
    }
    for (var lon = -180; lon <= 180; lon += 30) { var x = P.l + iw * (lon + 180) / 360; root.appendChild(el("line", { x1: x, y1: P.t, x2: x, y2: P.t + ih, class: "tc-grat" })); }
    for (var lat = -90; lat <= 90; lat += 30) { var y = P.t + ih * (90 - lat) / 180; root.appendChild(el("line", { x1: P.l, y1: y, x2: P.l + iw, y2: y, class: "tc-grat" })); root.appendChild(text(P.l + 2, y - 2, lat + "°", "tc-grat-lbl")); }
    var max = maxOf(pts, function (p) { return num(p.count); }) || 1;
    pts.forEach(function (p) {
      var xy = proj(p.lat, p.lon), r = 3 + 11 * Math.sqrt(num(p.count) / max);
      var circ = title(el("circle", { cx: xy.x, cy: xy.y, r: r, class: "tc-src", fill: p.sev ? SEV[p.sev] : SEV.high, "fill-opacity": 0.55, stroke: SEV.critical }), (p.label ? p.label + " · " : "") + fmt(p.count) + (p.country ? " — click for attacks from " + p.country : ""));
      // Clicking a bubble drills to the events from that place (by country).
      if (p.country) {
        var a = el("a", { class: "tc-srclink" });
        var href = "/events?country=" + encodeURIComponent(p.country);
        a.setAttribute("href", href);
        a.setAttributeNS("http://www.w3.org/1999/xlink", "href", href);
        a.appendChild(circ);
        root.appendChild(a);
      } else {
        root.appendChild(circ);
      }
    });
    return root;
  };

  // sessionreplay: { frames:[{t,text,dir?}] } — captured command/IO sequence as a terminal transcript.
  // sessionreplay: a timed terminal player for an asciinema-style cast.
  // frames = [{t: seconds, dir: "in"|"out", text}]. Renders the "out" stream
  // into a terminal (ANSI stripped, \r/\b/\t/\n handled), with play / pause /
  // seek / speed. A faithful-enough replay of the recorded shell session.
  charts.sessionreplay = function (d) {
    var frames = (d.frames || []).slice().sort(function (a, b) { return num(a.t) - num(b.t); });
    var dur = frames.length ? num(frames[frames.length - 1].t) : 0;
    var wrap = document.createElement("div"); wrap.className = "tc-replay";

    function mk(tag, cls, txt) { var e = document.createElement(tag); if (cls) e.className = cls; if (txt != null) e.textContent = txt; return e; }
    var ctrl = mk("div", "tc-rctrl");
    var playBtn = mk("button", "tc-rbtn", "▶"); playBtn.type = "button";
    var seek = mk("input", "tc-rseek"); seek.type = "range"; seek.min = 0; seek.max = 1000; seek.value = 0;
    var timeLbl = mk("span", "tc-rtime", "");
    var speed = mk("select", "tc-rspeed");
    [["1×", 1], ["2×", 2], ["4×", 4], ["8×", 8], ["0.5×", 0.5]].forEach(function (o) {
      var op = mk("option", null, o[0]); op.value = o[1]; speed.appendChild(op);
    });
    ctrl.appendChild(playBtn); ctrl.appendChild(seek); ctrl.appendChild(timeLbl); ctrl.appendChild(speed);
    ctrl.addEventListener("click", function (e) { e.stopPropagation(); }); // don't toggle chart zoom
    var term = mk("pre", "tc-term");
    wrap.appendChild(ctrl); wrap.appendChild(term);

    function stripAnsi(s) {
      return s
        .replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")  // OSC
        .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")          // CSI
        .replace(/\x1b[@-Z\\-_]/g, "")                      // other ESC
        .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, "");      // controls (keep \t\n\r)
    }
    function render(T) {
      var lines = [""], row = 0, col = 0;
      for (var i = 0; i < frames.length; i++) {
        var f = frames[i]; if (num(f.t) > T) break; if (f.dir !== "out") continue;
        var s = stripAnsi(String(f.text || ""));
        for (var j = 0; j < s.length; j++) {
          var c = s[j];
          if (c === "\n") { row++; if (lines[row] == null) lines[row] = ""; col = 0; }
          else if (c === "\r") { col = 0; }
          else if (c === "\t") { col += 4 - (col % 4); }
          else { var ln = lines[row] || ""; while (ln.length < col) ln += " "; lines[row] = ln.substring(0, col) + c + ln.substring(col + 1); col++; }
        }
      }
      if (lines.length > 600) lines = lines.slice(lines.length - 600); // cap rendered scrollback
      term.textContent = lines.join("\n");
      term.scrollTop = term.scrollHeight;
    }

    var T = 0, playing = false, last = 0, raf = 0;
    function setT(t) {
      T = Math.max(0, Math.min(dur, t));
      seek.value = dur ? Math.round(T / dur * 1000) : 0;
      timeLbl.textContent = "+" + T.toFixed(1) + "s / " + dur.toFixed(1) + "s";
      render(T);
    }
    function pause() { playing = false; playBtn.textContent = "▶"; if (raf) cancelAnimationFrame(raf); }
    function tick(ts) {
      if (!playing) return;
      if (!last) last = ts;
      T += (ts - last) / 1000 * (+speed.value || 1); last = ts;
      if (T >= dur) { setT(dur); pause(); return; }
      setT(T); raf = requestAnimationFrame(tick);
    }
    function play() { if (playing) return; if (T >= dur) setT(0); playing = true; playBtn.textContent = "⏸"; last = 0; raf = requestAnimationFrame(tick); }
    playBtn.addEventListener("click", function () { playing ? pause() : play(); });
    seek.addEventListener("input", function () { pause(); setT(dur * seek.value / 1000); });
    setT(0);
    return wrap;
  };

  // creds (credential attempt chart): { attempts:[{user,pass,count}] } -> top users hbar + user×pass scatter.
  charts.creds = function (d) {
    var att = d.attempts || [], box = document.createElement("div");
    var byUser = {}; att.forEach(function (a) { byUser[a.user] = (byUser[a.user] || 0) + (num(a.count) || 1); });
    var users = Object.keys(byUser).map(function (u) { return { label: u, value: byUser[u] }; }).sort(function (a, b) { return b.value - a.value; }).slice(0, 15);
    box.appendChild(charts.hbar({ series: users }));
    if (d.scatter !== false) {
      var us = users.map(function (u) { return u.label; });
      var ps = []; att.forEach(function (a) { if (ps.indexOf(a.pass) < 0) ps.push(a.pass); });
      var pts = att.filter(function (a) { return us.indexOf(a.user) >= 0; }).map(function (a) {
        return { x: us.indexOf(a.user), y: ps.indexOf(a.pass), r: 3 + Math.sqrt(num(a.count) || 1), label: a.user + " / " + a.pass, count: a.count };
      });
      if (pts.length) box.appendChild(charts.scatter({ points: pts, xlabel: "username (top)", ylabel: "password" }));
    }
    return box;
  };

  function wrapLegend(root, items) {
    // legend rendered as SVG text row below the plot area is fiddly; expose via a sibling div instead.
    root._legend = items;
  }

  // ---- rendering & auto-enhancement ------------------------------------
  function render(container, type, data) {
    if (!charts[type]) { return; }
    var node;
    try { node = charts[type](data || {}); } catch (e) { return; }
    container.textContent = "";
    var t = container.getAttribute && container.getAttribute("data-chart-title");
    if (t) { var h = document.createElement("figcaption"); h.className = "tc-cap"; h.textContent = t; container.appendChild(h); }
    container.appendChild(node);
    if (node._legend) container.appendChild(legend(node._legend));
    container.classList.add("tc-rendered");
    enableZoom(container);
  }
  // enableZoom: click a chart to toggle an enlarged overlay; click again (or
  // Escape) to restore. Attached once per container.
  function enableZoom(container) {
    if (container._tcZoom) return;
    container._tcZoom = true;
    container.classList.add("tc-zoomable");
    container.addEventListener("click", function (e) {
      if (e.target && e.target.closest && e.target.closest(".widget-toggle")) return;
      var sel = window.getSelection && window.getSelection();
      if (sel && String(sel).length > 0) return; // don't fight text selection
      container.classList.toggle("tc-zoom");
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") container.classList.remove("tc-zoom");
    });
  }
  function decode(el) {
    var b = el.getAttribute("data-chart-b64");
    if (b) { try { return JSON.parse(decodeURIComponent(escape(window.atob(b)))); } catch (e) { return null; } }
    try { return JSON.parse(el.textContent); } catch (e) { return null; }
  }
  function auto(rootEl) {
    var scope = rootEl || document;
    Array.prototype.forEach.call(scope.querySelectorAll("[data-chart]"), function (el) {
      if (el.classList.contains("tc-rendered")) return;
      var data = decode(el);
      if (data) render(el, el.getAttribute("data-chart"), data);
    });
  }
  if (document.readyState !== "loading") auto();
  else document.addEventListener("DOMContentLoaded", function () { auto(); });

  return { render: render, auto: auto, charts: charts, palette: PALETTE };
})();
