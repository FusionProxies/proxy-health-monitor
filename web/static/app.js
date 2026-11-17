/* Proxy Health Monitor dashboard. Plain JavaScript, no dependencies, no
   external requests. Everything it shows comes from the read-only /api. */
(function () {
  "use strict";

  var app = document.getElementById("app");
  var tooltip = document.getElementById("tooltip");
  var REFRESH_MS = 15000;
  var state = { route: null, window: "24h", search: "", stateFilter: "all", incStatus: "all", settings: null, lastData: null };
  var timer = null;

  // ---------- helpers ----------
  function esc(v) {
    return String(v == null ? "" : v).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function api(path, opts) {
    return fetch(path, Object.assign({ credentials: "same-origin", headers: { Accept: "application/json" } }, opts || {})).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        if (!r.ok) { var e = new Error(body.error || ("HTTP " + r.status)); e.status = r.status; throw e; }
        return body;
      });
    });
  }
  function fmtMs(ms) {
    if (!ms && ms !== 0) return "-";
    if (ms <= 0) return "-";
    if (ms < 1) return "<1 ms";
    if (ms < 1000) return Math.round(ms) + " ms";
    return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + " s";
  }
  function fmtPct(v, checks) {
    if (!checks) return "no data";
    if (v >= 100) return "100%";
    if (v >= 99) return v.toFixed(2) + "%";
    return v.toFixed(1) + "%";
  }
  function pad(n) { return n < 10 ? "0" + n : "" + n; }
  function fmtTime(iso, withSec) {
    if (!iso) return "-";
    var d = new Date(iso);
    var s = d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
    return withSec === false ? s : s + ":" + pad(d.getSeconds());
  }
  function fmtShort(d, spanMs) {
    if (spanMs > 2 * 86400000) return pad(d.getMonth() + 1) + "-" + pad(d.getDate());
    return pad(d.getHours()) + ":" + pad(d.getMinutes());
  }
  function fmtDur(sec) {
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return sec + "s";
    var m = Math.floor(sec / 60), h = Math.floor(m / 60), d = Math.floor(h / 24);
    if (d > 0) return d + "d " + (h % 24) + "h";
    if (h > 0) return h + "h " + (m % 60) + "m";
    return m + "m " + (sec % 60) + "s";
  }
  function ago(iso) {
    if (!iso) return "never";
    var s = (Date.now() - new Date(iso).getTime()) / 1000;
    if (s < 5) return "just now";
    return fmtDur(s) + " ago";
  }
  var ICONS = {
    healthy: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="#0ca30c"/><path d="M4.6 8.2l2.2 2.2 4.6-4.8" fill="none" stroke="#04150a" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    degraded: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5l7 12.5H1z" fill="#fab219"/><path d="M8 6v3.6M8 11.6v.1" stroke="#2a1d00" stroke-width="1.8" stroke-linecap="round"/></svg>',
    down: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="#d03b3b"/><path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/></svg>',
    unknown: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.3" fill="none" stroke="#8494ae" stroke-width="1.4"/><path d="M6.3 6.4a1.8 1.8 0 1 1 2.4 1.7c-.5.2-.7.6-.7 1.1M8 11.4v.1" fill="none" stroke="#8494ae" stroke-width="1.4" stroke-linecap="round"/></svg>',
    disabled: '<svg class="ico" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.3" fill="none" stroke="#8494ae" stroke-width="1.4"/><path d="M5 8h6" stroke="#8494ae" stroke-width="1.6" stroke-linecap="round"/></svg>'
  };
  var STATE_TEXT = { healthy: "Healthy", degraded: "Degraded", down: "Down", unknown: "No data yet", disabled: "Disabled" };
  function pill(st) {
    st = ICONS[st] ? st : "unknown";
    return '<span class="status ' + st + '">' + ICONS[st] + esc(STATE_TEXT[st]) + "</span>";
  }
  var KIND_TEXT = { down: "Down", latency: "Slow", availability: "Low availability" };
  function classText(c) {
    var map = (state.settings && state.settings.error_classes) || {};
    return map[c] || c || "";
  }
  function uptimeClass(v, checks, threshold) {
    if (!checks) return "nodata";
    if (v >= threshold) return "good";
    if (v >= 50) return "warning";
    return "critical";
  }

  // ---------- tooltip ----------
  function showTip(html, x, y) {
    tooltip.innerHTML = html;
    tooltip.hidden = false;
    var w = tooltip.offsetWidth, h = tooltip.offsetHeight;
    var left = x + 14, top = y + 14;
    if (left + w > window.innerWidth - 8) left = x - w - 14;
    if (top + h > window.innerHeight - 8) top = y - h - 14;
    tooltip.style.left = Math.max(8, left) + "px";
    tooltip.style.top = Math.max(8, top) + "px";
  }
  function hideTip() { tooltip.hidden = true; }

  // ---------- svg helpers ----------
  var NS = "http://www.w3.org/2000/svg";
  function niceMax(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var n = v / p;
    var m = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
    return m * p;
  }
  function roundedTop(x, y, w, h, r) {
    r = Math.max(0, Math.min(r, w / 2, h));
    var b = y + h;
    return "M" + x + "," + b + "V" + (y + r) + "Q" + x + "," + y + " " + (x + r) + "," + y +
      "H" + (x + w - r) + "Q" + (x + w) + "," + y + " " + (x + w) + "," + (y + r) + "V" + b + "Z";
  }

  // Latency: p50 and p95 per bucket, one axis, threshold reference line,
  // crosshair tooltip. Buckets without successful checks leave a gap.
  function latencyChart(el, data, thresholdMs) {
    var buckets = data.buckets || [];
    var W = Math.max(280, el.clientWidth), H = 230;
    var m = { l: 56, r: 44, t: 14, b: 28 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var from = new Date(data.from).getTime(), to = new Date(data.to).getTime(), span = to - from;
    var step = (data.bucket_seconds || 60) * 1000;
    var vmax = thresholdMs || 0;
    buckets.forEach(function (b) { if (b.successes > 0) vmax = Math.max(vmax, b.p95_ms, b.p50_ms); });
    var ymax = niceMax(vmax * 1.08 || 100);
    function X(t) { return m.l + (t - from) / span * pw; }
    function Y(v) { return m.t + ph - v / ymax * ph; }
    var out = [];
    for (var i = 0; i <= 4; i++) {
      var v = ymax * i / 4, y = Y(v);
      out.push('<line class="' + (i === 0 ? "base-line" : "grid-line") + '" x1="' + m.l + '" x2="' + (W - m.r) + '" y1="' + y + '" y2="' + y + '"/>');
      out.push('<text class="lbl" x="' + (m.l - 8) + '" y="' + (y + 4) + '" text-anchor="end">' + esc(fmtMs(v) === "-" ? "0" : fmtMs(v)) + "</text>");
    }
    var ticks = 5;
    for (var k = 0; k <= ticks; k++) {
      var t = from + span * k / ticks;
      out.push('<text class="lbl" x="' + X(t) + '" y="' + (H - 8) + '" text-anchor="' + (k === 0 ? "start" : k === ticks ? "end" : "middle") + '">' + esc(fmtShort(new Date(t), span)) + "</text>");
    }
    if (thresholdMs && thresholdMs < ymax) {
      var ty = Y(thresholdMs);
      out.push('<line class="threshold" x1="' + m.l + '" x2="' + (W - m.r) + '" y1="' + ty + '" y2="' + ty + '"/>');
      out.push('<text class="threshold-lbl" x="' + (W - m.r) + '" y="' + (ty - 5) + '" text-anchor="end">threshold ' + esc(fmtMs(thresholdMs)) + "</text>");
    }
    function path(key) {
      var d = "", pen = false;
      buckets.forEach(function (b) {
        if (b.successes > 0) {
          var x = X(new Date(b.start).getTime() + step / 2), y = Y(b[key]);
          d += (pen ? "L" : "M") + x.toFixed(1) + "," + y.toFixed(1);
          pen = true;
        } else pen = false;
      });
      return d;
    }
    var hasData = buckets.some(function (b) { return b.successes > 0; });
    if (hasData) {
      out.push('<path class="line s2" d="' + path("p95_ms") + '"/>');
      out.push('<path class="line s1" d="' + path("p50_ms") + '"/>');
      // Direct labels at the last point with data.
      var last = null;
      for (var j = buckets.length - 1; j >= 0; j--) if (buckets[j].successes > 0) { last = buckets[j]; break; }
      if (last) {
        var lx = X(new Date(last.start).getTime() + step / 2) + 6;
        var y50 = Y(last.p50_ms), y95 = Y(last.p95_ms);
        if (Math.abs(y50 - y95) < 13) { if (y95 <= y50) { y95 = y50 - 13; } else { y95 = y50 + 13; } }
        out.push('<text class="end-lbl" x="' + lx + '" y="' + (y95 + 4) + '">p95</text>');
        out.push('<text class="end-lbl" x="' + lx + '" y="' + (y50 + 4) + '">p50</text>');
      }
    } else {
      out.push('<text class="lbl" x="' + (m.l + pw / 2) + '" y="' + (m.t + ph / 2) + '" text-anchor="middle">No successful checks in this window</text>');
    }
    out.push('<g class="hover" visibility="hidden"><line class="cross" y1="' + m.t + '" y2="' + (m.t + ph) + '"/><circle class="hover-dot f-s2" r="4.5"/><circle class="hover-dot f-s1" r="4.5"/></g>');
    out.push('<rect class="hit" x="' + m.l + '" y="' + m.t + '" width="' + pw + '" height="' + ph + '"/>');
    el.innerHTML = '<svg role="img" aria-label="Response time per interval, median and 95th percentile" viewBox="0 0 ' + W + " " + H + '" height="' + H + '">' + out.join("") + "</svg>";

    var svg = el.querySelector("svg"), g = svg.querySelector(".hover"), hit = svg.querySelector(".hit");
    var cross = g.querySelector(".cross"), dots = g.querySelectorAll("circle");
    function move(ev) {
      var r = svg.getBoundingClientRect();
      var x = (ev.clientX - r.left) * (W / r.width);
      var t = from + (x - m.l) / pw * span;
      var idx = Math.floor((t - new Date(buckets[0] ? buckets[0].start : from).getTime()) / step);
      var b = buckets[Math.max(0, Math.min(buckets.length - 1, idx))];
      if (!b) return;
      var cx = X(new Date(b.start).getTime() + step / 2);
      cross.setAttribute("x1", cx); cross.setAttribute("x2", cx);
      g.setAttribute("visibility", "visible");
      if (b.successes > 0) {
        dots[0].setAttribute("cx", cx); dots[0].setAttribute("cy", Y(b.p95_ms));
        dots[1].setAttribute("cx", cx); dots[1].setAttribute("cy", Y(b.p50_ms));
        dots[0].setAttribute("visibility", "visible"); dots[1].setAttribute("visibility", "visible");
      } else { dots[0].setAttribute("visibility", "hidden"); dots[1].setAttribute("visibility", "hidden"); }
      var start = new Date(b.start), end = new Date(start.getTime() + step);
      var html = '<div class="t">' + esc(fmtTime(start, false) + " to " + fmtShort(end, 0)) + "</div>";
      if (b.successes > 0) {
        html += '<div class="r"><span class="k"><span class="dot-ico f-s2-bg"></span>p95</span><span>' + esc(fmtMs(b.p95_ms)) + "</span></div>";
        html += '<div class="r"><span class="k"><span class="dot-ico f-s1-bg"></span>p50</span><span>' + esc(fmtMs(b.p50_ms)) + "</span></div>";
      } else html += '<div class="r"><span class="k">no successful check</span></div>';
      html += '<div class="r"><span class="k">checks</span><span>' + b.successes + " of " + b.checks + " ok</span></div>";
      showTip(html, ev.clientX, ev.clientY);
    }
    hit.addEventListener("pointermove", move);
    hit.addEventListener("pointerleave", function () { g.setAttribute("visibility", "hidden"); hideTip(); });
  }

  // Availability: one bar per bucket, height = share of successful checks,
  // status color + legend, tooltip per bar.
  function availabilityChart(el, data, threshold) {
    var buckets = data.buckets || [];
    var W = Math.max(280, el.clientWidth), H = 170;
    var m = { l: 56, r: 44, t: 10, b: 28 };
    var pw = W - m.l - m.r, ph = H - m.t - m.b;
    var from = new Date(data.from).getTime(), to = new Date(data.to).getTime(), span = to - from;
    var n = Math.max(1, buckets.length), slot = pw / n, gap = slot > 6 ? 2 : slot > 3 ? 1 : 0, bw = Math.max(1, slot - gap);
    function Y(v) { return m.t + ph - v / 100 * ph; }
    var out = [];
    [0, 50, 100].forEach(function (v, i) {
      var y = Y(v);
      out.push('<line class="' + (i === 0 ? "base-line" : "grid-line") + '" x1="' + m.l + '" x2="' + (W - m.r) + '" y1="' + y + '" y2="' + y + '"/>');
      out.push('<text class="lbl" x="' + (m.l - 8) + '" y="' + (y + 4) + '" text-anchor="end">' + v + "%</text>");
    });
    for (var k = 0; k <= 5; k++) {
      var t = from + span * k / 5;
      out.push('<text class="lbl" x="' + (m.l + pw * k / 5) + '" y="' + (H - 8) + '" text-anchor="' + (k === 0 ? "start" : k === 5 ? "end" : "middle") + '">' + esc(fmtShort(new Date(t), span)) + "</text>");
    }
    buckets.forEach(function (b, i) {
      var x = m.l + i * slot + gap / 2, cls = uptimeClass(b.uptime, b.checks, threshold);
      var h = b.checks ? Math.max(2, b.uptime / 100 * ph) : 3;
      out.push('<path class="f-' + cls + '" data-i="' + i + '" d="' + roundedTop(x, m.t + ph - h, bw, h, 4) + '"/>');
    });
    var ty = Y(threshold);
    out.push('<line class="threshold" x1="' + m.l + '" x2="' + (W - m.r) + '" y1="' + ty + '" y2="' + ty + '"/>');
    out.push('<rect class="hit" x="' + m.l + '" y="' + m.t + '" width="' + pw + '" height="' + ph + '"/>');
    el.innerHTML = '<svg role="img" aria-label="Share of successful checks per interval" viewBox="0 0 ' + W + " " + H + '" height="' + H + '">' + out.join("") + "</svg>";
    var svg = el.querySelector("svg"), hit = svg.querySelector(".hit");
    var step = (data.bucket_seconds || 60) * 1000;
    hit.addEventListener("pointermove", function (ev) {
      var r = svg.getBoundingClientRect();
      var x = (ev.clientX - r.left) * (W / r.width);
      var i = Math.max(0, Math.min(n - 1, Math.floor((x - m.l) / slot)));
      var b = buckets[i];
      if (!b) return;
      var start = new Date(b.start), end = new Date(start.getTime() + step);
      var cls = uptimeClass(b.uptime, b.checks, threshold);
      var html = '<div class="t">' + esc(fmtTime(start, false) + " to " + fmtShort(end, 0)) + "</div>" +
        '<div class="r"><span class="k"><span class="sw ' + cls + '"></span>' + (b.checks ? "successful" : "no checks") + "</span><span>" + esc(fmtPct(b.uptime, b.checks)) + "</span></div>" +
        '<div class="r"><span class="k">checks</span><span>' + b.successes + " of " + b.checks + " ok</span></div>";
      showTip(html, ev.clientX, ev.clientY);
    });
    hit.addEventListener("pointerleave", hideTip);
  }

  function sparkline(values, threshold) {
    var n = values.length, cw = 5, gap = 1.5, h = 18;
    var w = n * (cw + gap);
    var parts = values.map(function (v, i) {
      var cls = v < 0 ? "nodata" : uptimeClass(v, 1, threshold);
      var label = v < 0 ? "no checks" : fmtPct(v, 1) + " successful";
      var hours = n - 1 - i;
      return '<rect class="f-' + cls + '" x="' + (i * (cw + gap)) + '" y="0" width="' + cw + '" height="' + h + '" rx="1.5"><title>' +
        esc((hours === 0 ? "this hour" : hours + "h ago") + ": " + label) + "</title></rect>";
    });
    return '<svg class="spark" width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + " " + h + '" role="img" aria-label="Hourly availability, last 24 hours">' + parts.join("") + "</svg>";
  }

  // ---------- views ----------
  function setActiveNav(name) {
    document.querySelectorAll("[data-nav]").forEach(function (a) { a.classList.toggle("active", a.getAttribute("data-nav") === name); });
  }
  function availabilityThreshold() {
    return state.settings && state.settings.thresholds ? state.settings.thresholds.availability : 95;
  }

  function renderOverviewShell() {
    app.innerHTML =
      '<div class="page-head"><div><h1>Overview</h1><div class="sub">Every configured proxy, checked through its own target endpoint.</div></div></div>' +
      '<div class="grid kpis" id="kpis"></div>' +
      '<section class="card"><div class="card-head"><h2>Proxies</h2><div class="controls">' +
      '<input type="search" id="search" placeholder="Filter by name, label or protocol" aria-label="Filter proxies">' +
      '<div class="seg" id="state-filter" role="group" aria-label="Filter by state">' +
      ["all", "healthy", "degraded", "down"].map(function (s) { return '<button type="button" data-v="' + s + '">' + (s === "all" ? "All" : STATE_TEXT[s]) + "</button>"; }).join("") +
      "</div></div></div><div class=\"table-wrap\" id=\"proxy-table\"></div></section>" +
      '<section class="card"><div class="card-head"><h2>Recent incidents</h2><a href="#/incidents">All incidents</a></div><div class="table-wrap" id="recent-incidents"></div></section>';
    var search = document.getElementById("search");
    search.value = state.search;
    search.addEventListener("input", function () { state.search = search.value; drawProxyTable(); });
    document.querySelectorAll("#state-filter button").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-v") === state.stateFilter ? "true" : "false");
      b.addEventListener("click", function () {
        state.stateFilter = b.getAttribute("data-v");
        document.querySelectorAll("#state-filter button").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        drawProxyTable();
      });
    });
  }

  function tile(label, value, note, icon) {
    return '<div class="card tile"><div class="label">' + (icon || "") + esc(label) + '</div><div class="value">' + esc(value) + "</div>" + (note ? '<div class="note">' + esc(note) + "</div>" : "") + "</div>";
  }

  function drawProxyTable() {
    var d = state.lastData;
    if (!d) return;
    var q = state.search.trim().toLowerCase();
    var rows = d.proxies.filter(function (p) {
      if (state.stateFilter !== "all" && p.state !== state.stateFilter) return false;
      if (!q) return true;
      var hay = (p.name + " " + p.protocol + " " + p.target + " " + Object.keys(p.labels || {}).map(function (k) { return k + "=" + p.labels[k]; }).join(" ")).toLowerCase();
      return hay.indexOf(q) >= 0;
    });
    var thr = availabilityThreshold();
    var el = document.getElementById("proxy-table");
    if (!rows.length) { el.innerHTML = '<div class="empty">No proxy matches this filter.</div>'; return; }
    el.innerHTML = "<table><thead><tr><th>Status</th><th>Proxy</th><th class=\"hide-sm\">Protocol</th><th>24h availability</th><th class=\"num\">p50</th><th class=\"num\">p95</th><th>Last check</th><th class=\"hide-sm\">Last error</th></tr></thead><tbody>" +
      rows.map(function (p) {
        var labels = Object.keys(p.labels || {}).sort().map(function (k) { return '<span class="chip">' + esc(k + "=" + p.labels[k]) + "</span>"; }).join("");
        return '<tr class="link" data-name="' + esc(p.name) + '" tabindex="0">' +
          "<td>" + pill(p.state) + "</td>" +
          '<td><div class="name">' + esc(p.name) + '</div><div class="url">' + esc(p.url) + "</div>" + labels + "</td>" +
          '<td class="hide-sm">' + esc(p.protocol) + "</td>" +
          '<td><div class="spark-wrap">' + sparkline(p.spark_24h || [], thr) + "<span>" + esc(fmtPct(p.last_24h.uptime, p.last_24h.checks)) + "</span></div></td>" +
          '<td class="num">' + esc(p.last_24h.successes ? fmtMs(p.last_24h.p50_ms) : "-") + "</td>" +
          '<td class="num">' + esc(p.last_24h.successes ? fmtMs(p.last_24h.p95_ms) : "-") + "</td>" +
          "<td>" + esc(ago(p.last_check)) + "</td>" +
          '<td class="err hide-sm">' + (p.state === "healthy" || !p.last_error_class ? "" : '<span class="cls">' + esc(p.last_error_class) + "</span><br>" + esc(p.last_error)) + "</td></tr>";
      }).join("") + "</tbody></table>";
    el.querySelectorAll("tr.link").forEach(function (tr) {
      function go() { location.hash = "#/proxy/" + encodeURIComponent(tr.getAttribute("data-name")); }
      tr.addEventListener("click", go);
      tr.addEventListener("keydown", function (e) { if (e.key === "Enter") go(); });
    });
  }

  function incidentTable(list, showProxy) {
    if (!list.length) return '<div class="empty">No incidents recorded.</div>';
    return "<table><thead><tr><th>Status</th>" + (showProxy ? "<th>Proxy</th>" : "") + "<th>Type</th><th>Started</th><th>Ended</th><th class=\"num\">Duration</th><th>Details</th></tr></thead><tbody>" +
      list.map(function (i) {
        var st = i.open ? (i.kind === "down" ? "down" : "degraded") : "healthy";
        var label = i.open ? "Open" : "Resolved";
        return "<tr><td><span class=\"status " + st + "\">" + ICONS[st] + label + "</span></td>" +
          (showProxy ? '<td><a href="#/proxy/' + encodeURIComponent(i.proxy) + '">' + esc(i.proxy) + "</a></td>" : "") +
          "<td>" + esc(KIND_TEXT[i.kind] || i.kind) + "</td>" +
          "<td>" + esc(fmtTime(i.started_at)) + "</td>" +
          "<td>" + (i.ended_at ? esc(fmtTime(i.ended_at)) : "ongoing") + "</td>" +
          '<td class="num">' + esc(fmtDur(i.duration_seconds)) + "</td>" +
          '<td class="err">' + esc(i.reason) + "</td></tr>";
      }).join("") + "</tbody></table>";
  }

  function loadOverview() {
    return Promise.all([api("/api/proxies"), api("/api/metrics"), api("/api/incidents?limit=8")]).then(function (r) {
      var list = r[0], sum = r[1], inc = r[2];
      state.lastData = list;
      setDemo(list.demo);
      var s = sum.states;
      document.getElementById("kpis").innerHTML =
        tile("Configured", String(sum.proxies), s.disabled ? s.disabled + " disabled" : "proxies in the config") +
        tile("Healthy", String(s.healthy), "", ICONS.healthy) +
        tile("Degraded", String(s.degraded), "slow, failing or below threshold", ICONS.degraded) +
        tile("Down", String(s.down), s.unknown ? s.unknown + " without data yet" : "", ICONS.down) +
        tile("Checks, 24h", sum.checks_24h ? fmtPct(sum.uptime_24h, sum.checks_24h) : "no data", sum.checks_24h + " checks, " + sum.open_incidents + " open incidents");
      drawProxyTable();
      document.getElementById("recent-incidents").innerHTML = incidentTable(inc.incidents, true);
    });
  }

  function renderProxyShell(name) {
    app.innerHTML =
      '<a class="crumb" href="#/">&larr; Overview</a>' +
      '<div class="page-head"><div><h1 id="p-name">' + esc(name) + '</h1><div class="sub" id="p-sub"></div></div><div id="p-actions"></div></div>' +
      '<div class="grid kpis" id="p-kpis"></div>' +
      '<section class="card"><div class="card-head"><h2>Response time</h2><div class="seg" id="win" role="group" aria-label="Time window">' +
      ["1h", "6h", "24h", "7d", "30d"].map(function (w) { return '<button type="button" data-v="' + w + '">' + w + "</button>"; }).join("") +
      '</div></div><div class="legend" id="lat-legend"></div><div class="chart" id="lat-chart"></div></section>' +
      '<section class="card"><div class="card-head"><h2>Availability</h2><span class="hint" id="av-hint"></span></div>' +
      '<div class="legend"><span class="key"><span class="sw good"></span>at or above threshold</span><span class="key"><span class="sw warning"></span>below threshold</span><span class="key"><span class="sw critical"></span>under 50%</span><span class="key"><span class="sw nodata"></span>no checks</span></div>' +
      '<div class="chart" id="av-chart"></div></section>' +
      '<div class="grid two"><section class="card"><div class="card-head"><h2>Connection details</h2></div><dl class="facts" id="p-facts"></dl></section>' +
      '<section class="card"><div class="card-head"><h2>Where the time goes</h2><span class="hint">median of successful checks, 24h</span></div><div id="p-phases"></div></section></div>' +
      '<section class="card"><div class="card-head"><h2>Recent errors</h2><span class="hint">last 7 days</span></div><div class="table-wrap" id="p-errors"></div></section>' +
      '<section class="card"><div class="card-head"><h2>Incidents</h2></div><div class="table-wrap" id="p-incidents"></div></section>' +
      '<section class="card"><div class="card-head"><h2>Latest checks</h2><span class="hint">table view of the charts\' source data</span></div><div class="table-wrap" id="p-checks"></div></section>';
    document.querySelectorAll("#win button").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-v") === state.window ? "true" : "false");
      b.addEventListener("click", function () {
        state.window = b.getAttribute("data-v");
        document.querySelectorAll("#win button").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        loadSeries(name);
      });
    });
  }

  var lastSeries = null, lastThr = null;
  function loadSeries(name) {
    return api("/api/proxies/" + encodeURIComponent(name) + "/series?window=" + state.window).then(function (s) {
      lastSeries = s;
      drawCharts();
      var hint = document.getElementById("av-hint");
      if (hint) hint.textContent = fmtPct(s.summary.uptime, s.summary.checks) + " of " + s.summary.checks + " checks in the last " + state.window + ", threshold " + availabilityThreshold() + "%";
    });
  }
  function drawCharts() {
    var lat = document.getElementById("lat-chart"), av = document.getElementById("av-chart");
    if (!lat || !lastSeries) return;
    latencyChart(lat, lastSeries, lastThr);
    availabilityChart(av, lastSeries, availabilityThreshold());
  }

  function loadProxy(name) {
    return api("/api/proxies/" + encodeURIComponent(name)).then(function (d) {
      setDemo(d.demo);
      var p = d.proxy;
      lastThr = d.thresholds.latency_ms;
      document.getElementById("p-name").innerHTML = esc(p.name) + " " + pill(p.state);
      document.getElementById("p-sub").textContent = p.protocol + " · " + p.url + " · checked every " + p.interval + " · last check " + ago(p.last_check);
      var act = document.getElementById("p-actions");
      if (d.management && !act.dataset.ready) {
        act.dataset.ready = "1";
        act.innerHTML = '<button class="btn" type="button" id="check-now">Check now</button><span class="btn-msg" id="check-msg"></span>';
        document.getElementById("check-now").addEventListener("click", function () {
          var btn = this, msg = document.getElementById("check-msg");
          btn.disabled = true;
          api("/api/proxies/" + encodeURIComponent(name) + "/check", { method: "POST", headers: { "X-Proxy-Monitor-Request": "1", Accept: "application/json" } })
            .then(function () { msg.textContent = "Check queued"; setTimeout(function () { refresh(); }, 2500); })
            .catch(function (e) { msg.textContent = e.message; })
            .then(function () { setTimeout(function () { btn.disabled = false; }, 3000); });
        });
      }
      var S = d.summaries;
      document.getElementById("p-kpis").innerHTML =
        tile("Availability 1h", fmtPct(S["1h"].uptime, S["1h"].checks), S["1h"].checks + " checks") +
        tile("Availability 24h", fmtPct(S["24h"].uptime, S["24h"].checks), S["24h"].checks + " checks") +
        tile("Availability 7d", fmtPct(S["7d"].uptime, S["7d"].checks), S["7d"].checks + " checks") +
        tile("Availability 30d", fmtPct(S["30d"].uptime, S["30d"].checks), S["30d"].checks + " checks") +
        tile("Median 24h", S["24h"].successes ? fmtMs(S["24h"].p50_ms) : "-", "p95 " + (S["24h"].successes ? fmtMs(S["24h"].p95_ms) : "-") + ", avg " + (S["24h"].successes ? fmtMs(S["24h"].avg_ms) : "-")) +
        tile("Failures in a row", String(p.consecutive_failures), "down after " + d.thresholds.failure_threshold + ", recovered after " + d.thresholds.recovery_threshold);
      document.getElementById("lat-legend").innerHTML =
        '<span class="key"><svg viewBox="0 0 22 10" aria-hidden="true"><line x1="1" y1="5" x2="21" y2="5" class="line s1"/></svg>p50 (median)</span>' +
        '<span class="key"><svg viewBox="0 0 22 10" aria-hidden="true"><line x1="1" y1="5" x2="21" y2="5" class="line s2"/></svg>p95</span>' +
        '<span class="key"><svg viewBox="0 0 22 10" aria-hidden="true"><line x1="1" y1="5" x2="21" y2="5" class="threshold"/></svg>latency threshold ' + esc(fmtMs(lastThr)) + "</span>";
      var labels = Object.keys(p.labels || {}).sort().map(function (k) { return '<span class="chip">' + esc(k + "=" + p.labels[k]) + "</span>"; }).join("") || "-";
      document.getElementById("p-facts").innerHTML =
        "<dt>Protocol</dt><dd>" + esc(p.protocol) + "</dd>" +
        "<dt>Proxy</dt><dd class=\"mono\">" + esc(p.url) + "</dd>" +
        "<dt>Target</dt><dd>" + esc(p.target) + ' <span class="mono">' + esc(p.target_url) + "</span> (" + esc(p.check === "tunnel" ? "tunnel only" : "HTTP request") + ")</dd>" +
        "<dt>Interval</dt><dd>every " + esc(p.interval) + ", timeout " + esc(p.timeout) + "</dd>" +
        "<dt>Last checked</dt><dd>" + esc(fmtTime(p.last_check)) + " (" + esc(ago(p.last_check)) + ")</dd>" +
        "<dt>Last success</dt><dd>" + esc(fmtTime(p.last_ok)) + "</dd>" +
        "<dt>Last failure</dt><dd>" + esc(fmtTime(p.last_failure)) + (p.last_error_class ? ' <span class="cls">' + esc(p.last_error_class) + "</span>" : "") + "</dd>" +
        "<dt>Labels</dt><dd>" + labels + "</dd>";
      var ph = d.phases_24h || {};
      var order = [["dns", "DNS lookup"], ["connect", "TCP connect"], ["proxy_handshake", "Proxy handshake"], ["tls", "TLS with target"], ["ttfb", "Time to first byte"]];
      var maxv = Math.max.apply(null, order.map(function (o) { return ph[o[0]] || 0; }).concat([1]));
      document.getElementById("p-phases").innerHTML = ph.total === undefined ? '<div class="empty">No successful check in the last 24 hours.</div>' :
        '<div class="phases">' + order.map(function (o) {
          var v = ph[o[0]] || 0, w = Math.max(v > 0 ? 2 : 0, v / maxv * 100);
          return '<span class="pn">' + o[1] + '</span><svg viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true"><rect class="f-track" x="0" y="2" width="100" height="8" rx="2"/><rect class="f-s1" x="0" y="2" width="' + w.toFixed(2) + '" height="8" rx="2"/></svg><span class="pv">' + esc(v ? fmtMs(v) : "0 ms") + "</span>";
        }).join("") + '<span class="pn"><strong>Total</strong></span><span></span><span class="pv"><strong>' + esc(fmtMs(ph.total)) + "</strong></span></div>";
      document.getElementById("p-errors").innerHTML = d.recent_errors.length ?
        "<table><thead><tr><th>Time</th><th>Class</th><th>Error</th></tr></thead><tbody>" + d.recent_errors.map(function (c) {
          return "<tr><td>" + esc(fmtTime(c.time)) + '</td><td><span class="cls">' + esc(c.error_class) + "</span><br><span class=\"url\">" + esc(classText(c.error_class)) + '</span></td><td class="err">' + esc(c.error) + "</td></tr>";
        }).join("") + "</tbody></table>" : '<div class="empty">No failed checks in the last 7 days.</div>';
      document.getElementById("p-incidents").innerHTML = incidentTable(d.incidents, false);
      document.getElementById("p-checks").innerHTML = d.recent_checks.length ?
        "<table><thead><tr><th>Time</th><th>Result</th><th class=\"num\">DNS</th><th class=\"num\">Connect</th><th class=\"num\">Handshake</th><th class=\"num\">TLS</th><th class=\"num\">TTFB</th><th class=\"num\">Total</th><th class=\"num hide-sm\">Bytes</th></tr></thead><tbody>" +
        d.recent_checks.map(function (c) {
          return "<tr><td>" + esc(fmtTime(c.time)) + "</td><td>" + (c.ok ? '<span class="status healthy">' + ICONS.healthy + "OK" + (c.status_code ? " " + c.status_code : "") + "</span>" : '<span class="status down">' + ICONS.down + esc(c.error_class) + "</span>") + "</td>" +
            '<td class="num">' + esc(fmtMs(c.dns_ms)) + '</td><td class="num">' + esc(fmtMs(c.connect_ms)) + '</td><td class="num">' + esc(fmtMs(c.handshake_ms)) + '</td><td class="num">' + esc(fmtMs(c.tls_ms)) + '</td><td class="num">' + esc(fmtMs(c.ttfb_ms)) + '</td><td class="num">' + esc(c.ok ? fmtMs(c.total_ms) : "-") + '</td><td class="num hide-sm">' + (c.bytes_in + c.bytes_out) + "</td></tr>";
        }).join("") + "</tbody></table>" : '<div class="empty">No checks yet.</div>';
      return loadSeries(name);
    });
  }

  function renderIncidentsShell() {
    app.innerHTML = '<div class="page-head"><div><h1>Incidents</h1><div class="sub">Outages, slow periods and low availability, with recovery times. Alerts are listed below.</div></div>' +
      '<div class="seg" id="inc-filter" role="group" aria-label="Filter incidents"><button type="button" data-v="all">All</button><button type="button" data-v="open">Open</button></div></div>' +
      '<section class="card"><div class="table-wrap" id="inc-table"></div></section>' +
      '<section class="card"><div class="card-head"><h2>Alert history</h2><span class="hint">sent and suppressed notifications</span></div><div class="table-wrap" id="alert-table"></div></section>';
    document.querySelectorAll("#inc-filter button").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-v") === state.incStatus ? "true" : "false");
      b.addEventListener("click", function () {
        state.incStatus = b.getAttribute("data-v");
        document.querySelectorAll("#inc-filter button").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
        loadIncidents();
      });
    });
  }
  function loadIncidents() {
    return Promise.all([api("/api/incidents?limit=300&status=" + state.incStatus), api("/api/alerts?limit=50")]).then(function (r) {
      setDemo(r[0].demo);
      document.getElementById("inc-table").innerHTML = incidentTable(r[0].incidents, true);
      var a = r[1].alerts;
      document.getElementById("alert-table").innerHTML = a.length ?
        "<table><thead><tr><th>Time</th><th>Proxy</th><th>Event</th><th>Status</th><th>Channels</th><th>Message</th></tr></thead><tbody>" + a.map(function (x) {
          return "<tr><td>" + esc(fmtTime(x.time)) + "</td><td>" + esc(x.proxy || "-") + "</td><td>" + esc(x.kind) + "</td><td>" + esc(x.status) + "</td><td>" + esc(x.channels || "-") + '</td><td class="err">' + esc(x.message) + "</td></tr>";
        }).join("") + "</tbody></table>" : '<div class="empty">No alerts yet.</div>';
    });
  }

  function loadSettings() {
    return api("/api/settings").then(function (s) {
      state.settings = s;
      setDemo(s.demo);
      function facts(obj) { return '<dl class="facts">' + obj.map(function (r) { return "<dt>" + esc(r[0]) + "</dt><dd>" + r[1] + "</dd>"; }).join("") + "</dl>"; }
      var m = s.monitor, t = s.thresholds, st = s.storage, sv = s.server, al = s.alerts;
      app.innerHTML = '<div class="page-head"><div><h1>Settings</h1><div class="sub">Read from <code>' + esc(s.config_file) + "</code>. Edit the file and restart the monitor to change them; the dashboard cannot change the configuration.</div></div></div>" +
        '<div class="grid two">' +
        '<section class="card"><div class="card-head"><h2>Monitoring frequency</h2></div>' + facts([
          ["Default interval", esc(m.interval)], ["Timeout", esc(m.timeout)], ["Jitter", Math.round(m.jitter * 100) + "% of the interval"],
          ["Concurrency", m.concurrency + " checks at once, all proxies together"], ["Minimum interval", esc(m.min_interval) + " (1s only for proxies on this machine)"]]) + "</section>" +
        '<section class="card"><div class="card-head"><h2>Alert thresholds</h2></div>' + facts([
          ["Down after", t.failure_threshold + " failed checks in a row"], ["Recovered after", t.recovery_threshold + " successful checks in a row"],
          ["Slow when", "median of the last " + t.latency_samples + " checks is above " + esc(t.latency)],
          ["Low availability", "below " + t.availability + "% over " + esc(t.availability_window) + " (at least " + t.availability_min_checks + " checks)"]]) + "</section>" +
        '<section class="card"><div class="card-head"><h2>Data retention</h2></div>' + facts([
          ["Database", "<code>" + esc(st.file) + "</code> (SQLite)"], ["Check results", "kept " + esc(st.retention)], ["Incidents and alerts", "kept " + esc(st.incident_retention)]]) + "</section>" +
        '<section class="card"><div class="card-head"><h2>Alerts</h2></div>' + facts([
          ["Channels", al.channels.length ? al.channels.map(function (c) { return '<span class="chip">' + esc(c) + "</span>"; }).join("") : "none"],
          ["Cooldown", esc(al.cooldown) + " per proxy and alert type"], ["Rate limit", al.max_per_minute + " per minute, the rest summarized"],
          ["Reminders", al.repeat_interval === "0s" ? "off" : "every " + esc(al.repeat_interval) + " while down"]]) + "</section>" +
        '<section class="card"><div class="card-head"><h2>Dashboard and API</h2></div>' + facts([
          ["Listening on", "<code>" + esc(sv.listen) + "</code>"], ["Authentication", sv.auth ? "token required" : "off (allowed only on localhost)"],
          ["Check now button", sv.management ? "enabled" : "disabled (needs server.auth_token)"],
          ["Extra host names", sv.allowed_hosts && sv.allowed_hosts.length ? esc(sv.allowed_hosts.join(", ")) : "none"]]) + "</section>" +
        "</div>" +
        '<section class="card"><div class="card-head"><h2>Authorized target endpoints</h2><span class="hint">the only URLs the monitor requests</span></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>URL</th><th>Check</th><th>Expect</th><th class="num">Limit</th><th class="num">Proxies</th></tr></thead><tbody>' +
        s.targets.map(function (x) {
          return "<tr><td class=\"name\">" + esc(x.name) + '</td><td class="url">' + esc(x.url) + "</td><td>" + esc(x.check === "tunnel" ? "tunnel only" : x.method) + "</td><td>HTTP " + esc(x.expect_status.join(", ")) + (x.expect_body ? " + body text" : "") +
            '</td><td class="num">' + x.max_concurrent + " at once, " + esc(x.min_spacing) + ' apart</td><td class="num">' + x.proxies + "</td></tr>";
        }).join("") + "</tbody></table></div></section>" +
        '<section class="card"><div class="card-head"><h2>Configured proxies</h2></div><div class="table-wrap"><table><thead><tr><th>Name</th><th>Target</th><th class="num">Interval</th><th class="num">Timeout</th><th>Enabled</th></tr></thead><tbody>' +
        s.proxies.map(function (p) { return "<tr><td class=\"name\">" + esc(p.name) + "</td><td>" + esc(p.target) + '</td><td class="num">' + esc(p.interval) + '</td><td class="num">' + esc(p.timeout) + "</td><td>" + (p.disabled ? "no" : "yes") + "</td></tr>"; }).join("") +
        "</tbody></table></div></section>";
    });
  }

  function setDemo(on) { document.getElementById("demo-banner").hidden = !on; }

  // ---------- router ----------
  function parseRoute() {
    var h = location.hash.replace(/^#/, "") || "/";
    var m = h.match(/^\/proxy\/(.+)$/);
    if (m) return { name: "proxy", arg: decodeURIComponent(m[1]) };
    if (h === "/incidents") return { name: "incidents" };
    if (h === "/settings") return { name: "settings" };
    return { name: "overview" };
  }
  function stamp() { document.getElementById("refresh").textContent = "Updated " + fmtTime(new Date().toISOString()) + ", refreshes every 15s"; }
  function fail(e) {
    if (e && e.status === 401) { app.innerHTML = '<div class="note-box">Authentication required. Reload the page and log in with any username and the API token as the password.</div>'; return; }
    app.insertAdjacentHTML("afterbegin", '<div class="note-box">Could not load data: ' + esc(e && e.message) + "</div>");
  }
  function load(r, first) {
    var p;
    if (r.name === "overview") { if (first) renderOverviewShell(); p = loadOverview(); }
    else if (r.name === "proxy") { if (first) renderProxyShell(r.arg); p = loadProxy(r.arg); }
    else if (r.name === "incidents") { if (first) renderIncidentsShell(); p = loadIncidents(); }
    else { p = first ? loadSettings() : Promise.resolve(); }
    return p.then(stamp, function (e) { if (e && e.status === 404) app.innerHTML = '<div class="empty">Not found. <a href="#/">Back to the overview</a></div>'; else fail(e); });
  }
  function refresh() { if (state.route && !document.hidden) load(state.route, false); }
  function navigate() {
    hideTip();
    state.route = parseRoute();
    setActiveNav(state.route.name === "proxy" ? "overview" : state.route.name);
    lastSeries = null;
    load(state.route, true);
    app.focus({ preventScroll: true });
  }

  var resizeT = null;
  window.addEventListener("resize", function () { clearTimeout(resizeT); resizeT = setTimeout(drawCharts, 150); });
  window.addEventListener("hashchange", navigate);
  document.addEventListener("visibilitychange", function () { if (!document.hidden) refresh(); });

  api("/api/settings").then(function (s) {
    state.settings = s;
    document.getElementById("version").textContent = "proxy-health-monitor " + s.version;
  }).catch(function () {}).then(function () {
    navigate();
    timer = setInterval(refresh, REFRESH_MS);
  });
})();
