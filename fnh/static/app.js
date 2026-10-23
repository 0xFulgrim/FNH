// FNH dashboard. Plain JS, no dependencies. Every string from a report comes
// from an external advisory feed: it is inserted with textContent only.
"use strict";

(() => {
  // Stack order is the validated one (status palette, adjacent-pair checks):
  // resolved > awaiting > failed > review. Status is never hue alone: each
  // group carries an icon and a label everywhere it appears.
  const GROUPS = [
    { key: "resolved", label: "Resolved", color: "var(--status-good)", statuses: ["patched", "mitigated"] },
    { key: "awaiting", label: "Awaiting promotion", color: "var(--status-warning)", statuses: ["awaiting_promotion"] },
    { key: "failed", label: "Failed", color: "var(--status-critical)", statuses: ["failed"] },
    { key: "review", label: "Needs review", color: "var(--status-serious)", statuses: ["needs_review"] },
  ];
  const OPEN = new Set(["awaiting", "failed", "review"]);
  const STATUS_LABEL = {
    patched: "Patched", mitigated: "Mitigated", awaiting_promotion: "Awaiting promotion",
    needs_review: "Needs review", failed: "Failed",
  };
  const SEVERITIES = ["critical", "high", "medium", "low"];
  const SEV_RANK = { low: 1, medium: 2, high: 3, critical: 4 };
  const POLL_MS = 30000;

  const state = {
    runs: [],
    report: null,
    history: [],
    promotions: { directory: null, requests: [] },
    run: null,
    followLatest: true,
    filters: { status: "open", severity: "all", environment: "all", source: "all", q: "" },
    sort: { key: "severity", dir: "desc" },
    expanded: new Set(),
    tableView: {},
  };

  // ---- DOM helpers ------------------------------------------------------
  const $ = (id) => document.getElementById(id);
  const SVG_NS = "http://www.w3.org/2000/svg";

  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    applyProps(node, props);
    for (const child of children.flat()) {
      if (child == null || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function svg(tag, props = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    applyProps(node, props);
    return node;
  }

  function applyProps(node, props) {
    for (const [key, value] of Object.entries(props)) {
      if (value == null || value === false) continue;
      if (key === "class") node.setAttribute("class", value);
      else if (key === "text") node.textContent = value;
      else if (key === "style") Object.assign(node.style, value);
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : value);
    }
  }

  const groupOf = (status) => (GROUPS.find((g) => g.statuses.includes(status)) || GROUPS[3]).key;
  const groupDef = (key) => GROUPS.find((g) => g.key === key);
  const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : "");
  const compact = (n) => (n >= 1000 ? `${(n / 1000).toFixed(1).replace(/\.0$/, "")}K` : String(n));
  const fmtDate = (iso, withTime = true) => {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso || "";
    const opts = { month: "short", day: "numeric" };
    if (withTime) Object.assign(opts, { hour: "2-digit", minute: "2-digit" });
    return d.toLocaleString(undefined, opts);
  };
  const outcomeKey = (o) => `${o.advisory.id}@${o.asset.id}`;

  function statusIcon(groupKey) {
    return el("span", { class: `status-icon s-${groupKey}`, "aria-hidden": "true" });
  }

  function severityCell(sev, cvss) {
    const rank = SEV_RANK[sev] || 0;
    const bars = el("span", { class: "sev-bars", "aria-hidden": "true" },
      [1, 2, 3, 4].map((i) => el("i", { class: i <= rank ? "on" : "" })));
    return el("span", { class: "severity" }, bars, cap(sev),
      cvss != null ? el("span", { class: "muted", text: Number(cvss).toFixed(1) }) : null);
  }

  // ---- Data ---------------------------------------------------------------
  async function api(path) {
    const resp = await fetch(path, { cache: "no-store" });
    if (!resp.ok) throw new Error(`${path}: HTTP ${resp.status}`);
    return resp.json();
  }

  function passesNonStatus(f, sev, env, source) {
    if (f.severity !== "all") {
      const floor = f.severity === "critical" ? 4 : f.severity === "high" ? 3 : 2;
      if ((SEV_RANK[sev] || 0) < floor) return false;
    }
    if (f.environment !== "all" && env !== f.environment) return false;
    if (f.source !== "all" && source !== f.source) return false;
    return true;
  }

  function passesStatus(f, groupKey) {
    if (f.status === "all") return true;
    if (f.status === "open") return OPEN.has(groupKey);
    return groupKey === f.status;
  }

  function passesSearch(f, o) {
    if (!f.q) return true;
    const q = f.q.toLowerCase();
    return [o.advisory.id, o.advisory.title, o.asset.name, o.asset.id]
      .some((v) => (v || "").toLowerCase().includes(q));
  }

  const outcomes = () => (state.report ? state.report.outcomes || [] : []);
  const baseOutcomes = () => outcomes().filter((o) =>
    passesNonStatus(state.filters, o.advisory.severity, o.asset.environment, o.advisory.source)
    && passesSearch(state.filters, o));
  const filteredOutcomes = () => baseOutcomes().filter((o) => passesStatus(state.filters, groupOf(o.status)));

  function statusFilterLabel() {
    const f = state.filters.status;
    if (f === "all") return "Findings";
    if (f === "open") return "Open findings";
    return `${groupDef(f).label} findings`;
  }

  // ---- Loading ------------------------------------------------------------
  async function loadAll(runName) {
    $("content").classList.add("loading");
    try {
      const [report, history, promotions] = await Promise.all([
        api(`/api/runs/${encodeURIComponent(runName)}`),
        api("/api/history"),
        api("/api/promotions"),
      ]);
      state.run = runName;
      state.report = report;
      state.history = history;
      state.promotions = promotions;
      syncFilterOptions();
      render();
    } catch (err) {
      $("run-meta").textContent = `Could not load the report: ${err.message}`;
    } finally {
      $("content").classList.remove("loading");
    }
  }

  async function refreshRuns(initial = false) {
    let runs;
    try {
      runs = await api("/api/runs");
    } catch (err) {
      $("run-meta").textContent = `Dashboard server unreachable: ${err.message}`;
      return;
    }
    const changed = runs.length !== state.runs.length || (runs[0] && state.runs[0] && runs[0].name !== state.runs[0].name);
    state.runs = runs;
    $("no-reports").hidden = runs.length > 0;
    $("content").hidden = runs.length === 0;
    if (!runs.length) {
      $("run-meta").textContent = "Waiting for reports";
      return;
    }
    renderRunSelect();
    if (initial || (changed && state.followLatest)) await loadAll(runs[0].name);
  }

  function syncFilterOptions() {
    const fill = (select, values, current) => {
      const keep = values.includes(current) ? current : "all";
      select.replaceChildren(el("option", { value: "all", text: "All" }),
        ...values.map((v) => el("option", { value: v, text: cap(v) })));
      select.value = keep;
      return keep;
    };
    const envs = [...new Set(outcomes().map((o) => o.asset.environment).filter(Boolean))].sort();
    const sources = [...new Set(outcomes().map((o) => o.advisory.source).filter(Boolean))].sort();
    state.filters.environment = fill($("f-environment"), envs, state.filters.environment);
    state.filters.source = fill($("f-source"), sources, state.filters.source);
  }

  function renderRunSelect() {
    const select = $("f-run");
    select.replaceChildren(...state.runs.map((r, i) => {
      const s = r.summary || {};
      const label = `${fmtDate(r.generated_at)}${i === 0 ? " (latest)" : ""}${r.dry_run ? " · dry run" : ""} · ${s.total ?? 0} findings`;
      return el("option", { value: r.name, text: label });
    }));
    if (state.run) select.value = state.run;
  }

  // ---- Rendering ----------------------------------------------------------
  function render() {
    renderMeta();
    renderKpis();
    renderCharts();
    renderFindings();
    renderPromotions();
  }

  function renderMeta() {
    const r = state.report;
    const meta = $("run-meta");
    meta.replaceChildren(
      `Run ${fmtDate(r.generated_at)} · sources: ${(r.sources || []).join(", ") || "none"} · inventory: ${r.inventory_source || "?"}`,
      ...(r.dry_run ? [el("span", { class: "badge", text: "dry run" })] : []),
    );
  }

  function previousRunFindings() {
    const idx = state.history.findIndex((h) => h.name === state.run);
    return idx > 0 ? state.history[idx - 1].findings : null;
  }

  function renderKpis() {
    const base = baseOutcomes();
    const counts = Object.fromEntries(GROUPS.map((g) => [g.key, 0]));
    for (const o of base) counts[groupOf(o.status)] += 1;
    const open = counts.awaiting + counts.failed + counts.review;
    $("kpi-open").textContent = compact(open);
    for (const g of GROUPS) $(`kpi-${g.key}`).textContent = compact(counts[g.key]);

    const delta = $("kpi-delta");
    delta.className = "tile-delta";
    const prev = previousRunFindings();
    if (!prev || state.filters.q) {
      delta.textContent = prev ? "Search not applied to the comparison" : "First run: no comparison yet";
    } else {
      const f = state.filters;
      const prevOpen = prev.filter((x) => passesNonStatus(f, x.severity, x.environment, x.source)
        && OPEN.has(groupOf(x.status))).length;
      const d = open - prevOpen;
      if (d === 0) delta.textContent = "No change vs previous run";
      else {
        // Fewer open findings is the good direction.
        delta.textContent = `${d > 0 ? "▲" : "▼"} ${Math.abs(d)} vs previous run`;
        delta.classList.add(d > 0 ? "bad" : "good");
      }
    }
    for (const tile of document.querySelectorAll(".tile")) {
      tile.classList.toggle("active", tile.dataset.status === state.filters.status);
      tile.setAttribute("aria-pressed", String(tile.dataset.status === state.filters.status));
    }
  }

  // ---- Tooltip ------------------------------------------------------------
  const tip = () => $("tooltip");

  function showTooltip(x, y, title, rows) {
    const t = tip();
    t.replaceChildren(
      ...(title ? [el("div", { class: "tooltip-title", text: title })] : []),
      ...rows.map((r) => el("div", { class: "tooltip-row" },
        r.color ? el("span", { class: "line-key", style: { background: r.color } }) : "",
        // Value leads, label follows.
        el("strong", { text: String(r.value) }),
        el("span", { text: r.label }))),
    );
    t.hidden = false;
    const pad = 12;
    const { width, height } = t.getBoundingClientRect();
    let left = x + pad;
    let top = y + pad;
    if (left + width > window.innerWidth - 8) left = x - width - pad;
    if (top + height > window.innerHeight - 8) top = y - height - pad;
    t.style.left = `${Math.max(8, left)}px`;
    t.style.top = `${Math.max(8, top)}px`;
  }

  const hideTooltip = () => { tip().hidden = true; };

  function bindMarkTooltip(node, title, rows) {
    node.addEventListener("pointermove", (e) => showTooltip(e.clientX, e.clientY, title, rows));
    node.addEventListener("pointerleave", hideTooltip);
    node.addEventListener("focus", () => {
      const b = node.getBoundingClientRect();
      showTooltip(b.right, b.top, title, rows);
    });
    node.addEventListener("blur", hideTooltip);
  }

  // ---- Charts -------------------------------------------------------------
  function niceScale(max, maxTicks = 5) {
    // These are counts: never let a handful of findings fill the whole axis.
    max = Math.max(max, 4);
    const raw = max / (maxTicks - 1);
    const mag = 10 ** Math.floor(Math.log10(raw));
    const step = Math.max(1, [1, 2, 5, 10].map((m) => m * mag).find((s) => s >= raw));
    const top = Math.ceil(max / step) * step;
    const ticks = [];
    for (let v = 0; v <= top + 1e-9; v += step) ticks.push(v);
    return { max: top, ticks };
  }

  // A bar whose data end (right) is rounded 4px and whose baseline end is square.
  function barPath(x, y, w, h, r = 4) {
    const rr = Math.min(r, w / 2, h / 2);
    return `M${x},${y}H${x + w - rr}A${rr},${rr} 0 0 1 ${x + w},${y + rr}`
      + `V${y + h - rr}A${rr},${rr} 0 0 1 ${x + w - rr},${y + h}H${x}Z`;
  }

  function chartWidth(container) {
    return Math.max(280, Math.floor(container.getBoundingClientRect().width));
  }

  function tableToggle(cardId, key, renderChart, renderTable) {
    const card = $(cardId);
    const button = card.querySelector(".table-toggle");
    const on = !!state.tableView[key];
    button.setAttribute("aria-pressed", String(on));
    button.onclick = () => { state.tableView[key] = !state.tableView[key]; renderCharts(); };
    const target = card.querySelector(".chart");
    target.replaceChildren(on ? renderTable() : renderChart(target));
  }

  function renderCharts() {
    hideTooltip();
    renderSeverity();
    renderTrend();
    renderAssets();
  }

  function severityData() {
    const f = state.filters;
    const rows = SEVERITIES.filter((s) => passesNonStatus({ ...f, environment: "all", source: "all" }, s));
    const groups = GROUPS.filter((g) => passesStatus(f, g.key));
    const data = rows.map((sev) => ({ sev, counts: Object.fromEntries(groups.map((g) => [g.key, 0])) }));
    for (const o of filteredOutcomes()) {
      const row = data.find((d) => d.sev === o.advisory.severity);
      const g = groupOf(o.status);
      if (row && g in row.counts) row.counts[g] += 1;
    }
    return { data, groups };
  }

  function renderSeverity() {
    const { data, groups } = severityData();
    const legend = $("severity-legend");
    legend.replaceChildren(...groups.map((g) =>
      el("span", { class: "legend-item" }, statusIcon(g.key), g.label)));
    $("severity-sub").textContent = `${statusFilterLabel()} in this run, by advisory severity`;

    tableToggle("card-severity", "severity", (container) => {
      const W = chartWidth(container);
      const labelW = 76, rightPad = 44, rowH = 36, barH = 20, top = 4, axisH = 24;
      const plotW = W - labelW - rightPad;
      const totals = data.map((d) => Object.values(d.counts).reduce((a, b) => a + b, 0));
      const scale = niceScale(Math.max(0, ...totals));
      const H = top + data.length * rowH + axisH;
      const x = (v) => labelW + (v / scale.max) * plotW;
      const root = svg("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img",
        "aria-label": `${statusFilterLabel()} by severity: ` + data.map((d, i) => `${d.sev} ${totals[i]}`).join(", ") });

      for (const t of scale.ticks) {
        root.append(svg("line", { class: "grid", x1: x(t), x2: x(t), y1: top, y2: top + data.length * rowH }));
        root.append(svg("text", { class: "axis-label", x: x(t), y: H - 6, "text-anchor": "middle", text: compact(t) }));
      }
      root.append(svg("line", { class: "baseline", x1: labelW, x2: labelW, y1: top, y2: top + data.length * rowH }));

      data.forEach((d, i) => {
        const y = top + i * rowH + (rowH - barH) / 2;
        root.append(svg("text", { x: labelW - 10, y: y + barH / 2 + 4, "text-anchor": "end", text: cap(d.sev) }));
        const segments = groups.filter((g) => d.counts[g.key] > 0);
        let cursor = labelW;
        segments.forEach((g, j) => {
          const count = d.counts[g.key];
          const w = (count / scale.max) * plotW;
          const last = j === segments.length - 1;
          // 2px surface gap between touching segments: the gap separates, not a stroke.
          const drawW = last ? w : Math.max(1, w - 2);
          const mark = last
            ? svg("path", { d: barPath(cursor, y, drawW, barH) })
            : svg("rect", { x: cursor, y, width: drawW, height: barH });
          mark.setAttribute("class", "mark");
          mark.setAttribute("tabindex", "0");
          mark.setAttribute("aria-label", `${cap(d.sev)}: ${count} ${g.label}`);
          mark.style.fill = g.color;
          // The hit target is the full row height, not just the painted bar.
          const hit = svg("rect", { x: cursor, y: top + i * rowH, width: Math.max(w, 4), height: rowH, fill: "transparent" });
          const rows = [{ value: count, label: g.label, color: g.color }];
          bindMarkTooltip(mark, `${cap(d.sev)} severity`, rows);
          bindMarkTooltip(hit, `${cap(d.sev)} severity`, rows);
          root.append(hit, mark);
          cursor += w;
        });
        root.append(svg("text", { class: "value-label", x: x(totals[i]) + 6, y: y + barH / 2 + 4, text: compact(totals[i]) }));
      });
      return root;
    }, () => el("table", { class: "data-table chart-table" },
      el("thead", {}, el("tr", {}, el("th", { text: "Severity" }), groups.map((g) => el("th", { text: g.label })), el("th", { text: "Total" }))),
      el("tbody", {}, data.map((d) => el("tr", {},
        el("td", { text: cap(d.sev) }),
        groups.map((g) => el("td", { class: "num", text: String(d.counts[g.key]) })),
        el("td", { class: "num", text: String(Object.values(d.counts).reduce((a, b) => a + b, 0)) }))))));
  }

  function trendData() {
    const f = state.filters;
    return state.history.map((h) => {
      const scoped = h.findings.filter((x) => passesNonStatus(f, x.severity, x.environment, x.source));
      return {
        name: h.name,
        at: h.generated_at,
        value: scoped.filter((x) => passesStatus(f, groupOf(x.status))).length,
        total: scoped.length,
      };
    });
  }

  function renderTrend() {
    const points = trendData();
    const label = statusFilterLabel();
    $("trend-title").textContent = `${label} over runs`;
    $("trend-sub").textContent = `Last ${points.length} run${points.length === 1 ? "" : "s"}`
      + (state.filters.q ? " · search doesn't apply here" : "") + " · click a point to open that run";

    tableToggle("card-trend", "trend", (container) => {
      if (points.length < 2) {
        return el("p", { class: "chart-empty", text: "The trend appears after two or more runs." });
      }
      const W = chartWidth(container);
      const H = 220, padL = 36, padR = 44, padT = 14, padB = 26;
      const plotW = W - padL - padR, plotH = H - padT - padB;
      const scale = niceScale(Math.max(...points.map((p) => p.value)), 4);
      const xs = points.map((_, i) => padL + (i * plotW) / (points.length - 1));
      const y = (v) => padT + plotH - (v / scale.max) * plotH;
      const root = svg("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img",
        "aria-label": `${label} over the last ${points.length} runs; latest ${points[points.length - 1].value}` });

      for (const t of scale.ticks) {
        root.append(svg("line", { class: t === 0 ? "baseline" : "grid", x1: padL, x2: padL + plotW, y1: y(t), y2: y(t) }));
        root.append(svg("text", { class: "axis-label", x: padL - 8, y: y(t) + 4, "text-anchor": "end", text: compact(t) }));
      }
      // Up to four x labels, evenly spread, so dates never collide.
      const step = Math.max(1, Math.ceil((points.length - 1) / 3));
      for (let i = 0; i < points.length; i += step) {
        root.append(svg("text", { class: "axis-label", x: xs[i], y: H - 6,
          "text-anchor": i === 0 ? "start" : "middle", text: fmtDate(points[i].at, false) }));
      }

      const linePts = points.map((p, i) => `${xs[i]},${y(p.value)}`).join(" L");
      const area = svg("path", { d: `M${xs[0]},${y(0)} L${linePts} L${xs[xs.length - 1]},${y(0)} Z` });
      area.style.fill = "var(--series-1-wash)";
      const line = svg("path", { d: `M${linePts}`, fill: "none", "stroke-width": 2,
        "stroke-linejoin": "round", "stroke-linecap": "round" });
      line.style.stroke = "var(--series-1)";
      root.append(area, line);

      const dot = (i, r = 4) => {
        const c = svg("circle", { cx: xs[i], cy: y(points[i].value), r, "stroke-width": 2 });
        c.style.fill = "var(--series-1)";
        c.style.stroke = "var(--surface-1)"; // 2px surface ring
        return c;
      };
      const last = points.length - 1;
      root.append(dot(last));
      root.append(svg("text", { class: "value-label", x: xs[last] + 8, y: y(points[last].value) + 4,
        text: compact(points[last].value) }));
      const selected = points.findIndex((p) => p.name === state.run);
      if (selected >= 0 && selected !== last) root.append(dot(selected));

      // Crosshair: snaps to the nearest run; same readout on keyboard focus.
      const cross = svg("line", { class: "crosshair", y1: padT, y2: padT + plotH, visibility: "hidden" });
      const hover = dot(0);
      hover.setAttribute("visibility", "hidden");
      const overlay = svg("rect", { x: padL - 8, y: padT, width: plotW + 16, height: plotH,
        fill: "transparent", tabindex: "0", class: "mark",
        "aria-label": "Trend: use the arrow keys to move between runs, Enter to open one" });
      let active = last;
      const show = (i, cx, cy) => {
        active = Math.max(0, Math.min(last, i));
        cross.setAttribute("x1", xs[active]);
        cross.setAttribute("x2", xs[active]);
        cross.setAttribute("visibility", "visible");
        hover.setAttribute("cx", xs[active]);
        hover.setAttribute("cy", y(points[active].value));
        hover.setAttribute("visibility", "visible");
        const p = points[active];
        const box = root.getBoundingClientRect();
        const rows = [{ value: p.value, label, color: "var(--series-1)" }];
        if (state.filters.status !== "all") rows.push({ value: p.total, label: "all statuses" });
        showTooltip(cx ?? box.left + xs[active], cy ?? box.top + y(p.value), fmtDate(p.at), rows);
      };
      const nearest = (clientX) => {
        const bx = root.getBoundingClientRect().left;
        let best = 0;
        xs.forEach((x, i) => { if (Math.abs(x + bx - clientX) < Math.abs(xs[best] + bx - clientX)) best = i; });
        return best;
      };
      const clear = () => {
        cross.setAttribute("visibility", "hidden");
        hover.setAttribute("visibility", "hidden");
        hideTooltip();
      };
      overlay.addEventListener("pointermove", (e) => show(nearest(e.clientX), e.clientX, e.clientY));
      overlay.addEventListener("pointerleave", clear);
      overlay.addEventListener("focus", () => show(active));
      overlay.addEventListener("blur", clear);
      overlay.addEventListener("keydown", (e) => {
        if (e.key === "ArrowLeft") { e.preventDefault(); show(active - 1); }
        else if (e.key === "ArrowRight") { e.preventDefault(); show(active + 1); }
        else if (e.key === "Enter") selectRun(points[active].name);
      });
      overlay.addEventListener("click", (e) => selectRun(points[nearest(e.clientX)].name));
      root.append(cross, hover, overlay);
      return root;
    }, () => el("table", { class: "data-table chart-table" },
      el("thead", {}, el("tr", {}, el("th", { text: "Run" }), el("th", { text: label }), el("th", { text: "All statuses" }))),
      el("tbody", {}, [...points].reverse().map((p) => el("tr", {},
        el("td", { text: fmtDate(p.at) }),
        el("td", { class: "num", text: String(p.value) }),
        el("td", { class: "num", text: String(p.total) }))))));
  }

  function assetsData() {
    const byAsset = new Map();
    for (const o of filteredOutcomes()) {
      const cur = byAsset.get(o.asset.id) || { id: o.asset.id, name: o.asset.name, env: o.asset.environment, count: 0 };
      cur.count += 1;
      byAsset.set(o.asset.id, cur);
    }
    return [...byAsset.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)).slice(0, 8);
  }

  function renderAssets() {
    const rows = assetsData();
    $("assets-sub").textContent = `${statusFilterLabel()} per asset, top ${rows.length || 8}`;
    tableToggle("card-assets", "assets", (container) => {
      if (!rows.length) return el("p", { class: "chart-empty", text: "No findings match these filters." });
      const W = chartWidth(container);
      const labelW = Math.min(180, Math.floor(W * 0.38)), rightPad = 40, rowH = 30, barH = 16, top = 2;
      const plotW = W - labelW - rightPad;
      const H = top + rows.length * rowH + 4;
      const scale = niceScale(Math.max(...rows.map((r) => r.count)));
      const maxChars = Math.floor((labelW - 12) / 7);
      const root = svg("svg", { width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: "img",
        "aria-label": "Findings per asset: " + rows.map((r) => `${r.name} ${r.count}`).join(", ") });
      root.append(svg("line", { class: "baseline", x1: labelW, x2: labelW, y1: top, y2: top + rows.length * rowH }));
      rows.forEach((r, i) => {
        const y = top + i * rowH + (rowH - barH) / 2;
        const name = r.name.length > maxChars ? `${r.name.slice(0, maxChars - 1)}…` : r.name;
        const text = svg("text", { x: labelW - 10, y: y + barH / 2 + 4, "text-anchor": "end", text: name });
        text.append(svg("title", { text: `${r.name} (${r.env})` }));
        root.append(text);
        const w = Math.max(2, (r.count / scale.max) * plotW);
        const mark = svg("path", { d: barPath(labelW, y, w, barH), class: "mark", tabindex: "0",
          "aria-label": `${r.name}: ${r.count}` });
        mark.style.fill = "var(--series-1)";
        const hit = svg("rect", { x: labelW, y: top + i * rowH, width: Math.max(w, plotW * 0.15), height: rowH, fill: "transparent" });
        const tipRows = [{ value: r.count, label: statusFilterLabel().toLowerCase(), color: "var(--series-1)" }];
        bindMarkTooltip(mark, `${r.name} · ${r.env}`, tipRows);
        bindMarkTooltip(hit, `${r.name} · ${r.env}`, tipRows);
        root.append(hit, mark,
          svg("text", { class: "value-label", x: labelW + w + 6, y: y + barH / 2 + 4, text: compact(r.count) }));
      });
      return root;
    }, () => el("table", { class: "data-table chart-table" },
      el("thead", {}, el("tr", {}, el("th", { text: "Asset" }), el("th", { text: "Environment" }), el("th", { text: "Findings" }))),
      el("tbody", {}, rows.map((r) => el("tr", {},
        el("td", { text: r.name }), el("td", { text: r.env }), el("td", { class: "num", text: String(r.count) }))))));
  }

  // ---- Findings table -----------------------------------------------------
  const SORTERS = {
    severity: (o) => SEV_RANK[o.advisory.severity] || 0,
    advisory: (o) => o.advisory.id,
    asset: (o) => o.asset.name.toLowerCase(),
    environment: (o) => o.asset.environment || "",
    status: (o) => GROUPS.findIndex((g) => g.key === groupOf(o.status)),
    source: (o) => o.advisory.source || "",
  };

  function sortedFindings() {
    const { key, dir } = state.sort;
    const get = SORTERS[key];
    const sign = dir === "asc" ? 1 : -1;
    return [...filteredOutcomes()].sort((a, b) => {
      const va = get(a), vb = get(b);
      if (va < vb) return -1 * sign;
      if (va > vb) return 1 * sign;
      return (SEV_RANK[b.advisory.severity] || 0) - (SEV_RANK[a.advisory.severity] || 0)
        || a.advisory.id.localeCompare(b.advisory.id);
    });
  }

  function safeLink(url) {
    return /^https?:\/\//i.test(url)
      ? el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: url })
      : el("span", { text: url });
  }

  function detailsRow(o) {
    const rem = o.remediation;
    const list = (items) => (items && items.length
      ? el("ul", {}, items.map((t) => el("li", { text: t })))
      : el("p", { class: "muted", text: "None" }));
    const section = (title, ...body) => el("div", {}, el("h3", { text: title }), ...body);
    return el("tr", { class: "details" }, el("td", { colspan: "7" }, el("div", { class: "details-grid" },
      section("Why it matched", el("p", { text: o.reason || "" })),
      section("Remediation",
        rem ? el("p", { text: `${cap(rem.kind)}: ${rem.description}` }) : el("p", { class: "muted", text: "None" }),
        rem && rem.steps && rem.steps.length ? el("pre", {}, el("code", { text: rem.steps.join("\n") })) : null),
      section("Next steps", list(o.recommendations)),
      section("Notes", list(o.notes)),
      section("References", o.advisory.references && o.advisory.references.length
        ? el("ul", {}, o.advisory.references.map((u) => el("li", {}, safeLink(u))))
        : el("p", { class: "muted", text: "None" })),
      section("Advisory", el("p", { text: o.advisory.title || o.advisory.id })),
    )));
  }

  function renderFindings() {
    const rows = sortedFindings();
    const body = document.querySelector("#findings-table tbody");
    const all = outcomes().length;
    $("findings-count").textContent = `${rows.length} of ${all} in this run`;
    $("findings-empty").hidden = rows.length > 0;

    for (const th of document.querySelectorAll("#findings-table th")) {
      const b = th.querySelector("button");
      if (!b) continue;
      th.setAttribute("aria-sort", b.dataset.sort === state.sort.key
        ? (state.sort.dir === "asc" ? "ascending" : "descending") : "none");
    }

    const frag = document.createDocumentFragment();
    for (const o of rows) {
      const key = outcomeKey(o);
      const open = state.expanded.has(key);
      const g = groupOf(o.status);
      const toggle = () => {
        if (state.expanded.has(key)) state.expanded.delete(key); else state.expanded.add(key);
        renderFindings();
      };
      const tr = el("tr", { class: "row", tabindex: "0", "aria-expanded": String(open),
        onclick: toggle,
        onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } } },
        el("td", {}, severityCell(o.advisory.severity, o.advisory.cvss)),
        el("td", {}, el("span", { class: "adv-id", text: o.advisory.id }),
          o.advisory.title && o.advisory.title !== o.advisory.id ? el("span", { class: "adv-title", text: o.advisory.title }) : null),
        el("td", {}, el("span", { class: "asset-name", text: o.asset.name }), " ",
          o.asset.version ? el("span", { class: "asset-version", text: o.asset.version }) : null),
        el("td", { text: o.asset.environment || "" }),
        el("td", {}, el("span", { class: "status-pill" }, statusIcon(g), STATUS_LABEL[o.status] || o.status)),
        el("td", { class: "muted", text: o.remediation ? o.remediation.description : "" }),
        el("td", { text: o.advisory.source || "" }));
      frag.append(tr);
      if (open) frag.append(detailsRow(o));
    }
    body.replaceChildren(frag);
  }

  // ---- Promotions ---------------------------------------------------------
  function renderPromotions() {
    const { directory, requests } = state.promotions;
    const body = document.querySelector("#promotions-table tbody");
    const empty = $("promotions-empty");
    const pending = requests.filter((r) => !r.result).length;
    $("promotions-sub").textContent = directory
      ? `${pending} pending · apply with fnh promote; the dashboard is read-only`
      : "Start the dashboard with --promote-dir to show queued production changes";
    empty.hidden = requests.length > 0;
    empty.textContent = directory ? "No promotion requests." : "";
    const kind = { applied: "resolved", failed: "failed" };
    body.replaceChildren(...[...requests].sort((a, b) => (b.created || "").localeCompare(a.created || "")).map((r) => {
      const g = kind[r.result] || "awaiting";
      const label = r.result === "applied" ? "Applied" : r.result === "failed" ? "Failed" : "Pending";
      const cmd = `fnh promote --promote-dir ${directory || "DIR"} --apply ${r.id} --approve --prod-host HOST`;
      return el("tr", {},
        el("td", {}, el("span", { class: "status-pill" }, statusIcon(g), label)),
        el("td", {}, el("code", { text: r.id }),
          !r.result ? el("div", { class: "cmd", text: cmd }) : null),
        el("td", { text: r.advisory_id }),
        el("td", { text: r.asset_id }),
        el("td", { class: "muted", text: r.description || "" }),
        el("td", { text: fmtDate(r.created) }));
    }));
  }

  // ---- Interaction --------------------------------------------------------
  async function selectRun(name) {
    if (!name || name === state.run) return;
    state.followLatest = state.runs.length > 0 && name === state.runs[0].name;
    $("f-run").value = name;
    await loadAll(name);
  }

  function bindControls() {
    $("f-run").addEventListener("change", (e) => selectRun(e.target.value));
    for (const [id, key] of [["f-status", "status"], ["f-severity", "severity"],
      ["f-environment", "environment"], ["f-source", "source"]]) {
      $(id).addEventListener("change", (e) => { state.filters[key] = e.target.value; render(); });
    }
    let timer;
    $("f-search").addEventListener("input", (e) => {
      clearTimeout(timer);
      timer = setTimeout(() => { state.filters.q = e.target.value.trim(); render(); }, 120);
    });
    for (const tile of document.querySelectorAll(".tile")) {
      tile.addEventListener("click", () => {
        state.filters.status = tile.dataset.status;
        $("f-status").value = tile.dataset.status;
        render();
      });
    }
    for (const b of document.querySelectorAll("#findings-table th button")) {
      b.addEventListener("click", () => {
        const key = b.dataset.sort;
        state.sort = state.sort.key === key
          ? { key, dir: state.sort.dir === "asc" ? "desc" : "asc" }
          : { key, dir: key === "severity" ? "desc" : "asc" };
        renderFindings();
      });
    }
    // Charts are drawn at their real width; redraw when it changes.
    let lastWidth = 0;
    new ResizeObserver(() => {
      const w = $("content").getBoundingClientRect().width;
      if (state.report && Math.abs(w - lastWidth) > 2) { lastWidth = w; renderCharts(); }
    }).observe($("content"));
    window.addEventListener("scroll", hideTooltip, { passive: true });
  }

  // ---- Theme --------------------------------------------------------------
  const THEMES = ["system", "light", "dark"];

  function applyTheme(mode) {
    if (mode === "system") delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = mode;
    $("theme-toggle").textContent = `Theme: ${mode}`;
  }

  function initTheme() {
    let mode = "system";
    try { mode = localStorage.getItem("fnh-theme") || "system"; } catch (_) { /* storage blocked */ }
    if (!THEMES.includes(mode)) mode = "system";
    applyTheme(mode);
    $("theme-toggle").addEventListener("click", () => {
      const current = document.documentElement.dataset.theme || "system";
      const next = THEMES[(THEMES.indexOf(current) + 1) % THEMES.length];
      applyTheme(next);
      try { localStorage.setItem("fnh-theme", next); } catch (_) { /* storage blocked */ }
    });
  }

  // ---- Start --------------------------------------------------------------
  initTheme();
  bindControls();
  refreshRuns(true);
  setInterval(() => refreshRuns(false), POLL_MS);
})();
