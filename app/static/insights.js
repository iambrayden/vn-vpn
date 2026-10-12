// Traffic insights dashboard: KPIs, bandwidth, categories, top lists and a live flow feed.
// Every list row is a filter: click it to narrow the whole dashboard (kept in the URL).
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const cfg = JSON.parse($('#ins-config').textContent);
  const FLAGS = new Set(cfg.flags);
  const CATS = cfg.categories;
  const svgNS = 'http://www.w3.org/2000/svg';
  const css = getComputedStyle(document.documentElement);
  const v = name => css.getPropertyValue(name).trim();
  const catColor = c => v(`--cat-${CATS.includes(c) ? CATS.indexOf(c) + 1 : 8}`);
  let regionNames; try { regionNames = new Intl.DisplayNames(['en'], { type: 'region' }); } catch { regionNames = null; }
  const countryName = c => { try { return c ? regionNames?.of(c) || c : 'Unknown'; } catch { return c; } };

  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const fmtBytes = n => {
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; n = +n || 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return i ? `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}` : `${n} B`;
  };
  const fmtNum = n => (+n || 0).toLocaleString();
  const fmtBps = n => {
    const u = ['bps', 'Kbps', 'Mbps', 'Gbps']; let i = 0; n = +n || 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return i ? `${+n.toFixed(n < 10 ? 1 : 0)} ${u[i]}` : `${Math.round(n)} bps`;
  };
  const fmtTime = (t, withDate) => new Date(t * 1000).toLocaleString([], withDate
    ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' } : { hour: '2-digit', minute: '2-digit' });
  const ago = t => { const s = Math.max(0, Date.now() / 1000 - t); return s < 60 ? `${Math.round(s)}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : fmtTime(t, true); };
  const PORTS = { 80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 853: 'DNS-TLS', 22: 'SSH', 25: 'SMTP', 465: 'SMTPS', 587: 'SMTP',
    993: 'IMAPS', 123: 'NTP', 3478: 'STUN', 5228: 'Google Play', 5223: 'Apple Push', 3389: 'RDP', 8080: 'HTTP-alt' };
  const portLabel = (p, proto) => proto === 'icmp' ? 'ping' : `${(proto || '').toUpperCase()} ${p}${PORTS[p] ? ' · ' + PORTS[p] : ''}`;
  const flag = c => c && FLAGS.has(c)
    ? `<img class="flag-img" src="/static/flags/${c.toLowerCase()}.svg" alt="" width="20" height="15">`
    : `<span class="cc">${esc(c || '??')}</span>`;
  const appIcon = (name, cat) => `<span class="app-ic" style="background:${catColor(cat)}">${esc((name || '?').replace(/^www\./, '')[0].toUpperCase())}</span>`;
  const el = (tag, attrs = {}, parent) => {
    const e = document.createElementNS(svgNS, tag);
    for (const [k, val] of Object.entries(attrs)) e.setAttribute(k, val);
    parent?.append(e); return e;
  };
  const niceStep = x => { const p = 10 ** Math.floor(Math.log10(x)); return [1, 2, 2.5, 5, 10].map(m => m * p).find(s => s >= x * 0.999); };

  // ---------------------------------------------------------------- state (mirrors the URL)
  const FILTER_KEYS = ['node', 'device', 'user', 'category', 'app', 'country', 'dest', 'port', 'q'];
  const LABELS = { node: 'Server', device: 'Device', user: 'Customer', category: 'Category', app: 'App', country: 'Country', dest: 'Destination', port: 'Port', q: 'Search' };
  const url = new URL(location.href);
  let range = ['1h', '24h', '7d'].includes(url.searchParams.get('range')) ? url.searchParams.get('range') : '24h';
  const filters = {}, names = {};
  for (const k of FILTER_KEYS) if (url.searchParams.get(k)) filters[k] = url.searchParams.get(k);
  try { Object.assign(names, JSON.parse(sessionStorage.getItem('ins-names') || '{}')); } catch { /* private mode */ }

  const query = extra => {
    const p = new URLSearchParams({ range, ...filters, ...extra });
    return p.toString();
  };
  const syncUrl = () => history.replaceState(null, '', `?${query()}`);
  const label = (k, val) => names[`${k}:${val}`] || (k === 'country' ? countryName(val) : k === 'node' ? ($(`#ins-node option[value="${CSS.escape(val)}"]`)?.textContent || val) : val);

  function setFilter(k, val, name) {
    if (val === undefined || val === null || val === '') delete filters[k]; else filters[k] = String(val);
    if (name) { names[`${k}:${val}`] = name; try { sessionStorage.setItem('ins-names', JSON.stringify(names)); } catch { /* ignore */ } }
    if (k === 'node') $('#ins-node').value = filters.node || '';
    if (k === 'q') $('#ins-q').value = filters.q || '';
    syncUrl(); renderChips(); refresh(true);
  }

  function renderChips() {
    $('#ins-chips').innerHTML = Object.entries(filters).map(([k, val]) =>
      `<button class="chip filter" data-unset="${k}" title="Remove filter"><span>${LABELS[k]}</span><b>${esc(label(k, val))}</b>✕</button>`).join('')
      + (Object.keys(filters).length > 1 ? '<button class="chip" data-unset="*">Clear all</button>' : '');
  }
  $('#ins-chips').addEventListener('click', e => {
    const b = e.target.closest('[data-unset]'); if (!b) return;
    if (b.dataset.unset === '*') { for (const k of Object.keys(filters)) delete filters[k]; $('#ins-node').value = ''; $('#ins-q').value = ''; syncUrl(); renderChips(); refresh(true); }
    else setFilter(b.dataset.unset, '');
  });
  $$('[data-range]').forEach(b => {
    b.classList.toggle('active', b.dataset.range === range);
    b.addEventListener('click', () => { range = b.dataset.range; $$('[data-range]').forEach(x => x.classList.toggle('active', x === b)); syncUrl(); refresh(true); });
  });
  $('#ins-node').value = filters.node || '';
  $('#ins-node').addEventListener('change', e => setFilter('node', e.target.value));
  $('#ins-q').value = filters.q || '';
  let qTimer;
  $('#ins-q').addEventListener('input', e => { clearTimeout(qTimer); qTimer = setTimeout(() => setFilter('q', e.target.value.trim()), 400); });

  // any element with data-f="key" data-v="value" [data-n="label"] is a filter shortcut
  document.addEventListener('click', e => {
    const t = e.target.closest('[data-f]');
    if (!t || !t.dataset.v) return;
    e.preventDefault();
    setFilter(t.dataset.f, t.dataset.v, t.dataset.n);
  });

  // ---------------------------------------------------------------- charts
  function axes(svg, { W, H, L, R, T, B, yMax, step, fmt, x0, x1 }) {
    const Y = val => T + (1 - val / yMax) * (H - T - B);
    const grid = el('g', { class: 'grid' }, svg);
    for (let val = 0; val <= yMax + step / 1000; val += step) {
      el('line', { x1: L, x2: W - R, y1: Y(val), y2: Y(val) }, grid);
      el('text', { x: L - 6, y: Y(val) + 4, 'text-anchor': 'end', class: 'tick' }, svg).textContent = fmt(val);
    }
    const span = x1 - x0, n = W < 500 ? 3 : 6;
    for (let i = 0; i <= n; i++) {
      const t = x0 + span * i / n;
      el('text', { x: L + (W - L - R) * i / n, y: H - 4, 'text-anchor': i === 0 ? 'start' : i === n ? 'end' : 'middle', class: 'tick' }, svg)
        .textContent = span > 2 * 86400 ? new Date(t * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' }) : fmtTime(t, span > 86400);
    }
    return Y;
  }

  function tooltip(box) {
    const tip = document.createElement('div'); tip.className = 'chart-tip'; tip.hidden = true; box.append(tip);
    return {
      show(px, html) {
        tip.innerHTML = html; tip.hidden = false;
        const W = box.clientWidth;
        tip.style.left = `${px + 12 + tip.offsetWidth > W ? Math.max(0, px - tip.offsetWidth - 12) : px + 12}px`; tip.style.top = '0px';
      },
      hide() { tip.hidden = true; },
    };
  }

  function bandwidthChart(box, d) {
    box.replaceChildren();
    const pts = d.throughput;
    if (!pts.length) { box.innerHTML = '<div class="empty-msg">No server metrics for this period</div>'; return; }
    const W = box.clientWidth, H = box.clientHeight, L = 64, R = 8, T = 8, B = 22, x0 = d.since, x1 = d.until;
    const peak = Math.max(...pts.flatMap(p => [p.rx, p.tx])) || 1000;
    const step = niceStep(peak / 3.5), yMax = Math.ceil(peak * 1.05 / step) * step;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Bandwidth, latest in ${fmtBps(pts.at(-1).rx)}, out ${fmtBps(pts.at(-1).tx)}` }, box);
    const Y = axes(svg, { W, H, L, R, T, B, yMax, step, fmt: fmtBps, x0, x1 });
    const X = t => L + (t + d.bucket / 2 - x0) / (x1 - x0) * (W - L - R);
    const series = [{ k: 'rx', label: 'In', c: v('--series-1') }, { k: 'tx', label: 'Out', c: v('--series-2') }];
    for (const s of series) {
      let line = '', prev = null;
      for (const p of pts) { line += `${!prev || p.t - prev.t > d.bucket * 2.5 ? 'M' : 'L'}${X(p.t).toFixed(1)},${Y(p[s.k]).toFixed(1)}`; prev = p; }
      el('path', { d: line, class: 'line', stroke: s.c }, svg);
    }
    const cross = el('line', { class: 'cross', y1: T, y2: H - B, visibility: 'hidden' }, svg);
    const dots = series.map(s => el('circle', { r: 4, fill: s.c, class: 'dot-hover', visibility: 'hidden' }, svg));
    const tip = tooltip(box);
    const hit = el('rect', { x: L, y: T, width: W - L - R, height: H - T - B, fill: 'transparent' }, svg);
    hit.addEventListener('pointermove', ev => {
      const mx = ev.clientX - svg.getBoundingClientRect().left, t = x0 + (mx - L) / (W - L - R) * (x1 - x0) - d.bucket / 2;
      const p = pts.reduce((a, b) => Math.abs(b.t - t) < Math.abs(a.t - t) ? b : a), px = X(p.t);
      cross.setAttribute('x1', px); cross.setAttribute('x2', px); cross.setAttribute('visibility', 'visible');
      series.forEach((s, i) => { dots[i].setAttribute('cx', px); dots[i].setAttribute('cy', Y(p[s.k])); dots[i].setAttribute('visibility', 'visible'); });
      tip.show(px, `<div class="t">${fmtTime(p.t, true)}</div>` + series.map(s =>
        `<div class="row"><span class="swatch" style="background:${s.c}"></span>${s.label}<b>${fmtBps(p[s.k])}</b></div>`).join('')
        + `<div class="row"><span class="swatch"></span>Devices<b>${Math.round(p.peers)}</b></div>`);
    });
    hit.addEventListener('pointerleave', () => { tip.hide(); cross.setAttribute('visibility', 'hidden'); dots.forEach(x => x.setAttribute('visibility', 'hidden')); });
  }

  function categoryChart(box, d) {
    box.replaceChildren();
    const rows = d.timeline;
    if (!rows.length) { box.innerHTML = '<div class="empty-msg">No traffic recorded for this period</div>'; return; }
    const W = box.clientWidth, H = box.clientHeight, L = 64, R = 8, T = 8, B = 22, x0 = d.since, x1 = d.until;
    const total = r => CATS.reduce((a, c) => a + (r[c] || 0), 0);
    const peak = Math.max(...rows.map(total)) || 1;
    const step = niceStep(peak / 3.5), yMax = Math.ceil(peak * 1.05 / step) * step;
    const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Data by category over time' }, box);
    const Y = axes(svg, { W, H, L, R, T, B, yMax, step, fmt: fmtBytes, x0, x1 });
    const bw = (W - L - R) * d.bucket / (x1 - x0), gap = Math.min(2, bw * 0.2);
    const tip = tooltip(box);
    for (const r of rows) {
      const g = el('g', { class: 'bar-col' }, svg);
      const x = L + (r.t - x0) / (x1 - x0) * (W - L - R);
      let acc = 0;
      for (const c of CATS) {
        if (!r[c]) continue;
        const y1 = Y(acc), y2 = Y(acc + r[c]);
        el('rect', { class: 'seg-bar', x: Math.max(L, x + gap / 2), y: y2, width: Math.max(1, bw - gap), height: Math.max(0.5, y1 - y2 - (acc ? 1 : 0)), fill: catColor(c) }, g);
        acc += r[c];
      }
      el('rect', { x: Math.max(L, x), y: T, width: Math.max(1, bw), height: H - T - B, fill: 'transparent' }, g)
        .addEventListener('pointerenter', () => tip.show(x + bw / 2, `<div class="t">${fmtTime(r.t, true)} · ${fmtBytes(total(r))}</div>` +
          CATS.filter(c => r[c]).sort((a, b) => r[b] - r[a]).map(c =>
            `<div class="row"><span class="swatch" style="background:${catColor(c)};height:10px"></span>${esc(c)}<b>${fmtBytes(r[c])}</b></div>`).join('')));
    }
    svg.addEventListener('pointerleave', () => tip.hide());
  }

  // ---------------------------------------------------------------- lists
  function barList(id, rows, { value, name, sub, icon, filter, color, empty = 'No data for these filters' }) {
    const box = $(id);
    if (!rows.length) { box.innerHTML = `<li class="empty">${empty}</li>`; return; }
    const max = Math.max(...rows.map(value)) || 1;
    box.innerHTML = rows.map(r => {
      const [fk, fv, fn] = filter(r);
      return `<li data-f="${fk}" data-v="${esc(fv)}" data-n="${esc(fn ?? '')}" title="Filter by ${esc(fn || fv)}">
        <div class="row">${icon ? icon(r) : ''}<span class="name">${esc(name(r))}</span>${sub ? `<span class="sub">${esc(sub(r))}</span>` : ''}
          <span class="val">${r._label ?? fmtBytes(value(r))}</span></div>
        <div class="track"><i style="width:${(100 * value(r) / max).toFixed(1)}%;background:${color(r)}"></i></div></li>`;
    }).join('');
  }

  function render(d) {
    const k = d.kpi;
    const set = (key, text) => { $(`[data-kpi="${key}"]`).textContent = text; };
    set('down', fmtBytes(k.down)); set('up', fmtBytes(k.up)); set('clients', fmtNum(k.clients)); set('conns', fmtNum(k.conns));
    set('dests', fmtNum(k.dests)); set('dns', fmtNum(k.dns)); set('top_app', k.top_app || '—');
    $('[data-kpi="top_app"]').title = k.top_app || '';
    $('#tp-sub').textContent = filters.node ? `${label('node', filters.node)}, network interface` : 'all servers, network interface';

    const total = d.categories.reduce((a, c) => a + c.down + c.up, 0);
    $('#cat-total').textContent = total ? fmtBytes(total) : '';
    $('#cat-bar').innerHTML = d.categories.filter(c => c.down + c.up > 0).map(c =>
      `<i style="width:${(100 * (c.down + c.up) / total).toFixed(2)}%;background:${catColor(c.name)}" title="${esc(c.name)}: ${fmtBytes(c.down + c.up)}"></i>`).join('');
    $('#cat-bar').setAttribute('aria-label', d.categories.map(c => `${c.name} ${total ? Math.round(100 * (c.down + c.up) / total) : 0}%`).join(', '));
    $('#cat-list').innerHTML = d.categories.map(c => {
      const b = c.down + c.up;
      return `<li class="${b ? '' : 'zero'}" data-f="category" data-v="${esc(c.name)}"><span class="dot" style="background:${catColor(c.name)}"></span>${esc(c.name)}
        <span class="val">${fmtBytes(b)}</span><span class="pct">${total ? Math.round(100 * b / total) + '%' : '—'}</span></li>`;
    }).join('');

    bandwidthChart($('#chart-tp'), d);
    categoryChart($('#chart-cat'), d);
    const tot = r => r.down + r.up;
    barList('#list-apps', d.apps, { value: tot, name: r => r.name, sub: r => r.category, icon: r => appIcon(r.name, r.category),
      filter: r => ['app', r.name], color: r => catColor(r.category) });
    barList('#list-clients', d.clients, { value: tot, name: r => r.device || r.ip, sub: r => `${r.user || 'unknown'}${r.top_app ? ' · ' + r.top_app : ''}`,
      icon: r => `<span class="avatar" style="width:22px;height:22px;font-size:11px">${esc((r.user || '?')[0])}</span>`,
      filter: r => r.device_id ? ['device', r.device_id, `${r.device} (${r.user})`] : ['q', r.ip], color: () => v('--series-1') });
    barList('#list-dests', d.destinations, { value: tot, name: r => r.name, sub: r => r.name === r.ip ? r.org : r.app,
      icon: r => flag(r.country), filter: r => ['dest', r.name], color: r => catColor(r.category) });
    barList('#list-countries', d.countries, { value: tot, name: r => countryName(r.code), sub: r => `${fmtNum(r.dests)} IPs`,
      icon: r => flag(r.code), filter: r => ['country', r.code], color: () => v('--series-1'), empty: 'No destination countries yet' });
    barList('#list-dns', d.dns.map(r => ({ ...r, _label: fmtNum(r.lookups) })), { value: r => r.lookups, name: r => r.name,
      sub: r => r.app && r.app !== r.name ? r.app : '', filter: r => ['dest', r.name], color: r => catColor(r.category || 'Other'),
      empty: 'No DNS lookups recorded (needs agent 0.5+)' });
    barList('#list-ports', d.ports.map(r => ({ ...r, _label: `${fmtNum(r.conns)} conns` })), { value: r => r.conns,
      name: r => portLabel(r.port, r.proto), sub: r => fmtBytes(tot(r)), filter: r => ['port', r.port], color: () => v('--series-1') });
    barList('#list-servers', d.servers, { value: tot, name: r => r.name, sub: r => `${fmtNum(r.conns)} conns`,
      filter: r => ['node', r.id], color: () => v('--series-1') });
    $('#servers-card').hidden = !!filters.node;
    $('#ins-updated').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
  }

  // ---------------------------------------------------------------- live feed
  let lastId = 0, paused = false;
  const liveRow = (f, isNew) => {
    const client = f.device_name
      ? `<a data-f="device" data-v="${f.device_id ?? ''}" data-n="${esc(`${f.device_name} (${f.user_email})`)}">${esc(f.device_name)}</a> <span class="muted">${esc(f.user_email)}</span>`
      : `<span class="mono">${esc(f.src)}</span>`;
    const dest = f.host ? `${esc(f.host)} <span class="muted mono">${esc(f.dst)}</span>` : `<span class="mono">${esc(f.dst)}</span>${f.org ? ` <span class="muted">${esc(f.org)}</span>` : ''}`;
    return `<tr class="${isNew ? 'new' : ''}"><td class="muted" title="${esc(fmtTime(f.first_seen, true))}">${ago(f.last_seen)}</td>
      <td>${client}</td>
      <td><a class="cell" data-f="app" data-v="${esc(f.app)}">${appIcon(f.app, f.category)}${esc(f.app)}</a></td>
      <td class="dest"><a data-f="dest" data-v="${esc(f.host || f.dst)}">${dest}</a></td>
      <td class="hide-md">${f.country ? `<a class="cell" data-f="country" data-v="${esc(f.country)}">${flag(f.country)}${esc(f.country)}</a>` : '<span class="muted">—</span>'}</td>
      <td class="hide-md">${esc(portLabel(f.dport, f.proto))}</td><td>${fmtBytes(f.bytes_in)}</td><td>${fmtBytes(f.bytes_out)}</td></tr>`;
  };
  let liveRows = [];
  async function pollLive(reset) {
    if (reset) { lastId = 0; liveRows = []; }
    try {
      const r = await fetch(`/admin/insights/live.json?${query({ after: lastId })}`, { headers: { Accept: 'application/json' } });
      if (!r.ok) return;
      const { flows } = await r.json();
      const fresh = new Set(lastId ? flows.map(f => f.id) : []);
      if (flows.length) lastId = Math.max(lastId, ...flows.map(f => f.id));
      liveRows = [...flows, ...liveRows].slice(0, 25);
      $('#live-body').innerHTML = liveRows.length ? liveRows.map(f => liveRow(f, fresh.has(f.id))).join('')
        : '<tr><td colspan="8" class="muted">No flows for these filters yet. Flows arrive as servers check in (every 15s).</td></tr>';
    } catch { /* offline: try again next tick */ }
  }
  $('#live-toggle').addEventListener('click', e => {
    paused = !paused; e.target.textContent = paused ? 'Resume' : 'Pause';
    $('#live-dot').classList.toggle('paused', paused);
    if (!paused) pollLive();
  });

  // ---------------------------------------------------------------- refresh loop
  let lastData = null, inflight = 0;
  async function refresh(reset) {
    const my = ++inflight;
    try {
      const r = await fetch(`/admin/insights/data.json?${query()}`, { headers: { Accept: 'application/json' } });
      if (!r.ok || my !== inflight) return;
      lastData = await r.json();
      render(lastData);
    } catch { /* keep the last view */ }
    if (reset) pollLive(true);
  }
  renderChips();
  refresh(true);
  setInterval(() => { if (!document.hidden) refresh(); }, 30000);
  setInterval(() => { if (!document.hidden && !paused) pollLive(); }, 5000);
  let rt; addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => lastData && render(lastData), 150); });
})();
