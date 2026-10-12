// Small progressive enhancements: toasts, dialogs, confirm, copy, tabs, filters, live status.
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => [...el.querySelectorAll(s)];

  // ---------------------------------------------------------------- toasts
  const toastBox = $('#toasts');
  function dismiss(t) { t.classList.add('leaving'); setTimeout(() => t.remove(), 200); }
  function arm(t) {
    $('.x', t)?.addEventListener('click', () => dismiss(t));
    if (!t.classList.contains('sticky')) setTimeout(() => dismiss(t), t.classList.contains('error') ? 8000 : 5000);
  }
  window.toast = (msg, kind = 'ok', sticky = false) => {
    const t = document.createElement('div');
    t.className = `toast ${kind}${sticky ? ' sticky' : ''}`;
    t.setAttribute('role', 'status');
    t.innerHTML = '<span></span><button class="x" aria-label="Dismiss">×</button>';
    t.firstChild.textContent = msg;
    toastBox.append(t); arm(t);
  };
  $$('.toast', toastBox).forEach(arm);

  // ---------------------------------------------------------------- dialogs
  document.addEventListener('click', e => {
    const opener = e.target.closest('[data-open]');
    if (opener) { e.preventDefault(); opener.closest('details.menu')?.removeAttribute('open'); $('#' + opener.dataset.open)?.showModal(); }
    const closer = e.target.closest('[data-close]');
    if (closer) closer.closest('dialog')?.close();
    if (e.target.tagName === 'DIALOG') e.target.close(); // click on backdrop
    // close any open dropdown menus when clicking elsewhere
    $$('details.menu[open]').forEach(d => { if (!d.contains(e.target)) d.open = false; });
  });

  // Confirm before destructive submits: <form data-confirm="Delete X?" data-confirm-label="Delete">
  const confirmDlg = $('#confirm-dialog');
  let pendingForm = null;
  document.addEventListener('submit', e => {
    const f = e.target;
    if (!f.dataset.confirm || f.dataset.confirmed) return;
    e.preventDefault();
    pendingForm = f;
    $('#confirm-text').textContent = f.dataset.confirm;
    $('#confirm-ok').textContent = f.dataset.confirmLabel || 'Confirm';
    confirmDlg.showModal();
  });
  $('#confirm-ok')?.addEventListener('click', () => {
    confirmDlg.close();
    if (pendingForm) { pendingForm.dataset.confirmed = '1'; pendingForm.requestSubmit(); }
  });

  // ---------------------------------------------------------------- row menus
  // Row "•••" menus live inside scrollable tables; float them above the page instead of
  // letting the table clip them (which also produced a scrollbar).
  document.addEventListener('toggle', e => {
    const d = e.target;
    if (!(d instanceof HTMLDetailsElement) || !d.classList.contains('row-menu') || !d.open) return;
    $$('details.row-menu[open]').forEach(o => o !== d && (o.open = false));
    const pop = $('.menu-pop', d), r = $('summary', d).getBoundingClientRect();
    pop.style.position = 'fixed';
    pop.style.left = 'auto';
    pop.style.right = `${Math.max(8, window.innerWidth - r.right)}px`;
    const below = window.innerHeight - r.bottom, h = pop.offsetHeight;
    pop.style.top = below < h + 12 && r.top > h + 12 ? `${r.top - h - 6}px` : `${r.bottom + 6}px`;
  }, true);
  const closeRowMenus = () => $$('details.row-menu[open]').forEach(d => (d.open = false));
  window.addEventListener('scroll', closeRowMenus, true);
  window.addEventListener('resize', closeRowMenus);

  // ---------------------------------------------------------------- copy & reveal
  document.addEventListener('click', async e => {
    const b = e.target.closest('[data-copy]');
    if (!b) return;
    const src = $(b.dataset.copy);
    const text = src ? (src.value ?? src.textContent).trim() : b.dataset.copy;
    try { await navigator.clipboard.writeText(text); } catch {
      const ta = Object.assign(document.createElement('textarea'), { value: text });
      document.body.append(ta); ta.select(); document.execCommand('copy'); ta.remove();
    }
    const old = b.textContent; b.textContent = 'Copied ✓';
    setTimeout(() => (b.textContent = old), 1500);
  });
  document.addEventListener('click', e => {
    const b = e.target.closest('[data-reveal]');
    if (!b) return;
    const input = b.parentElement.querySelector('input');
    input.type = input.type === 'password' ? 'text' : 'password';
    b.textContent = input.type === 'password' ? 'Show' : 'Hide';
  });

  // ---------------------------------------------------------------- tabs (synced with #hash)
  const tabs = $('[data-tabs]');
  if (tabs) {
    const show = name => {
      if (!$(`[data-panel="${name}"]`)) name = $('[data-tab]', tabs).dataset.tab;
      $$('[data-tab]', tabs).forEach(b => b.classList.toggle('active', b.dataset.tab === name));
      $$('[data-panel]').forEach(p => (p.hidden = p.dataset.panel !== name));
    };
    tabs.addEventListener('click', e => {
      const b = e.target.closest('[data-tab]');
      if (b) { history.replaceState(null, '', '#' + b.dataset.tab); show(b.dataset.tab); }
    });
    const fromHash = () => show(location.hash.slice(1).split('/')[0]);
    window.addEventListener('hashchange', fromHash); fromHash();
  }

  // ---------------------------------------------------------------- list filters
  // <input data-filter="#rows"> filters children by text; <button class="chip" data-chip="active" data-chip-for="#rows">
  function applyFilter(container) {
    const q = ($(`[data-filter="#${container.id}"]`)?.value || '').toLowerCase().trim();
    const chip = $(`.chip.active[data-chip-for="#${container.id}"]`)?.dataset.chip || '';
    let visible = 0;
    for (const row of container.children) {
      if (row.dataset.static) continue;
      const ok = (!q || row.textContent.toLowerCase().includes(q)) && (!chip || (row.dataset.tags || '').split(' ').includes(chip));
      row.hidden = !ok; visible += ok;
    }
    const empty = $(`[data-empty-for="#${container.id}"]`);
    if (empty) empty.hidden = visible > 0;
  }
  $$('[data-filter]').forEach(i => i.addEventListener('input', () => applyFilter($(i.dataset.filter))));
  document.addEventListener('click', e => {
    const c = e.target.closest('[data-chip-for]');
    if (!c) return;
    $$(`[data-chip-for="${c.dataset.chipFor}"]`).forEach(x => x.classList.toggle('active', x === c));
    applyFilter($(c.dataset.chipFor));
  });

  // ---------------------------------------------------------------- helpers
  const fmtBytes = n => {
    const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; n = +n || 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return i ? n.toFixed(1) + ' ' + u[i] : n + ' B';
  };
  const fmtBps = n => {
    const u = ['bps', 'Kbps', 'Mbps', 'Gbps']; let i = 0; n = +n || 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return i ? n.toFixed(1) + ' ' + u[i] : Math.round(n) + ' bps';
  };
  const poll = (url, fn, ms = 10000) => {
    const tick = () => document.hidden || fetch(url, { credentials: 'same-origin' })
      .then(r => (r.ok ? r.json() : null)).then(d => d && fn(d)).catch(() => {});
    setInterval(tick, ms);
    document.addEventListener('visibilitychange', () => !document.hidden && tick());
  };

  // ---------------------------------------------------------------- client portal
  const page = document.body.dataset.page;
  if (page === 'portal') {
    // Highlight the download link for the visitor's platform
    const ua = navigator.userAgent;
    const os = /iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1) ? 'ios'
      : /Android/.test(ua) ? 'android' : /Windows/.test(ua) ? 'windows' : /Mac OS X/.test(ua) ? 'macos' : /Linux/.test(ua) ? 'linux' : '';
    const mine = $(`.platforms a[data-os="${os}"]`);
    if (mine) { mine.classList.add('mine'); $('.platforms')?.prepend(mine); }
    const isMobile = os === 'ios' || os === 'android';
    $$('[data-desktop-only]').forEach(el => (el.hidden = isMobile));
    $$('[data-mobile-only]').forEach(el => (el.hidden = !isMobile));

    // "Setting up: <device>" picker rewrites every download / QR link for the chosen device
    const pick = $('#device-pick');
    const applyDevice = () => {
      if (!pick) return;
      const id = pick.value, name = pick.selectedOptions[0]?.textContent || '';
      $$('[data-device-href]').forEach(a => (a.href = `${a.dataset.deviceHref}?device=${id}`));
      $$('[data-device-src]').forEach(img => {
        const src = `${img.dataset.deviceSrc}?device=${id}`;
        if (img.getAttribute('src') !== src) { img.classList.remove('failed'); img.nextElementSibling.hidden = true; img.src = src; }
      });
      $$('[data-k=device-name]').forEach(el => (el.textContent = name));
    };
    let lastPick = pick?.value;
    pick?.addEventListener('change', () => {
      if (pick.value === 'new') { pick.value = lastPick; $('#add-device')?.showModal(); return; }
      lastPick = pick.value;
      applyDevice();
      const u = new URL(location.href); u.searchParams.set('device', pick.value); history.replaceState(null, '', u);
    });
    applyDevice();
    // Warn before giving a device's config for a location it already has (likely a second machine)
    const downloaded = JSON.parse($('#locations')?.dataset.downloaded || '{}');
    let pendingConfig = null;
    document.addEventListener('click', e => {
      const el = e.target.closest('[data-config-node]');
      if (!el || !pick || el.dataset.confirmed) return;
      const done = downloaded[pick.value] || [];
      if (!done.includes(+el.dataset.configNode)) {
        done.push(+el.dataset.configNode); downloaded[pick.value] = done;  // first time: fine
        return;
      }
      e.preventDefault(); e.stopImmediatePropagation();
      pendingConfig = el;
      $('[data-k=dup-device]').textContent = pick.selectedOptions[0].textContent;
      $('#dup-config').showModal();
    }, true);
    $('#dup-continue')?.addEventListener('click', () => {
      $('#dup-config').close();
      if (!pendingConfig) return;
      pendingConfig.dataset.confirmed = '1'; pendingConfig.click(); delete pendingConfig.dataset.confirmed;
    });

    // Suggest a device name from the browser
    const nameInput = $('#device-name');
    if (nameInput) nameInput.value = { ios: 'iPhone', android: 'Android phone', windows: 'Windows PC', macos: 'Mac', linux: 'Linux PC' }[os] || '';

    let wasConnected = $$('.device-icon.on').length;
    let signature = null;
    poll('/portal/status.json', data => {
      const sig = JSON.stringify(data.devices.map(d => [d.id, d.connected, d.blocked, d.kicked, d.node_name]));
      if (signature !== null && sig !== signature && !$('dialog[open]')) {
        // connection state changed: reload so devices, limits and notices are all consistent
        const n = data.devices.filter(d => d.connected).length;
        if (n > wasConnected) sessionStorage.setItem('vn-toast', `Connected ✓ ${data.devices.find(d => d.connected)?.name || ''}`);
        location.reload(); return;
      }
      signature = sig;
      // live traffic counters without reloading
      const live = data.devices.filter(d => d.connected);
      if (live.length) {
        $('[data-k=down]').textContent = fmtBytes(live.reduce((a, d) => a + d.down, 0));
        $('[data-k=up]').textContent = fmtBytes(live.reduce((a, d) => a + d.up, 0));
      }
      for (const n of data.nodes) {
        const card = $(`[data-node="${n.id}"]`);
        if (!card) continue;
        card.classList.toggle('is-offline', !n.online);
        const m = $('.meter', card);
        m.className = 'meter' + (n.load >= 80 ? ' high' : n.load >= 50 ? ' mid' : '');
        $('i', m).style.width = Math.max(4, n.load) + '%';
        $('[data-k=load]', card).textContent = n.load >= 80 ? 'Busy' : n.load >= 50 ? 'Moderate' : 'Low load';
      }
    }, 8000);
    const pending = sessionStorage.getItem('vn-toast');
    if (pending) { sessionStorage.removeItem('vn-toast'); toast(pending); }
  }

  // ---------------------------------------------------------------- server page charts
  if (page === 'server') {
    const id = $('[data-server]').dataset.server;
    let range = '1h';
    const svgNS = 'http://www.w3.org/2000/svg';
    const el = (tag, attrs = {}, parent) => {
      const e = document.createElementNS(svgNS, tag);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
      parent?.append(e); return e;
    };
    const fmtTime = (t, withDate) => new Date(t * 1000).toLocaleString([], withDate
      ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' } : { hour: '2-digit', minute: '2-digit' });
    // smallest round step (1, 2, 2.5, 5 x 10^k) at least as big as the target -> 3-5 gridlines
    const niceStep = v => { const p = 10 ** Math.floor(Math.log10(v)); return [1, 2, 2.5, 5, 10].map(m => m * p).find(s => s >= v * 0.999); };

    // One-axis line chart; series = [{key, label, color, fmt}]. Lines break where data is missing (server offline).
    function lineChart(box, data, series, { max, fmt }) {
      box.replaceChildren();
      const pts = data.points;
      if (!pts.length) { box.innerHTML = '<div class="empty-msg">No data for this period yet</div>'; return; }
      const W = box.clientWidth, H = box.clientHeight, L = 44, R = 8, T = 8, B = 22;
      const x0 = data.since, x1 = data.until;
      const peak = Math.max(...pts.flatMap(p => series.map(s => p[s.key]))) || 1;
      const step = max ? niceStep(max / 4) : niceStep(peak / 3.5);
      const yMax = max ?? Math.ceil(peak * 1.05 / step) * step;
      const X = t => L + (t - x0) / (x1 - x0) * (W - L - R), Y = v => T + (1 - v / yMax) * (H - T - B);
      const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img',
        'aria-label': series.map(s => `${s.label}: latest ${s.fmt(pts.at(-1)[s.key])}`).join(', ') }, box);
      const grid = el('g', { class: 'grid' }, svg);
      for (let v = 0; v <= yMax + step / 1000; v += step) {
        const y = Y(v);
        el('line', { x1: L, x2: W - R, y1: y, y2: y }, grid);
        el('text', { x: L - 6, y: y + 4, 'text-anchor': 'end', class: 'tick' }, svg).textContent = fmt(v);
      }
      const span = x1 - x0, ticks = 5;
      for (let i = 0; i <= ticks; i++) {
        const t = x0 + span * i / ticks;
        el('text', { x: X(t), y: H - 4, 'text-anchor': i === 0 ? 'start' : i === ticks ? 'end' : 'middle', class: 'tick' }, svg)
          .textContent = fmtTime(t, span > 86400);
      }
      for (const s of series) {
        let d = '', prev = null;
        for (const p of pts) {
          const gap = prev && p.t - prev.t > data.bucket * 2.5;
          d += `${!prev || gap ? 'M' : 'L'}${X(p.t + data.bucket / 2).toFixed(1)},${Y(p[s.key]).toFixed(1)}`;
          prev = p;
        }
        el('path', { d, class: 'line', stroke: s.color }, svg);
      }
      // hover: crosshair + tooltip on the nearest bucket
      const cross = el('line', { class: 'cross', y1: T, y2: H - B, visibility: 'hidden' }, svg);
      const dots = series.map(s => el('circle', { r: 4, fill: s.color, class: 'dot-hover', visibility: 'hidden' }, svg));
      const tip = document.createElement('div'); tip.className = 'chart-tip'; tip.hidden = true; box.append(tip);
      const hit = el('rect', { x: L, y: T, width: W - L - R, height: H - T - B, fill: 'transparent' }, svg);
      const show = ev => {
        const r = svg.getBoundingClientRect(), mx = (ev.touches?.[0] ?? ev).clientX - r.left;
        const t = x0 + (mx - L) / (W - L - R) * (x1 - x0);
        const p = pts.reduce((a, b) => Math.abs(b.t - t) < Math.abs(a.t - t) ? b : a);
        const px = X(p.t + data.bucket / 2);
        cross.setAttribute('x1', px); cross.setAttribute('x2', px); cross.setAttribute('visibility', 'visible');
        series.forEach((s, i) => { dots[i].setAttribute('cx', px); dots[i].setAttribute('cy', Y(p[s.key])); dots[i].setAttribute('visibility', 'visible'); });
        tip.innerHTML = `<div class="t">${fmtTime(p.t, true)}</div>` + series.map(s =>
          `<div class="row"><span class="swatch" style="background:${s.color}"></span>${s.label}<b>${s.fmt(p[s.key])}</b></div>`).join('');
        tip.hidden = false;
        const left = Math.min(Math.max(px + 12, 0), W - tip.offsetWidth);
        tip.style.left = `${px + 12 + tip.offsetWidth > W ? px - tip.offsetWidth - 12 : left}px`; tip.style.top = '0px';
      };
      const hide = () => { tip.hidden = true; cross.setAttribute('visibility', 'hidden'); dots.forEach(d => d.setAttribute('visibility', 'hidden')); };
      hit.addEventListener('pointermove', show); hit.addEventListener('pointerleave', hide);
      hit.addEventListener('touchstart', show, { passive: true });
    }

    const css = getComputedStyle(document.documentElement);
    const c1 = () => css.getPropertyValue('--series-1').trim(), c2 = () => css.getPropertyValue('--series-2').trim();
    const pct = v => `${Math.round(v)}%`;
    const mbps = v => v === 0 ? '0' : `${+(v / 1e6).toFixed(v < 1e7 ? 1 : 0)} Mbps`;
    let last = null;
    const draw = data => {
      last = data;
      lineChart($('#chart-cpu'), data, [{ key: 'cpu', label: 'CPU', color: c1(), fmt: pct }], { max: 100, fmt: pct });
      lineChart($('#chart-mem'), data, [{ key: 'mem', label: 'Memory', color: c1(), fmt: pct }], { max: 100, fmt: pct });
      lineChart($('#chart-bw'), data, [
        { key: 'rx', label: 'In', color: c1(), fmt: mbps }, { key: 'tx', label: 'Out', color: c2(), fmt: mbps }], { fmt: mbps });
      lineChart($('#chart-peers'), data, [{ key: 'peers', label: 'Devices', color: c1(), fmt: v => v.toFixed(v < 10 && v % 1 ? 1 : 0) }],
        { fmt: v => Math.round(v) });
      const cap = $('#chart-bw').closest('figure').querySelector('figcaption');
      if (!$('.legend', cap)) cap.insertAdjacentHTML('beforeend',
        `<span class="legend"><span><i class="swatch" style="background:${c1()}"></i>In</span><span><i class="swatch" style="background:${c2()}"></i>Out</span></span>`);
      const m = data.latest;
      if (m) {
        $('[data-k=cpu]').textContent = pct(m.cpu);
        $('[data-k=load]').textContent = `load ${(+m.load1).toFixed(2)} · ${m.cores} core${m.cores === 1 ? '' : 's'}`;
        $('[data-k=mem]').textContent = pct(m.mem_pct);
        $('[data-k=mem-detail]').textContent = `${fmtBytes(m.mem_used)} of ${fmtBytes(m.mem_total)}`;
        $('[data-k=bw]').textContent = fmtBps(m.rx_bps + m.tx_bps);
        $('[data-k=bw-detail]').textContent = `↓ ${fmtBps(m.rx_bps)} in · ↑ ${fmtBps(m.tx_bps)} out`;
        $('[data-k=peers]').textContent = m.active_peers;
        $('[data-k=disk]').textContent = `disk ${Math.round(m.disk_pct)}% · ${fmtBytes(m.disk_used)} of ${fmtBytes(m.disk_total)}`;
      }
      const on = $('[data-k=online]');
      on.className = `pill ${data.online ? 'on' : 'off'}`;
      on.innerHTML = `<span class="dot${data.online ? ' live' : ''}"></span>${data.online ? 'Online' : 'Offline'} · <span data-k="seen">${data.last_seen}</span>`;
    };
    const load = () => fetch(`/admin/servers/${id}/metrics.json?range=${range}`).then(r => r.json()).then(draw).catch(() => {});
    // re-enroll card: notice when the one-time command has been used
    const re = $('[data-reenroll-pending]');
    if (re) poll(`/admin/servers/${id}/metrics.json?range=1h`, d => {
      if (d.reenroll === 'pending') return;
      const w = $('#reenroll-waiting');
      if (d.reenroll === 'used') { w.classList.add('done'); w.textContent = '✓ Re-enrolled — reloading…'; }
      else { w.textContent = 'This command expired — reloading…'; }
      setTimeout(() => location.replace(location.pathname), 1500);
    }, 4000);
    $$('[data-range]').forEach(b => b.addEventListener('click', () => {
      range = b.dataset.range;
      $$('[data-range]').forEach(x => x.classList.toggle('active', x === b));
      load();
    }));
    window.addEventListener('resize', () => last && draw(last));
    load();
    poll(`/admin/servers/${id}/metrics.json?range=1h`, d => range === '1h' ? draw(d) : null, 15000);
  }

  // ---------------------------------------------------------------- admin
  if (page === 'admin') {
    // Add-server wizard: build the install command from the form fields
    const wiz = $('#add-server');
    const buildCmd = () => {
      const tok = $('#wiz-token').value;
      const q = s => `"${s.replace(/(["\\$`])/g, '\\$1')}"`;
      let cmd = `curl -fsSL ${wiz.dataset.url}/agent/install.sh | sudo bash -s -- --token ${tok || '<create a token first>'}`;
      const name = $('#wiz-name').value.trim(), loc = $('#wiz-location').value.trim(), cc = $('#wiz-country').value;
      if (name) cmd += ` --name ${q(name)}`;
      if (loc) cmd += ` --location ${q(loc)}`;
      if (cc) cmd += ` --country ${cc}`;
      $('#wiz-cmd').textContent = cmd;
      $('#wiz-copy').disabled = !tok;
    };
    if (wiz) {
      $$('#add-server input, #add-server select').forEach(el => el.addEventListener('input', buildCmd));
      buildCmd();
      if (location.hash === '#servers/add') wiz.showModal();
    }

    let knownIds = new Set($$('[data-node-row]').map(r => r.dataset.nodeRow));
    poll('/admin/status.json', data => {
      $('[data-k=online]') && ($('[data-k=online]').textContent = `${data.online}/${data.nodes.length}`);
      const live = $('#live-sessions');
      if (live) {
        live.replaceChildren(...(data.sessions.length ? data.sessions.map(x => {
          const tr = document.createElement('tr');
          [x.email, x.device, x.node, x.down, x.up, x.since].forEach((v, i) => {
            const td = document.createElement('td'); td.textContent = v;
            if (i === 3 || i === 4) td.className = 'hide-sm';
            if (i === 5) td.className = 'muted';
            tr.append(td);
          });
          return tr;
        }) : [Object.assign(document.createElement('tr'), { innerHTML: '<td colspan="6" class="muted">Nobody is connected right now.</td>' })]));
      }
      $('[data-k=active]') && ($('[data-k=active]').textContent = data.active);
      for (const n of data.nodes) {
        $$(`[data-node-status="${n.id}"]`).forEach(el => {
          el.className = 'pill ' + (n.online ? 'on' : 'off');
          el.innerHTML = `<span class="dot${n.online ? ' live' : ''}"></span>${n.online ? 'Online' : 'Offline'}`;
        });
        $$(`[data-node-active="${n.id}"]`).forEach(el => (el.textContent = n.active));
        $$(`[data-node-seen="${n.id}"]`).forEach(el => (el.textContent = n.last_seen));
        $$(`[data-node-traffic="${n.id}"]`).forEach(el => (el.textContent = n.traffic));
        const m = data.metrics?.[n.id];
        if (m) {
          const mini = (pct, label) => `<span class="meter${pct >= 90 ? ' high' : pct >= 70 ? ' mid' : ''}"><i style="width:${Math.max(2, pct)}%"></i></span><span>${label}</span>`;
          $$(`[data-node-cpu="${n.id}"]`).forEach(el => (el.innerHTML = mini(m.cpu, `${Math.round(m.cpu)}%`)));
          $$(`[data-node-mem="${n.id}"]`).forEach(el => (el.innerHTML = mini(m.mem_pct, `${Math.round(m.mem_pct)}%`)));
          $$(`[data-node-bw="${n.id}"]`).forEach(el => (el.textContent = fmtBps(m.rx_bps + m.tx_bps)));
        }
      }
      const fresh = data.nodes.filter(n => !knownIds.has(String(n.id)));
      if (fresh.length) {
        const w = $('#wiz-waiting');
        if (w) { w.classList.add('done'); w.innerHTML = `✓ ${fresh[0].name} connected! Reloading…`; }
        toast(`New server connected: ${fresh.map(n => n.name).join(', ')}`);
        knownIds = new Set(data.nodes.map(n => String(n.id)));
        setTimeout(() => (location.hash = 'servers', location.reload()), 1800);
      }
    }, 5000);
  }
})();
