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
    if (opener) { e.preventDefault(); $('#' + opener.dataset.open)?.showModal(); }
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
        img.dataset.src = `${img.dataset.deviceSrc}?device=${id}`;
        if (img.getAttribute('src')) img.src = img.dataset.src;
      });
      $$('[data-k=device-name]').forEach(el => (el.textContent = name));
    };
    pick?.addEventListener('change', () => {
      applyDevice();
      const u = new URL(location.href); u.searchParams.set('device', pick.value); history.replaceState(null, '', u);
    });
    applyDevice();
    // QR codes load only when their dialog opens (and reload after switching device)
    document.addEventListener('click', e => {
      const b = e.target.closest('[data-open^="qr-"]');
      const img = b && $(`#${b.dataset.open} img[data-src]`);
      if (img && img.getAttribute('src') !== img.dataset.src) img.src = img.dataset.src;
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
