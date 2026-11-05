/* TraceForge console - single-page front end (no framework, no external requests). */
(function () {
  'use strict';
  const C = window.TFCharts;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const TYPE_LABEL = { login_failure: 'Failed login', login_success: 'Successful login', web_request: 'Web request', process_exec: 'Process execution', network_flow: 'Network flow',
    firewall_block: 'Firewall block', firewall_allow: 'Firewall allow', account_created: 'Account created', group_add: 'Privileged group change', log_cleared: 'Audit log cleared',
    service_install: 'Service installed', scheduled_task: 'Scheduled task created', mfa_denied: 'MFA prompt denied', registry_set: 'Registry change', dns_query: 'DNS query', file_create: 'File created', access_denied: 'Access denied' };
  const typeLabel = t => TYPE_LABEL[t] || String(t || 'event').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase());

  /* ------------------------------------------------------------ icons */
  const P = {
    upload: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5"/><path d="M12 3v12"/>',
    download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>',
    search: '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>', chev: '<path d="m6 9 6 6 6-6"/>', clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    server: '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>', globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
    warn: '<path d="M12 3 2 20h20L12 3z"/><path d="M12 10v4M12 17.5h.01"/>', check: '<path d="m5 12 5 5 9-10"/>', x: '<path d="M18 6 6 18M6 6l12 12"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/>', file: '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>',
    sort: '<path d="M7 4v16M3 16l4 4 4-4M17 20V4M13 8l4-4 4 4"/>', sliders: '<path d="M4 6h10M18 6h2M4 12h2M10 12h10M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="8" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
    grid: '<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
    shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/>', list: '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>', trash: '<path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"/>',
    terminal: '<path d="m4 17 6-5-6-5M12 19h8"/>', network: '<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v5M12 12 5 17M12 12l7 5"/>',
    lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>', pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>', flag: '<path d="M5 21V4M5 4h12l-2 4 2 4H5"/>',
    edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>', dot: '<circle cx="12" cy="12" r="3"/>', play: '<path d="m8 5 11 7-11 7z"/>', plus: '<path d="M12 5v14M5 12h14"/>', reset: '<path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/>',
  };
  const ic = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24">${P[n] || ''}</svg>`;
  const TYPE_ICON = { login_failure: 'lock', login_success: 'lock', web_request: 'globe', process_exec: 'terminal', network_flow: 'network', firewall_block: 'shield', firewall_allow: 'network', account_created: 'user', group_add: 'user', log_cleared: 'file', service_install: 'server', scheduled_task: 'clock', mfa_denied: 'lock', registry_set: 'edit', dns_query: 'globe', file_create: 'file', access_denied: 'shield' };

  /* ------------------------------------------------------------ helpers */
  const fmtDT = s => s ? s.replace('T', ' ').replace('Z', '') : '';
  const fmtT = s => s ? s.slice(11, 19) : '';
  const fmtD = s => s ? s.slice(0, 10) : '';
  const fmtHM = s => s ? s.slice(0, 16).replace('T', ' ') : '';
  const num = n => Number(n || 0).toLocaleString('en-US');
  function dur(a, b) { const s = Math.max(0, (new Date(b) - new Date(a)) / 1000); if (s < 60) return Math.round(s) + 's'; if (s < 3600) return Math.round(s / 60) + 'm'; return Math.floor(s / 3600) + 'h ' + String(Math.round((s % 3600) / 60)).padStart(2, '0') + 'm'; }
  function spanFmt(h) { if (h < 1) return Math.round(h * 60) + ' min'; if (h < 48) return h.toFixed(1).replace(/\.0$/, '') + ' h'; return (h / 24).toFixed(1) + ' days'; }
  const sevChip = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
  const stateBadge = (label) => `<span class="badge ${esc(String(label).toLowerCase().replace(/\s+/g, '-'))}">${esc(label)}</span>`;
  const tlpCls = t => (t || '').includes('RED') ? 'red' : (t || '').includes('AMBER') ? 'amber' : (t || '').includes('GREEN') ? 'green' : 'clear';
  const techTag = t => `<span class="tag"><b>${esc(t.id)}</b>${esc(t.name || '')}</span>`;
  const debounce = (fn, ms = 250) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

  async function api(path, opts = {}) {
    const o = { ...opts };
    if (o.json !== undefined) { o.method = o.method || 'POST'; o.headers = { 'Content-Type': 'application/json' }; o.body = JSON.stringify(o.json); delete o.json; }
    let r;
    try { r = await fetch(path, o); } catch (e) { throw new Error('Cannot reach the TraceForge server. Is it still running?'); }
    if (!r.ok) { let msg = r.statusText; try { const j = await r.json(); msg = j.error || j.detail || msg; } catch (e) { /* not json */ } throw new Error(typeof msg === 'string' ? msg : 'Request failed'); }
    const ct = r.headers.get('content-type') || '';
    return ct.includes('json') ? r.json() : r;
  }
  function toast(msg, err) {
    const t = document.createElement('div'); t.className = 'toast' + (err ? ' err' : ''); t.textContent = msg; $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), err ? 6500 : 3200);
  }
  const guard = fn => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message || String(e), true); console.error(e); } };

  /* ------------------------------------------------------------ state */
  const S = { meta: null, view: 'dashboard', sort: 'severity', sortDir: 1, stateFilter: 'all', selInc: null, selEvent: null, sev: 'all', q: '', scope: 'all', bucket: null,
    tab: 'summary', fSev: new Set(), fRule: '', fQ: '', fSel: null, tl: { lane: 'src_ip', q: '', flagged: false, types: new Set() }, evPage: 1, incList: null, incDetail: null, incEvents: null };
  const view = $('#view');
  const loading = () => { view.innerHTML = '<div class="loading"><span class="spin"></span>&nbsp; Loading…</div>'; };

  async function refreshMeta() { S.meta = await api('/api/meta'); renderChrome(); }

  function renderChrome() {
    const m = S.meta;
    const items = [['dashboard', 'grid', 'Dashboard'], ['evidence', 'list', 'Evidence', (m.files || []).length], ['incidents', 'shield', 'Incidents', m.incidents], ['timeline', 'pulse', 'Timeline'], ['findings', 'flag', 'Findings', m.findings],
      ['iocs', 'target', 'IOCs', m.iocs], ['reports', 'file', 'Reports'], ['audit', 'lock', 'Audit'], ['settings', 'sliders', 'Settings']];
    $('#nav').innerHTML = items.map(([id, ico, label, n]) => `<a href="#/${id}" title="${label}" class="${S.view === id ? 'on' : ''}">${ic(ico)}<span class="t">${label}</span>${n ? `<span class="count">${n}</span>` : ''}</a>`).join('');
    $('#imp-ico').innerHTML = ic('upload');
    let bar = $('#integ-bar'); if (!bar) { bar = document.createElement('div'); bar.id = 'integ-bar'; view.parentNode.insertBefore(bar, view); }
    const bad = m.integrity && !m.integrity.ok;
    bar.className = 'integ-bar' + (bad ? '' : ' hidden');
    bar.innerHTML = bad ? `${ic('warn')} <b>Evidence integrity check failed</b> for ${m.integrity.problems.length} file(s): ${m.integrity.problems.map(p => esc(p.name)).join(', ')}. Affected files are excluded from the analysis. <a href="#/audit">Details</a>` : '';
    const c = m.case;
    $('#case-pill').innerHTML = `<div class="avatar">${esc((c.analyst || 'A')[0].toUpperCase())}</div><div><small class="lbl">Investigation</small><b>${esc(c.name)}</b></div><span class="tlp ${tlpCls(c.tlp)}">${esc(c.tlp)}</span><span class="pen">${ic('edit')}</span>`;
    document.title = (m.has_data ? c.name + ' · ' : '') + 'TraceForge';
    $('#case-pill').title = `${c.name} · ${c.analyst} · ${c.tlp} — click to edit this investigation or start a new one`;
  }

  /* ------------------------------------------------------------ routing */
  const NEEDS_DATA = new Set(['dashboard', 'incidents', 'timeline', 'findings']);
  const guardedRoute = guard(route);
  async function route() {
    closeOverlay();
    const [, v, arg] = (location.hash || '#/dashboard').split('/');
    S.view = ['dashboard', 'evidence', 'incidents', 'timeline', 'findings', 'iocs', 'reports', 'audit', 'settings'].includes(v) ? v : 'dashboard';
    if (!S.meta) await refreshMeta(); else renderChrome();
    view.scrollTop = 0;
    if (!S.meta.has_data && NEEDS_DATA.has(S.view)) return welcome();
    loading();
    ({ dashboard: viewDashboard, evidence: viewEvidence, incidents: viewIncidents, timeline: viewTimeline, findings: viewFindings, iocs: viewIocs, reports: viewReports, audit: viewAudit, settings: viewSettings })[S.view](arg);
  }
  window.addEventListener('hashchange', guardedRoute);
  function navigate(h) { if (location.hash === h) guardedRoute(); else location.hash = h; }

  /* ------------------------------------------------------------ welcome / import */
  function welcome() {
    const c = S.meta.case, named = c.name !== 'Untitled investigation';
    view.innerHTML = `<div class="welcome"><div class="welcome-in">
      <h1>Start an investigation</h1>
      <p class="lead">Name it, add the log files you collected, and TraceForge builds one timeline, flags suspicious activity and groups it into incidents.</p>
      <div class="wizard">
        <div class="wstep"><div class="wnum">1</div><div class="wbody"><h3>Name your investigation</h3>
          <p class="muted">This is the title on your report. You can change it later by clicking the investigation name at the top right.</p>
          <div class="wgrid"><div><label class="f">Investigation name</label><input class="input" id="w-name" maxlength="120" placeholder="e.g. Suspicious VPN logins – March" value="${named ? esc(c.name) : ''}"></div>
          <div><label class="f">Analyst (your name)</label><input class="input" id="w-an" maxlength="120" placeholder="Your name" value="${c.analyst === 'Analyst' ? '' : esc(c.analyst)}"></div></div></div></div>
        <div class="wstep"><div class="wnum">2</div><div class="wbody"><h3>Add your log files</h3>
          <div class="drop" id="drop"><div style="color:var(--accent)">${ic('upload').replace('class="ic ', 'style="width:34px;height:34px" class="ic ')}</div>
            <div class="big">Drop log files here, or click to browse</div><div class="muted">CSV · JSON · NDJSON · LOG · TXT — up to 50 MB each. You can add more files at any time from the <b>Evidence</b> tab.</div></div>
          <div class="wsample"><span class="muted">Just want to try it?</span><button class="btn" id="load-sample">${ic('play')} Load synthetic sample intrusion</button></div></div></div>
      </div>
      <p class="faint" style="margin-top:22px">TraceForge analyses only the evidence you import. It is not a live SIEM, and an empty result never proves absence of malicious activity.</p></div></div>`;
    $('#drop').onclick = () => $('#file').click();
    $('#load-sample').onclick = guard(async () => { await commitWelcome(); await api('/api/sample', { method: 'POST' }); toast('Sample data loaded'); await refreshMeta(); navigate('#/incidents'); });
  }

  /* Save the "name your investigation" fields (if they are on screen) before anything is imported. */
  async function commitWelcome() {
    const n = $('#w-name'), a = $('#w-an'); if (!n) return;
    const body = {}; if (n.value.trim()) body.name = n.value; if (a && a.value.trim()) body.analyst = a.value;
    if (Object.keys(body).length) { S.meta = await api('/api/case', { method: 'PUT', json: body }); renderChrome(); }
  }

  function askAboutSample() {
    return new Promise(resolve => {
      modal(`<h3>Sample data is currently loaded</h3><p class="muted" style="margin-top:0">What should happen to the synthetic sample logs when you add your own files?</p>
        <div class="choice"><button class="btn primary" id="a-rep">Replace the sample with my files</button><span class="faint">Recommended. You analyse only your own evidence.</span></div>
        <div class="choice"><button class="btn" id="a-add">Keep the sample and add my files</button><span class="faint">Both sets are merged on one timeline.</span></div>
        <div class="acts"><button class="btn" id="a-no">Cancel</button></div>`);
      $('#a-rep').onclick = () => { closeOverlay(); resolve(true); }; $('#a-add').onclick = () => { closeOverlay(); resolve(false); }; $('#a-no').onclick = () => { closeOverlay(); resolve(null); };
    });
  }

  const uploadFiles = guard(async function (files) {
    files = Array.from(files || []); if (!files.length) return;
    let replace = false;
    if (S.meta && S.meta.sample) { replace = await askAboutSample(); if (replace === null) return; }
    await commitWelcome();
    const hadData = S.meta && S.meta.has_data;
    const fd = new FormData(); files.forEach(f => fd.append('files', f));
    toast(`Importing ${files.length} file${files.length > 1 ? 's' : ''}…`);
    const res = await api('/api/upload?replace=' + replace, { method: 'POST', body: fd });
    S.meta = res.meta; renderChrome(); S.selInc = null;
    if (res.files_added) toast(`Added ${res.files_added} file${res.files_added > 1 ? 's' : ''} · ${num(res.events)} events in total`);
    if (res.duplicates && res.duplicates.length) toast(`Skipped (already imported): ${res.duplicates.join(', ')}`);
    (res.rejected || []).forEach(r => toast(`${r.name}: ${r.error}`, true));
    if (!res.files_added) return;
    if (!hadData || replace) navigate('#/dashboard'); else guardedRoute();
  });
  $('#btn-import').onclick = () => $('#file').click();
  $('#file').onchange = e => { uploadFiles(e.target.files); e.target.value = ''; };
  $('#brand').onclick = () => { location.hash = '#/dashboard'; };
  let dragDepth = 0;
  addEventListener('dragenter', e => { if ([...(e.dataTransfer?.types || [])].includes('Files')) { dragDepth++; if (!$('.dropveil')) $('#overlay').innerHTML = '<div class="dropveil">Drop logs to add them to this investigation</div>'; } });
  addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('.dropveil')?.remove(); } });
  addEventListener('dragover', e => e.preventDefault());
  addEventListener('drop', e => { e.preventDefault(); dragDepth = 0; $('.dropveil')?.remove(); uploadFiles(e.dataTransfer.files); });

  /* ------------------------------------------------------------ overlays */
  function closeOverlay() { $('#overlay').innerHTML = ''; }
  addEventListener('keydown', e => { if (e.key === 'Escape') { closeOverlay(); $$('.dd-menu').forEach(m => m.remove()); } });
  function modal(html) { $('#overlay').innerHTML = `<div class="modal-bg"><div class="modal">${html}</div></div>`; $('.modal-bg').addEventListener('mousedown', e => { if (e.target.classList.contains('modal-bg')) closeOverlay(); }); }
  function openCaseModal() {
    const c = S.meta.case;
    modal(`<h3>Investigation details</h3><p class="muted" style="margin:-6px 0 14px">Shown on the report. Saved on this computer.</p>
      <div class="row"><label class="f">Investigation name</label><input class="input" id="c-name" maxlength="120" value="${esc(c.name)}"></div>
      <div class="row"><label class="f">Analyst</label><input class="input" id="c-an" maxlength="120" value="${esc(c.analyst)}"></div>
      <div class="row"><label class="f">Organisation (optional)</label><input class="input" id="c-org" maxlength="120" value="${esc(c.organization)}"></div>
      <div class="row"><label class="f">Sharing marking (TLP — who may see the report)</label><select class="select" id="c-tlp">${S.meta.tlp_options.map(t => `<option ${t === c.tlp ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>
      <div class="acts spread"><button class="btn danger" id="c-new">${ic('plus')} New investigation…</button><span class="sp"></span><button class="btn" id="c-cancel">Cancel</button><button class="btn primary" id="c-save">Save</button></div>`);
    $('#c-cancel').onclick = closeOverlay; $('#c-new').onclick = openNewInvestigation;
    $('#c-save').onclick = guard(async () => { S.meta = await api('/api/case', { method: 'PUT', json: { name: $('#c-name').value, analyst: $('#c-an').value, organization: $('#c-org').value, tlp: $('#c-tlp').value } }); closeOverlay(); renderChrome(); toast('Investigation updated'); if (S.view === 'reports') viewReports(); if (S.view === 'dashboard' && S.meta.has_data) viewDashboard(); });
  }
  function openNewInvestigation() {
    const c = S.meta.case;
    modal(`<h3>Start a new investigation</h3>
      <div class="warnbox">${ic('warn')}<span>This clears the current <b>evidence files, incident states, notes and checklists</b> so you start from a blank page.${S.meta.has_data || S.meta.iocs ? ' <a href="/api/export/case" download>Download the current case file</a> first if you want to keep your work.' : ''}</span></div>
      <div class="row"><label class="f">Name of the new investigation</label><input class="input" id="n-name" maxlength="120" placeholder="e.g. Phishing – Finance dept" autofocus></div>
      <div class="row"><label class="f">Analyst</label><input class="input" id="n-an" maxlength="120" value="${esc(c.analyst)}"></div>
      <div class="row"><label class="f">Organisation (optional)</label><input class="input" id="n-org" maxlength="120" value="${esc(c.organization)}"></div>
      <div class="row"><label class="f">Sharing marking (TLP)</label><select class="select" id="n-tlp">${S.meta.tlp_options.map(t => `<option ${t === 'TLP:AMBER' ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>
      <label class="chk"><input type="checkbox" id="n-ioc" checked> Also clear the recorded IOCs <span class="faint">(${S.meta.iocs} recorded)</span></label>
      <div class="acts"><button class="btn" id="n-cancel">Cancel</button><button class="btn primary" id="n-go">Start new investigation</button></div>`);
    $('#n-cancel').onclick = closeOverlay; $('#n-name').focus();
    $('#n-go').onclick = guard(async () => {
      const name = $('#n-name').value.trim(); if (!name) return toast('Give the new investigation a name first', true);
      S.meta = await api('/api/case/new', { json: { name, analyst: $('#n-an').value, organization: $('#n-org').value, tlp: $('#n-tlp').value, clear_iocs: $('#n-ioc').checked } });
      S.selInc = null; closeOverlay(); renderChrome(); toast(`New investigation “${name}” started — now add your logs`); navigate('#/evidence');
    });
  }
  $('#case-pill').onclick = openCaseModal;
  document.addEventListener('click', e => {
    const cp = e.target.closest('[data-copy]'); if (cp) { const v = cp.dataset.copy; (navigator.clipboard ? navigator.clipboard.writeText(v) : Promise.reject()).catch(() => { const t = document.createElement('textarea'); t.value = v; document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove(); }); toast('Copied'); return; }
    if (e.target.closest('[data-edit-case]')) { openCaseModal(); return; }
    if (e.target.closest('[data-new-case]')) { openNewInvestigation(); return; }
    if (e.target.closest('[data-add-logs]')) { $('#file').click(); return; }
    const go = e.target.closest('[data-go]'); if (go) { location.hash = go.dataset.go; return; }
    if (!e.target.closest('.dd')) $$('.dd-menu').forEach(m => m.remove());
  });

  /* ------------------------------------------------------------ event detail (shared) */
  function evDetailHTML(ev) {
    const fd = ev.finding_details || [], sev = ev.sev;
    const title = fd.length ? fd[0].tactic : typeLabel(ev.type);
    const seen = new Set(), techs = []; fd.forEach(f => f.techniques.forEach(t => { if (!seen.has(t.id)) { seen.add(t.id); techs.push(t); } }));
    const main = ev.command || ev.url || ev.message || '';
    const rows = [['Event type', typeLabel(ev.type)], ['Account', ev.user], ['Source IP', ev.src_ip], ['Destination', ev.dst_ip ? ev.dst_ip + (ev.dst_port != null ? ':' + Math.round(ev.dst_port) : '') : null],
      ['Host', ev.host], ['HTTP status', ev.status != null ? Math.round(ev.status) : null], ['Bytes out', ev.bytes_out != null ? num(ev.bytes_out) : null], ['Log source', ev.source], ['Event ID', ev.id]].filter(r => r[1] != null && r[1] !== '');
    return `<div class="evd-h s-${sev}"><span class="score">${sev === 'info' ? 'ctx' : sev}</span><div><h3>${esc(title)}</h3><time>${ic('clock')} ${esc(fmtDT(ev.ts))} UTC</time></div></div>
    <div class="evd-b s-${sev}">
      <details class="acc" open><summary>Details ${ic('chev', 'chev')}</summary><div class="acc-b">
        ${main ? `<div class="code">${esc(main)}<button class="iconbtn cp" data-copy="${esc(main)}" title="Copy">${ic('copy')}</button></div><div style="height:10px"></div>` : ''}
        <dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="${k === 'Event ID' || k.includes('IP') ? 'mono' : ''}">${esc(v)}</dd>`).join('')}</dl></div></details>
      <details class="acc" open><summary>${fd.length ? 'Why it was flagged' : 'Context'} ${ic('chev', 'chev')}</summary><div class="acc-b">
        ${fd.length ? fd.map(f => `<div class="why s-${esc(f.severity)}"><b>${esc(f.rule_name)} ${sevChip(f.severity)}</b><span>${esc(f.summary)}</span><br><span class="faint">${esc(f.description)}</span></div>`).join('')
          : '<span class="muted">This event did not trigger a rule. It is shown because it shares an IP, account or host with the incident within a few minutes of its window.</span>'}</div></details>
      ${techs.length ? `<details class="acc" open><summary>MITRE ATT&amp;CK ${ic('chev', 'chev')}</summary><div class="acc-b" style="display:flex;gap:6px;flex-wrap:wrap">${fd.map(f => `<span class="tag tac">${esc(f.tactic)}</span>`).filter((v, i, a) => a.indexOf(v) === i).join('')}${techs.map(techTag).join('')}</div></details>` : ''}
      <details class="acc"><summary>Raw event ${ic('chev', 'chev')}</summary><div class="acc-b"><div class="rawjson">${esc(JSON.stringify(ev.raw || {}, null, 2))}</div></div></details>
    </div>`;
  }
  const openEventDrawer = guard(async function (id) {
    const ev = await api('/api/events/' + encodeURIComponent(id));
    $('#overlay').innerHTML = `<div class="drawer-bg"></div><aside class="drawer"><div style="padding:10px 12px 0;text-align:right"><button class="iconbtn" id="dclose">${ic('x')}</button></div>${evDetailHTML(ev)}</aside>`;
    $('.drawer-bg').onclick = closeOverlay; $('#dclose').onclick = closeOverlay;
  });

  /* ------------------------------------------------------------ dashboard */
  async function viewDashboard() {
    const d = await api('/api/dashboard'); S.meta = d;
    const sevDots = o => SEVS.slice(0, 4).filter(s => o[s]).map(s => `<span><span class="dotc" style="background:${C.COLOR[s]}"></span> ${o[s]} ${s}</span>`).join('') || '<span>none</span>';
    const maxT = Math.max(1, ...Object.values(d.by_tactic).map(o => Object.values(o).reduce((a, b) => a + b, 0)));
    const maxIp = Math.max(1, ...d.top_ips.map(i => i.events));
    view.innerHTML = `<div class="page">
      <div class="page-h"><div><h1>${esc(d.case.name)} <button class="iconbtn" data-edit-case title="Edit investigation details">${ic('edit')}</button></h1><p>${esc(fmtHM(d.start))} → ${esc(fmtHM(d.end))} UTC · ${num(d.events)} events from ${d.sources} log source(s)</p></div><div class="sp"></div>
        <button class="btn" data-go="#/reports">${ic('file')} Build report</button><button class="btn primary" data-go="#/incidents">${ic('shield')} Open incidents</button></div>
      ${d.diagnostics.length ? `<div class="diag"><b>${ic('warn')} ${d.diagnostics.length} detection rule(s) failed and were skipped</b>${d.diagnostics.map(x => `<div class="mono" style="font-size:12px;margin-top:4px">${esc(x.rule_name)}: ${esc(x.error)}</div>`).join('')}<div class="muted" style="margin-top:4px">Other rules ran normally. Please report this together with the log format you imported.</div></div>` : ''}
      <div class="kpis">
        <div class="kpi"><div class="l">Events</div><div class="v">${num(d.events)}</div><div class="s">${d.sources} sources</div></div>
        <div class="kpi" style="--k:var(--low)"><div class="l">Time span</div><div class="v">${spanFmt(d.span_hours)}</div><div class="s">${esc(fmtD(d.start))}</div></div>
        <div class="kpi" style="--k:var(--high)"><div class="l">Findings</div><div class="v">${d.findings}</div><div class="s">${sevDots(d.finding_counts)}</div></div>
        <div class="kpi" style="--k:var(--critical)"><div class="l">Incidents</div><div class="v">${d.incidents}</div><div class="s">${sevDots(d.incident_counts)}</div></div>
        <div class="kpi" style="--k:var(--tag)"><div class="l">IOCs recorded</div><div class="v">${d.iocs}</div><div class="s">analyst-managed</div></div>
        <div class="kpi" style="--k:var(--ok)"><div class="l">Rules active</div><div class="v">${d.rules.filter(r => r.enabled).length}<small class="muted" style="font-size:15px">/${d.rules.length}</small></div><div class="s">${d.rules.filter(r => r.findings).length} fired</div></div>
      </div>
      <div class="grid2">
        <div class="panel"><div class="panel-h">Events over time <small>colour = highest severity of a finding that flagged the event</small><div class="legend">${SEVS.map(s => `<span><span class="dotc" style="background:${C.COLOR[s]}"></span>${s === 'info' ? 'unflagged' : s}</span>`).join('')}</div></div><div class="panel-b" id="dchart"></div></div>
        <div class="panel"><div class="panel-h">Top incidents</div><div class="panel-b">${d.top_incidents.length ? d.top_incidents.map(i => `<div class="mini-inc" data-go="#/incidents/${esc(i.id)}"><span class="sev ${esc(i.severity)}">${esc(i.severity)}</span><span class="t">${esc(i.id)} · ${esc(i.title)}</span>${stateBadge(i.state)}</div>`).join('') : '<div class="empty">No incidents were reconstructed.</div>'}</div></div>
      </div>
      <div class="grid2" style="grid-template-columns:1fr 1fr">
        <div class="panel"><div class="panel-h">Findings by ATT&amp;CK tactic</div><div class="panel-b">${d.tactic_order.length ? d.tactic_order.map(t => { const o = d.by_tactic[t], tot = Object.values(o).reduce((a, b) => a + b, 0); return `<div class="hb"><span class="n">${esc(t)}</span><div class="bar" style="width:${(tot / maxT) * 100}%">${SEVS.filter(s => o[s]).map(s => `<i style="flex:${o[s]};background:${C.COLOR[s]}"></i>`).join('')}</div><span class="v">${tot}</span></div>`; }).join('') : '<div class="empty">No findings.</div>'}</div></div>
        <div class="panel"><div class="panel-h">Top source IPs <small>by event volume · ⚑ = involved in findings</small></div><div class="panel-b">${d.top_ips.map(i => `<div class="hb"><span class="n mono">${esc(i.ip)} ${i.internal ? '' : '<span class="tag" style="padding:0 6px;font-size:10.5px">ext</span>'}</span><div class="bar" style="width:${(i.events / maxIp) * 100}%"><i style="flex:1;background:${i.findings ? 'var(--high)' : 'var(--accent-d)'}"></i></div><span class="v">${i.events}${i.findings ? ' ⚑' : ''}</span></div>`).join('')}</div></div>
      </div>
      <div class="grid2" style="grid-template-columns:1fr 1.25fr">
        <div class="panel"><div class="panel-h">Detection coverage</div><div class="panel-b" style="padding-top:6px"><table class="tbl"><thead><tr><th>Rule</th><th>Tactic</th><th class="num">Findings</th></tr></thead><tbody>${d.rules.map(r => `<tr><td>${r.enabled ? '' : '<span class="faint">(off) </span>'}${esc(r.name)}</td><td class="muted">${esc(r.tactic)}</td><td class="num">${r.findings ? `<b>${r.findings}</b>` : '<span class="faint">0</span>'}</td></tr>`).join('')}</tbody></table></div></div>
        <div class="panel"><div class="panel-h">Evidence integrity &amp; data quality</div><div class="panel-b" style="padding-top:6px"><table class="tbl"><thead><tr><th>File</th><th class="num">Rows kept</th><th class="num">Bad time</th><th class="num">Bad IP</th><th>SHA-256</th></tr></thead><tbody>${d.quality.map(q => `<tr><td><b>${esc(q.filename)}</b><div class="faint" style="font-size:11.5px">${Object.keys(q.mapped).length} fields mapped${q.unmapped.length ? ' · ' + q.unmapped.length + ' unmapped' : ''}${q.truncated ? ' · <span style="color:var(--high)">truncated</span>' : ''}</div></td><td class="num">${q.rows_kept}/${q.rows_read}</td><td class="num">${q.bad_timestamp}</td><td class="num">${q.invalid_ips}</td><td class="mono" style="font-size:11.5px">${esc(q.sha256.slice(0, 16))}… <button class="iconbtn" data-copy="${esc(q.sha256)}" title="Copy full hash">${ic('copy')}</button></td></tr>`).join('')}</tbody></table></div></div>
      </div></div>`;
    const draw = () => $('#dchart') && C.stackedBars($('#dchart'), { buckets: d.histogram.buckets, step: d.histogram.step, height: 230 });
    draw(); S._redraw = draw;
  }
  new ResizeObserver(() => { if (S._redraw && $('#dchart')) S._redraw(); if (S._redrawInc && $('#chart')) S._redrawInc(); if (S._redrawTl && $('#swim')) S._redrawTl(); }).observe(document.body);

  /* ------------------------------------------------------------ incidents workspace */
  const SORTS = { severity: 'Severity', start: 'First alert time', confidence: 'Confidence', events: 'Total events' };
  const FILTERS = [['all', 'Incidents', () => true], ['Unreviewed', 'New', i => i.verdict === 'Unreviewed'], ['Investigating', 'Investigating', i => i.verdict === 'Investigating'],
    ['Needs escalation', 'Escalated', i => i.verdict === 'Needs escalation'], ['True positive', 'Confirmed', i => i.verdict === 'True positive'],
    ['closed', 'Closed', i => i.verdict === 'False positive' || i.verdict === 'Benign true positive']];

  function sortedIncidents() {
    const f = FILTERS.find(x => x[0] === S.stateFilter) || FILTERS[0];
    const key = { severity: i => SEV_RANK[i.severity] * 1000 + i.confidence, start: i => -new Date(i.start).getTime(), confidence: i => i.confidence, events: i => i.total_events }[S.sort];
    return S.incList.incidents.filter(f[2]).sort((a, b) => (key(b) - key(a)) * S.sortDir);
  }
  function primaryEntity(d) {
    const e = d.entities, ext = e.ip.find(x => !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)/.test(x));
    if (e.host.length) return ['server', e.host[0].toUpperCase()]; if (ext) return ['globe', ext]; if (e.user.length) return ['user', e.user[0]]; return ['shield', d.id];
  }

  async function viewIncidents(arg) {
    S.incList = await api('/api/incidents');
    const list = S.incList.incidents;
    if (!list.length) { view.innerHTML = `<div class="page"><div class="panel"><div class="empty" style="padding:70px 20px"><h2 style="color:var(--text);margin:0 0 8px">No incidents were reconstructed</h2>${num(S.meta.events)} events were analysed but no enabled rule produced a finding.<br>That does <b>not</b> prove the absence of malicious activity. Try lowering thresholds in <a href="#/settings">Settings</a> or adding IOCs.</div></div></div>`; return; }
    view.innerHTML = `<div class="inc-layout">
      <div class="col"><div class="panel scope" id="scope"></div>
        <div class="order">Issues order by <select class="select" id="sortsel">${Object.entries(SORTS).map(([k, v]) => `<option value="${k}" ${k === S.sort ? 'selected' : ''}>${v}</option>`).join('')}</select><button class="iconbtn" id="sortdir" title="Reverse order">${ic('sort')}</button></div>
        <div class="scroll cards" id="cards"></div></div>
      <div class="col"><div class="mid" style="display:flex;flex-direction:column;flex:1;min-height:0">
        <div class="mid-h" id="midh"></div>
        <div class="mid-tools"><span class="lbl">Event severity</span><select class="select" id="sevsel"><option value="all">All</option>${SEVS.map(s => `<option value="${s}">${s === 'info' ? 'context' : s}</option>`).join('')}</select>
          <div class="search">${ic('search')}<input class="input" id="evq" placeholder="Search events (IP, user, URL, command…)"></div>
          <div class="seg" id="scopeseg"><button data-v="all" class="on">All</button><button data-v="alerted">Alerted</button></div><button class="btn sm" id="evreset">${ic('reset')} Reset</button></div>
        <div class="chartbox" id="chart"></div><div class="chartinfo" id="chartinfo"></div>
        <div class="evlist" id="evlist"></div></div></div>
      <div class="col"><div class="panel rpanel" id="rtop" style="max-height:48%"></div><div class="panel evd" id="evd"></div></div></div>`;
    $('#sortsel').onchange = e => { S.sort = e.target.value; renderCards(); };
    $('#sortdir').onclick = () => { S.sortDir *= -1; renderCards(); };
    $('#sevsel').onchange = e => { S.sev = e.target.value; loadIncidentEvents(); };
    $('#evq').oninput = debounce(e => { S.q = e.target.value; loadIncidentEvents(); }, 250);
    $('#scopeseg').onclick = e => { const b = e.target.closest('button'); if (!b) return; S.scope = b.dataset.v; $$('#scopeseg button').forEach(x => x.classList.toggle('on', x === b)); loadIncidentEvents(); };
    $('#evreset').onclick = () => { S.sev = 'all'; S.q = ''; S.scope = 'all'; S.bucket = null; $('#sevsel').value = 'all'; $('#evq').value = ''; $$('#scopeseg button').forEach(x => x.classList.toggle('on', x.dataset.v === 'all')); loadIncidentEvents(); };
    const target = list.find(i => i.id === arg) || list.find(i => i.id === S.selInc) || sortedIncidents()[0] || list[0];
    await selectIncident(target.id, true);
  }

  function renderCards() {
    const cards = $('#cards'); if (!cards) return;
    const L = S.incList, items = sortedIncidents();
    cards.innerHTML = items.length ? items.map(i => `<div class="icard s-${esc(i.severity)} ${i.id === S.selInc ? 'sel' : ''}" data-id="${esc(i.id)}">
        <div class="row1">${stateBadge(i.state)}${sevChip(i.severity)}<span class="sp"></span><span class="faint mono" style="font-size:11.5px">${esc(i.id)}</span></div>
        <h4>${esc(i.title)}</h4><div class="when">${ic('clock')} ${esc(fmtHM(i.start))} <span class="faint">(${esc(dur(i.start, i.end))})</span></div>
        <div class="tacs">${i.tactics.slice(0, 3).map(t => `<span>${esc(t)}</span>`).join('')}${i.tactic_total > 3 ? `<div class="more">+${i.tactic_total - 3} more tactics</div>` : ''}</div>
        <div class="nums"><div><b>${num(i.total_events)}</b><span>Total Events</span></div><div class="al"><b>${num(i.alerted_events)}</b><span>Alerted Events</span></div></div></div>`).join('')
      : '<div class="empty">No incidents in this state.</div>';
    $$('.icard', cards).forEach(c => c.onclick = () => selectIncident(c.dataset.id));
    const c = L.counts, closed = (c['False positive'] || 0) + (c['Benign true positive'] || 0);
    const cnt = { all: L.total, Unreviewed: c.Unreviewed, Investigating: c.Investigating, 'Needs escalation': c['Needs escalation'], 'True positive': c['True positive'], closed };
    $('#scope-stats') && ($('#scope-stats').innerHTML = FILTERS.map(f => `<button data-f="${f[0]}" class="${S.stateFilter === f[0] ? 'on' : ''}"><b>${cnt[f[0]] || 0}</b>${f[1]}</button>`).join(''));
    $$('#scope-stats button').forEach(b => b.onclick = () => { S.stateFilter = b.dataset.f; renderCards(); });
  }

  const selectIncident = guard(async function (id, first) {
    S.selInc = id; S.sev = 'all'; S.q = ''; S.scope = 'all'; S.bucket = null; S.selEvent = null;
    if (!first) { $('#sevsel').value = 'all'; $('#evq').value = ''; $$('#scopeseg button').forEach(x => x.classList.toggle('on', x.dataset.v === 'all')); }
    history.replaceState(null, '', '#/incidents/' + id);
    S.incDetail = await api('/api/incidents/' + id);
    renderScope(); renderCards(); renderMidHead(); renderRight();
    await loadIncidentEvents(true);
  });

  function renderScope() {
    const d = S.incDetail, [ico, name] = primaryEntity(d);
    $('#scope').innerHTML = `<span class="crumb">Incidents</span> <span class="faint">›</span>
      <div class="scope-t"><div class="ico">${ic(ico)}</div><h2 title="${esc(name)}">${esc(name)}</h2></div>
      <div class="meta"><span>${ic('clock')} First alert ${esc(fmtDT(d.start))} UTC</span><span>${ic('file')} ${d.sources.length} log source(s): ${esc(d.sources.join(', '))}</span>
      <span>${ic('network')} ${esc([...d.entities.ip.slice(0, 2), ...d.entities.user.slice(0, 2).map(u => '@' + u)].join(' · ') || '—')}</span></div>
      <div class="stats6" id="scope-stats"></div>`;
  }

  function renderMidHead() {
    const d = S.incDetail;
    $('#midh').innerHTML = `${stateBadge(d.state)}<h2 title="${esc(d.title)}">${esc(d.id)} · ${esc(d.title)}</h2>${sevChip(d.severity)}
      <div class="dd"><button class="btn" id="chstate">Change State ${ic('chev')}</button></div>`;
    $('#chstate').onclick = e => {
      e.stopPropagation(); const dd = e.target.closest('.dd'); if ($('.dd-menu', dd)) { $('.dd-menu', dd).remove(); return; }
      const labels = S.incList.state_labels;
      dd.insertAdjacentHTML('beforeend', `<div class="dd-menu">${S.incList.states.map(v => `<button data-v="${esc(v)}" class="${v === d.verdict ? 'on' : ''}">${v === d.verdict ? ic('check') : '<span style="width:16px"></span>'}${esc(labels[v])}</button>`).join('')}</div>`);
      $$('.dd-menu button', dd).forEach(b => b.onclick = () => setState(b.dataset.v));
    };
  }

  const setState = guard(async function (verdict, override) {
    const r = await api('/api/incidents/' + S.selInc + '/state', { method: 'PUT', json: { verdict, confidence_override: override === undefined ? (S.incDetail.overridden ? S.incDetail.confidence : null) : override } });
    Object.assign(S.incDetail, r); S.incList = await api('/api/incidents');
    renderCards(); renderMidHead(); renderRight(); toast('State set to ' + r.state);
  });

  const loadIncidentEvents = guard(async function (initial) {
    const qs = new URLSearchParams({ sev: S.sev, q: S.q, scope: S.scope });
    if (S.bucket) { qs.set('t0', new Date(S.bucket.t0 * 1000).toISOString()); qs.set('t1', new Date(S.bucket.t1 * 1000).toISOString()); }
    const my = (S._evreq = (S._evreq || 0) + 1);
    const r = await api(`/api/incidents/${S.selInc}/events?${qs}`);
    if (my !== S._evreq) return; // a newer request superseded this one
    S.incEvents = r;
    const drawChart = () => { const box = $('#chart'); if (box) C.stackedBars(box, { buckets: r.histogram.buckets, step: r.histogram.step, height: 150, selected: S.bucket, onPick: (t, step) => { S.bucket = t == null || (S.bucket && S.bucket.t0 === t) ? null : { t0: t, t1: t + step }; loadIncidentEvents(); } }); };
    drawChart(); S._redrawInc = drawChart;
    $('#chartinfo').innerHTML = `<span><b style="color:var(--text)">${num(r.total)}</b> event(s) shown${r.truncated ? ' <span style="color:var(--high)">(first 1,500)</span>' : ''}</span>${S.bucket ? `<span class="chipx">${ic('clock')} ${esc(new Date(S.bucket.t0 * 1000).toISOString().slice(11, 16))}–${esc(new Date(S.bucket.t1 * 1000).toISOString().slice(11, 16))} <button class="iconbtn" id="clrb" style="padding:0">${ic('x')}</button></span>` : '<span class="faint">· click a bar to filter by time</span>'}`;
    $('#clrb') && ($('#clrb').onclick = () => { S.bucket = null; loadIncidentEvents(); });
    renderEvList();
    if (initial || (S.selEvent && !r.events.some(e => e.id === S.selEvent))) {
      const pick = r.events.filter(e => e.alerted).sort((a, b) => SEV_RANK[b.sev] - SEV_RANK[a.sev])[0] || r.events[0];
      if (pick) { S.selEvent = pick.id; renderEvList(); $('#evlist [data-id].sel, #evlist .grp.open')?.scrollIntoView({ block: 'center' }); selectEvent(pick.id); } else { S.selEvent = null; $('#evd').innerHTML = '<div class="empty">No event selected.</div>'; }
    }
  });

  function evExpand(e) {
    const kv = [['Type', typeLabel(e.type)], ['Account', e.user], ['Source', e.src_ip], ['Dest', e.dst_ip ? e.dst_ip + (e.dst_port != null ? ':' + Math.round(e.dst_port) : '') : null], ['Host', e.host], ['Log', e.source]].filter(r => r[1]);
    return `<div class="x"><dl class="kv">${kv.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join('')}</dl>${e.findings.map(f => `<span class="chipx">${ic('flag')} ${esc(f)}</span>`).join('')}</div>`;
  }
  function groupEvents(ev) {
    const key = x => [x.findings.join(','), x.type, x.src_ip, x.user, x.host].join('|'), out = [];
    for (let i = 0; i < ev.length;) {
      let j = i + 1;
      if (ev[i].alerted) while (j < ev.length && ev[j].alerted && key(ev[j]) === key(ev[i])) j++;
      if (j - i >= 4) out.push({ many: ev.slice(i, j) }); else for (let k = i; k < j; k++) out.push({ one: ev[k] });
      i = j;
    }
    return out;
  }
  function renderEvList() {
    const box = $('#evlist'); if (!box) return;
    const ev = S.incEvents.events;
    if (!ev.length) { box.innerHTML = '<div class="empty">No events match the current filters.</div>'; return; }
    const rule = {}; (S.incDetail.findings || []).forEach(f => { rule[f.id] = f.rule_name; });
    box.innerHTML = groupEvents(ev).map(g => {
      if (g.one) {
        const e = g.one, ctx = !e.alerted, big = e.sev === 'critical' || e.sev === 'high';
        return `<div class="evrow s-${esc(e.sev)} ${ctx ? 'ctx' : ''} ${e.id === S.selEvent ? 'sel' : ''}" data-id="${esc(e.id)}"><time>${esc(fmtT(e.ts))}</time>
          <div class="rail"><span class="evdot ${big ? 'fill' : ''}">${ctx ? '' : ic(big ? 'warn' : (TYPE_ICON[e.type] || 'dot'))}</span></div>
          <div class="evbox"><div class="l">${ctx ? '' : `<span class="sevtag">${esc(e.sev)}</span>`}<span class="tx" title="${esc(e.label)}">${esc(e.label)}</span><button class="iconbtn chev-b">${ic('chev', 'chev')}</button></div>${evExpand(e)}</div></div>`;
      }
      const m = g.many, f = m[0], big = m.some(e => e.sev === 'critical' || e.sev === 'high'), top = m.reduce((a, e) => SEV_RANK[e.sev] > SEV_RANK[a] ? e.sev : a, 'info');
      const open = m.some(e => e.id === S.selEvent), name = rule[f.findings[0]] || typeLabel(f.type);
      return `<div class="evrow grp s-${esc(top)} ${open ? 'open' : ''}"><time>${esc(fmtT(f.ts))}<small>→ ${esc(fmtT(m[m.length - 1].ts))}</small></time>
        <div class="rail"><span class="evdot ${big ? 'fill' : ''}" data-n="${m.length}">${ic(TYPE_ICON[f.type] || 'dot')}</span></div>
        <div class="evbox"><div class="l"><span class="sevtag">${esc(top)}</span><span class="tx"><b>${m.length}×</b>${esc(name)} <span class="faint">· ${esc(f.label)} …</span></span><button class="iconbtn chev-b">${ic('chev', 'chev')}</button></div>
        <div class="x">${m.map(e => `<div class="mem ${e.id === S.selEvent ? 'sel' : ''}" data-id="${esc(e.id)}"><time>${esc(fmtT(e.ts))}</time><span title="${esc(e.label)}">${esc(e.label)}</span></div>`).join('')}</div></div></div>`;
    }).join('');
    $$('.evrow', box).forEach(row => {
      row.onclick = e => {
        const mem = e.target.closest('.mem'); if (mem) { selectEvent(mem.dataset.id); return; }
        if (e.target.closest('.chev-b') || row.classList.contains('grp')) { row.classList.toggle('open'); return; }
        selectEvent(row.dataset.id);
      };
    });
  }
  const selectEvent = guard(async function (id) {
    S.selEvent = id; $$('#evlist [data-id]').forEach(r => r.classList.toggle('sel', r.dataset.id === id));
    const ev = await api('/api/events/' + encodeURIComponent(id));
    if (S.selEvent === id && $('#evd')) $('#evd').innerHTML = evDetailHTML(ev);
  });

  function renderRight() {
    const d = S.incDetail, box = $('#rtop'); if (!box) return;
    const done = d.remediation.filter(r => r.done).length, tabs = [['summary', 'Summary'], ['actions', 'Actions', `${done}/${d.remediation.length}`], ['notes', 'Notes', d.notes.length || ''], ['iocs', 'IOCs', d.ioc_candidates.filter(c => !c.recorded).length || '']];
    box.innerHTML = `<div class="tabs">${tabs.map(([k, l, n]) => `<button data-t="${k}" class="${S.tab === k ? 'on' : ''}">${l}${n !== '' && n != null ? `<span class="n">${n}</span>` : ''}</button>`).join('')}</div><div class="tabbody" id="tabbody"></div>`;
    $$('.tabs button', box).forEach(b => b.onclick = () => { S.tab = b.dataset.t; renderRight(); });
    const tb = $('#tabbody');
    if (S.tab === 'summary') {
      const s = d.summary, lines = s.slice(2, -1);
      tb.innerHTML = `<div class="sum"><p class="first">${esc(s[0])}</p>${s[1] && s[1].startsWith('Observed') ? `<div class="tagrow">${d.tactics.map(t => `<span class="tag tac">${esc(t)}</span>`).join('')}</div>` : ''}
        ${lines.length ? `<ul>${lines.map(l => `<li>${esc(l)}</li>`).join('')}</ul>` : ''}
        <div class="tagrow">${d.techniques.map(techTag).join('')}</div>
        <div style="display:flex;align-items:baseline;gap:10px;margin-top:12px"><b>Confidence</b><span style="font-size:20px;font-weight:700">${d.confidence}</span><span class="muted">/100 · ${esc(d.confidence_label)}${d.overridden ? ' (analyst override)' : ''}</span></div>
        <div class="meter"><i style="width:${d.confidence}%"></i></div>
        <details class="acc"><summary>Why this score ${ic('chev', 'chev')}</summary><div class="acc-b"><table class="tbl"><tbody>${d.confidence_factors.map(f => `<tr><td>${esc(f.factor)}</td><td class="num" style="color:${f.points < 0 ? 'var(--critical)' : 'var(--ok)'}">${f.points > 0 ? '+' : ''}${f.points}</td></tr>`).join('')}</tbody></table><p class="faint" style="margin:8px 0 0">Heuristic, not a probability. Override it in Actions if your analysis disagrees.</p></div></details>
        <details class="acc"><summary>Findings in this incident <span class="n tabs" style="all:unset;background:var(--panel3);border-radius:99px;padding:0 7px;font-size:11px">${d.findings.length}</span> ${ic('chev', 'chev')}</summary><div class="acc-b">${d.findings.map(f => `<div class="why s-${esc(f.severity)}" style="cursor:pointer" data-go="#/findings/${esc(f.id)}"><b>${esc(f.id)} · ${esc(f.rule_name)} ${sevChip(f.severity)}</b><span>${esc(f.summary)}</span></div>`).join('')}</div></details>
        <p class="note">${esc(s[s.length - 1])}</p></div>`;
    } else if (S.tab === 'actions') {
      tb.innerHTML = `<b>Recommended remediation</b> <span class="muted">(containment first)</span><div class="meter"><i style="width:${d.remediation.length ? (done / d.remediation.length) * 100 : 0}%"></i></div>
        ${d.remediation.map((r, i) => `<label class="check ${r.done ? 'done' : ''}"><input type="checkbox" data-i="${i}" ${r.done ? 'checked' : ''}><span>${esc(r.step)}</span></label>`).join('')}
        <div style="height:14px"></div><b>Analyst decision</b>
        <div style="display:grid;grid-template-columns:1fr;gap:10px;margin-top:8px"><div><label class="f">State</label><select class="select" id="dstate">${S.incList.states.map(v => `<option value="${esc(v)}" ${v === d.verdict ? 'selected' : ''}>${esc(S.incList.state_labels[v])}</option>`).join('')}</select></div>
        <div><label class="f"><input type="checkbox" id="dov" ${d.overridden ? 'checked' : ''}> Override confidence: <b id="dovv">${d.confidence}</b></label><input type="range" id="dovr" min="0" max="100" value="${d.confidence}" style="width:100%;accent-color:var(--accent)" ${d.overridden ? '' : 'disabled'}></div>
        <button class="btn primary" id="dsave">Save decision</button></div>`;
      $$('.check input', tb).forEach(cb => cb.onchange = guard(async () => { const r = d.remediation[+cb.dataset.i]; r.done = cb.checked; await api(`/api/incidents/${S.selInc}/remediation`, { method: 'PUT', json: { step: r.step, done: cb.checked } }); renderRight(); }));
      $('#dov').onchange = e => { $('#dovr').disabled = !e.target.checked; };
      $('#dovr').oninput = e => { $('#dovv').textContent = e.target.value; };
      $('#dsave').onclick = () => setState($('#dstate').value, $('#dov').checked ? +$('#dovr').value : null);
    } else if (S.tab === 'notes') {
      tb.innerHTML = `${d.notes.length ? d.notes.map(n => `<div class="note-i"><small>${esc(n.at)} UTC · ${esc(n.author)}</small>${esc(n.note)}</div>`).join('') : '<div class="muted" style="margin-bottom:10px">No notes yet. Record what you checked and why you reached your verdict — it goes into the report.</div>'}
        <textarea class="input" id="ntext" placeholder="Add investigation note…"></textarea><div style="margin-top:8px;text-align:right"><button class="btn primary" id="nadd">${ic('plus')} Add note</button></div>`;
      $('#nadd').onclick = guard(async () => { const t = $('#ntext').value; if (!t.trim()) return toast('Write a note first', true); S.incDetail = await api(`/api/incidents/${S.selInc}/notes`, { json: { note: t } }); renderRight(); toast('Note added'); });
    } else {
      const c = d.ioc_candidates, open = c.filter(x => !x.recorded);
      tb.innerHTML = `<b>Indicator candidates</b><p class="muted" style="margin:4px 0 8px">Extracted from this incident's findings. Recording an IOC makes every matching event a finding.</p>
        ${c.length ? c.map((x, i) => `<label class="check ${x.recorded ? 'done' : ''}"><input type="checkbox" data-i="${i}" ${x.recorded ? 'disabled' : 'checked'}><span><span class="mono">${esc(x.value)}</span> <span class="tag" style="padding:0 6px;font-size:10.5px">${esc(x.ioc_type)}</span>${x.recorded ? ' <span class="faint">recorded</span>' : ''}<br><span class="muted" style="font-size:12px">${esc(x.note)}</span></span></label>`).join('') : '<div class="muted">No candidates.</div>'}
        ${open.length ? `<div style="margin-top:10px"><button class="btn primary" id="iadd">${ic('plus')} Add selected to IOC list</button></div>` : ''}`;
      $('#iadd') && ($('#iadd').onclick = guard(async () => { const vals = $$('.check input:checked:not(:disabled)', tb).map(cb => c[+cb.dataset.i].value); if (!vals.length) return; const r = await api(`/api/incidents/${S.selInc}/iocs`, { json: { values: vals } }); toast(`${r.added} IOC(s) recorded`); await refreshMeta(); S.incList = await api('/api/incidents'); S.incDetail = await api('/api/incidents/' + S.selInc); renderCards(); renderRight(); }));
    }
  }

  /* ------------------------------------------------------------ findings */
  async function viewFindings(arg) {
    const d = await api('/api/findings'); S.findings = d.findings;
    if (arg) S.fSel = arg;
    const rules = [...new Set(d.findings.map(f => f.rule_name))].sort();
    view.innerHTML = `<div class="page"><div class="page-h"><div><h1>Findings</h1><p>Every finding lists the exact events that triggered it, so you can verify or reject the conclusion.</p></div></div>
      <div class="toolbar"><div class="search">${ic('search')}<input class="input" id="fq" placeholder="Search summary, IP, user, host…" value="${esc(S.fQ)}"></div>
        <select class="select" id="frule"><option value="">All rules</option>${rules.map(r => `<option ${r === S.fRule ? 'selected' : ''}>${esc(r)}</option>`).join('')}</select>
        <div class="pills" id="fsev">${SEVS.slice(0, 4).map(s => `<button data-s="${s}" class="s-${s} ${S.fSev.has(s) ? 'on' : ''}">${s}</button>`).join('')}</div></div>
      <div class="split"><div class="panel" style="overflow:auto;max-height:calc(100vh - 230px)"><table class="tbl"><thead><tr><th>ID</th><th>Severity</th><th>Rule</th><th>Tactic</th><th>Start (UTC)</th><th class="num">Events</th><th>Incident</th></tr></thead><tbody id="ftb"></tbody></table></div>
      <div class="panel sticky" id="fdet" style="max-height:calc(100vh - 230px);overflow:auto"><div class="empty">Select a finding to see its evidence and response guidance.</div></div></div></div>`;
    const draw = () => {
      const q = S.fQ.toLowerCase();
      const rows = S.findings.filter(f => (!S.fSev.size || S.fSev.has(f.severity)) && (!S.fRule || f.rule_name === S.fRule) && (!q || [f.summary, f.src_ip, f.user, f.host, f.id].join(' ').toLowerCase().includes(q)));
      $('#ftb').innerHTML = rows.length ? rows.map(f => `<tr class="row ${f.id === S.fSel ? 'sel' : ''}" data-id="${esc(f.id)}"><td class="mono">${esc(f.id)}</td><td>${sevChip(f.severity)}</td><td><b>${esc(f.rule_name)}</b><div class="muted" style="font-size:12px;max-width:380px">${esc(f.summary)}</div></td><td>${esc(f.tactic)}</td><td class="mono" style="font-size:12px">${esc(fmtDT(f.start))}</td><td class="num">${f.count}</td><td>${f.incident ? `<a href="#/incidents/${esc(f.incident)}" onclick="event.stopPropagation()">${esc(f.incident)}</a>` : '—'}</td></tr>`).join('') : '<tr><td colspan="7" class="empty">No findings match.</td></tr>';
      $$('#ftb tr.row').forEach(r => r.onclick = () => { S.fSel = r.dataset.id; $$('#ftb tr').forEach(x => x.classList.toggle('sel', x === r)); showFinding(r.dataset.id); });
    };
    $('#fq').oninput = debounce(e => { S.fQ = e.target.value; draw(); }, 150);
    $('#frule').onchange = e => { S.fRule = e.target.value; draw(); };
    $('#fsev').onclick = e => { const b = e.target.closest('button'); if (!b) return; S.fSev.has(b.dataset.s) ? S.fSev.delete(b.dataset.s) : S.fSev.add(b.dataset.s); b.classList.toggle('on'); draw(); };
    draw(); if (S.fSel) showFinding(S.fSel);
  }
  const showFinding = guard(async function (id) {
    const f = await api('/api/findings/' + id), box = $('#fdet'); if (!box) return;
    box.innerHTML = `<div class="panel-h" style="padding-top:16px"><span class="mono">${esc(f.id)}</span> · ${esc(f.rule_name)} ${sevChip(f.severity)}</div><div class="panel-b">
      <p style="margin:0 0 8px">${esc(f.summary)}</p><p class="muted" style="margin:0 0 10px">${esc(f.description)}</p>
      <div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px"><span class="tag tac">${esc(f.tactic)}</span>${f.techniques.map(techTag).join('')}${f.incident ? `<a class="tag" href="#/incidents/${esc(f.incident)}">${esc(f.incident)} →</a>` : ''}</div>
      <details class="acc" open><summary>Suggested response ${ic('chev', 'chev')}</summary><div class="acc-b"><ul style="margin:0;padding-left:18px">${f.remediation.map(r => `<li style="margin-bottom:4px">${esc(r)}</li>`).join('')}</ul></div></details>
      <details class="acc" open><summary>Evidence events (${f.count}) ${ic('chev', 'chev')}</summary><div class="acc-b"><table class="tbl"><tbody>${f.events.slice(0, 80).map(e => `<tr class="row" data-ev="${esc(e.id)}"><td class="mono" style="font-size:11.5px;white-space:nowrap">${esc(fmtT(e.ts))}</td><td class="mono" style="font-size:12px;word-break:break-all">${esc(e.label)}</td></tr>`).join('')}</tbody></table>${f.count > 80 ? `<p class="faint">Showing first 80 of ${f.count}.</p>` : ''}</div></details></div>`;
    $$('[data-ev]', box).forEach(r => r.onclick = () => openEventDrawer(r.dataset.ev));
  });

  /* ------------------------------------------------------------ timeline */
  async function viewTimeline() {
    const T = S.tl, qs = () => new URLSearchParams({ lane: T.lane, q: T.q, flagged: T.flagged, types: [...T.types].join(',') });
    view.innerHTML = `<div class="page"><div class="page-h"><div><h1>Timeline</h1><p>Every imported event on one UTC axis. Large dots are events that triggered a finding, diamonds are findings, shaded bands are incidents. Drag to zoom, double-click to reset.</p></div></div>
      <div class="toolbar"><span class="muted">Group by</span><select class="select" id="tlane">${[['src_ip', 'Source IP'], ['user', 'User'], ['host', 'Host'], ['source', 'Log source'], ['event_type', 'Event type']].map(([k, v]) => `<option value="${k}" ${k === T.lane ? 'selected' : ''}>${v}</option>`).join('')}</select>
        <div class="search">${ic('search')}<input class="input" id="tq" placeholder="Search IP, user, URL, command, message…" value="${esc(T.q)}"></div>
        <div class="seg" id="tflag"><button data-v="0" class="${T.flagged ? '' : 'on'}">All events</button><button data-v="1" class="${T.flagged ? 'on' : ''}">Flagged only</button></div><button class="btn sm hidden" id="tzoom">${ic('reset')} Reset zoom</button><span class="muted" id="tinfo"></span></div>
      <div class="pills" id="ttypes" style="margin-bottom:12px"></div>
      <div class="panel" style="padding:10px"><div id="swwrap"><canvas class="swim" id="swim"></canvas></div></div>
      <div class="page-h" style="margin-top:22px"><div><h1 style="font-size:17px">Events</h1></div><div class="sp"></div><a class="btn sm" href="/api/export/events.csv">${ic('download')} Export all (CSV)</a></div>
      <div class="panel" style="overflow:auto"><table class="tbl"><thead><tr><th>Time (UTC)</th><th>Sev</th><th>Type</th><th>Source IP</th><th>User</th><th>Host</th><th>Detail</th><th>Log</th></tr></thead><tbody id="etb"></tbody></table></div><div class="pager" id="pager"></div></div>`;
    const load = guard(async () => {
      const r = await api('/api/timeline?' + qs()); S.tlData = r;
      if (!T.typesAll) { T.typesAll = Object.keys((await api('/api/dashboard')).event_types); }
      $('#ttypes').innerHTML = T.typesAll.map(t => `<button data-t="${esc(t)}" class="${T.types.has(t) ? 'on' : ''}">${esc(typeLabel(t))}</button>`).join('');
      $('#tinfo').textContent = `${num(r.total)} events${r.sampled ? ' (display sampled; flagged events always shown)' : ''}`;
      if (!r.points.length) { $('#swwrap').innerHTML = '<div class="empty">No events match.</div>'; return; }
      if (!$('#swim')) $('#swwrap').innerHTML = '<canvas class="swim" id="swim"></canvas>';
      const draw = () => $('#swim') && C.swimlane($('#swim'), r, { key: qs().toString(), onPick: openEventDrawer, onZoom: z => $('#tzoom').classList.toggle('hidden', !z) });
      draw(); S._redrawTl = draw;
    });
    const loadTable = guard(async () => {
      const q = new URLSearchParams({ page: S.evPage, size: 100, q: T.q, flagged: T.flagged, types: [...T.types].join(',') });
      const r = await api('/api/events?' + q);
      $('#etb').innerHTML = r.events.map(e => `<tr class="row" data-id="${esc(e.id)}"><td class="mono" style="font-size:12px;white-space:nowrap">${esc(fmtDT(e.ts))}</td><td><span class="sevtag s-${esc(e.sev)}" style="${e.alerted ? '' : 'color:var(--faint)'}">${e.alerted ? esc(e.sev) : '—'}</span></td><td>${esc(typeLabel(e.type))}</td><td class="mono">${esc(e.src_ip || '')}</td><td>${esc(e.user || '')}</td><td>${esc(e.host || '')}</td><td class="mono" style="font-size:12px;max-width:440px;word-break:break-all">${esc(e.label.slice(0, 160))}</td><td class="faint">${esc(e.source)}</td></tr>`).join('') || '<tr><td colspan="8" class="empty">No events match.</td></tr>';
      $$('#etb tr.row').forEach(r => r.onclick = () => openEventDrawer(r.dataset.id));
      const pages = Math.max(1, Math.ceil(r.total / r.size));
      $('#pager').innerHTML = `<span>${num(r.total)} events · page ${r.page}/${pages}</span><button class="btn sm" id="pp" ${r.page <= 1 ? 'disabled' : ''}>← Prev</button><button class="btn sm" id="pn" ${r.page >= pages ? 'disabled' : ''}>Next →</button>`;
      $('#pp').onclick = () => { S.evPage = r.page - 1; loadTable(); }; $('#pn').onclick = () => { S.evPage = r.page + 1; loadTable(); };
    });
    $('#tlane').onchange = e => { T.lane = e.target.value; load(); };
    $('#tq').oninput = debounce(e => { T.q = e.target.value; S.evPage = 1; load(); loadTable(); }, 300);
    $('#tflag').onclick = e => { const b = e.target.closest('button'); if (!b) return; T.flagged = b.dataset.v === '1'; $$('#tflag button').forEach(x => x.classList.toggle('on', x === b)); S.evPage = 1; load(); loadTable(); };
    $('#ttypes').onclick = e => { const b = e.target.closest('button'); if (!b) return; T.types.has(b.dataset.t) ? T.types.delete(b.dataset.t) : T.types.add(b.dataset.t); b.classList.toggle('on'); S.evPage = 1; load(); loadTable(); };
    $('#tzoom').onclick = () => $('#swim').resetZoom();
    load(); loadTable();
  }

  /* ------------------------------------------------------------ IOCs */
  async function viewIocs() {
    const d = await api('/api/iocs');
    view.innerHTML = `<div class="page"><div class="page-h"><div><h1>Indicators of compromise</h1><p>Recorded indicators are matched against every imported event; each match becomes a finding automatically.</p></div><div class="sp"></div>${d.iocs.length ? `<a class="btn" href="/api/export/iocs.csv">${ic('download')} Export CSV</a>` : ''}</div>
      <div class="grid2" style="grid-template-columns:1.2fr 1fr"><div class="panel"><div class="panel-h">Record an indicator</div><div class="panel-b"><div style="display:grid;grid-template-columns:2fr 1fr;gap:10px"><div><label class="f">Value (IP, domain, URL, hash, e-mail, username)</label><input class="input" id="iv"></div><div><label class="f">Type</label><select class="select" id="it"><option value="">auto-detect</option>${d.types.map(t => `<option>${esc(t)}</option>`).join('')}</select></div></div>
        <div style="margin-top:10px"><label class="f">Note</label><input class="input" id="in"></div><div style="margin-top:12px"><button class="btn primary" id="iaddb">${ic('plus')} Record IOC</button></div></div></div>
      <div class="panel"><div class="panel-h">Bulk add <small>one indicator per line</small></div><div class="panel-b"><textarea class="input" id="ibulk" style="min-height:96px" placeholder="198.51.100.77&#10;evil.example.com&#10;44d88612fea8a8f36de82e1278abb02f"></textarea><div style="margin-top:10px"><button class="btn" id="ibulkb">Add list</button></div></div></div></div>
      <div class="panel"><table class="tbl"><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Note</th><th>Added (UTC)</th><th class="num">Matching events</th><th></th></tr></thead><tbody>${d.iocs.length ? d.iocs.map(i => `<tr><td><span class="tag">${esc(i.type)}</span></td><td class="mono">${esc(i.value)}</td><td class="muted">${esc(i.source)}</td><td>${esc(i.note)}</td><td class="muted mono" style="font-size:12px">${esc(i.added)}</td><td class="num">${i.matches ? `<b style="color:var(--high)">${i.matches}</b>` : '<span class="faint">0</span>'}</td><td><button class="iconbtn" data-del="${i.id}" title="Delete">${ic('trash')}</button></td></tr>`).join('') : `<tr><td colspan="7" class="empty">No IOCs yet. Add one above, or open an incident → IOCs tab to record its candidate indicators.</td></tr>`}</tbody></table></div></div>`;
    const add = guard(async (payload) => { const r = await api('/api/iocs', { json: payload }); toast(`${r.added} added${r.duplicates ? ` · ${r.duplicates} already existed` : ''}`); await refreshMeta(); viewIocs(); });
    $('#iaddb').onclick = () => { const v = $('#iv').value.trim(); if (!v) return toast('Enter an indicator', true); add({ value: v, type: $('#it').value, note: $('#in').value }); };
    $('#ibulkb').onclick = () => { const v = $('#ibulk').value.trim(); if (!v) return toast('Paste at least one indicator', true); add({ values: v.split(/\r?\n/), note: 'bulk import' }); };
    $$('[data-del]').forEach(b => b.onclick = guard(async () => { await api('/api/iocs/' + b.dataset.del, { method: 'DELETE' }); toast('IOC deleted'); await refreshMeta(); viewIocs(); }));
  }

  /* ------------------------------------------------------------ reports */
  async function viewReports() {
    const p = S.meta.has_data ? await api('/api/report/preview') : { points: [], unreviewed: [] };
    const has = S.meta.has_data, c = S.meta.case;
    view.innerHTML = `<div class="page" style="max-width:1100px"><div class="page-h"><div><h1>Reports &amp; export</h1><p>Reports are built from the current state: states, notes, IOCs and confidence overrides are included.</p></div></div>
      <div class="grid2" style="grid-template-columns:1.4fr 1fr">
      <div class="panel"><div class="panel-h">Executive summary preview</div><div class="panel-b">${has ? `<ul style="margin:0;padding-left:18px">${p.points.map(x => `<li style="margin-bottom:8px">${esc(x)}</li>`).join('')}</ul>${p.unreviewed.length ? `<div class="diag" style="margin:14px 0 0;background:rgba(244,195,47,.08);border-color:rgba(244,195,47,.5)">${ic('warn')} ${p.unreviewed.length} incident(s) still have no analyst state (${esc(p.unreviewed.join(', '))}). They will appear as <b>New</b> in the report.</div>` : ''}` : '<div class="empty">Import evidence to generate a report.</div>'}
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:18px"><button class="btn primary" id="rpdf" ${has ? '' : 'disabled'}>${ic('download')} Download PDF report</button><a class="btn ${has ? '' : 'hidden'}" href="/api/export/markdown">${ic('download')} Markdown</a><a class="btn ${has ? '' : 'hidden'}" href="/api/export/json">${ic('download')} JSON</a><a class="btn ${has ? '' : 'hidden'}" href="/api/export/evidence.csv">${ic('download')} Evidence CSV</a></div>
        <p class="faint" style="margin:12px 0 0">The PDF is generated fresh from the current state each time you download it.</p></div></div>
      <div style="display:flex;flex-direction:column;gap:14px"><div class="panel"><div class="panel-h">Investigation</div><div class="panel-b"><dl class="kv"><dt>Name</dt><dd>${esc(c.name)}</dd><dt>Analyst</dt><dd>${esc(c.analyst)}</dd><dt>Organisation</dt><dd>${esc(c.organization) || '—'}</dd><dt>Marking</dt><dd><span class="tlp ${tlpCls(c.tlp)}">${esc(c.tlp)}</span></dd></dl><div style="margin-top:12px"><button class="btn sm" id="redit">Edit details</button> <button class="btn sm" data-new-case>New investigation…</button></div></div></div>
        <div class="panel"><div class="panel-h">Save &amp; restore <small>case file</small></div><div class="panel-b"><p class="muted" style="margin:0 0 10px">Download your IOCs, notes, states and checklists as one file and re-import them later or on another machine.</p><div style="display:flex;gap:10px"><a class="btn" href="/api/export/case">${ic('download')} Download</a><button class="btn" id="rimp">${ic('upload')} Restore…</button><input type="file" id="rfile" accept=".json" hidden></div></div></div>
        <div class="panel"><div class="panel-h">Evidence <small>${(c0 => c0)((S.meta.files || []).length)} file(s)</small></div><div class="panel-b"><div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn" id="rimport">${ic('upload')} Add logs</button><a class="btn" href="#/evidence">Manage files</a><button class="btn danger" id="rclear" ${has ? '' : 'disabled'}>${ic('trash')} Clear evidence</button></div></div></div></div></div></div>`;
    $('#redit').onclick = () => $('#case-pill').click();
    $('#rimport').onclick = () => $('#file').click();
    $('#rpdf').onclick = guard(async () => { const b = $('#rpdf'); b.disabled = true; b.innerHTML = '<span class="spin"></span> Rendering PDF…'; try { const r = await api('/api/export/pdf' + redactQS()); const blob = await r.blob(); const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = (r.headers.get('content-disposition') || '').match(/filename="(.+?)"/)?.[1] || 'traceforge_report.pdf'; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 4000); toast('PDF downloaded'); } finally { b.disabled = false; b.innerHTML = ic('download') + ' Download PDF report'; } });
    $('#rimp').onclick = () => $('#rfile').click();
    $('#rfile').onchange = guard(async e => { const fd = new FormData(); fd.append('file', e.target.files[0]); const r = await api('/api/import/case', { method: 'POST', body: fd }); toast(`Restored ${r.iocs_added} IOC(s) and ${r.notes} note(s)`); await refreshMeta(); viewReports(); });
    $('#rclear').onclick = guard(async () => { if (!confirm('Remove all imported evidence and per-incident notes, states and checklists? IOCs are kept.')) return; S.meta = await api('/api/clear', { method: 'POST' }); S.selInc = null; toast('Evidence cleared'); navigate('#/dashboard'); });
    reportsExtras(p);
  }

  /* ------------------------------------------------------------ sharing, standards, encrypted case file */
  const RED = { mode: 'auto' };
  const redactQS = () => (RED.mode === 'auto' ? '' : '?redact=' + RED.mode);
  async function saveBlob(path, opts, fallbackName) {
    // fetch directly: api() would parse a JSON file download instead of returning the Response
    const o = { ...opts };
    if (o.json !== undefined) { o.method = 'POST'; o.headers = { 'Content-Type': 'application/json' }; o.body = JSON.stringify(o.json); delete o.json; }
    const r = await fetch(path, o);
    if (!r.ok) { let msg = r.statusText; try { const j = await r.json(); msg = j.error || j.detail || msg; } catch (e) { /* not json */ } throw new Error(typeof msg === 'string' ? msg : 'Request failed'); }
    const blob = await r.blob(), a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = (r.headers.get('content-disposition') || '').match(/filename="(.+?)"/)?.[1] || fallbackName; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  }
  function reportsExtras(p) {
    const has = S.meta.has_data, page = $('.page', view);
    const links = $$('a.btn[href^="/api/export/"]', view).filter(a => /(markdown|json|evidence\.csv|events\.csv|iocs\.csv)$/.test(a.getAttribute('href')));
    page.insertAdjacentHTML('beforeend', `<div class="grid2" style="margin-top:14px;grid-template-columns:1fr 1fr">
      <div class="panel"><div class="panel-h">Sharing &amp; standards</div><div class="panel-b">
        <label class="f" for="redact-mode">Mask internal identifiers in shared files</label>
        <select class="select" id="redact-mode"><option value="auto">Automatic (by marking: ${esc(p.tlp || S.meta.case.tlp)})</option><option value="on">Always mask usernames, hostnames and internal IPs</option><option value="off">Off - include everything</option></select>
        <p class="faint" style="margin:8px 0 12px">${p.redaction_auto ? esc(p.redaction_auto) : 'The current marking does not require masking. TLP:GREEN masks identifiers; TLP:CLEAR also withholds notes and the organisation name.'}</p>
        <div style="display:flex;gap:10px;flex-wrap:wrap"><a class="btn" id="stix-link" href="/api/export/iocs.stix.json">${ic('download')} IOCs as STIX 2.1</a><a class="btn ${has ? '' : 'hidden'}" href="/api/export/attack-layer.json">${ic('download')} ATT&amp;CK Navigator layer</a></div>
      </div></div>
      <div class="panel"><div class="panel-h">Encrypted case file <small>passphrase protected</small></div><div class="panel-b">
        <label class="f" for="cpass">Passphrase (at least 10 characters)</label>
        <input class="input" id="cpass" type="password" autocomplete="new-password" placeholder="Needed to save and to restore">
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px"><button class="btn" id="cenc">${ic('lock')} Download encrypted</button><button class="btn" id="cdec">${ic('upload')} Restore encrypted…</button><input type="file" id="cdecfile" hidden></div>
        <p class="faint" style="margin:10px 0 0">AES-256-GCM with a scrypt-derived key. There is no recovery: a lost passphrase cannot be reset.</p>
      </div></div></div>`);
    links.push($('#stix-link'));
    links.forEach(a => { a.dataset.base = a.getAttribute('href'); });
    $('#redact-mode').onchange = e => { RED.mode = e.target.value; links.forEach(a => { a.href = a.dataset.base + redactQS(); }); };
    $('#cenc').onclick = guard(async () => {
      const pw = $('#cpass').value; if (pw.length < 10) return toast('Use a passphrase of at least 10 characters', true);
      await saveBlob('/api/export/case/encrypted', { json: { passphrase: pw } }, 'traceforge_case.tfcase'); toast('Encrypted case file downloaded');
    });
    $('#cdec').onclick = () => $('#cdecfile').click();
    $('#cdecfile').onchange = guard(async e => {
      const f = e.target.files[0]; e.target.value = ''; if (!f) return;      // reset first so the same file can be chosen again after an error
      const fd = new FormData(); fd.append('file', f); fd.append('passphrase', $('#cpass').value);
      const r = await api('/api/import/case', { method: 'POST', body: fd });
      toast(`Restored ${r.iocs_added} IOC(s), ${r.notes} note(s) and ${r.sigma_rules} Sigma rule(s)` + (r.evidence_check && r.evidence_check.missing.length ? ` · evidence not loaded: ${r.evidence_check.missing.join(', ')}` : ''));
      await refreshMeta(); viewReports();
    });
  }

  /* ------------------------------------------------------------ evidence */
  async function viewEvidence() {
    await refreshMeta();
    const m = S.meta, files = m.files || [];
    const rows = files.map((f, i) => {
      const issues = [f.bad_timestamp ? `<span class="chip warn">${num(f.bad_timestamp)} rows without a time were skipped</span>` : '', f.invalid_ips ? `<span class="chip warn">${num(f.invalid_ips)} invalid IPs ignored</span>` : '',
        f.truncated ? '<span class="chip warn">only the first 200,000 rows were read</span>' : '', f.sample ? '<span class="chip">sample data</span>' : ''].join('');
      const mapped = Object.entries(f.mapped || {}).map(([k, v]) => `<span class="chip" title="column “${esc(v)}” → ${esc(k)}">${esc(k)} ← ${esc(v)}</span>`).join('');
      return `<div class="efile"><div class="efile-main"><div class="efile-ico">${ic('file')}</div>
        <div class="efile-t"><b>${esc(f.name)}</b><div class="muted">${num(f.events)} event${f.events === 1 ? '' : 's'}${f.rows_read !== f.events ? ` of ${num(f.rows_read)} rows` : ''} · ${f.start ? esc(fmtHM(f.start)) + ' → ' + esc(fmtHM(f.end)) + ' UTC' : 'no time range'} · ${(f.size / 1024).toFixed(f.size > 102400 ? 0 : 1)} KB</div>
        <div class="chips">${issues}</div></div>
        <button class="btn sm" data-copy="${esc(f.sha256)}" title="Copy SHA-256 (proof of which exact file was analysed)">SHA-256 ${esc(f.sha256.slice(0, 10))}…</button>
        <button class="btn sm danger" data-rm="${esc(f.sha256)}" data-name="${esc(f.name)}">${ic('trash')} Remove</button></div>
        <details class="acc" style="margin-top:8px"><summary>How TraceForge read this file ${ic('chev', 'chev')}</summary><div class="acc-b"><div class="chips">${mapped || '<span class="muted">No fields were recognised.</span>'}</div>
          ${f.unmapped.length ? `<p class="faint" style="margin:8px 0 0">Ignored columns: ${f.unmapped.map(esc).join(', ')}${f.unmapped.length >= 12 ? '…' : ''}</p>` : ''}</div></details></div>`;
    }).join('');
    view.innerHTML = `<div class="page" style="max-width:1000px"><div class="page-h"><div><h1>Evidence</h1><p>Log files in <b>${esc(m.case.name)}</b>. Add as many as you like — they are merged onto one timeline.</p></div><div class="sp"></div>
      ${files.length ? `<button class="btn danger" id="e-clear">${ic('trash')} Remove all</button>` : `<button class="btn" id="e-sample">${ic('play')} Load sample data</button>`}</div>
      <div class="drop compact" id="edrop"><div style="color:var(--accent)">${ic('plus').replace('class="ic ', 'style="width:26px;height:26px" class="ic ')}</div>
        <div><div class="big">${files.length ? 'Add more log files' : 'Add your first log file'}</div><div class="muted">Drop files here or click to browse · CSV, JSON, NDJSON, LOG, TXT, Windows XML, Zeek, ZIP, GZ · up to 50 MB each · duplicates are skipped automatically</div></div></div>
      ${files.length ? `<div class="efiles">${rows}</div><p class="faint" style="margin-top:14px">Removing a file recalculates findings and incidents. Your notes, states and IOCs are kept.</p>`
        : `<div class="panel" style="margin-top:16px"><div class="panel-b muted">No evidence yet. Add a log file above, or load the sample data to explore TraceForge.</div></div>`}</div>`;
    $('#edrop').onclick = () => $('#file').click();
    const smp = $('#e-sample'); if (smp) smp.onclick = guard(async () => { await api('/api/sample', { method: 'POST' }); toast('Sample data loaded'); await refreshMeta(); viewEvidence(); });
    $$('[data-rm]').forEach(b => b.onclick = guard(async () => {
      if (!confirm(`Remove “${b.dataset.name}” from this investigation?\n\nFindings and incidents will be recalculated. Your notes, states and IOCs are kept.`)) return;
      S.meta = await api('/api/files/' + b.dataset.rm, { method: 'DELETE' }); S.selInc = null; renderChrome(); toast('File removed'); viewEvidence();
    }));
    const clr = $('#e-clear'); if (clr) clr.onclick = guard(async () => {
      if (!confirm('Remove ALL evidence files from this investigation?\n\nIncident states, notes and checklists are cleared too. Recorded IOCs are kept.')) return;
      S.meta = await api('/api/clear', { method: 'POST' }); S.selInc = null; renderChrome(); toast('Evidence removed'); viewEvidence();
    });
  }

  /* ------------------------------------------------------------ settings */
  async function viewSettings() {
    const d = await api('/api/settings');
    view.innerHTML = `<div class="page" style="max-width:1100px"><div class="page-h"><div><h1>Detection settings</h1><p>Every threshold is editable. Changes re-run detection and correlation on the loaded evidence immediately.</p></div><div class="sp"></div><button class="btn" id="sreset">Reset to defaults</button><button class="btn primary" id="sapply">${ic('check')} Apply &amp; re-run</button></div>
      <div class="panel" style="margin-bottom:14px" id="srules">${d.rules.map(r => `<div class="rule ${r.enabled ? '' : 'off'}" data-r="${esc(r.id)}"><label class="sw"><input type="checkbox" data-en ${r.enabled ? 'checked' : ''}><i></i></label>
        <div><b>${esc(r.name)}</b> ${sevChip(r.severity)} <span class="tag tac">${esc(r.tactic)}</span><div class="muted" style="margin-top:3px">${esc(r.description)}</div></div><span class="faint mono" style="font-size:12px">${esc(r.technique)}</span>
        ${r.params.length ? `<div class="params">${r.params.map(p => p.kind === 'bool' ? `<div><label class="f">${esc(p.label)}</label><label class="sw"><input type="checkbox" data-p="${esc(p.key)}" ${p.value ? 'checked' : ''}><i></i></label></div>` : `<div><label class="f">${esc(p.label)}</label><input class="input" type="number" data-p="${esc(p.key)}" min="${p.min}" max="${p.max}" value="${esc(p.value)}"></div>`).join('')}</div>` : ''}</div>`).join('')}</div>
      <div class="panel"><div class="panel-h">Correlation &amp; privileged accounts</div><div class="panel-b" style="display:grid;grid-template-columns:1fr 2fr;gap:14px"><div><label class="f">Link findings sharing an entity within (minutes)</label><input class="input" type="number" id="sgap" min="5" max="2880" value="${d.correlation_gap}"></div><div><label class="f">Privileged accounts (comma separated) — logins and failures on these are scored higher</label><input class="input" id="spriv" value="${esc(d.privileged_users.join(', '))}"></div></div></div></div>`;
    $$('[data-en]').forEach(cb => cb.onchange = () => cb.closest('.rule').classList.toggle('off', !cb.checked));
    $('#sapply').onclick = guard(async () => {
      const cfg = {}; $$('#srules .rule').forEach(el => { const o = { enabled: $('[data-en]', el).checked }; $$('[data-p]', el).forEach(i => { o[i.dataset.p] = i.type === 'checkbox' ? i.checked : i.value; }); cfg[el.dataset.r] = o; });
      cfg.correlation = { max_gap_minutes: $('#sgap').value }; cfg.privileged_users = $('#spriv').value.split(',').map(x => x.trim()).filter(Boolean);
      const r = await api('/api/settings', { method: 'PUT', json: cfg }); S.meta = r.meta; renderChrome(); toast(S.meta.has_data ? `Re-ran detection: ${r.meta.findings} findings, ${r.meta.incidents} incidents` : 'Settings saved'); viewSettings();
    });
    $('#sreset').onclick = guard(async () => { const r = await api('/api/settings/reset', { method: 'POST' }); S.meta = r.meta; renderChrome(); toast('Defaults restored'); viewSettings(); });
    sigmaPanel();
  }

  /* ------------------------------------------------------------ Sigma rules (settings) */
  async function sigmaPanel() {
    const page = $('.page', view), box = document.createElement('div');
    box.className = 'panel'; box.style.marginTop = '14px'; page.appendChild(box);
    const lvl = l => sevChip(l === 'informational' ? 'info' : l);
    async function draw() {
      const d = await api('/api/sigma');
      box.innerHTML = `<div class="panel-h">Imported Sigma rules <small>${d.rules.length} of ${d.limit}</small><div class="sp"></div><button class="btn sm" id="sg-add">${ic('upload')} Import rules…</button><input type="file" id="sg-file" accept=".yml,.yaml" multiple hidden></div>
        <div class="panel-b">${d.rules.length ? `<table class="tbl"><thead><tr><th>Title</th><th>Level</th><th>Tactic</th><th>Techniques</th><th class="num">Findings</th><th></th></tr></thead><tbody>${d.rules.map(r => `<tr><td>${esc(r.title)}</td><td>${lvl(r.level)}</td><td>${esc(r.tactic)}</td><td class="mono">${esc((r.techniques || []).join(', ')) || '—'}</td><td class="num">${num(r.matches)}</td><td><button class="btn sm danger" data-sg="${r.id}" title="Remove rule">${ic('trash')}</button></td></tr>`).join('')}</tbody></table>`
          : '<div class="muted">No Sigma rules imported yet. Import .yml rules (for example from the SigmaHQ repository or your own detections). Matches become findings that keep the rule\'s severity and ATT&amp;CK tags.</div>'}
        <p class="faint" style="margin:10px 0 0">Supported: selections, field modifiers (contains, startswith, endswith, re, all, cidr), and / or / not and "1 of" / "all of" conditions. Rules using aggregation (count, near) are skipped with a reason.</p></div>`;
      $('#sg-add').onclick = () => $('#sg-file').click();
      $('#sg-file').onchange = guard(async e => {
        const picked = Array.from(e.target.files); e.target.value = '';
        const fd = new FormData(); picked.forEach(f => fd.append('files', f));
        const r = await api('/api/sigma', { method: 'POST', body: fd }); S.meta = r.meta; renderChrome();
        toast(`${r.added.length} rule(s) imported` + (r.skipped.length ? ` · ${r.skipped.length} skipped: ${r.skipped[0].name} ${r.skipped[0].reason}` : ''), r.skipped.length > 0 && !r.added.length);
        draw();
      });
      $$('[data-sg]', box).forEach(b => b.onclick = guard(async () => { if (!confirm('Remove this Sigma rule? Its findings will disappear.')) return; const r = await api('/api/sigma/' + b.dataset.sg, { method: 'DELETE' }); S.meta = r.meta; renderChrome(); draw(); }));
    }
    await draw();
  }

  /* ------------------------------------------------------------ audit & integrity */
  async function viewAudit() {
    const [a, chain, about] = await Promise.all([api('/api/audit?limit=300'), api('/api/audit/verify'), api('/api/about')]);
    await refreshMeta();
    const integ = S.meta.integrity || { ok: true, problems: [], files: 0 }, files = S.meta.files || [];
    const detail = d => { const t = Object.entries(d || {}).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · '); return t.length > 170 ? t.slice(0, 167) + '…' : t; };
    const rows = a.entries.map(e => `<tr><td class="num">${e.seq}</td><td class="mono" style="white-space:nowrap">${esc(fmtDT(e.ts).slice(0, 19))}</td><td>${esc(e.actor)}</td><td><span class="tag">${esc(e.action)}</span></td><td>${esc(e.target)}</td><td class="muted" style="max-width:420px;word-break:break-word">${esc(detail(e.detail))}</td><td class="mono faint" title="${esc(e.entry_hash)}">${esc(e.entry_hash.slice(0, 10))}…</td></tr>`).join('');
    view.innerHTML = `<div class="page" style="max-width:1200px"><div class="page-h"><div><h1>Audit &amp; integrity</h1><p>Who did what, and proof that the evidence and the log itself have not been altered.</p></div></div>
      <div class="grid2">
        <div class="panel"><div class="panel-h">Evidence integrity <small>${integ.checked_utc ? 'last checked ' + esc(integ.checked_utc) + ' UTC' : 'not checked yet'}</small></div><div class="panel-b">
          <p style="margin:0 0 10px">${integ.ok ? `<span class="chip">${ic('check')} All ${files.length} stored file(s) match their SHA-256</span>` : `<span class="chip warn">${ic('warn')} ${integ.problems.length} file(s) failed verification</span>`}</p>
          ${integ.problems.map(p => `<div class="diag">${ic('warn')} <b>${esc(p.name)}</b> — ${esc(p.problem)}. Upload the original file again to repair it.</div>`).join('')}
          <p class="faint" style="margin:0 0 12px">${S.meta.integrity && S.meta.integrity.stored ? 'Every imported file is kept as a read-only copy named after its SHA-256 and re-checked at start-up.' : 'This session is in memory only (no database file), so evidence is not stored between runs.'}</p>
          <button class="btn" id="verify-int" ${files.length || integ.problems.length ? '' : 'disabled'}>${ic('check')} Verify evidence now</button></div></div>
        <div class="panel"><div class="panel-h">Audit log <small>${num(a.head.entries)} entries</small></div><div class="panel-b">
          <p style="margin:0 0 10px">${chain.ok ? `<span class="chip">${ic('check')} Hash chain intact</span>` : `<span class="chip warn">${ic('warn')} Chain broken at entry ${chain.first_bad_seq}</span>`}</p>
          ${chain.ok ? '' : `<div class="diag">${ic('warn')} ${esc(chain.problem)} The log may have been edited; do not rely on entries from that point on.</div>`}
          <p class="faint" style="margin:0 0 6px">Head hash (record it elsewhere to detect truncation):</p><p class="mono" style="margin:0 0 12px;word-break:break-all;font-size:12px">${esc(chain.head_hash)}</p>
          <div style="display:flex;gap:10px;flex-wrap:wrap"><button class="btn" id="verify-chain">${ic('check')} Re-verify chain</button><a class="btn" href="/api/export/audit.csv">${ic('download')} Download CSV</a></div></div></div>
      </div>
      <div class="panel" style="margin-top:14px"><div class="panel-h">Recent actions <small>newest first · showing ${a.entries.length}</small></div><div class="panel-b" style="padding:0;overflow:auto;max-height:520px">
        <table class="tbl"><thead><tr><th class="num">#</th><th>Time (UTC)</th><th>Analyst</th><th>Action</th><th>Target</th><th>Details</th><th>Hash</th></tr></thead><tbody>${rows || '<tr><td colspan="7" class="empty">No actions recorded yet.</td></tr>'}</tbody></table></div></div>
      <p class="faint" style="margin-top:14px">${esc(about.privacy)} · TraceForge v${esc(about.version)} · ${about.rules} built-in rules${about.token_required ? ' · access token required' : ''}. The analyst name is whatever you entered in the investigation details; it is not an authenticated identity.</p></div>`;
    $('#verify-int').onclick = guard(async () => { const r = await api('/api/integrity/verify', { method: 'POST' }); toast(r.ok ? 'All evidence files verified' : `${r.problems.length} file(s) failed verification`, !r.ok); await refreshMeta(); viewAudit(); });
    $('#verify-chain').onclick = guard(async () => { await viewAudit(); toast('Audit chain re-verified'); });
  }

  guardedRoute();
})();
