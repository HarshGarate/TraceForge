/* Dependency-free charts for TraceForge: stacked severity bars + zoomable swim-lane timeline. */
(function (G) {
  'use strict';
  const SEV = ['info', 'low', 'medium', 'high', 'critical']; // stack order, bottom -> top
  const COLOR = { critical: '#f0485a', high: '#f5923e', medium: '#f4c32f', low: '#38b6e8', info: '#6d7396' };
  const NS = 'http://www.w3.org/2000/svg';
  const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const utc = (sec, fmt) => { const d = new Date(sec * 1000).toISOString(); return fmt === 't' ? d.slice(11, 16) : fmt === 'd' ? d.slice(5, 10) : d.slice(0, 16).replace('T', ' '); };

  let tipEl;
  function tip(html, x, y) {
    if (!tipEl) { tipEl = document.createElement('div'); tipEl.className = 'tip'; document.body.appendChild(tipEl); }
    if (html == null) { tipEl.style.display = 'none'; return; }
    tipEl.innerHTML = html; tipEl.style.display = 'block';
    const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
    tipEl.style.left = Math.min(x + 14, innerWidth - w - 10) + 'px';
    tipEl.style.top = (y + 16 + h > innerHeight ? y - h - 12 : y + 16) + 'px';
  }

  function niceMax(v) {
    if (v <= 4) return 4;
    const p = Math.pow(10, Math.floor(Math.log10(v))), n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
  }

  /* opts: {buckets:[{t,counts}], step, height, selected:{t0,t1}|null, onPick(bucketStartSec|null), fillGaps} */
  function stackedBars(el, opts) {
    const W = Math.max(320, el.clientWidth), H = opts.height || 170;
    const m = { l: 34, r: 8, t: 10, b: 34 };
    let bs = opts.buckets.slice();
    if (!bs.length) { el.innerHTML = '<div class="empty">No events in this view.</div>'; return; }
    const step = opts.step;
    if (opts.fillGaps !== false) { // continuous x axis so quiet periods are visible
      const map = new Map(bs.map(b => [b.t, b])), out = [];
      const n = (bs[bs.length - 1].t - bs[0].t) / step;
      if (n < 400) { for (let t = bs[0].t; t <= bs[bs.length - 1].t; t += step) out.push(map.get(t) || { t, counts: {} }); bs = out; }
    }
    const tot = b => SEV.reduce((a, s) => a + (b.counts[s] || 0), 0);
    const ymax = niceMax(Math.max(...bs.map(tot)));
    const iw = W - m.l - m.r, ih = H - m.t - m.b, bw = iw / bs.length, gap = Math.min(3, bw * 0.22);
    let g = '<g class="grid">';
    for (let i = 0; i <= 4; i++) {
      const y = m.t + ih - (ih * i) / 4;
      g += `<line x1="${m.l}" x2="${W - m.r}" y1="${y}" y2="${y}"/><text x="${m.l - 7}" y="${y + 4}" text-anchor="end">${Math.round((ymax * i) / 4)}</text>`;
    }
    g += '</g>';
    let bars = '';
    bs.forEach((b, i) => {
      const x = m.l + i * bw + gap / 2; let y = m.t + ih;
      const sel = opts.selected && b.t === opts.selected.t0;
      const dim = opts.selected && !sel ? ' dim' : '';
      let segs = '';
      SEV.forEach(s => { const c = b.counts[s] || 0; if (!c) return; const h = Math.max(2, (c / ymax) * ih); y -= h; segs += `<rect x="${x}" y="${y}" width="${Math.max(1, bw - gap)}" height="${h}" fill="${COLOR[s]}" rx="${bw > 8 ? 2 : 0}"/>`; });
      bars += `<g class="bar${dim}" data-i="${i}">${segs}<rect x="${m.l + i * bw}" y="${m.t}" width="${bw}" height="${ih}" fill="transparent"/></g>`;
    });
    // x labels: ~7 evenly spaced, with the date whenever it changes
    let xl = '', last = '';
    const every = Math.max(1, Math.round(bs.length / 7));
    bs.forEach((b, i) => {
      if (i % every) return;
      const x = m.l + i * bw + bw / 2, d = utc(b.t, 'd');
      xl += `<text x="${x}" y="${H - 16}" text-anchor="middle">${utc(b.t, 't')}</text>`;
      if (d !== last) { xl += `<text x="${x}" y="${H - 3}" text-anchor="middle" style="fill:#6e7292">${d}</text>`; last = d; }
    });
    el.innerHTML = `<svg class="chart-svg" viewBox="0 0 ${W} ${H}" height="${H}">${g}${bars}${xl}</svg>`;
    const svg = el.firstChild;
    svg.querySelectorAll('.bar').forEach(node => {
      const b = bs[+node.dataset.i];
      node.addEventListener('mousemove', e => {
        const rows = SEV.slice().reverse().filter(s => b.counts[s]).map(s => `<div class="r"><i style="background:${COLOR[s]}"></i>${s}: <b style="display:inline;margin:0;color:#fff">${b.counts[s]}</b></div>`).join('');
        tip(`<b>${utc(b.t)} – ${utc(b.t + step, 't')} UTC</b>${rows || '<div class="r">no events</div>'}`, e.clientX, e.clientY);
      });
      node.addEventListener('mouseleave', () => tip(null));
      node.addEventListener('click', () => opts.onPick && opts.onPick(tot(b) ? b.t : null, step));
    });
  }

  /* data: {lanes:[str], points:[{id,t,lane,type,sev}], incidents:[{id,severity,start,end}], findings:[{id,t,severity,summary}]}
     opts: {height, onPick(eventId)} */
  function swimlane(canvas, data, opts) {
    const dpr = window.devicePixelRatio || 1;
    const laneH = 26, top = 30, left = 150, right = 14, bottom = 26;
    const H = Math.max(opts.height || 300, top + bottom + data.lanes.length * laneH);
    const W = canvas.parentElement.clientWidth;
    canvas.width = W * dpr; canvas.height = H * dpr; canvas.style.height = H + 'px';
    const ctx = canvas.getContext('2d'); ctx.scale(dpr, dpr);
    const tmin = Math.min(...data.points.map(p => p.t), ...data.findings.map(f => f.t)), tmax = Math.max(...data.points.map(p => p.t), ...data.findings.map(f => f.t));
    const pad = Math.max(60000, (tmax - tmin) * 0.02);
    const full = [tmin - pad, tmax + pad];
    let dom = canvas._dom && canvas._key === opts.key ? canvas._dom : full.slice();
    canvas._key = opts.key;
    const x = t => left + ((t - dom[0]) / (dom[1] - dom[0])) * (W - left - right);
    const inv = px => dom[0] + ((px - left) / (W - left - right)) * (dom[1] - dom[0]);
    let hover = null, drag = null;

    function draw() {
      ctx.clearRect(0, 0, W, H);
      ctx.font = '11px ' + getComputedStyle(document.body).fontFamily; ctx.textBaseline = 'middle';
      // lane stripes + labels
      data.lanes.forEach((l, i) => {
        const y = top + i * laneH;
        if (i % 2 === 0) { ctx.fillStyle = 'rgba(255,255,255,.025)'; ctx.fillRect(left, y, W - left - right, laneH); }
        ctx.fillStyle = '#9a9ebb'; ctx.textAlign = 'right';
        let s = String(l); if (s.length > 22) s = s.slice(0, 21) + '…';
        ctx.fillText(s, left - 10, y + laneH / 2);
      });
      // time grid
      const span = (dom[1] - dom[0]) / 1000, steps = [60, 300, 900, 1800, 3600, 7200, 21600, 43200, 86400];
      const st = (steps.find(s => span / s <= 9) || 86400) * 1000;
      ctx.textAlign = 'center'; ctx.strokeStyle = '#2f3350'; ctx.lineWidth = 1;
      for (let t = Math.ceil(dom[0] / st) * st; t < dom[1]; t += st) {
        const px = Math.round(x(t)) + .5; ctx.beginPath(); ctx.moveTo(px, top - 6); ctx.lineTo(px, H - bottom); ctx.stroke();
        ctx.fillStyle = '#8c91b2'; const d = new Date(t).toISOString(); ctx.fillText(d.slice(11, 16), px, H - 12);
        if (d.slice(11, 16) === '00:00' || t === Math.ceil(dom[0] / st) * st) { ctx.fillStyle = '#6e7292'; ctx.fillText(d.slice(5, 10), px, H - 1); }
      }
      // incident bands
      data.incidents.forEach(inc => {
        const a = Math.max(left, x(inc.start * 1)), b = Math.min(W - right, x(inc.end * 1));
        if (b < left || a > W - right) return;
        ctx.fillStyle = COLOR[inc.severity] + '22'; ctx.fillRect(a, top, Math.max(2, b - a), data.lanes.length * laneH);
        ctx.fillStyle = COLOR[inc.severity]; ctx.textAlign = 'left'; ctx.fillRect(a, top - 3, Math.max(2, b - a), 2);
        ctx.fillText(inc.id, a + 3, top - 12);
      });
      // points: context first, flagged on top
      const flagged = [], plain = [];
      data.points.forEach(p => (p.sev === 'info' ? plain : flagged).push(p));
      const dot = (p, r, a) => {
        const px = x(p.t); if (px < left - 4 || px > W - right + 4) return;
        const py = top + p.lane * laneH + laneH / 2;
        ctx.globalAlpha = a; ctx.fillStyle = COLOR[p.sev]; ctx.beginPath(); ctx.arc(px, py, r, 0, 6.2832); ctx.fill();
        if (a === 1) { ctx.strokeStyle = 'rgba(255,255,255,.75)'; ctx.lineWidth = 1; ctx.stroke(); } ctx.globalAlpha = 1;
      };
      plain.forEach(p => dot(p, 2.6, .55)); flagged.forEach(p => dot(p, 5, 1));
      // finding diamonds on the top edge
      data.findings.forEach(f => {
        const px = x(f.t); if (px < left || px > W - right) return;
        ctx.fillStyle = COLOR[f.severity]; ctx.beginPath(); ctx.moveTo(px, top - 8); ctx.lineTo(px + 5, top - 3); ctx.lineTo(px, top + 2); ctx.lineTo(px - 5, top - 3); ctx.closePath(); ctx.fill();
      });
      if (hover) { ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(x(hover.t), top + hover.lane * laneH + laneH / 2, 7, 0, 6.2832); ctx.stroke(); }
      if (drag && Math.abs(drag.x1 - drag.x0) > 3) { ctx.fillStyle = 'rgba(51,214,201,.16)'; ctx.strokeStyle = '#33d6c9'; const a = Math.min(drag.x0, drag.x1); ctx.fillRect(a, top, Math.abs(drag.x1 - drag.x0), H - top - bottom); ctx.strokeRect(a, top, Math.abs(drag.x1 - drag.x0), H - top - bottom); }
    }
    function nearest(mx, my) {
      let best = null, bd = 12 * 12;
      for (const p of data.points) {
        const dx = x(p.t) - mx, dy = top + p.lane * laneH + laneH / 2 - my, d = dx * dx + dy * dy;
        if (d < bd || (d === bd && best && p.sev !== 'info' && best.sev === 'info')) { bd = d; best = p; }
      }
      return best;
    }
    const pos = e => { const r = canvas.getBoundingClientRect(); return [e.clientX - r.left, e.clientY - r.top]; };
    canvas.onmousemove = e => {
      const [mx, my] = pos(e);
      if (drag) { drag.x1 = mx; draw(); return; }
      const f = data.findings.find(f => Math.abs(x(f.t) - mx) < 7 && my < top + 4);
      if (f) { tip(`<b>${esc(f.id)} · ${esc(f.severity)}</b><div class="r">${esc(f.summary)}</div>`, e.clientX, e.clientY); canvas.style.cursor = 'default'; return; }
      const p = nearest(mx, my);
      if (p !== hover) { hover = p; draw(); }
      canvas.style.cursor = p ? 'pointer' : 'crosshair';
      if (p) tip(`<b>${esc(p.id)} · ${esc(p.type)}</b><div class="r"><i style="background:${COLOR[p.sev]}"></i>${p.sev} · ${new Date(p.t).toISOString().slice(0, 19).replace('T', ' ')} UTC</div><div class="r">${esc(data.lanes[p.lane])}</div>`, e.clientX, e.clientY); else tip(null);
    };
    canvas.onmouseleave = () => { hover = null; drag = null; tip(null); draw(); };
    canvas.onmousedown = e => { const [mx] = pos(e); if (mx > left) drag = { x0: mx, x1: mx }; };
    canvas.onmouseup = e => {
      const [mx, my] = pos(e);
      if (drag && Math.abs(drag.x1 - drag.x0) > 6) {
        const a = inv(Math.min(drag.x0, drag.x1)), b = inv(Math.max(drag.x0, drag.x1)); dom = [a, b]; canvas._dom = dom; drag = null; draw(); opts.onZoom && opts.onZoom(true); return;
      }
      drag = null; const p = nearest(mx, my); if (p && opts.onPick) opts.onPick(p.id);
    };
    canvas.ondblclick = () => { dom = full.slice(); canvas._dom = null; draw(); opts.onZoom && opts.onZoom(false); };
    canvas.resetZoom = () => { dom = full.slice(); canvas._dom = null; draw(); opts.onZoom && opts.onZoom(false); };
    draw();
  }

  G.TFCharts = { stackedBars, swimlane, tip, COLOR, SEV };
})(window);
