(function () {
  const KEY = 'cws_history_v1';
  const $ = (id) => document.getElementById(id);
  const listEl = $('hist-list'), emptyEl = $('hist-empty'), clearBtn = $('hist-clear'), countEl = $('hist-count');
  const cmp = $('compare'), cmpTitle = $('cmp-title'), selA = $('cmp-a'), selB = $('cmp-b'), cmpBody = $('cmp-body');
  let cmpHost = null;

  const load = () => { try { const v = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; } };
  const save = (l) => { try { localStorage.setItem(KEY, JSON.stringify(l)); } catch (e) {} };
  const gradeClass = (g) => 'grade-' + (!g || g === 'N/A' ? 'na' : String(g).toLowerCase());
  const valid = (s) => s.grade && s.grade !== 'N/A';
  const scoreText = (s) => valid(s) ? s.score + ' / 100' : 'Tidak dinilai';
  const label = (s) => (s.scanned_at || '-') + ' · ' + (s.grade || 'N/A') + (valid(s) ? ' (' + s.score + ')' : '');
  const isRisk = (f) => /^Risiko /.test(String(f));
  const keyOf = (f) => String(f).replace(/\([^)]*\)/g, '').replace(/\d+/g, '#').replace(/\s+/g, ' ').trim().toLowerCase();

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function hostOf(s) {
    try { return new URL(s.final_url || s.target).hostname.replace(/^www\./, '').toLowerCase(); }
    catch (e) { return String(s.target || '').replace(/^https?:\/\//, '').replace(/^www\./, '').split(/[\/?#:]/)[0].toLowerCase(); }
  }
  function scansOfHost(host) {
    return load().filter((s) => hostOf(s) === host).sort((a, b) => String(b.scanned_at).localeCompare(String(a.scanned_at)));
  }
  function rescan(url) {
    const f = el('form'); f.method = 'post'; f.action = '/scan';
    const i = el('input'); i.type = 'hidden'; i.name = 'url'; i.value = url;
    f.appendChild(i); document.body.appendChild(f); f.submit();
  }
  function delta(n, lowerIsBetter) {
    const d = el('span', 'delta');
    if (!n) { d.textContent = '±0'; d.classList.add('d-same'); return d; }
    const good = lowerIsBetter ? n < 0 : n > 0;
    d.textContent = (n > 0 ? '+' : '') + n;
    d.classList.add(good ? 'd-up' : 'd-down');
    return d;
  }
  function side(s, cap) {
    const w = el('div', 'cmp-side'), t = el('div');
    t.append(el('div', 'cmp-cap', cap), el('div', null, scoreText(s)), el('div', 'date', s.scanned_at || '-'));
    w.append(el('div', 'gpill ' + gradeClass(s.grade), s.grade || 'N/A'), t);
    return w;
  }
  function block(title, items, kind, emptyText) {
    const w = el('div', 'cmp-block');
    w.appendChild(el('h3', null, title + ' (' + items.length + ')'));
    if (!items.length) { w.appendChild(el('p', 'note', emptyText)); return w; }
    const ul = el('ul', 'rows');
    items.forEach((f) => {
      const m = String(f).match(/^Risiko ([^:]+):\s*(.*)$/);
      const li = el('li'), top = el('div', 'top');
      top.append(el('span', null, m ? m[2] : f), el('span', 'badge b-' + kind, m ? m[1] : 'Info'));
      li.appendChild(top); ul.appendChild(li);
    });
    w.appendChild(ul);
    return w;
  }
  function renderCompare() {
    const scans = scansOfHost(cmpHost);
    const a0 = scans.find((s) => s.id === selA.value), b0 = scans.find((s) => s.id === selB.value);
    cmpBody.textContent = '';
    if (!a0 || !b0) return;
    if (a0.id === b0.id) { cmpBody.appendChild(el('p', 'note', 'Pilih dua scan yang berbeda.')); return; }
    const pair = String(a0.scanned_at) <= String(b0.scanned_at) ? [a0, b0] : [b0, a0];
    const oldS = pair[0], newS = pair[1];

    const sum = el('div', 'cmp-sum');
    sum.append(side(oldS, 'Sebelumnya'), el('div', 'cmp-arrow', '→'), side(newS, 'Terbaru'));
    if (valid(oldS) && valid(newS)) {
      const d = el('div', 'cmp-delta');
      d.append(el('span', 'cmp-cap', 'Perubahan skor'), delta(newS.score - oldS.score, false));
      sum.appendChild(d);
    }
    cmpBody.appendChild(sum);
    if (!(valid(oldS) && valid(newS))) cmpBody.appendChild(el('p', 'note', 'Salah satu scan tidak valid, sehingga perubahan skor tidak dihitung.'));

    const names = ['Kritis', 'Tinggi', 'Menengah', 'Rendah'];
    const co = oldS.counts || [0, 0, 0, 0], cn = newS.counts || [0, 0, 0, 0];
    const grid = el('div', 'counts cmp-counts');
    names.forEach((n, i) => {
      const c = el('div', 'count');
      c.append(el('b', null, String(cn[i])), el('span', null, n), delta(cn[i] - co[i], true));
      grid.appendChild(c);
    });
    cmpBody.appendChild(grid);

    const fo = (oldS.findings || []).filter(isRisk), fn = (newS.findings || []).filter(isRisk);
    const ko = new Set(fo.map(keyOf)), kn = new Set(fn.map(keyOf));
    cmpBody.append(
      block('Sudah diperbaiki', fo.filter((f) => !kn.has(keyOf(f))), 'pass', 'Tidak ada temuan yang hilang.'),
      block('Temuan baru', fn.filter((f) => !ko.has(keyOf(f))), 'fail', 'Tidak ada temuan baru.'),
      block('Masih ada', fn.filter((f) => ko.has(keyOf(f))), 'info', 'Tidak ada temuan yang tersisa dari scan sebelumnya.')
    );
    cmpBody.appendChild(el('p', 'note', 'Temuan dicocokkan berdasarkan jenisnya; angka dan detail dalam kurung diabaikan agar perubahan kecil tidak dianggap temuan baru.'));
  }
  function openCompare(s) {
    cmpHost = hostOf(s);
    const scans = scansOfHost(cmpHost);
    selA.textContent = ''; selB.textContent = '';
    scans.forEach((x) => { selA.appendChild(new Option(label(x), x.id)); selB.appendChild(new Option(label(x), x.id)); });
    const idx = scans.findIndex((x) => x.id === s.id);
    selB.value = s.id;
    selA.value = (scans[idx + 1] || scans[idx - 1] || s).id;
    cmpTitle.textContent = 'Perbandingan: ' + cmpHost;
    cmp.hidden = false;
    renderCompare();
    cmp.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function closeCompare() { cmp.hidden = true; cmpHost = null; }
  function render() {
    const list = load();
    const perHost = {};
    list.forEach((s) => { const h = hostOf(s); perHost[h] = (perHost[h] || 0) + 1; });
    listEl.textContent = '';
    countEl.textContent = list.length ? list.length + ' pemindaian tersimpan di browser ini' : '';
    emptyEl.hidden = list.length > 0;
    clearBtn.hidden = list.length === 0;
    list.forEach((s) => {
      const li = el('li'), info = el('div', 'info');
      const u = el('div', 'url', s.target || '-'); u.title = s.target || '';
      const c = Array.isArray(s.counts) ? s.counts : [0, 0, 0, 0];
      info.append(u, el('div', 'date', (s.scanned_at || '-') + ' · ' + scoreText(s) + ' · ' + c[0] + ' kritis, ' + c[1] + ' tinggi, ' + c[2] + ' menengah, ' + c[3] + ' rendah'));
      if (Array.isArray(s.findings) && s.findings.length) {
        const d = el('details');
        d.appendChild(el('summary', null, 'Lihat ' + s.findings.length + ' temuan'));
        const ul = el('ul', 'list');
        s.findings.forEach((f) => ul.appendChild(el('li', null, f)));
        d.appendChild(ul);
        info.appendChild(d);
      }
      const act = el('div', 'hist-actions');
      if (perHost[hostOf(s)] > 1) {
        const b0 = el('button', 'btn', 'Bandingkan'); b0.type = 'button';
        b0.addEventListener('click', () => openCompare(s));
        act.appendChild(b0);
      }
      const b1 = el('button', 'btn', 'Pindai ulang'); b1.type = 'button';
      b1.addEventListener('click', () => rescan(s.target));
      const b2 = el('button', 'btn btn-ghost', 'Hapus'); b2.type = 'button';
      b2.addEventListener('click', () => { save(load().filter((x) => x.id !== s.id)); closeCompare(); render(); });
      act.append(b1, b2);
      li.append(el('div', 'gpill ' + gradeClass(s.grade), s.grade || 'N/A'), info, act);
      listEl.appendChild(li);
    });
  }

  selA.addEventListener('change', renderCompare);
  selB.addEventListener('change', renderCompare);
  $('cmp-close').addEventListener('click', closeCompare);
  clearBtn.addEventListener('click', () => {
    if (confirm('Hapus semua riwayat di browser ini?')) { localStorage.removeItem(KEY); closeCompare(); render(); }
  });
  render();
  const hm = location.hash.match(/^#cmp=(.+)$/);
  if (hm) {
    const target = load().find((x) => x.id === decodeURIComponent(hm[1]));
    if (target && scansOfHost(hostOf(target)).length > 1) openCompare(target);
  }
})();