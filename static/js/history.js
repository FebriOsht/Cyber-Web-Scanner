(function () {
  const KEY = 'cws_history_v1';
  const listEl = document.getElementById('hist-list'), emptyEl = document.getElementById('hist-empty'),
        clearBtn = document.getElementById('hist-clear'), countEl = document.getElementById('hist-count');
  const load = () => { try { const v = JSON.parse(localStorage.getItem(KEY) || '[]'); return Array.isArray(v) ? v : []; } catch (e) { return []; } };
  const save = (l) => { try { localStorage.setItem(KEY, JSON.stringify(l)); } catch (e) {} };
  const gradeClass = g => 'grade-' + (!g || g === 'N/A' ? 'na' : String(g).toLowerCase());
  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }
  function rescan(url) {
    const f = el('form'); f.method = 'post'; f.action = '/scan';
    const i = el('input'); i.type = 'hidden'; i.name = 'url'; i.value = url;
    f.appendChild(i); document.body.appendChild(f); f.submit();
  }
  function render() {
    const list = load();
    listEl.textContent = '';
    countEl.textContent = list.length ? list.length + ' pemindaian tersimpan di browser ini' : '';
    emptyEl.hidden = list.length > 0;
    clearBtn.hidden = list.length === 0;
    list.forEach((s) => {
      const li = el('li');
      const info = el('div', 'info');
      const u = el('div', 'url', s.target || '-'); u.title = s.target || '';
      const c = Array.isArray(s.counts) ? s.counts : [0, 0, 0, 0];
      const skor = (!s.grade || s.grade === 'N/A') ? 'Tidak dinilai' : s.score + ' / 100';
      info.append(u, el('div', 'date', (s.scanned_at || '-') + ' · ' + skor + ' · ' + c[0] + ' kritis, ' + c[1] + ' tinggi, ' + c[2] + ' menengah, ' + c[3] + ' rendah'));
      if (Array.isArray(s.findings) && s.findings.length) {
        const d = el('details');
        d.appendChild(el('summary', null, 'Lihat ' + s.findings.length + ' temuan'));
        const ul = el('ul', 'list');
        s.findings.forEach(f => ul.appendChild(el('li', null, f)));
        d.appendChild(ul);
        info.appendChild(d);
      }
      const act = el('div', 'hist-actions');
      const b1 = el('button', 'btn', 'Pindai ulang'); b1.type = 'button';
      b1.addEventListener('click', () => rescan(s.target));
      const b2 = el('button', 'btn btn-ghost', 'Hapus'); b2.type = 'button';
      b2.addEventListener('click', () => { save(load().filter(x => x.id !== s.id)); render(); });
      act.append(b1, b2);
      li.append(el('div', 'gpill ' + gradeClass(s.grade), s.grade || 'N/A'), info, act);
      listEl.appendChild(li);
    });
  }
  clearBtn.addEventListener('click', () => {
    if (confirm('Hapus semua riwayat di browser ini?')) { localStorage.removeItem(KEY); render(); }
  });
  render();
})();