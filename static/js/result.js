if (window.lucide) lucide.createIcons();
  const btn = document.getElementById('download-pdf');
  if (btn) btn.addEventListener('click', async () => {
    const el = document.getElementById('report');
    const det = el.querySelectorAll('details');
    det.forEach(d => d.open = true);
    const label = btn.innerHTML;
    btn.disabled = true; btn.textContent = 'Menyiapkan PDF...';
    try {
      const canvas = await html2canvas(el, { scale: 2, backgroundColor: '#0b0f14' });
      const { jsPDF } = window.jspdf;
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pw = pdf.internal.pageSize.getWidth(), ph = pdf.internal.pageSize.getHeight();
      const ih = canvas.height * pw / canvas.width, img = canvas.toDataURL('image/png');
      for (let y = 0; y < ih; y += ph) { if (y > 0) pdf.addPage(); pdf.addImage(img, 'PNG', 0, -y, pw, ih); }
      pdf.save('hasil-pemindaian-cyber-web-scanner.pdf');
    } finally {
      det.forEach(d => d.open = false);
      btn.disabled = false; btn.innerHTML = label;
      if (window.lucide) lucide.createIcons();
    }
  });

(function () {
  const el = document.getElementById('scan-meta');
  if (!el) return;
  let meta;
  try { meta = JSON.parse(el.dataset.meta); } catch (e) { return; }
  const KEY = 'cws_history_v1', MAX = 50;
  let list = [];
  try { list = JSON.parse(localStorage.getItem(KEY) || '[]'); if (!Array.isArray(list)) list = []; } catch (e) { list = []; }
  meta.id = (meta.scanned_at || '') + '|' + (meta.target || '');
  if (list.some(x => x.id === meta.id)) return;
  list.unshift(meta);
  try { localStorage.setItem(KEY, JSON.stringify(list.slice(0, MAX))); } catch (e) {}
})();

(function () {
  const metaEl = document.getElementById('scan-meta'), box = document.getElementById('prev-compare');
  if (!metaEl || !box) return;
  let meta, list;
  try { meta = JSON.parse(metaEl.dataset.meta); list = JSON.parse(localStorage.getItem('cws_history_v1') || '[]'); } catch (e) { return; }
  if (!Array.isArray(list)) return;
  const hostOf = (s) => { try { return new URL(s.final_url || s.target).hostname.replace(/^www\./, '').toLowerCase(); } catch (e) { return ''; } };
  const valid = (s) => s.grade && s.grade !== 'N/A';
  const isRisk = (f) => /^Risiko /.test(String(f));
  const keyOf = (f) => String(f).replace(/\([^)]*\)/g, '').replace(/\d+/g, '#').replace(/\s+/g, ' ').trim().toLowerCase();
  const id = (meta.scanned_at || '') + '|' + (meta.target || '');
  const host = hostOf(meta);
  if (!host) return;
  const prev = list.filter((s) => s.id !== id && hostOf(s) === host && String(s.scanned_at) < String(meta.scanned_at))
                   .sort((a, b) => String(b.scanned_at).localeCompare(String(a.scanned_at)))[0];
  if (!prev) return;
  const kn = new Set((meta.findings || []).filter(isRisk).map(keyOf));
  const ko = new Set((prev.findings || []).filter(isRisk).map(keyOf));
  const cspGone = [...kn].some((k) => k.includes('content-security-policy tidak ada'));
  const fixed = [...ko].filter((k) => !kn.has(k) && !(cspGone && k.includes('csp lemah'))).length, added = [...kn].filter((k) => !ko.has(k)).length;
  let txt = 'Dibanding scan sebelumnya (' + prev.scanned_at + ', grade ' + (prev.grade || 'N/A') + '): ';
  if (valid(prev) && valid(meta)) { const d = meta.score - prev.score; txt += 'skor ' + (d > 0 ? '+' + d : d < 0 ? String(d) : '±0') + ', '; }
  txt += fixed + ' temuan diperbaiki, ' + added + ' temuan baru.';
  box.textContent = txt;
  const a = document.createElement('a');
  a.href = '/history#cmp=' + encodeURIComponent(id);
  a.textContent = 'Lihat perbandingan';
  box.appendChild(a);
  box.hidden = false;
})();
