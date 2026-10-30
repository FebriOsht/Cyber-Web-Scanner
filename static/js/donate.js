(function () {
  if (window.lucide) lucide.createIcons();
  const el = document.getElementById('qr'), addr = el ? el.dataset.addr : '';
  if (el && addr && window.QRCode) {
    new QRCode(el, { text: 'bitcoin:' + addr, width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
  }
  const btn = document.getElementById('copy-addr');
  if (btn) btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(addr);
      const old = btn.innerHTML;
      btn.innerHTML = '<i data-lucide="check"></i> Tersalin';
      if (window.lucide) lucide.createIcons();
      setTimeout(() => { btn.innerHTML = old; if (window.lucide) lucide.createIcons(); }, 2000);
    } catch (e) {
      const r = document.createRange(); r.selectNode(document.getElementById('addr-text'));
      getSelection().removeAllRanges(); getSelection().addRange(r);
    }
  });
})();