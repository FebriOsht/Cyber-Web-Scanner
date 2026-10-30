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
