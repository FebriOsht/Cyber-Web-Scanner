if (window.lucide) lucide.createIcons();
  const form = document.getElementById('scanForm'), input = document.getElementById('url'),
        btn = document.getElementById('scanBtn'), err = document.getElementById('formError'),
        wait = document.getElementById('waitHint');
  const idle = btn.innerHTML;
  let timer = null;
  form.addEventListener('submit', (e) => {
    const v = input.value.trim();
    input.value = v;
    if (!/^(https?:\/\/)?[^\s\/]+\.[a-z]{2,}([\/?#:].*)?$/i.test(v)) {
      e.preventDefault();
      err.textContent = 'Masukkan URL yang valid, misalnya contoh.com';
      input.focus();
      return;
    }
    err.textContent = '';
    btn.disabled = true; input.readOnly = true; wait.hidden = false;
    btn.innerHTML = '<span class="spin"></span><span>Memindai...</span>';
    let s = 0;
    timer = setInterval(() => { s++; btn.lastChild.textContent = 'Memindai... ' + s + ' dtk'; }, 1000);
  });
  window.addEventListener('pageshow', () => {
    clearInterval(timer);
    btn.disabled = false; input.readOnly = false; wait.hidden = true;
    btn.innerHTML = idle;
    if (window.lucide) lucide.createIcons();
  });
