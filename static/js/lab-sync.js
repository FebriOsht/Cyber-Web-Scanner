// Saat dibuka di dalam bingkai lab.vulpfest.com, beri tahu Lab alamat halaman saat ini,
// supaya kolom alamat browser ikut berubah (misalnya lab.vulpfest.com/scanner/docs).
(function () {
  if (window.parent === window) return;
  try {
    window.parent.postMessage({ type: "lab:path", path: location.pathname + location.search }, "https://lab.vulpfest.com");
  } catch (e) {}
})();
