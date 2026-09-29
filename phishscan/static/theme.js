/* Applied before first paint so the saved theme never flashes. */
(function () {
  try {
    var t = localStorage.getItem('ps-theme');
    if (t === 'dark' || t === 'light') document.documentElement.dataset.theme = t;
  } catch (e) { /* storage blocked: follow the system theme */ }
})();
