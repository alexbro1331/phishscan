/* PhishScan console behavior. Plain JavaScript, no dependencies. Every page still works for reading without it. */
(function () {
  'use strict';
  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var reduceMotion = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var csrf = function () { var m = $('meta[name=csrf-token]'); return m ? m.content : ''; };
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };

  /* ---- toasts ---- */
  function toast(msg) {
    var box = $('#toasts'); if (!box) return;
    var t = document.createElement('div'); t.className = 'toast'; t.textContent = msg; box.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(function () { t.remove(); }, 320); }, 2600);
  }

  /* ---- theme ---- */
  $$('[data-theme-toggle]').forEach(function (b) {
    b.addEventListener('click', function () {
      var cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      var next = cur === 'dark' ? 'light' : 'dark';
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem('ps-theme', next); } catch (e) { /* ignore */ }
    });
  });

  /* ---- count-up numbers ---- */
  $$('[data-count]').forEach(function (el) {
    var to = Number(el.dataset.count);
    if (reduceMotion || !isFinite(to) || to <= 0) return;
    var t0 = performance.now(), dur = 900;
    el.textContent = '0';
    (function tick(t) {
      var p = Math.min(1, (t - t0) / dur);
      el.textContent = String(Math.round(to * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick); else el.textContent = String(to);
    })(t0);
  });

  /* ---- relative times ---- */
  function ago(iso) {
    var s = (Date.now() - Date.parse(iso)) / 1000;
    if (!isFinite(s) || s < 0) return '';
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + ' min ago';
    if (s < 86400) return Math.floor(s / 3600) + ' h ago';
    if (s < 86400 * 14) return Math.floor(s / 86400) + ' d ago';
    return '';
  }
  $$('time[data-ago]').forEach(function (t) {
    var a = ago(t.getAttribute('datetime'));
    if (a) { t.title = t.textContent; t.textContent = a; }
  });

  /* ---- rows, copy, dialogs, small helpers ---- */
  $$('tr[data-href]').forEach(function (tr) {
    tr.addEventListener('click', function (e) { if (!e.target.closest('a,button,input,select')) location.href = tr.dataset.href; });
  });
  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-copy]'); if (!b) return;
    var text = b.dataset.copy;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(
      function () { toast('Copied to clipboard'); }, function () { toast('Copy is not available here'); });
  });
  $$('[data-open-dialog]').forEach(function (b) {
    b.addEventListener('click', function () { var d = document.getElementById(b.dataset.openDialog); if (d && d.showModal) d.showModal(); });
  });
  $$('[data-close-dialog]').forEach(function (b) { b.addEventListener('click', function () { b.closest('dialog').close(); }); });
  $$('select[data-autosubmit]').forEach(function (s) { s.addEventListener('change', function () { s.form.submit(); }); });
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName)) {
      var s = $('[data-search]'); if (s) { e.preventDefault(); s.focus(); }
    }
  });
  var qs = new URLSearchParams(location.search);
  if (qs.get('dup')) toast('Already analyzed. Showing the existing case.');
  if (qs.get('deleted')) toast('Case deleted');
  if (qs.get('purged')) toast('All cases deleted');
  if (qs.get('seeded')) toast('Demo data loaded');

  /* ---- JSON posts (status, notes) ---- */
  function postJSON(url, data) {
    return fetch(url, { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'X-CSRF-Token': csrf() },
      body: JSON.stringify(data) });
  }
  $$('select[data-status]').forEach(function (sel) {
    var prev = sel.value;
    sel.addEventListener('change', function () {
      postJSON('/cases/' + sel.dataset.case + '/status', { status: sel.value }).then(function (r) {
        if (r.ok) { prev = sel.value; toast('Status updated'); } else { sel.value = prev; toast('Could not update status'); }
      }, function () { sel.value = prev; toast('Could not reach the server'); });
    });
  });
  $$('textarea[data-notes]').forEach(function (ta) {
    var saved = $('#saved'), timer;
    ta.addEventListener('input', function () {
      if (saved) saved.textContent = 'Editing…';
      clearTimeout(timer);
      timer = setTimeout(function () {
        if (saved) saved.textContent = 'Saving…';
        postJSON('/cases/' + ta.dataset.case + '/notes', { notes: ta.value }).then(function (r) {
          if (saved) saved.textContent = r.ok ? 'Saved' : 'Not saved';
        }, function () { if (saved) saved.textContent = 'Not saved'; });
      }, 700);
    });
  });

  /* ---- analysis: overlay + upload ---- */
  var overlay = $('#scan'), stepsEl = $('#scan-steps'), errEl = $('#scan-err'), closeRow = $('#scan-close');
  var STEPS = ['Reading headers and message structure', 'Checking SPF, DKIM and DMARC',
    'Extracting links, addresses and attachments', 'Looking for look-alikes and disguised links', 'Scoring and building the report'];
  var ticker;
  function showScan() {
    if (!overlay) return;
    stepsEl.innerHTML = ''; errEl.hidden = true; closeRow.hidden = true;
    STEPS.forEach(function (s) { var li = document.createElement('li'); li.textContent = s; stepsEl.appendChild(li); });
    var items = $$('li', stepsEl), i = 0;
    items[0].className = 'active';
    overlay.classList.add('show');
    clearInterval(ticker);
    ticker = setInterval(function () {
      if (i < items.length - 1) { items[i].className = 'done'; i++; items[i].className = 'active'; }
    }, reduceMotion ? 250 : 420);
  }
  function finishScan() { clearInterval(ticker); $$('li', stepsEl).forEach(function (li) { li.className = 'done'; }); }
  function failScan(msg) {
    clearInterval(ticker); $$('li.active', stepsEl).forEach(function (li) { li.className = ''; });
    errEl.textContent = msg; errEl.hidden = false; closeRow.hidden = false;
  }
  var closeBtn = $('[data-scan-close]');
  if (closeBtn) closeBtn.addEventListener('click', function () { overlay.classList.remove('show'); });

  function analyze(url, formData) {
    formData.set('csrf_token', csrf());
    showScan();
    var started = Date.now();
    return fetch(url, { method: 'POST', body: formData, credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json().catch(function () { return { error: 'The server sent an unexpected response.' }; }).then(function (d) { return [r, d]; }); })
      .then(function (rd) {
        var r = rd[0], d = rd[1];
        return sleep(Math.max(0, 1300 - (Date.now() - started))).then(function () {
          if (r.ok && d.id) { finishScan(); return sleep(260).then(function () { location.href = '/cases/' + d.id + (d.duplicate ? '?dup=1' : ''); }); }
          failScan(d.error || 'Something went wrong. Nothing was saved.');
        });
      }, function () { failScan('Could not reach the server. Check your connection and try again.'); });
  }

  $$('form[data-scan]').forEach(function (f) {
    f.addEventListener('submit', function (e) { e.preventDefault(); analyze(f.action, new FormData(f)); });
  });
  $$('[data-dropzone]').forEach(function (zone) {
    var input = $('[data-file]', zone);
    function send(file) {
      if (!file) return;
      var fd = new FormData(); fd.append('eml', file); analyze('/analyze', fd);
    }
    if (input) input.addEventListener('change', function () { send(input.files[0]); input.value = ''; });
    ['dragenter', 'dragover'].forEach(function (ev) { zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('over'); }); });
    zone.addEventListener('drop', function (e) { send(e.dataTransfer && e.dataTransfer.files[0]); });
  });
  /* a missed drop must not make the browser navigate away to the raw file */
  ['dragover', 'drop'].forEach(function (ev) { window.addEventListener(ev, function (e) { e.preventDefault(); }); });
})();
