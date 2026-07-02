(function () {
  'use strict';
  var SESSION_KEY = 'huddle-session-v1';
  var SO = '<scr' + 'ipt>';
  var SC = '</scr' + 'ipt>';

  var payloads;
  try {
    payloads = JSON.parse(document.getElementById('payloads').textContent);
  } catch (e) { payloads = null; }

  var gate = document.getElementById('gate');
  var app = document.getElementById('app');
  var form = document.getElementById('gate-form');
  var errBox = document.getElementById('gate-err');
  var btn = document.getElementById('gate-btn');

  function err(msg) {
    errBox.textContent = msg;
    errBox.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Sign in →';
  }

  if (!window.crypto || !crypto.subtle) {
    err('This browser cannot decrypt the site (WebCrypto unavailable). Please use a current version of Edge, Chrome, Firefox, or Safari.');
    return;
  }
  if (!payloads) { err('Site payload failed to load. Please contact Matt Johnson.'); return; }

  /* ---------- crypto helpers ---------- */
  function b64ToBuf(b64) {
    var bin = atob(b64);
    var buf = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf;
  }
  function bufToB64(buf) {
    var bytes = new Uint8Array(buf), bin = '';
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function sha256Hex(str) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(function (h) {
      return Array.prototype.map.call(new Uint8Array(h), function (b) {
        return ('0' + b.toString(16)).slice(-2);
      }).join('');
    });
  }
  function deriveKey(u, p, saltB64, iters) {
    return crypto.subtle.importKey('raw', new TextEncoder().encode(u + ':' + p), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return crypto.subtle.deriveKey(
          { name: 'PBKDF2', salt: b64ToBuf(saltB64), iterations: iters, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']
        );
      });
  }
  function importKey(rawB64) {
    return crypto.subtle.importKey('raw', b64ToBuf(rawB64), { name: 'AES-GCM' }, true, ['decrypt']);
  }
  function decrypt(key, ivB64, ctB64) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(ivB64) }, key, b64ToBuf(ctB64))
      .then(function (pt) { return new TextDecoder().decode(pt); });
  }

  /* ---------- unlock flow ---------- */
  function unlockWithKey(key, rec, manual) {
    var personal;
    return decrypt(key, rec.iv, rec.ct)
      .then(function (json) {
        personal = JSON.parse(json);
        return importKey(personal.siteKey);
      })
      .then(function (siteKey) {
        return decrypt(siteKey, payloads.common.iv, payloads.common.ct);
      })
      .then(function (commonJson) {
        var common = JSON.parse(commonJson);
        if (manual) {
          /* fresh sign-in always opens on Start Here */
          try { history.replaceState(null, '', '#home'); } catch (e) { location.hash = 'home'; }
        }
        render(common.src, personal);
        return crypto.subtle.exportKey('raw', key).then(function (raw) {
          try {
            localStorage.setItem(SESSION_KEY, JSON.stringify({ uh: rec._uh, k: bufToB64(raw) }));
          } catch (e) {}
        });
      });
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function render(src, personal) {
    var navHtml = src.slice(src.indexOf('<nav'), src.indexOf('</nav>') + 6);
    var mainHtml = src.slice(src.indexOf('<main'), src.indexOf('</main>') + 7);
    var footHtml = src.slice(src.indexOf('<footer'), src.indexOf('</footer>') + 9);
    var jsStart = src.lastIndexOf(SO);
    var siteJs = src.slice(jsStart + SO.length, src.lastIndexOf(SC));

    app.innerHTML = navHtml + mainHtml + footHtml;

    /* ---- For You page ---- */
    var isAdmin = personal.panels.length > 1;
    var panelsHtml = personal.panels.map(function (p, i) {
      var head = '';
      if (isAdmin && i > 0) head = '<hr class="fy-divider"><p class="fy-owner">' + escapeHtml(p.label || p.owner) + '</p>';
      return head + p.html;
    }).join('\n');

    var heroSub = isAdmin
      ? 'Admin view: every personalized panel on the site, exactly as each person sees it.'
      : 'This page was written for you specifically. It is the part of the site that changes based on who signs in, and your answers here land in the same feedback compiler as the rest of the site.';

    var fyPage = document.createElement('div');
    fyPage.className = 'page';
    fyPage.id = 'page-foryou';
    fyPage.innerHTML =
      '<header class="hero"><div class="wrap">' +
      '<p class="hero-kicker">For You</p>' +
      '<h1>For ' + escapeHtml(personal.first) + '</h1>' +
      '<p class="tagline">' + heroSub + '</p>' +
      '</div></header><div class="wrap">' + panelsHtml + '</div>';
    app.querySelector('main').appendChild(fyPage);

    var fyTab = document.createElement('button');
    fyTab.className = 'nav-tab';
    fyTab.setAttribute('data-page', 'foryou');
    fyTab.textContent = isAdmin ? 'All Panels' : 'For ' + personal.first;
    var tabs = app.querySelector('.nav-tabs');
    tabs.insertBefore(fyTab, tabs.querySelector('[data-page="feedback"]'));

    /* ---- signed-in indicator ---- */
    var out = document.createElement('button');
    out.className = 'nav-signout';
    out.textContent = personal.first + ' · Sign out';
    out.addEventListener('click', function () {
      try { localStorage.removeItem(SESSION_KEY); } catch (e) {}
      location.reload();
    });
    app.querySelector('.nav-inner').appendChild(out);

    /* ---- hand off to the site ---- */
    window.HUDDLE = { user: { u: personal.u, first: personal.first, name: personal.name, title: personal.title } };
    gate.style.display = 'none';
    app.style.display = 'block';
    try {
      new Function(siteJs)();
    } catch (e) {
      /* site must still be readable even if interactivity fails */
      if (window.console) console.error(e);
    }
  }

  /* ---------- login ---------- */
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    errBox.style.display = 'none';
    var u = document.getElementById('gate-u').value.trim().toLowerCase();
    var p = document.getElementById('gate-p').value.trim().toLowerCase();
    if (!u || !p) { err('Enter both your username and password.'); return; }
    btn.disabled = true;
    btn.textContent = 'Unlocking…';
    sha256Hex(u).then(function (uh) {
      var rec = payloads.users[uh];
      if (!rec) throw new Error('bad');
      rec._uh = uh;
      return deriveKey(u, p, rec.salt, payloads.kdf.iters).then(function (key) {
        return unlockWithKey(key, rec, true);
      });
    }).catch(function () {
      err("That username and password combination didn't work. Credentials aren't case-sensitive. If you're stuck, contact Matt.");
    });
  });

  /* ---------- auto-login from saved session ---------- */
  (function tryResume() {
    var saved = null;
    try { saved = JSON.parse(localStorage.getItem(SESSION_KEY)); } catch (e) {}
    if (!saved || !saved.uh || !saved.k || !payloads.users[saved.uh]) return;
    var rec = payloads.users[saved.uh];
    rec._uh = saved.uh;
    importKey(saved.k).then(function (key) {
      return unlockWithKey(key, rec);
    }).catch(function () {
      try { localStorage.removeItem(SESSION_KEY); } catch (e) {}
    });
  })();
})();
