// popup do Cache Poisoning Hunter
'use strict';

function fill(id, items, clsFn) {
  var ul = document.getElementById(id);
  ul.textContent = '';
  if (!items || !items.length) {
    var li = document.createElement('li');
    li.textContent = '—';
    ul.appendChild(li);
    return;
  }
  items.forEach(function (it) {
    var li = document.createElement('li');
    li.textContent = it.msg;
    if (clsFn) li.className = clsFn(it);
    ul.appendChild(li);
  });
}

function load() {
  chrome.runtime.sendMessage({ type: 'cp-get-state' }, function (resp) {
    var st = (resp && resp.state) || null;
    if (!st) {
      document.getElementById('info').textContent = 'sem dados — navegue/recarregue a página do alvo';
      return;
    }
    document.getElementById('info').textContent =
      (st.gate ? (st.gate.keyed ? 'buster KEYED comprovado ✓' : 'buster NÃO comprovado — testes bloqueados') :
        'portão ainda não rodou');
    fill('passivo', st.passivo, function (p) { return p.high ? 'ok' : ''; });
    fill('gate', st.gate ? [{
      msg: 'repeat HIT: ' + st.gate.hit2 + ' · chave nova MISS: ' + st.gate.miss3 +
        ' → keyed: ' + st.gate.keyed
    }] : []);
    fill('testes', st.testes.map(function (t) {
      return {
        msg: (t.cacheado ? 'CONFIRMADO ' : (t.refletido ? 'refletido ' : '')) +
          '[' + t.tipo + '] ' + t.header + (t.ctx ? ' (' + t.ctx + ')' : '') +
          (t.hit ? ' — HIT' : '') + (t.status2 ? ' — status ' + t.status2 : '')
      };
    }), function (t) {
      return t.msg.indexOf('CONFIRMADO') === 0 ? 'ok' : '';
    });
  });
}

document.getElementById('run').addEventListener('click', function () {
  var btn = document.getElementById('run');
  btn.disabled = true;
  btn.textContent = 'rodando... (veja o toast na página)';
  chrome.runtime.sendMessage({ type: 'cp-run' });
  setTimeout(function () {
    btn.disabled = false;
    btn.textContent = '▶ Rodar testes (cache-buster seguro)';
  }, 4000);
});

// modo sniper: roda sozinho ao navegar
chrome.storage.local.get('sniper', function (v) {
  document.getElementById('sniper').checked = !!(v && v.sniper);
});
document.getElementById('sniper').addEventListener('change', function () {
  chrome.storage.local.set({ sniper: this.checked });
});

// copia o report pronto (curl + evidências)
document.getElementById('copy').addEventListener('click', function () {
  chrome.runtime.sendMessage({ type: 'cp-get-state' }, function (resp) {
    var st = (resp && resp.state) || null;
    if (!st || !st.testes || !st.testes.length) {
      navigator.clipboard.writeText('(nada a copiar — rode os testes antes)');
      return;
    }
    var lin = ['# Cache Poisoning — report', 'URL: ' + (st.url || '(pegar do debug)')];
    if (st.gate) lin.push('Buster keyed: ' + (st.gate.keyed ? 'SIM (HIT no repeat + MISS na chave nova)' : 'NAO'));
    st.testes.forEach(function (t) {
      var v = (t.cacheado || t.esi) ? 'CONFIRMADO' : (t.refletido ? 'refletido' : '');
      if (!v) return;
      lin.push(v + ' [' + t.tipo + '] ' + t.header +
        (t.ctx ? ' (' + t.ctx + ')' : '') + (t.hit ? ' HIT' : '') +
        (t.msg ? ' ' + t.msg : '') +
        (t.pocUrl ? '\n  PoC: abrir ' + t.pocUrl + ' (sem o header)' : ''));
    });
    navigator.clipboard.writeText(lin.join('\n'));
    document.getElementById('copy').textContent = '✓ copiado';
    setTimeout(function () { document.getElementById('copy').textContent = '📋 Copiar report'; }, 1500);
  });
});

load();
