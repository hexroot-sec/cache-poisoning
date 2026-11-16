// Cache Poisoning Hunter — background (MV3 service worker).
// Guarda o estado por aba (passivo/portão/testes), badge e responde ao popup.
'use strict';

var store = {}; // tabId -> state

function badge(tabId) {
  var st = store[tabId];
  if (!st) return;
  var conf = (st.state && st.state.testes || []).filter(function (t) { return t.cacheado; }).length;
  var text, color;
  if (conf) { text = 'POC!'; color = '#15803d'; }
  else if (st.state && st.state.gate && !st.state.gate.keyed) { text = 'BLQ'; color = '#b91c1c'; }
  else if (st.state && st.state.passivo.some(function (p) { return p.high; })) { text = 'CACHE'; color = '#b45309'; }
  else { text = 'OK'; color = '#475569'; }
  try {
    chrome.action.setBadgeText({ tabId: tabId, text: text });
    chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: color });
  } catch (e) {}
}

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || !msg.type) return;

  if (msg.type === 'cp-result' && sender.tab && sender.tab.id >= 0) {
    store[sender.tab.id] = { state: msg.state };
    badge(sender.tab.id);
  }

  if (msg.type === 'cp-get-state') {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tabId = tabs[0] && tabs[0].id;
      if (tabId >= 0 && store[tabId]) {
        sendResponse({ state: store[tabId].state });
        return;
      }
      // popup aberto como ABA: usa a última aba http com dados
      chrome.tabs.query({}, function (all) {
        for (var i = all.length - 1; i >= 0; i--) {
          if (/^https?:/.test(all[i].url || '') && store[all[i].id]) {
            sendResponse({ state: store[all[i].id].state });
            return;
          }
        }
        sendResponse({ state: (tabId >= 0 && store[tabId] && store[tabId].state) || null });
      });
    });
    return true;
  }

  if (msg.type === 'cp-run') {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tabId = tabs[0] && tabs[0].id;
      var send = function (id) {
        chrome.tabs.sendMessage(id, { type: 'cp-run' }, function () {
          void chrome.runtime.lastError;
        });
      };
      if (tabId >= 0 && /^https?:/.test(tabs[0].url || '')) {
        send(tabId);
        return;
      }
      // popup aberto como ABA: mira a última aba http
      chrome.tabs.query({}, function (all) {
        for (var i = all.length - 1; i >= 0; i--) {
          if (/^https?:/.test(all[i].url || '')) { send(all[i].id); return; }
        }
      });
    });
  }
});

chrome.tabs.onRemoved.addListener(function (tabId) { delete store[tabId]; });
chrome.tabs.onUpdated.addListener(function (tabId, info) {
  if (info.status === 'loading') { delete store[tabId]; badge(tabId); }
});
