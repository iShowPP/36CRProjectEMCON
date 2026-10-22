import { send, $, esc } from './msg.js';

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
let url = null;
try { url = new URL(tab.url); } catch { /* chrome:// etc. */ }
const domain = url && /^https?:$/.test(url.protocol) ? url.hostname.replace(/^www\./, '') : null;
$('#host').textContent = domain || '';

document.querySelectorAll('.tabs button').forEach((b) => (b.onclick = () => {
  document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('on', x === b));
  document.querySelectorAll('section').forEach((s) => s.classList.toggle('hidden', s.id !== 'tab-' + b.dataset.tab));
}));

// ---------- This site ----------
const LEVEL = { danger: ['bad', '⛔ Dangerous'], caution: ['warn', '⚠️ Be careful'], trusted: ['ok', '✅ Trusted by your network'], unknown: ['', '• No warning signs found'] };
async function renderVerdict() {
  const v = await send({ type: 'wot:tab', tabId: tab.id }).catch(() => null);
  if (!v) return;
  const [cls, label] = LEVEL[v.level];
  $('#verdict').innerHTML = `<div class="level ${cls}">${label}</div>
    <div class="small muted">Risk ${v.risk}/100 · ${esc(v.domain)}</div>
    <ul class="small">${v.signals.map((s) => `<li>${s.pts > 0 ? '🔺' : s.pts < 0 ? '🔻' : '•'} ${esc(s.text)}</li>`).join('') || '<li>Nothing notable.</li>'}</ul>
    ${v.evidence.length ? `<div class="small"><b>Evidence from your web of trust</b>${v.evidence.map((e) => `<div>${e.verdict === 'scam' ? '🚩' : '👍'} weight ${e.weight} · ${e.hops} hop(s) · ${esc(e.note)}</div>`).join('')}</div>` : ''}`;
}
renderVerdict();

async function attest(verdict) {
  if (!domain) return;
  try {
    await send({ type: 'wot:attest', domain, verdict, transacted: verdict === 'trusted' });
    $('#attMsg').textContent = '✅ Signed and published. Reload to re-score.';
  } catch (e) { $('#attMsg').textContent = '⚠️ ' + e.message; }
}
$('#attGood').onclick = () => attest('trusted');
$('#attScam').onclick = () => attest('scam');
if (!domain) $('#attGood').disabled = $('#attScam').disabled = true;

// ---------- Ghost ----------
async function renderGhost() {
  const g = await send({ type: 'ghost:status' }).catch((e) => ({ error: e.message }));
  if (g.error) { $('#ghost').textContent = '⚠️ ' + g.error; return; }
  if (!g.enrolled) {
    $('#ghost').innerHTML = `<h2>👻 Ghost identities</h2><p class="small">Verify once, then sign up anywhere as a different, unlinkable "ghost" that can still prove you're a real adult.</p><button class="primary" id="setup">Set up Ghost</button>`;
    $('#setup').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/setup.html') });
    return;
  }
  const sites = Object.entries(g.sites);
  $('#ghost').innerHTML = `<h2>👻 Ghost is active <span class="chip">${g.unlock === 'passkey' ? 'passkey' : 'PIN'} unlock</span></h2>
    <div class="small">Humanity tokens: ${g.bundles.map((b) => `<span class="chip">${esc(b)}: ${g.tokens[b]}</span>`).join(' ')}</div>
    <div class="small muted">Pinned issuer keys: ${Object.entries(g.pinnedKeys).map(([b, k]) => `${esc(b)}=${esc(k)}`).join(', ')}</div>
    <div class="row" style="margin:8px 0">${g.bundles.map((b) => `<button data-refill="${esc(b)}">Refill ${esc(b)}</button>`).join('')}</div>
    <h2 style="margin-top:8px">Your site identities</h2>
    ${sites.length ? sites.map(([o, s]) => `<div class="small row"><span style="flex:1"><b>${esc(o)}</b><br><span class="mono">${esc(s.pseudonym)}…</span> · ${esc(s.claims.join(', '))}</span><button data-reset="${esc(o)}" title="Start over with a brand-new pseudonym">New identity</button></div>`).join('') : '<div class="small muted">None yet.</div>'}
    <div id="gMsg" class="small"></div>`;
  document.querySelectorAll('[data-refill]').forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    try { await send({ type: 'ghost:refill', bundle: b.dataset.refill }); renderGhost(); } catch (e) { $('#gMsg').textContent = '⚠️ ' + e.message; b.disabled = false; }
  }));
  document.querySelectorAll('[data-reset]').forEach((b) => (b.onclick = async () => { await send({ type: 'ghost:reset-site', origin: b.dataset.reset }); renderGhost(); }));
}
renderGhost();

// ---------- Trust ----------
async function renderTrust() {
  const { did, roots } = await send({ type: 'wot:me' });
  $('#myDid').textContent = did;
  $('#copyDid').onclick = () => navigator.clipboard.writeText(did);
  $('#roots').innerHTML = roots.length ? roots.map((r) => `<div class="row" style="padding:4px 0"><span style="flex:1">${r.kind === 'group' ? '🛡️' : '🧑'} <b>${esc(r.label)}</b> · trust ${r.weight}<br><span class="mono muted">${esc(r.did.slice(0, 32))}…</span></span><button data-untrust="${esc(r.did)}">Remove</button></div>`).join('') : '<span class="muted">Nobody yet.</span>';
  document.querySelectorAll('[data-untrust]').forEach((b) => (b.onclick = async () => { await send({ type: 'wot:untrust', did: b.dataset.untrust }); renderTrust(); }));
}
$('#tAdd').onclick = async () => {
  try {
    await send({ type: 'wot:trust', did: $('#tDid').value.trim(), label: $('#tLabel').value, weight: $('#tWeight').value, publish: $('#tPublish').checked });
    $('#tMsg').textContent = '✅ Added.'; $('#tDid').value = ''; renderTrust();
  } catch (e) { $('#tMsg').textContent = '⚠️ ' + e.message; }
};
renderTrust();

// ---------- Settings ----------
const s = await send({ type: 'settings:get' });
for (const k of ['farble', 'provenance', 'provRecovery', 'wot']) {
  $('#s_' + k).checked = s[k];
  $('#s_' + k).onchange = (e) => send({ type: 'settings:set', patch: { [k]: e.target.checked } });
}
$('#s_exception').checked = !!(domain && s.farbleExceptions.includes(url.hostname));
$('#s_exception').disabled = !domain;
$('#s_exception').onchange = async (e) => {
  const cur = (await send({ type: 'settings:get' })).farbleExceptions.filter((h) => h !== url.hostname);
  send({ type: 'settings:set', patch: { farbleExceptions: e.target.checked ? [...cur, url.hostname] : cur } });
};
$('#s_server').value = s.server;
$('#s_server').onchange = (e) => send({ type: 'settings:set', patch: { server: e.target.value.replace(/\/+$/, '') } });
