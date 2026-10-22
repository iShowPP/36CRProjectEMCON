import { send, $, esc } from './msg.js';

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
let url = null;
try { url = new URL(tab.url); } catch { /* chrome:// etc. */ }
const domain = url && /^https?:$/.test(url.protocol) ? url.hostname.replace(/^www\./, '') : null;
$('#host').textContent = domain || '';

document.querySelectorAll('nav button').forEach((b) => (b.onclick = () => {
  document.querySelectorAll('nav button').forEach((x) => x.classList.toggle('on', x === b));
  document.querySelectorAll('main > section').forEach((s) => s.classList.toggle('hidden', s.id !== 'tab-' + b.dataset.tab));
  if (b.dataset.tab === 'privacy') renderPrivacy();
}));

const STATUS = { found: 'Found', unknown: 'Unknown', good: 'Good', note: 'Note', clear: 'Clear', na: 'N/A', kept: 'Kept', broken: 'Broken', untested: 'Untested' };
const ORDER = { found: 0, unknown: 1, good: 2, note: 3, clear: 4, na: 5 };
const evRows = (rows) => `<ol class="ev">${rows.map((r) => `<li class="${r.status}"><span class="tag">${STATUS[r.status] || r.status}</span><div><b>${esc(r.label)}</b><span class="d">${esc(r.detail)}</span></div></li>`).join('')}</ol>`;

// ---------- This site ----------
const HEAD = { danger: 'Very likely a scam', caution: 'Be careful here', trusted: 'Trusted by your network', unknown: 'No warning signs found' };
function renderVerdict(v) {
  if (!v) return;
  const rows = [...v.checks].sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  $('#verdict').innerHTML = `
    <div class="kicker">Verdict · risk ${v.risk}/100</div>
    <h1 class="${v.level === 'danger' ? 'bad' : v.level === 'caution' ? 'warn' : v.level === 'trusted' ? 'ok' : ''}">${HEAD[v.level]}</h1>
    <div class="meter ${v.level}"><i style="width:${Math.max(2, v.risk)}%"></i></div>
    <p class="small muted" style="margin:6px 0 10px">${rows.length} checks on ${esc(v.domain)}. Each row is a deterministic check or a signed report; the score is the sum of the points shown in the receipt.</p>
    ${evRows(rows)}
    ${v.chain?.length > 1 ? `<div class="kicker" style="margin-top:12px">How you got here</div><div class="chainline">${v.chain.map((h, i) => `${i ? ` <i>→ ${esc(h.via)} →</i> ` : ''}${esc(h.label || h.host)}`).join('')}</div>` : ''}`;
}
renderVerdict(await send({ type: 'wot:tab', tabId: tab.id }).catch(() => null));

$('#msgGo').onclick = async () => {
  $('#msgOut').textContent = 'Checking…';
  try {
    const v = await send({ type: 'chain:message', tabId: tab.id, text: $('#msg').value });
    if (v) { renderVerdict(v); $('#msgOut').textContent = 'Updated.'; } else $('#msgOut').textContent = 'Saved. Reload the page to re-check.';
  } catch (e) { $('#msgOut').textContent = e.message; }
};
$('#receipt').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL(`pages/receipt.html?tab=${tab.id}`) });

async function attest(verdict) {
  if (!domain) return;
  try {
    await send({ type: 'wot:attest', domain, verdict, transacted: verdict === 'trusted' });
    $('#attMsg').textContent = 'Signed with your key and published. Reload to re-check.';
  } catch (e) { $('#attMsg').textContent = e.message; }
}
$('#attGood').onclick = () => attest('trusted');
$('#attScam').onclick = () => attest('scam');
if (!domain) $('#attGood').disabled = $('#attScam').disabled = $('#receipt').disabled = true;

// ---------- Privacy ----------
async function renderPrivacy() {
  const p = await send({ type: 'privacy:tab', tabId: tab.id }).catch(() => null);
  if (!p) return;
  const promiseRows = p.promises.map((x) => ({ status: x.status, label: `${x.text} (${x.source})`, detail: x.evidence }));
  $('#privacy').innerHTML = `
    <div class="kicker">Observed on ${esc(p.host)} since ${new Date(p.since).toLocaleTimeString()}</div>
    <div class="stats">
      <div><div class="num">${p.thirdPartyCount}</div><div class="small muted">third-party domains</div></div>
      <div><div class="num ${p.trackerCount ? 'bad' : ''}">${p.trackerCount}</div><div class="small muted">known trackers</div></div>
      <div><div class="num ${p.features.some((f) => f.fingerprinting) ? 'warn' : ''}">${p.features.length}</div><div class="small muted">sensitive features</div></div>
    </div>
    <div class="kicker">Promises checked</div>
    ${p.declared.length ? '' : '<p class="small muted" style="margin:4px 0">This site declares no machine-readable privacy promise, so only the legal baseline is checked.</p>'}
    ${evRows(promiseRows)}
    <div class="row" style="margin:10px 0"><button id="said-no" ${p.consent?.state === 'denied' ? 'disabled' : ''}>${p.consent?.state === 'denied' ? 'You said no' : 'I said no to tracking here'}</button><span class="small muted">${p.consent ? esc(p.consent.state === 'denied' ? 'Consent denied: ' + p.consent.how : 'Consent given: ' + p.consent.how) : 'No consent decision seen yet'}</span></div>
    ${p.features.length ? `<div class="kicker">Browser features used</div>${evRows(p.features.map((f) => ({ status: f.fingerprinting ? 'found' : 'note', label: f.label, detail: `${f.n}×${f.afterDenial && p.consent?.state === 'denied' ? `, ${f.afterDenial}× after you said no` : ''}` })))}` : ''}
    ${p.thirdParties.length ? `<div class="kicker" style="margin-top:10px">Third-party domains contacted</div>${evRows(p.thirdParties.slice(0, 15).map((t) => ({ status: t.tracker ? 'found' : 'note', label: t.host, detail: `${t.tracker ? t.tracker + ' · ' : ''}${t.n} request(s)${t.afterDenial ? `, ${t.afterDenial} after you said no` : ''}` })))}` : ''}`;
  $('#said-no')?.addEventListener('click', async () => { await send({ type: 'privacy:mark', tabId: tab.id, state: 'denied' }); renderPrivacy(); });
}

// ---------- Ghost ----------
async function renderGhost() {
  const g = await send({ type: 'ghost:status' }).catch((e) => ({ error: e.message }));
  if (g.error) { $('#ghost').textContent = g.error; return; }
  if (!g.enrolled) {
    $('#ghost').innerHTML = `<h2>Ghost sign-in</h2><p class="small">Verify once, then sign up on sites that accept EMCON as a different, unlinkable identity that can still prove you're a real adult.</p><button class="primary" id="setup">Set up Ghost</button>`;
    $('#setup').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/setup.html') });
    return;
  }
  const sites = Object.entries(g.sites);
  $('#ghost').innerHTML = `<div class="kicker">Ghost is active · ${g.unlock === 'passkey' ? 'passkey' : 'PIN'} unlock</div>
    <h2 style="margin-top:4px">Humanity tokens</h2>
    <div class="small">${g.bundles.map((b) => `<span class="mono">${esc(b)}</span> ${g.tokens[b]}`).join(' &nbsp;·&nbsp; ')}</div>
    <div class="small muted">Pinned issuer keys: <span class="mono">${Object.entries(g.pinnedKeys).map(([b, k]) => `${esc(b)}=${esc(k)}`).join(', ')}</span></div>
    <div class="row" style="margin:8px 0">${g.bundles.map((b) => `<button data-refill="${esc(b)}">Refill ${esc(b)}</button>`).join('')}</div>
    <hr><div class="kicker">Your site identities</div>
    ${sites.length ? sites.map(([o, s]) => `<div class="row small" style="padding:6px 0;border-bottom:1px solid var(--rule)"><span style="flex:1"><b>${esc(o)}</b><br><span class="mono">${esc(s.pseudonym)}…</span> · ${esc(s.claims.join(', '))}</span><button data-reset="${esc(o)}" title="Start over with a brand-new pseudonym">New identity</button></div>`).join('') : '<p class="small muted">None yet.</p>'}
    <div id="gMsg" class="small"></div>`;
  document.querySelectorAll('[data-refill]').forEach((b) => (b.onclick = async () => {
    b.disabled = true;
    try { await send({ type: 'ghost:refill', bundle: b.dataset.refill }); renderGhost(); } catch (e) { $('#gMsg').textContent = e.message; b.disabled = false; }
  }));
  document.querySelectorAll('[data-reset]').forEach((b) => (b.onclick = async () => { await send({ type: 'ghost:reset-site', origin: b.dataset.reset }); renderGhost(); }));
}
renderGhost();

// ---------- Trust ----------
async function renderTrust() {
  const { did, roots } = await send({ type: 'wot:me' });
  $('#myDid').textContent = did;
  $('#copyDid').onclick = () => navigator.clipboard.writeText(did);
  $('#roots').innerHTML = roots.length ? roots.map((r) => `<div class="row" style="padding:6px 0;border-bottom:1px solid var(--rule)"><span style="flex:1"><b>${esc(r.label)}</b> <span class="muted">· ${r.kind === 'group' ? 'source' : 'person'} · trust ${r.weight}</span><br><span class="mono muted">${esc(r.did.slice(0, 34))}…</span></span><button data-untrust="${esc(r.did)}">Remove</button></div>`).join('') : '<p class="muted">Nobody yet.</p>';
  document.querySelectorAll('[data-untrust]').forEach((b) => (b.onclick = async () => { await send({ type: 'wot:untrust', did: b.dataset.untrust }); renderTrust(); }));
}
$('#tAdd').onclick = async () => {
  try {
    await send({ type: 'wot:trust', did: $('#tDid').value.trim(), label: $('#tLabel').value, weight: $('#tWeight').value, publish: $('#tPublish').checked });
    $('#tMsg').textContent = 'Added.'; $('#tDid').value = ''; renderTrust();
  } catch (e) { $('#tMsg').textContent = e.message; }
};
renderTrust();

// ---------- Settings ----------
const s = await send({ type: 'settings:get' });
for (const k of ['farble', 'privacy', 'provenance', 'provRecovery', 'wot']) {
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
