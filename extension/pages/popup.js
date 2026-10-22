import { send, $, esc } from './msg.js';
import { icon, fillIcons, verdictHtml, evList, pill, byOrder } from './ui.js';
import { lureFindings, urlsIn } from '../lib/signals.js';

fillIcons();
// ?tab=<id> shows another tab's results (used for screenshots and tests).
const forced = Number(new URLSearchParams(location.search).get('tab'));
const tab = forced ? await chrome.tabs.get(forced) : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
let url = null;
try { url = new URL(tab.url); } catch { /* chrome:// etc. */ }
const domain = url && /^https?:$/.test(url.protocol) ? url.hostname.replace(/^www\./, '') : null;
$('#host').textContent = domain || '';
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;

// ---------- navigation: bottom tabs, plus sub-views under "More" ----------
function showTab(name) {
  document.querySelectorAll('nav.tabs button').forEach((x) => x.classList.toggle('on', x.dataset.tab === name));
  document.querySelectorAll('main > section').forEach((s) => s.classList.toggle('hidden', s.id !== 'tab-' + name));
  $('#main').scrollTop = 0;
  if (name === 'privacy') renderPrivacy();
  if (name === 'more') { showView(null); renderWeek(); }
}
function showView(name) {
  $('#more-home').classList.toggle('hidden', !!name);
  for (const v of ['ghost', 'trust', 'settings']) $('#view-' + v).classList.toggle('hidden', v !== name);
  $('#main').scrollTop = 0;
}
document.querySelectorAll('nav.tabs button').forEach((b) => (b.onclick = () => showTab(b.dataset.tab)));
document.querySelectorAll('[data-view]').forEach((b) => (b.onclick = () => showView(b.dataset.view)));
document.querySelectorAll('[data-back]').forEach((b) => (b.onclick = () => showView(null)));

// ---------- This site ----------
const empty = (title, text, ic = 'shield') => `<div class="empty"><span class="dot-icon role-neutral">${icon(ic, 24)}</span><h2>${esc(title)}</h2><p class="small" style="margin-top:4px">${esc(text)}</p></div>`;
function renderVerdict(v) {
  $('#verdict').innerHTML = v ? verdictHtml(v)
    : domain ? empty('Not checked yet', 'Reload the page and EMCON will check it.')
      : empty('Nothing to check here', 'Open a website and EMCON checks it automatically.');
}
const verdict = await send({ type: 'wot:tab', tabId: tab.id }).catch(() => null);
renderVerdict(verdict);

async function renderTiles() {
  const [p, imgs, st] = await Promise.all([
    send({ type: 'privacy:tab', tabId: tab.id }).catch(() => null),
    send({ type: 'prov:tab', tabId: tab.id }).catch(() => ({})),
    send({ type: 'settings:get' }),
  ]);
  const v = verdict;
  const warnings = v ? v.checks.filter((c) => c.status === 'found').length : 0;
  const photos = Object.values(imgs).reduce((a, b) => a + b, 0);
  const badPhotos = (imgs.altered || 0) + (imgs.forged || 0);
  const fpOff = !st.farble || (url && st.farbleExceptions.includes(url.hostname));
  const tile = (go, role, ic, title, big, sub) => `<button class="tile role-${role}" data-go="${go}"><span class="top">${icon(ic, 16)}${esc(title)}</span><span class="big">${esc(big)}</span><span class="sub">${esc(sub)}</span></button>`;
  $('#tiles').innerHTML = [
    tile('checks', !v ? 'neutral' : warnings ? 'danger' : 'safe', 'shield', 'Scam checks', !v ? '–' : warnings ? plural(warnings, 'warning') : 'All clear', v ? `${v.checks.length} checks on this page` : 'not run yet'),
    tile('privacy', !p ? 'neutral' : p.trackerCount ? 'caution' : 'safe', 'eye', 'Tracking', p ? String(p.trackerCount) : '–', p ? `tracking ${p.trackerCount === 1 ? 'company' : 'companies'} seen` : 'nothing observed yet'),
    tile('photos', badPhotos ? 'danger' : photos ? 'safe' : 'neutral', 'image', 'Photos', String(photos), photos ? Object.entries(imgs).map(([k, n]) => `${n} ${({ verified: 'verified', recovered: 'recovered', untrusted: 'unknown signer', altered: 'altered', forged: 'forged', c2pa: 'C2PA' })[k] || k}`).join(' · ') : 'no labelled photos'),
    tile('settings', fpOff ? 'caution' : 'safe', 'fingerprint', 'Fingerprint', fpOff ? 'Paused' : 'Protected', fpOff ? 'not protected on this site' : 'new noise every visit'),
  ].join('');
  document.querySelectorAll('[data-go]').forEach((b) => (b.onclick = () => {
    const go = b.dataset.go;
    if (go === 'privacy') showTab('privacy');
    else if (go === 'settings') { showTab('more'); showView('settings'); }
    else if (go === 'checks') { const d = document.querySelector('#verdict details.more'); if (d) { d.open = true; d.scrollIntoView({ behavior: 'smooth' }); } }
  }));
}
renderTiles();

$('#msgGo').onclick = async () => {
  $('#msgOut').textContent = 'Checking…';
  try {
    const v = await send({ type: 'chain:message', tabId: tab.id, text: $('#msg').value });
    if (v) { renderVerdict(v); $('#msgOut').textContent = 'Updated above.'; $('#main').scrollTop = 0; } else $('#msgOut').textContent = 'Saved. Reload the page to re-check.';
  } catch (e) { $('#msgOut').textContent = e.message; }
};
$('#receipt').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL(`pages/receipt.html?tab=${tab.id}`) });

async function attest(kind) {
  if (!domain) return;
  try {
    await send({ type: 'wot:attest', domain, verdict: kind, transacted: kind === 'trusted' });
    $('#attMsg').innerHTML = `<span class="ok">Thanks.</span> Your ${kind === 'scam' ? 'report' : 'vouch'} is signed with your key and shared with people who trust you.`;
  } catch (e) { $('#attMsg').textContent = e.message; }
}
$('#attGood').onclick = () => attest('trusted');
$('#attScam').onclick = () => attest('scam');
if (!domain) $('#attGood').disabled = $('#attScam').disabled = $('#receipt').disabled = true;

// ---------- Check a message or link (without opening it) ----------
function messageBubble(text) {
  const phrases = lureFindings(text).map((l) => l.phrase).filter(Boolean);
  const links = urlsIn(text);
  let html = esc(text);
  for (const ph of phrases) html = html.replace(new RegExp(esc(ph).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), (m) => `<mark>${m}</mark>`);
  const first = links[0] && text.match(/\b(?:https?:\/\/)?(?:localhost|\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:\/[^\s<>"')]*)?/i)?.[0];
  if (first) html = html.replace(esc(first), `<span class="lnk">${esc(first)}</span>`);
  return `<div class="bubble them">${html}</div>${phrases.length ? `<p class="tiny" style="margin:6px 2px 0;color:var(--danger)">Highlighted: words scammers use to rush you.</p>` : ''}`;
}
$('#chkGo').onclick = async () => {
  const text = $('#chk').value.trim();
  if (!text) { $('#chkOut').textContent = 'Paste a message or link first.'; return; }
  $('#chkGo').disabled = true;
  $('#chkOut').innerHTML = `<span class="muted">Following the link safely…</span>`;
  $('#chkResult').innerHTML = '';
  try {
    const v = await send({ type: 'link:check', text });
    $('#chkOut').innerHTML = '';
    const lands = (() => { try { return new URL(v.url).hostname.replace(/^www\./, ''); } catch { return v.url; } })();
    $('#chkResult').innerHTML = `
      ${/\s/.test(text) ? `<div class="section-title" style="margin-top:4px">Your message</div>${messageBubble(text)}<div style="height:10px"></div>` : ''}
      ${verdictHtml(v, { where: `the link lands on <b>${esc(lands)}</b>`, pathTitle: 'Where the link goes', start: 'The link you pasted' })}
      <div class="actions"><button class="primary wide" id="chkReceipt">${icon('receipt', 18)}Save signed proof of this check</button></div>`;
    $('#chkReceipt').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL(`pages/receipt.html?check=${v.checkId}`) });
  } catch (e) { $('#chkOut').innerHTML = `<div class="notice role-caution">${icon('alert', 18)}<div>${esc(e.message)}</div></div>`; }
  $('#chkGo').disabled = false;
};

// ---------- Privacy ----------
async function renderPrivacy() {
  const p = await send({ type: 'privacy:tab', tabId: tab.id }).catch(() => null);
  if (!p) { $('#privacy').innerHTML = empty('Nothing observed yet', domain ? 'Reload the page and EMCON will watch who it talks to.' : 'Open a website to see who it shares your visit with.', 'eye'); return; }
  const companies = [...new Set(p.thirdParties.filter((t) => t.tracker).map((t) => t.tracker.replace(/\s*\(.*\)$/, '')))];
  const fp = p.features.filter((f) => f.fingerprinting);
  const broken = p.promises.filter((x) => x.status === 'broken');
  const role = broken.length ? 'danger' : p.trackerCount ? 'caution' : 'safe';
  const named = companies.length ? `${companies.slice(0, 3).map(esc).join(', ')}${companies.length > 3 ? ` and ${companies.length - 3} more` : ''}` : '';
  const said = p.consent?.state === 'denied';
  $('#privacy').innerHTML = `
    <div class="panel role-${role}">
      <div class="hero"><span class="dot-icon">${icon(role === 'safe' ? 'shieldCheck' : 'eye', 26)}</span><div>
        <h1>${p.trackerCount ? `${plural(p.trackerCount, 'tracking company', 'tracking companies')} watched this visit` : 'No known trackers on this page'}</h1>
        <div class="where">on <b>${esc(p.host)}</b> · since ${esc(new Date(p.since).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))}</div></div></div>
      ${named ? `<p class="advice">Including ${named}.${p.gpc ? ' Your browser had asked every one of them not to sell or share your data.' : ''}</p>` : ''}
      <div class="stat-row">
        <div class="role-neutral"><b>${p.thirdPartyCount}</b><span>other sites contacted</span></div>
        <div class="role-${p.trackerCount ? 'caution' : 'safe'}"><b>${p.trackerCount}</b><span>tracking companies</span></div>
        <div class="role-${fp.length ? 'danger' : 'safe'}"><b>${fp.length}</b><span>fingerprinting tricks</span></div>
      </div>
    </div>
    <div class="section-title">Promises checked</div>
    <div class="card" style="padding:2px 14px">${evList([...p.promises].sort(byOrder).map((x) => ({ status: x.status, label: x.text, detail: `${x.evidence} (${x.source})` })))}</div>
    <button id="said-no" class="block" style="margin-top:10px" ${said ? 'disabled' : ''}>${icon(said ? 'check' : 'x', 18)}${said ? 'You said no to tracking here' : 'I said no to tracking here'}</button>
    <p class="tiny faint" style="margin:6px 2px 0">${p.consent ? esc(said ? `Recorded: ${p.consent.how}. Everything after that is counted separately.` : `Consent given: ${p.consent.how}`) : 'Say no on the site\'s cookie banner, or press this button, then keep using the page.'}</p>
    ${companies.length ? `<details class="more"><summary>Tracking companies (${p.trackerCount}) ${icon('chevronDown', 18)}</summary><div class="card" style="padding:2px 14px">${evList(p.thirdParties.filter((t) => t.tracker).map((t) => ({ status: t.afterDenial && said ? 'found' : 'note', label: t.tracker, detail: `${t.host} · ${plural(t.n, 'request')}${t.afterDenial && said ? `, ${t.afterDenial} after you said no` : ''}` })))}</div></details>` : ''}
    ${p.features.length ? `<details class="more"><summary>Browser features used (${p.features.length}) ${icon('chevronDown', 18)}</summary><div class="card" style="padding:2px 14px">${evList(p.features.map((f) => ({ status: f.fingerprinting ? 'found' : 'note', label: f.label[0].toUpperCase() + f.label.slice(1), detail: `${f.n}×${f.afterDenial && said ? `, ${f.afterDenial}× after you said no` : ''}` })))}</div></details>` : ''}
    ${p.thirdPartyCount > p.trackerCount ? `<details class="more"><summary>Other sites contacted (${p.thirdPartyCount - p.trackerCount}) ${icon('chevronDown', 18)}</summary><div class="card" style="padding:2px 14px">${evList(p.thirdParties.filter((t) => !t.tracker).slice(0, 25).map((t) => ({ status: 'note', label: t.host, detail: plural(t.n, 'request') })))}</div></details>` : ''}`;
  $('#said-no')?.addEventListener('click', async () => { await send({ type: 'privacy:mark', tabId: tab.id, state: 'denied' }); renderPrivacy(); });
}

// ---------- More: this week ----------
async function renderWeek() {
  const w = await send({ type: 'stats:week' }).catch(() => ({}));
  const cell = (n, label, role) => `<div><b class="${n && role ? role : ''}">${n || 0}</b><span>${label}</span></div>`;
  $('#week').innerHTML = cell(w.pages, 'pages checked') + cell(w.blocked, 'scams blocked', 'bad') + cell(w.warned, 'warnings', 'warn')
    + cell(w.links, 'messages checked') + cell(w.photos, 'photos labelled') + cell(w.trackers, 'trackers spotted');
}

// ---------- Ghost ----------
async function renderGhost() {
  const g = await send({ type: 'ghost:status' }).catch((e) => ({ error: e.message }));
  if (g.error) { $('#ghost').innerHTML = `<div class="notice role-caution">${icon('alert', 18)}<div>${esc(g.error)}</div></div>`; return; }
  if (!g.enrolled) {
    $('#ghostSub').textContent = 'Not set up · sign up without email or phone';
    $('#ghost').innerHTML = `<div class="card"><p>Verify once, then sign up on sites that accept EMCON with a different, unlinkable identity on each, that can still prove you're a real adult.</p><p class="small muted">Sites learn nothing else: no name, email, phone or birthdate.</p><button class="primary block" id="setup">${icon('ghost', 18)}Set up Ghost</button></div>`;
    $('#setup').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/setup.html') });
    return;
  }
  const sites = Object.entries(g.sites);
  const total = g.bundles.reduce((a, b) => a + (g.tokens[b] || 0), 0);
  $('#ghostSub').textContent = `Active · ${plural(sites.length, 'site')} · ${plural(total, 'token')} left`;
  $('#ghost').innerHTML = `
    <div class="panel role-safe"><div class="hero"><span class="dot-icon">${icon('ghost', 24)}</span><div><h1 style="font-size:19px">Ghost is ready</h1><div class="where">Unlocks with your ${g.unlock === 'passkey' ? 'passkey' : 'PIN'}</div></div></div>
      <div class="row" style="margin-top:10px">${g.bundles.map((b) => `<span class="pill role-calm">${g.tokens[b]} × ${esc(b)}</span><button class="sm" data-refill="${esc(b)}">Refill</button>`).join('')}</div></div>
    <div class="section-title">Your identities</div>
    <div class="card" style="padding:2px 14px">${sites.length ? sites.map(([o, s]) => `<div class="src"><div><b>${esc(new URL(o).host)}</b><span>Pseudonym ${esc(s.pseudonym)}… · shares ${esc(s.claims.join(', ') || 'nothing else')}</span></div><button class="sm" data-reset="${esc(o)}" title="Start over with a brand-new pseudonym">New identity</button></div>`).join('') : '<p class="small muted" style="padding:10px 0;margin:0">None yet. Sites that accept Ghost show a "Continue with EMCON Ghost" button.</p>'}</div>
    <details class="more"><summary>Technical details ${icon('chevronDown', 18)}</summary><p class="tiny mono">Pinned issuer keys: ${Object.entries(g.pinnedKeys).map(([b, k]) => `${esc(b)}=${esc(k)}`).join(', ')}</p></details>
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
  $('#copyDid').onclick = async () => { await navigator.clipboard.writeText(did); $('#copyDid').lastChild.textContent = 'Copied'; };
  $('#trustSub').textContent = `${plural(roots.length, 'source')} · whose scam reports count`;
  const howMuch = (w) => (w >= 0.95 ? 'trusted completely' : w >= 0.6 ? 'trusted a lot' : 'trusted somewhat');
  $('#roots').innerHTML = roots.length ? roots.map((r) => `<div class="src"><span class="li-ic" style="display:grid;place-items:center;width:32px;height:32px;border-radius:9px;background:var(--primary-tint);color:var(--primary)">${icon(r.kind === 'group' ? 'shield' : 'users', 16)}</span><div><b>${esc(r.label)}</b><span>${r.kind === 'group' ? 'Security source' : 'Person'} · ${howMuch(r.weight)}</span></div><button class="sm" data-untrust="${esc(r.did)}">Remove</button></div>`).join('') : '<p class="small muted" style="padding:10px 0;margin:0">Nobody yet.</p>';
  document.querySelectorAll('[data-untrust]').forEach((b) => (b.onclick = async () => { await send({ type: 'wot:untrust', did: b.dataset.untrust }); renderTrust(); }));
}
$('#tAdd').onclick = async () => {
  try {
    await send({ type: 'wot:trust', did: $('#tDid').value.trim(), label: $('#tLabel').value, weight: $('#tWeight').value, publish: $('#tPublish').checked });
    $('#tMsg').innerHTML = '<span class="ok">Added.</span>'; $('#tDid').value = ''; $('#tLabel').value = ''; renderTrust();
  } catch (e) { $('#tMsg').textContent = e.message; }
};
renderTrust();

// ---------- Settings ----------
const s = await send({ type: 'settings:get' });
for (const k of ['farble', 'privacy', 'gpc', 'provenance', 'provRecovery', 'wot']) {
  $('#s_' + k).checked = s[k];
  $('#s_' + k).onchange = (e) => send({ type: 'settings:set', patch: { [k]: e.target.checked } }).then(renderTiles);
}
$('#s_exception').checked = !!(domain && s.farbleExceptions.includes(url.hostname));
$('#s_exception').disabled = !domain;
if (domain) $('#exceptionSub').textContent = `On ${domain}, only if the site misbehaves`;
$('#s_exception').onchange = async (e) => {
  const cur = (await send({ type: 'settings:get' })).farbleExceptions.filter((h) => h !== url.hostname);
  await send({ type: 'settings:set', patch: { farbleExceptions: e.target.checked ? [...cur, url.hostname] : cur } });
  renderTiles();
};
$('#s_server').value = s.server;
$('#s_server').onchange = (e) => send({ type: 'settings:set', patch: { server: e.target.value.replace(/\/+$/, '') } });
