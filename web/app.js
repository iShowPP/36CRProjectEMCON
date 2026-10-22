// EMCON dashboard: one page, hash routes. Everything comes from /api/me.
import { $, $$, esc, api, icon, toast, hasExtension, strength } from '/site.js';

const fillIcons = (root = document) => $$('[data-i]', root).forEach((el) => { el.outerHTML = icon(el.dataset.i); });
fillIcons();
let S = null; // last /api/me
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const ago = (t) => { const s = Math.round((Date.now() - t) / 1000); return s < 60 ? 'just now' : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : `${Math.round(s / 86400)} d ago`; };
const date = (t) => new Date(t).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
const rupees = (n) => (n ? `₹${n.toLocaleString('en-IN')}` : '₹0');

async function load() {
  try { S = await api('/api/me'); } catch (e) { if (e.status === 401) location.href = '/login?next=' + encodeURIComponent('/app' + location.hash); throw e; }
  const u = S.user;
  $('#who').textContent = u.email || u.name;
  $('#avatar').textContent = (u.name || '?')[0].toUpperCase();
  $('#sidePlan').innerHTML = `<b>${esc(u.plan.name)} plan</b><span class="muted">${S.devices.length} of ${u.plan.devices} browsers</span>${u.plan.id !== 'business' ? '<br><a href="#billing">Upgrade</a>' : ''}`;
}
$('#logout').onclick = async () => { await api('/api/auth/logout', { method: 'POST' }); location.href = '/'; };

function modal(html, wire) {
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal" role="dialog" aria-modal="true">${html}</div>`;
  bg.onclick = (e) => { if (e.target === bg) bg.remove(); };
  document.body.append(bg);
  const close = () => bg.remove();
  wire?.(bg, close);
  bg.querySelector('input, button')?.focus();
  return close;
}

// ---------- views ----------
const VIEWS = {
  overview: { title: 'Overview', render() {
    const u = S.user, w = S.week;
    const steps = [
      [hasExtension(), 'Install the EMCON extension', 'https://github.com/iShowPP/36CRProjectEMCON/releases/latest', 'Download'],
      [S.devices.length > 0, 'Connect this browser to your account', '#devices', 'Connect'],
      [S.family.length > 0, 'Add someone you want to protect', '#devices', 'Add'],
      [u.recoverySet || u.signIn.ghost, 'Save your recovery key', '#settings', 'Open'],
    ];
    return `
      <p class="lead" style="font-size:18px;margin:0 0 20px">Hello ${esc(u.name)}. Here's what EMCON did across your browsers in the last 7 days.</p>
      <div class="kpis">
        <div class="kpi"><span>Scams blocked</span><b class="${w.blocked ? 'bad' : ''}">${w.blocked || 0}</b><small>across ${plural(S.devices.length, 'browser')}</small></div>
        <div class="kpi"><span>Warnings shown</span><b>${w.warned || 0}</b><small>sites to be careful on</small></div>
        <div class="kpi"><span>Pages checked</span><b>${(w.pages || 0).toLocaleString()}</b><small>plus ${w.links || 0} messages</small></div>
        <div class="kpi"><span>Trackers spotted</span><b>${(w.trackers || 0).toLocaleString()}</b><small>${w.photos || 0} photos labelled</small></div>
      </div>
      <div class="grid" style="margin-top:22px;grid-template-columns:1.2fr 1fr">
        <div>
          <div class="panel-h" style="margin-top:0"><h2>Recent alerts</h2></div>
          <div class="list">${S.alerts.length ? S.alerts.slice(0, 6).map((a) => `<div class="li"><span class="ico" style="background:var(--bad-tint);color:var(--bad)">${icon('shield')}</span><div class="txt"><b>${esc(a.text)}</b><span>${esc(a.device)} · ${ago(a.at)}</span></div></div>`).join('')
            : `<div class="empty">No scams blocked this week. When EMCON blocks one on any connected browser, it appears here. You'll see that it happened, never which sites anyone visits.</div>`}</div>
        </div>
        <div>
          <div class="panel-h" style="margin-top:0"><h2>Get set up</h2><span class="small muted">${steps.filter((s) => s[0]).length} of ${steps.length} done</span></div>
          <div class="list"><ul class="steps-check">${steps.map(([done, text, href, cta]) => `<li class="${done ? 'done' : ''}"><span class="tick">${done ? icon('check', 14) : ''}</span><b style="flex:1;font-weight:550">${text}</b>${done ? '' : `<a class="btn sm" style="min-height:34px;padding:6px 12px" href="${href}">${cta}</a>`}</li>`).join('')}</ul></div>
        </div>
      </div>
      <div class="panel-h"><h2>Check a message or link</h2><span class="small muted">${S.usage.today} of ${S.usage.limit} checks used today</span></div>
      <div class="card">
        <textarea id="q" rows="3" placeholder="Paste a suspicious SMS, WhatsApp message or link"></textarea>
        <div class="row" style="margin-top:10px"><button class="primary" id="qGo">Check safely</button><span class="small muted">The link is followed on our server; it never opens in your browser.</span></div>
        <div id="qOut" style="margin-top:12px"></div>
      </div>`;
  }, wire() { $('#qGo').onclick = () => runCheck($('#q').value, $('#qOut'), $('#qGo')); } },

  devices: { title: 'Browsers & family', render() {
    const owners = [{ id: '', name: `${S.user.name} (you)` }, ...S.family];
    return `
      <div class="panel-h" style="margin-top:0"><h2>Connected browsers</h2><button class="primary" id="pairMe">${icon('plus', 18)}Connect a browser</button></div>
      <div class="list">${S.devices.length ? S.devices.map((d) => `<div class="li"><span class="ico">${icon('devices')}</span><div class="txt"><b>${esc(d.owner)} · ${esc(d.name)}</b><span>Seen ${ago(d.lastSeen)} · this week: ${d.stats?.blocked || 0} scams blocked, ${d.stats?.pages || 0} pages checked${d.version ? ` · EMCON ${esc(d.version)}` : ''}</span></div><button class="sm danger" data-rmdev="${d.id}">Remove</button></div>`).join('')
        : `<div class="empty">No browsers connected yet. Connect yours, then your parents' or kids'.</div>`}</div>
      <p class="small muted">Connected browsers send weekly counts only: pages checked, scams blocked, warnings. Never the sites anyone visits, and never message text.</p>

      <div class="panel-h"><h2>People you protect</h2><button id="addFam">${icon('plus', 18)}Add a person</button></div>
      <div class="list">${S.family.length ? S.family.map((m) => {
        const devs = S.devices.filter((d) => d.member === m.id);
        return `<div class="li"><span class="avatar" style="background:var(--primary-tint);color:var(--primary)">${esc(m.name[0].toUpperCase())}</span><div class="txt"><b>${esc(m.name)}${m.relation ? ` <span class="muted" style="font-weight:400">· ${esc(m.relation)}</span>` : ''}</b><span>${devs.length ? plural(devs.length, 'browser') + ' connected' : 'No browser connected yet'}</span></div><button class="sm" data-pair="${m.id}">Connect their browser</button><button class="sm danger" data-rmfam="${m.id}" title="Remove">${icon('trash', 16)}</button></div>`;
      }).join('') : `<div class="empty">Add a parent, child or friend. Each gets a code to connect their own browser.</div>`}</div>
      <span hidden>${owners.length}</span>`;
  }, wire() {
    $('#pairMe').onclick = () => pair(null);
    $('#addFam').onclick = () => modal(`<h2>Add a person</h2><p class="muted small">They'll connect their own browser with a code. You'll see when EMCON protects them.</p>
      <label for="fn">Name</label><input id="fn" placeholder="e.g. Mum"><label for="fr">Relation (optional)</label><input id="fr" placeholder="e.g. mother">
      <div class="row" style="margin-top:16px;justify-content:flex-end"><button id="fc">Cancel</button><button class="primary" id="fok">Add</button></div><div class="form-msg bad" id="fm"></div>`, (m, close) => {
      $('#fc', m).onclick = close;
      $('#fok', m).onclick = async () => {
        try { const r = await api('/api/me/family', { method: 'POST', body: { name: $('#fn', m).value, relation: $('#fr', m).value } }); close(); await refresh(); pair(r.member.id); }
        catch (e) { $('#fm', m).textContent = e.message; }
      };
    });
    $$('[data-pair]').forEach((b) => (b.onclick = () => pair(b.dataset.pair)));
    $$('[data-rmdev]').forEach((b) => (b.onclick = async () => { if (confirm('Disconnect this browser? It keeps protecting, but stops reporting to your dashboard.')) { await api(`/api/me/devices/${b.dataset.rmdev}/remove`, { method: 'POST' }); refresh(); } }));
    $$('[data-rmfam]').forEach((b) => (b.onclick = async () => { if (confirm('Remove this person and disconnect their browsers?')) { await api(`/api/me/family/${b.dataset.rmfam}/remove`, { method: 'POST' }); refresh(); } }));
  } },

  api: { title: 'Link-check API', render() {
    const host = location.origin;
    return `
      <p class="lead" style="font-size:17px;margin:0 0 18px">Check links and messages from your own app, helpdesk or SMS gateway. Same evidence as the extension: scam reports, look-alike addresses, shorteners, redirects and scam wording.</p>
      <div class="kpis" style="grid-template-columns:repeat(3,1fr)">
        <div class="kpi"><span>Checks today</span><b>${S.usage.today}</b><small>of ${S.usage.limit.toLocaleString()} on ${esc(S.user.plan.name)}</small></div>
        <div class="kpi"><span>Active keys</span><b>${S.keys.length}</b><small>up to 10</small></div>
        <div class="kpi"><span>Response time</span><b>~1 s</b><small>follows up to 10 redirects</small></div>
      </div>
      <div class="panel-h"><h2>API keys</h2><button class="primary" id="newKey">${icon('plus', 18)}Create a key</button></div>
      <div class="list">${S.keys.length ? S.keys.map((k) => `<div class="li"><span class="ico">${icon('key')}</span><div class="txt"><b>${esc(k.name)}</b><span class="mono">${esc(k.prefix)}</span><span> · created ${date(k.created)}${k.lastUsed ? ` · last used ${ago(k.lastUsed)}` : ' · never used'}</span></div><button class="sm danger" data-revoke="${k.id}">Revoke</button></div>`).join('') : '<div class="empty">No keys yet. Keys are shown once, when you create them.</div>'}</div>
      <div class="panel-h"><h2>Quick start</h2></div>
      <pre class="code">curl -X POST ${esc(host)}/api/v1/check \\
  -H "Authorization: Bearer emk_live_…" \\
  -H "content-type: application/json" \\
  -d '{"text": "Your parcel is on hold. Pay the fee: https://bit.ly/…"}'</pre>
      <pre class="code">{
  "result": {
    "verdict": "scam",            // scam | suspicious | no_warnings
    "risk": 93,
    "final": "https://fake-courier-fee.example/pay",
    "hops": ["https://bit.ly/…", "https://fake-courier-fee.example/pay"],
    "reasons": [
      { "id": "reports", "text": "Reported as a scam: Listed in the OpenPhish feed", "points": 70 },
      { "id": "wording", "text": "Scam-style wording in the message: \\"on hold\\"", "points": 15 }
    ]
  },
  "usage": { "today": 12, "limit": 500 }
}</pre>
      <p class="small muted">GET <span class="mono">/api/v1/check?url=…</span> works too. Errors: 401 bad key, 429 daily limit reached, 400 no link found.</p>`;
  }, wire() {
    $('#newKey').onclick = () => modal(`<h2>Create an API key</h2><label for="kn">Name</label><input id="kn" placeholder="e.g. Helpdesk bot"><div class="row" style="margin-top:16px;justify-content:flex-end"><button id="kc">Cancel</button><button class="primary" id="kok">Create</button></div><div id="kout"></div>`, (m, close) => {
      $('#kc', m).onclick = close;
      $('#kok', m).onclick = async () => {
        try {
          const r = await api('/api/me/keys', { method: 'POST', body: { name: $('#kn', m).value || 'API key' } });
          m.querySelector('.modal').innerHTML = `<h2>Your new API key</h2><p class="small muted">Copy it now. For your safety we only store a hash, so we can't show it again.</p><div class="keybox" style="font-size:14px;word-break:break-all">${esc(r.key)}</div><div class="row" style="justify-content:flex-end"><button id="kcopy">Copy</button><button class="primary" id="kdone">Done</button></div>`;
          $('#kcopy', m).onclick = async () => { await navigator.clipboard.writeText(r.key); toast('API key copied'); };
          $('#kdone', m).onclick = () => { close(); refresh(); };
        } catch (e) { $('#kout', m).innerHTML = `<p class="form-msg bad">${esc(e.message)}</p>`; }
      };
    });
    $$('[data-revoke]').forEach((b) => (b.onclick = async () => { if (confirm('Revoke this key? Apps using it stop working immediately.')) { await api(`/api/me/keys/${b.dataset.revoke}/revoke`, { method: 'POST' }); refresh(); } }));
  } },

  billing: { title: 'Plan & billing', render() {
    const cur = S.user.plan.id;
    const FEATURES = {
      free: ['Scam, phishing and look-alike protection', 'Message checks and photo labels', '2 browsers', '50 link-check API calls a day'],
      family: ['Everything in Free', '8 browsers for the whole family', 'Alerts when a scam is blocked for someone you protect', '500 API calls a day'],
      business: ['Everything in Family', '100 team browsers', '20,000 link-check API calls a day', 'Signed evidence receipts for incident reports'],
    };
    return `
      <div class="demo-banner"><b>Demo billing.</b> No payment provider is connected yet, so changing plan is free and instant. Going live needs a Razorpay or Stripe account.</div>
      <div class="plans">${S.plans.map((p) => `<div class="plan-card ${p.id === 'family' ? 'featured' : ''}">
        <h3>${esc(p.name)}${p.id === 'family' ? '<span class="badge-pop">Most popular</span>' : ''}</h3>
        <div class="price">${rupees(p.price)}<small> / month</small></div>
        <div class="small muted">${esc(p.blurb)}</div>
        <ul>${FEATURES[p.id].map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
        ${p.id === cur ? '<button disabled>Your current plan</button>' : `<button class="${p.price > S.user.plan.price ? 'primary' : ''}" data-plan="${p.id}">${p.price > S.user.plan.price ? 'Upgrade' : 'Switch'} to ${esc(p.name)}</button>`}
      </div>`).join('')}</div>
      <div class="panel-h"><h2>Invoices</h2></div>
      <div class="list">${S.invoices.length ? `<table><thead><tr><th style="padding-left:18px">Invoice</th><th>Date</th><th>Change</th><th>Amount</th><th>Status</th></tr></thead><tbody>${S.invoices.map((i) => `<tr><td class="mono" style="padding-left:18px">${esc(i.id)}</td><td>${date(i.at)}</td><td>${esc(i.note)}</td><td>${rupees(i.amount)}</td><td><span class="chip ${i.amount ? 'warn' : ''}">${esc(i.status)}</span></td></tr>`).join('')}</tbody></table>` : '<div class="empty">No invoices yet.</div>'}</div>`;
  }, wire() {
    $$('[data-plan]').forEach((b) => (b.onclick = async () => {
      b.disabled = true;
      try { await api('/api/me/plan', { method: 'POST', body: { plan: b.dataset.plan } }); toast('Plan changed'); refresh(); } catch (e) { toast(e.message); b.disabled = false; }
    }));
  } },

  settings: { title: 'Settings', render() {
    const u = S.user;
    return `
      <div class="grid" style="grid-template-columns:1fr 1fr;align-items:start">
        <div class="card"><h3>Profile</h3><label for="pn">Name</label><input id="pn" value="${esc(u.name)}"><label for="pe" style="margin-top:12px">Email</label><input id="pe" value="${esc(u.email || '')}" disabled placeholder="Signed up with Ghost: no email"><button class="primary" id="pSave" style="margin-top:14px">Save</button></div>
        <div class="card"><h3>${u.signIn.password ? 'Change password' : 'Add a password'}</h3>
          ${u.signIn.password ? '<label for="pc">Current password</label><input id="pc" type="password" autocomplete="current-password">' : '<label for="pem">Email</label><input id="pem" type="email" autocomplete="username">'}
          <label for="pw" style="margin-top:12px">New password</label><input id="pw" type="password" autocomplete="new-password"><div class="meter"><i id="pbar"></i></div>
          <button class="primary" id="pwSave" style="margin-top:14px">${u.signIn.password ? 'Change password' : 'Add password'}</button></div>
        <div class="card"><h3>Recovery key</h3><p class="small muted">${u.recoverySet ? 'You have a recovery key. Making a new one replaces it.' : 'You have no recovery key yet.'}</p><button id="rkNew">Make a new recovery key</button></div>
        <div class="card"><h3>Sessions</h3><p class="small muted">Signed in somewhere you don't recognise? Sign out everywhere, then change your password.</p><button id="outAll">Sign out everywhere</button></div>
      </div>
      <div class="panel-h"><h2>Recent account activity</h2></div>
      <div class="list">${S.audit.length ? S.audit.map((a) => `<div class="li"><div class="txt"><b>${esc(a.what)}</b><span>${new Date(a.at).toLocaleString()} · ${esc(a.agent.replace(/\(.*?\)/g, '').slice(0, 70))}</span></div></div>`).join('') : '<div class="empty">Nothing yet.</div>'}</div>
      <div class="panel-h"><h2>Your data</h2></div>
      <div class="card"><div class="row"><button id="export">Download my data (JSON)</button><button class="danger" id="del">${icon('trash', 18)}Delete my account</button></div>
        <p class="small muted" style="margin:10px 0 0">Deleting removes your account, browsers, family and API keys immediately. The EMCON extension keeps protecting each browser on its own.</p></div>`;
  }, wire() {
    const u = S.user;
    $('#pSave').onclick = async () => { await api('/api/me/profile', { method: 'POST', body: { name: $('#pn').value } }); toast('Saved'); refresh(); };
    $('#pw').oninput = () => { const s = strength($('#pw').value); $('#pbar').style.width = `${Math.max(8, s.score * 25)}%`; $('#pbar').style.background = s.color; };
    $('#pwSave').onclick = async () => {
      try { await api('/api/me/password', { method: 'POST', body: { current: $('#pc')?.value, email: $('#pem')?.value, next: $('#pw').value } }); toast('Password saved'); refresh(); } catch (e) { toast(e.message); }
    };
    $('#rkNew').onclick = async () => {
      if (!confirm('Make a new recovery key? Your old one stops working.')) return;
      const r = await api('/api/me/recovery', { method: 'POST' });
      modal(`<h2>Your new recovery key</h2><p class="small muted">Save it somewhere safe. It's the only way back in if you forget your password.</p><div class="keybox">${esc(r.recoveryKey)}</div><div class="row" style="justify-content:flex-end"><button id="rc">Copy</button><button class="primary" id="rd">Done</button></div>`, (m, close) => {
        $('#rc', m).onclick = async () => { await navigator.clipboard.writeText(r.recoveryKey); toast('Copied'); };
        $('#rd', m).onclick = () => { close(); refresh(); };
      });
    };
    $('#outAll').onclick = async () => { await api('/api/me/signout-all', { method: 'POST' }); location.href = '/login'; };
    $('#export').onclick = async () => {
      const data = await api('/api/me/export');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
      a.download = 'emcon-account-data.json'; a.click();
    };
    $('#del').onclick = () => modal(`<h2>Delete your account?</h2><p class="small muted">This can't be undone.</p>${u.signIn.password ? '<label for="dp">Password</label><input id="dp" type="password">' : ''}<label for="dc">Type DELETE to confirm</label><input id="dc"><div class="row" style="margin-top:16px;justify-content:flex-end"><button id="dn">Cancel</button><button class="danger" id="dy">Delete account</button></div><div class="form-msg bad" id="dm"></div>`, (m, close) => {
      $('#dn', m).onclick = close;
      $('#dy', m).onclick = async () => {
        try { await api('/api/me/delete', { method: 'POST', body: { confirm: $('#dc', m).value, password: $('#dp', m)?.value } }); location.href = '/'; } catch (e) { $('#dm', m).textContent = e.message; }
      };
    });
  } },
};

async function pair(memberId) {
  try {
    const r = await api('/api/me/pair', { method: 'POST', body: { member: memberId } });
    modal(`<h2>Connect ${esc(r.for === 'you' ? 'your browser' : `${r.for}'s browser`)}</h2>
      <p class="small muted">On ${r.for === 'you' ? 'the browser' : 'their browser'}: click the EMCON icon → <b>More</b> → <b>Settings</b> → <b>EMCON account</b>, and type this code.</p>
      <div class="code-big">${esc(r.code.slice(0, 3))} ${esc(r.code.slice(3))}</div>
      <p class="small muted" style="text-align:center">Works once, for 10 minutes.</p>
      <div class="row" style="justify-content:flex-end"><button class="primary" id="pd">Done</button></div>`, (m, close) => { $('#pd', m).onclick = () => { close(); refresh(); }; });
  } catch (e) { toast(e.message); }
}

async function runCheck(text, out, btn) {
  if (!text.trim()) { out.innerHTML = '<p class="form-msg bad">Paste a message or link first.</p>'; return; }
  btn.disabled = true;
  out.innerHTML = '<p class="muted small">Following the link safely…</p>';
  try {
    const { result: r, usage } = await api('/api/v1/check', { method: 'POST', body: { text } });
    const role = { scam: ['bad', 'Very likely a scam'], suspicious: ['warn', 'Be careful'], no_warnings: ['ok', 'No warning signs found'] }[r.verdict];
    out.innerHTML = `<div class="notice ${role[0]}"><b class="${role[0]}" style="font-size:17px">${role[1]}</b> · lands on <span class="mono">${esc(r.site)}</span> · risk ${r.risk}/100
      ${r.reasons.length ? `<ul style="margin:8px 0 0;padding-left:18px">${r.reasons.map((x) => `<li>${esc(x.text)}</li>`).join('')}</ul>` : '<p style="margin:6px 0 0">No reports, look-alike address, shortener or scam wording found.</p>'}
      ${r.hops.length > 1 ? `<p class="small muted" style="margin:8px 0 0">Path: ${r.hops.map(esc).join(' → ')}</p>` : ''}</div>`;
    S.usage = usage;
  } catch (e) { out.innerHTML = `<p class="form-msg bad">${esc(e.message)}</p>`; }
  btn.disabled = false;
}

function route() {
  const name = VIEWS[location.hash.slice(1)] ? location.hash.slice(1) : 'overview';
  $$('.side a.nav').forEach((a) => a.classList.toggle('on', a.dataset.v === name));
  $('#title').textContent = VIEWS[name].title;
  document.title = `${VIEWS[name].title} · EMCON`;
  $('#view').innerHTML = VIEWS[name].render();
  VIEWS[name].wire?.();
}
async function refresh() { await load(); route(); }
addEventListener('hashchange', route);
// the extension sets its marker a moment after load; re-render the checklist once it has
await refresh();
setTimeout(() => { if (hasExtension() && (location.hash || '#overview') === '#overview') route(); }, 900);
