import { send, $, esc } from './msg.js';
import { verifyReceipt } from '../lib/receipt.js';
import { icon, LEVEL, evList, pathHtml, byOrder } from './ui.js';

const q = new URLSearchParams(location.search);
const IMAGE = {
  verified: ['safe', 'checkCircle'], recovered: ['safe', 'recover'], untrusted: ['caution', 'help'], altered: ['danger', 'xCircle'],
  forged: ['danger', 'xCircle'], c2pa: ['calm', 'info'], none: ['neutral', 'image'],
};

try {
  const vc = await send({ type: 'receipt:create', ...(q.get('check') ? { checkId: q.get('check') } : q.get('img') ? { image: q.get('img') } : { tabId: Number(q.get('tab')) }) });
  const s = vc.credentialSubject;
  const { server } = await send({ type: 'settings:get' });
  let tsDid = null;
  try { tsDid = (await (await fetch(server + '/api/timestamp/key')).json()).did; } catch { /* offline */ }
  const check = await verifyReceipt(vc, { timestampDid: tsDid });

  const isImage = s.kind === 'image';
  const L = LEVEL[s.verdict.level] || LEVEL.unknown;
  const [role, ic] = isImage ? IMAGE[s.verdict.status] || IMAGE.none : [L.role, L.icon];
  const title = isImage ? s.verdict.summary : L.head;
  const subject = s.kind === 'link' ? 'Link checked' : isImage ? 'Photo' : 'Website';
  document.title = `EMCON receipt: ${title}`;
  $('#title').remove();
  const ts = check.timestamp.status;
  $('#body').innerHTML = `
    <div class="panel role-${role}">
      <div class="hero"><span class="dot-icon">${icon(ic, 28)}</span><div><h1 id="title">${esc(title)}</h1>
        <div class="where">${subject}: <span class="mono">${esc(s.id)}</span>${s.lands && s.lands !== s.id ? `<br>Lands on <span class="mono">${esc(s.lands)}</span>` : ''}</div></div></div>
      ${isImage ? '' : `<p class="advice">${esc(L.advice)}</p>`}
    </div>

    <div class="card proof">
      <div class="line">${icon(check.signature ? 'checkCircle' : 'xCircle', 22, check.signature ? 'ok' : 'bad')}<div><b>${check.signature ? 'Signed by your EMCON key: signature valid' : 'Signature INVALID: this file was changed'}</b><span class="mono">${esc(vc.issuer)}</span></div></div>
      <div class="line">${icon(ts === 'valid' ? 'checkCircle' : ts === 'missing' ? 'help' : 'xCircle', 22, ts === 'valid' ? 'ok' : ts === 'missing' ? 'warn' : 'bad')}<div>${ts === 'valid'
        ? `<b>Timestamped ${esc(new Date(check.timestamp.time).toLocaleString())}</b><span>countersigned by the EMCON server, which saw only a hash of this receipt</span>`
        : ts === 'missing' ? '<b>Server unreachable</b><span>Self-timestamped only</span>' : '<b>Timestamp does not verify</b><span>The time may have been edited</span>'}</div></div>
      <div class="line">${icon('info', 22, 'faint')}<div><b>Checked ${esc(new Date(s.checkedAt).toLocaleString())}</b><span>${esc(s.engine.name)} ${esc(s.engine.version)}${isImage ? '' : ` · risk ${s.verdict.risk}/100, the sum of the points below`}</span></div></div>
    </div>

    <div class="section-title" style="font-size:15px">Evidence (${s.checks.length} checks)</div>
    <div class="card" style="padding:2px 16px">${evList([...s.checks].sort(byOrder))}</div>
    ${pathHtml((s.path || []).map((h) => ({ ...h, label: h.host })), s.kind === 'link' ? 'Where the link goes' : 'How the browser got there', role)}
    ${s.privacy ? `<div class="section-title" style="font-size:15px">Privacy promises</div>
      <p class="small muted" style="margin:0 2px 8px">${s.privacy.thirdPartyDomains} other sites contacted, ${s.privacy.trackingDomains} tracking companies. Consent: ${esc(s.privacy.consent)}.</p>
      <div class="card" style="padding:2px 16px">${evList(s.privacy.promises.map((p) => ({ status: p.status, label: p.promise, detail: p.evidence })))}</div>` : ''}

    <div class="actions">
      <button class="primary" id="dl">${icon('download', 18)}Download receipt (.json)</button>
      <button id="copy">${icon('copy', 18)}Copy</button>
      <a class="btn" href="${esc(server)}/verify.html" target="_blank" rel="noopener">${icon('external', 18)}Open the public verifier</a>
    </div>
    <div class="notice role-neutral note">${icon('info', 18)}<div>Anyone can check this file. The signature proves it came from your EMCON key unchanged; the timestamp proves when it existed. It doesn't prove a site is guilty. It proves exactly what EMCON observed.</div></div>`;
  const json = JSON.stringify(vc, null, 2);
  $('#dl').onclick = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    a.download = `emcon-receipt-${(s.domain || 'image').replace(/[^a-z0-9.-]/gi, '_')}-${s.checkedAt.slice(0, 10)}.json`;
    a.click();
  };
  $('#copy').onclick = async () => { await navigator.clipboard.writeText(json); $('#copy').lastChild.textContent = 'Copied'; };
  window.__receipt = vc; // handy for testing
} catch (e) {
  $('#title').textContent = 'Could not build a receipt';
  $('#body').innerHTML = `<div class="notice role-caution" style="margin-top:10px">${icon('alert', 18)}<div>${esc(e.message)}</div></div>`;
}
