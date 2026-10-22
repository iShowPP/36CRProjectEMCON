import { send, $, esc } from './msg.js';
import { verifyReceipt } from '../lib/receipt.js';

const q = new URLSearchParams(location.search);
const STATUS = { found: 'Found', unknown: 'Unknown', good: 'Good', note: 'Note', clear: 'Clear', na: 'N/A', kept: 'Kept', broken: 'Broken', untested: 'Untested' };
const HEAD = { danger: 'Very likely a scam', caution: 'Be careful', trusted: 'Trusted by your network', unknown: 'No warning signs found' };
const rows = (list) => `<ol class="ev">${list.map((r) => `<li class="${r.status}"><span class="tag">${STATUS[r.status] || r.status}</span><div><b>${esc(r.label)}</b><span class="d">${esc(r.detail)}${r.points ? ` <span class="mono">(${r.points > 0 ? '+' : ''}${r.points})</span>` : ''}</span></div></li>`).join('')}</ol>`;

try {
  const vc = await send({ type: 'receipt:create', ...(q.get('img') ? { image: q.get('img') } : { tabId: Number(q.get('tab')) }) });
  const s = vc.credentialSubject;
  const { server } = await send({ type: 'settings:get' });
  let tsDid = null;
  try { tsDid = (await (await fetch(server + '/api/timestamp/key')).json()).did; } catch { /* offline */ }
  const check = await verifyReceipt(vc, { timestampDid: tsDid });

  const title = s.kind === 'image' ? s.verdict.summary : HEAD[s.verdict.level];
  $('#title').textContent = title;
  if (s.kind === 'website') $('#doc').classList.add(s.verdict.level);
  $('#body').innerHTML = `
    <dl>
      <dt>Subject</dt><dd class="mono">${esc(s.id)}</dd>
      <dt>Checked</dt><dd>${esc(new Date(s.checkedAt).toLocaleString())}</dd>
      ${s.kind === 'website' ? `<dt>Risk score</dt><dd>${s.verdict.risk}/100 (sum of the points below)</dd>` : ''}
      <dt>Signed by</dt><dd class="mono">${esc(vc.issuer)} · ${check.signature ? '<span class="ok">signature valid</span>' : '<span class="bad">signature INVALID</span>'}</dd>
      <dt>Timestamp</dt><dd>${check.timestamp.status === 'valid' ? `<span class="ok">${esc(new Date(check.timestamp.time).toLocaleString())}</span>, countersigned by the EMCON server (it saw only a hash of this receipt)` : check.timestamp.status === 'missing' ? '<span class="warn">Server unreachable: self-timestamped only</span>' : '<span class="bad">Timestamp does not verify</span>'}</dd>
      <dt>Engine</dt><dd>${esc(s.engine.name)} ${esc(s.engine.version)}</dd>
    </dl>
    <h2>Evidence</h2>
    ${rows(s.checks)}
    ${s.path?.length > 1 ? `<h2>How the browser got there</h2><div class="chainline">${s.path.map((h, i) => `${i ? ` <i>→ ${esc(h.via)} →</i> ` : ''}${esc(h.host)}`).join('')}</div>` : ''}
    ${s.privacy ? `<h2>Privacy promises</h2><p class="small muted">${s.privacy.thirdPartyDomains} third-party domain(s), ${s.privacy.trackingDomains} known tracker(s); consent: ${esc(s.privacy.consent)}.</p>${rows(s.privacy.promises.map((p) => ({ status: p.status, label: p.promise, detail: p.evidence })))}` : ''}
    <div class="actions">
      <button class="primary" id="dl">Download receipt (.json)</button>
      <button id="copy">Copy JSON</button>
      <a href="${esc(server)}/verify.html" target="_blank" rel="noopener"><button>Open the public verifier</button></a>
    </div>
    <p class="small muted" style="margin-top:12px">Anyone can check this file: the signature proves it came from your EMCON key unchanged, and the timestamp proves when it existed. It does not prove the page was a scam; it proves exactly what EMCON observed.</p>`;
  const json = JSON.stringify(vc, null, 2);
  $('#dl').onclick = () => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    a.download = `emcon-receipt-${(s.domain || 'image').replace(/[^a-z0-9.-]/gi, '_')}-${s.checkedAt.slice(0, 10)}.json`;
    a.click();
  };
  $('#copy').onclick = async () => { await navigator.clipboard.writeText(json); $('#copy').textContent = 'Copied'; };
  window.__receipt = vc; // handy for testing
} catch (e) {
  $('#title').textContent = 'Could not build a receipt';
  $('#body').innerHTML = `<p>${esc(e.message)}</p>`;
}
