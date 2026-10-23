import { send, $, esc } from './msg.js';
import { icon, fillIcons } from './ui.js';

fillIcons();
const q = new URLSearchParams(location.search);

// ---------- tabs ----------
function tab(name) {
  document.querySelectorAll('.tabs button').forEach((b) => b.classList.toggle('on', b.dataset.tab === name));
  for (const t of ['contact', 'vouch', 'scan', 'list']) $('#t-' + t).classList.toggle('hidden', t !== name);
  if (name !== 'scan') stopCam();
  if (name === 'list') renderList();
}
document.querySelectorAll('.tabs button').forEach((b) => (b.onclick = () => tab(b.dataset.tab)));

// ---------- drawing a QR ----------
function qrHtml(text, caption) {
  const qr = window.qrcode(0, 'M');
  qr.addData(text, 'Byte');
  qr.make();
  return `<div class="qrbox">${qr.createSvgTag({ cellSize: 6, margin: 4, scalable: true })}</div>
    <p class="small muted" style="text-align:center;margin:0 0 8px">${caption}</p>
    <div class="payload">${esc(text)}</div>
    <div class="row" style="margin-top:10px;justify-content:center"><button class="sm" data-copy="${esc(text)}">${icon('copy', 16)}Copy text</button><button class="sm" data-save>${icon('download', 16)}Save as image</button></div>`;
}
function wireQr(root, filename) {
  root.querySelector('[data-copy]').onclick = async (e) => { await navigator.clipboard.writeText(e.currentTarget.dataset.copy); e.currentTarget.lastChild.textContent = 'Copied'; };
  root.querySelector('[data-save]').onclick = () => {
    const svg = root.querySelector('.qrbox svg').outerHTML;
    const img = new Image();
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = c.height = 600;
      const g = c.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, 600, 600); g.drawImage(img, 0, 0, 600, 600);
      const a = document.createElement('a'); a.href = c.toDataURL('image/png'); a.download = filename; a.click();
    };
    img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  };
}

// ---------- my contact code ----------
$('#nick').value = localStorage.getItem('emcon-nick') || '';
$('#mkContact').onclick = async () => {
  localStorage.setItem('emcon-nick', $('#nick').value);
  const r = await send({ type: 'qr:contact', nickname: $('#nick').value });
  $('#contactOut').innerHTML = qrHtml(r.text, `${esc($('#nick').value || 'Your')} EMCON contact code. Only show it to people you know.`);
  wireQr($('#contactOut'), 'emcon-contact.png');
};

// ---------- vouch ----------
if (q.get('domain')) $('#vDomain').value = q.get('domain');
async function vouch(claim) {
  try {
    const r = await send({ type: 'qr:attest', domain: $('#vDomain').value, claim });
    $('#vouchOut').innerHTML = `<div class="notice role-${claim === 'safe' ? 'safe' : 'danger'}" style="margin-top:14px">${icon(claim === 'safe' ? 'checkCircle' : 'alert', 18)}<div>Signed: <b>${claim === 'safe' ? 'I used' : 'Scam warning for'} ${esc(r.domain)}</b>${claim === 'safe' ? ' safely' : ''}. Valid until ${new Date(r.expires).toLocaleDateString()}. Let your friends scan this.</div></div>`
      + qrHtml(r.text, `Signed by your EMCON key. Changing one character breaks it.`);
    wireQr($('#vouchOut'), `emcon-${claim}-${r.domain}.png`);
  } catch (e) { $('#vouchOut').innerHTML = `<p class="bad small" style="margin-top:10px">${esc(e.message)}</p>`; }
}
$('#mkSafe').onclick = () => vouch('safe');
$('#mkScam').onclick = () => vouch('scam');

// ---------- scanning ----------
let stream = null, raf = 0, busy = false;
function stopCam() { cancelAnimationFrame(raf); stream?.getTracks().forEach((t) => t.stop()); stream = null; $('#video').classList.add('hidden'); }
$('#cam').onclick = async () => {
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const v = $('#video');
    v.srcObject = stream; v.classList.remove('hidden'); await v.play();
    const c = document.createElement('canvas'), g = c.getContext('2d', { willReadFrequently: true });
    const tick = () => {
      if (!stream) return;
      if (v.videoWidth && !busy) {
        c.width = v.videoWidth; c.height = v.videoHeight; g.drawImage(v, 0, 0);
        const code = window.jsQR(g.getImageData(0, 0, c.width, c.height).data, c.width, c.height, { inversionAttempts: 'dontInvert' });
        if (code?.data) { stopCam(); handle(code.data); return; }
      }
      raf = requestAnimationFrame(tick);
    };
    tick();
  } catch (e) { $('#scanOut').innerHTML = `<p class="bad small">Camera unavailable (${esc(e.name || e.message)}). Upload an image or paste the code instead.</p>`; }
};
$('#file').onchange = async () => {
  const f = $('#file').files[0];
  if (!f) return;
  const bmp = await createImageBitmap(f);
  const c = document.createElement('canvas'); c.width = bmp.width; c.height = bmp.height;
  const g = c.getContext('2d'); g.drawImage(bmp, 0, 0);
  const code = window.jsQR(g.getImageData(0, 0, c.width, c.height).data, c.width, c.height);
  $('#file').value = '';
  code?.data ? handle(code.data) : ($('#scanOut').innerHTML = '<p class="bad small">No QR code found in that image. Try a sharper, straight-on photo.</p>');
};
$('#usePaste').onclick = () => handle($('#paste').value);

async function handle(text) {
  busy = true;
  try {
    const r = await send({ type: 'qr:import', text });
    if (r.kind === 'contact') {
      if (r.isMe) { $('#scanOut').innerHTML = `<div class="notice role-neutral">${icon('info', 18)}<div>That's your own contact code.</div></div>`; return; }
      $('#scanOut').innerHTML = `<div class="panel role-safe"><div class="hero"><span class="dot-icon">${icon('users', 24)}</span><div><h1 style="font-size:20px">${esc(r.nickname || 'Someone')}'s contact code</h1><div class="where">Signature checked: this key really made this code.${r.known ? ` Already in your contacts as <b>${esc(r.known)}</b>.` : ''}</div></div></div>
        <label for="cName">Save as</label><input id="cName" value="${esc(r.nickname)}">
        <label for="cTrust">How much do you trust them?</label><select id="cTrust"><option value="1">Completely</option><option value="0.7" selected>A lot</option><option value="0.4">Somewhat</option></select>
        <p class="tiny faint mono" style="margin:8px 0 0">${esc(r.did)}</p>
        <button class="primary block" id="cAdd" style="margin-top:12px">Add to people I trust</button></div>`;
      $('#cAdd').onclick = async () => {
        await send({ type: 'wot:trust', did: r.did, label: $('#cName').value || r.nickname || 'Friend', weight: $('#cTrust').value, publish: false });
        $('#scanOut').innerHTML = `<div class="notice role-safe">${icon('checkCircle', 18)}<div><b>${esc($('#cName').value || r.nickname)}</b> is now in your contacts. Their vouches and warnings will count in your checks.</div></div>`;
      };
      return;
    }
    const safe = r.claim === 'safe';
    $('#scanOut').innerHTML = `<div class="panel role-${safe ? 'safe' : 'danger'}"><div class="hero"><span class="dot-icon">${icon(safe ? 'checkCircle' : 'alert', 24)}</span><div>
      <h1 style="font-size:20px">${esc(r.from)} ${safe ? 'vouches for' : 'warns about'} ${esc(r.domain)}</h1>
      <div class="where">Signature valid · signed ${new Date(r.issued).toLocaleDateString()} · valid until ${new Date(r.expires).toLocaleDateString()}</div></div></div>
      <p class="advice">${r.stored ? `Saved. When you open ${esc(r.domain)}, EMCON counts this ${safe ? 'vouch' : 'warning'}.` : 'You already have this, or a newer one from the same person.'}</p></div>`;
  } catch (e) {
    $('#scanOut').innerHTML = `<div class="notice role-danger">${icon('xCircle', 18)}<div><b>Rejected.</b> ${esc(e.message)}</div></div>`;
  } finally { busy = false; }
}

// ---------- list ----------
async function renderList() {
  const list = await send({ type: 'qr:list' });
  $('#listOut').innerHTML = `<div class="card" style="padding:2px 16px">${list.length ? list.map((a) => `<div class="src" style="display:flex;gap:10px;align-items:center;padding:12px 0;border-bottom:1px solid var(--border)">
      <span class="pill role-${a.claim === 'safe' ? 'safe' : 'danger'}">${a.claim === 'safe' ? 'Vouch' : 'Scam'}</span>
      <div style="flex:1"><b>${esc(a.domain)}</b><div class="small muted">from ${esc(a.from)} · until ${new Date(a.expires).toLocaleDateString()}</div></div>
      <button class="sm" data-rm="${esc(a.issuer)}|${esc(a.domain)}">Remove</button></div>`).join('')
    : '<p class="muted" style="padding:14px 0;margin:0">No vouches yet. Scan a friend\'s contact code, then their vouches.</p>'}</div>`;
  document.querySelectorAll('[data-rm]').forEach((b) => (b.onclick = async () => { const [issuer, domain] = b.dataset.rm.split('|'); await send({ type: 'qr:remove', issuer, domain }); renderList(); }));
}

tab(q.get('tab') || (q.get('domain') ? 'vouch' : 'contact'));
