import { send, $, esc } from './msg.js';

const id = new URLSearchParams(location.search).get('id');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

let info;
try { info = await send({ type: 'ghost:approval-info', id }); } catch (e) { $('#msg').textContent = '⚠️ ' + e.message; }

if (info) {
  $('#origin').textContent = info.origin;
  $('#shares').innerHTML = [
    `A pseudonym that only exists on <b>${esc(new URL(info.origin).host)}</b>`,
    'Proof that you are a verified human',
    ...(info.claims.includes('over18') ? ['Proof that you are over 18 (not your age or birthdate)'] : []),
    ...(info.isNewSite ? ['One single-use humanity token (stops fake mass sign-ups)'] : ['Nothing new: you already have an account here']),
  ].map((s) => `<li>${s}</li>`).join('');
  if (info.unlock === 'pin') $('#pinBox').classList.remove('hidden');
}

$('#ok').onclick = async () => {
  try {
    if (info.unlock === 'passkey') {
      // Local user-verification gate: proves a human is present at this device right now.
      await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), allowCredentials: [{ type: 'public-key', id: fromB64u(info.credId) }], userVerification: 'required', timeout: 60000 } });
    }
    await send({ type: 'ghost:approve', id, ok: true, pin: $('#pin').value });
    window.close();
  } catch (e) { $('#msg').textContent = '⚠️ ' + (e.message || e.name); }
};
$('#no').onclick = async () => { await send({ type: 'ghost:approve', id, ok: false }).catch(() => {}); window.close(); };
$('#pin').onkeydown = (e) => e.key === 'Enter' && $('#ok').click();
