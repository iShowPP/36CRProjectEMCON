import { send, $ } from './msg.js';
import { fillIcons } from './ui.js';

fillIcons();

const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
let credId = null;

$('#passkey').onclick = async () => {
  try {
    const cred = await navigator.credentials.create({
      publicKey: {
        rp: { name: 'EMCON Ghost' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'emcon-ghost', displayName: 'EMCON Ghost (this browser)' },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { userVerification: 'required', residentKey: 'discouraged' },
        timeout: 60000,
      },
    });
    credId = b64u(cred.rawId);
    $('#pkMsg').textContent = 'Passkey created. Sign-ins will ask for it.';
  } catch (e) {
    $('#pkMsg').textContent = `Passkey unavailable here (${e.name}). Use the PIN option instead.`;
  }
};

$('#go').onclick = async () => {
  $('#go').disabled = true;
  $('#msg').textContent = 'Verifying and minting blind tokens…';
  try {
    const s = await send({ type: 'ghost:enroll', dob: $('#dob').value, credId, pin: $('#pin').value });
    const { server } = await send({ type: 'settings:get' });
    $('#msg').className = 'notice role-safe';
    $('#msg').innerHTML = `Done. You hold ${Object.entries(s.tokens).map(([b, n]) => `${n} "${b}" tokens`).join(' and ')}.<br>Try it at <a href="${server}/rp.html" target="_blank">ShopNorth</a>, a demo site that accepts Ghost sign-in. You can close this tab.`;
  } catch (e) {
    $('#msg').textContent = e.message;
    $('#go').disabled = false;
  }
};
