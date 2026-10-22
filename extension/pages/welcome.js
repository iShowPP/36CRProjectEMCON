import { send, $, esc } from './msg.js';
import { fillIcons } from './ui.js';

fillIcons();

async function check() {
  const { server } = await send({ type: 'settings:get' });
  $('#server').value = server;
  $('#status').textContent = 'Checking…';
  try {
    const r = await fetch(server + '/api/wot/groups', { credentials: 'omit' });
    const groups = await r.json();
    if (!r.ok || !Array.isArray(groups)) throw new Error('not an EMCON server');
    $('#status').innerHTML = `<span class="ok" style="font-weight:650">Connected.</span> Following ${groups.map((g) => esc(g.name)).join(', ')} for scam reports.`;
    $('#t-wot').textContent = 'active now';
    $('#t-wot').className = 'pill role-safe';
  } catch (e) {
    $('#status').innerHTML = `<span class="bad">Can't reach ${esc(server)}</span> (${esc(e.message)}). Enter your EMCON server's address above.`;
  }
  const g = await send({ type: 'ghost:status' }).catch(() => null);
  if (g?.enrolled) { $('#t-ghost').textContent = 'active now'; $('#t-ghost').className = 'pill role-safe'; $('#ghost').classList.add('hidden'); }
}

$('#check').onclick = async () => {
  await send({ type: 'settings:set', patch: { server: $('#server').value.trim().replace(/\/+$/, '') } });
  check();
};
$('#server').onkeydown = (e) => e.key === 'Enter' && $('#check').click();
$('#ghost').onclick = () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/setup.html') });
check();
