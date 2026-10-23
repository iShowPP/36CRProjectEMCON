import { createApp } from './app.js';
import { DEMO } from './config.js';
import { flush } from './store.js';

const PORT = Number(process.env.PORT) || 8787;
const server = await createApp();
server.listen(PORT, () => {
  console.log(`\n  EMCON server running on http://localhost:${PORT}/`);
  console.log(`  Sign in ............ http://localhost:${PORT}/login`);
  console.log(`  Dashboard .......... http://localhost:${PORT}/app`);
  console.log(`  On real websites ... http://localhost:${PORT}/real.html`);
  if (DEMO) console.log('  Test site (EMCON_DEMO_SITE=1) is being served from test/site');
  console.log('');
});

// Render stops the old instance on every deploy: write pending changes first.
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, async () => { await flush(); process.exit(0); });
