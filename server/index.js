import { createApp } from './app.js';

const PORT = Number(process.env.PORT) || 8787;
const server = await createApp();
server.listen(PORT, () => {
  console.log(`\n  EMCON server running\n`);
  console.log(`  Demo hub ............ http://localhost:${PORT}/`);
  console.log(`  Ghost sign-in (RP) .. http://localhost:${PORT}/rp.html   (also try http://127.0.0.1:${PORT}/rp.html)`);
  console.log(`  Provenance studio ... http://localhost:${PORT}/sign.html`);
  console.log(`  Kestrel Bank vault .. http://localhost:${PORT}/vault.html`);
  console.log(`  Phishing clone ...... http://127.0.0.1:${PORT}/phish-login.html\n`);
});
