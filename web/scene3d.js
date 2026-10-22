// EMCON hero scene: a 3D globe of the web, an extruded EMCON shield in front of it, and links
// flying in. Scam links bounce off the shield's field (with a "Blocked" tag); safe links pass.
// Plain canvas 2D with our own projection: no WebGL library, no third-party script.
export function mountScene(canvas, { compact = false, onDark = false } = {}) {
  const ctx = canvas.getContext('2d');
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const darkQ = matchMedia('(prefers-color-scheme: dark)');
  let W = 0, H = 0;
  const resize = () => {
    const dpr = Math.min(2, devicePixelRatio || 1);
    const r = canvas.getBoundingClientRect();
    W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };
  let ready = false;
  new ResizeObserver(() => { resize(); if (ready) draw(performance.now(), 0); }).observe(canvas);
  resize();

  // ---------- math ----------
  const rotY = ([x, y, z], a) => [x * Math.cos(a) + z * Math.sin(a), y, -x * Math.sin(a) + z * Math.cos(a)];
  const rotX = ([x, y, z], a) => [x, y * Math.cos(a) - z * Math.sin(a), y * Math.sin(a) + z * Math.cos(a)];
  const add = (a, b) => [a[0] + b[0], a[1] + b[1], a[2] + b[2]];
  const sub = (a, b) => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
  const mul = (a, k) => [a[0] * k, a[1] * k, a[2] * k];
  const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
  const len = (a) => Math.hypot(a[0], a[1], a[2]);
  const norm = (a) => mul(a, 1 / (len(a) || 1));
  const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
  const CAM = 5.2;
  let view = { yaw: 0, pitch: 0 };
  const cam = (p) => rotX(rotY(p, view.yaw), view.pitch);
  const project = (p) => {
    const q = cam(p);
    const z = q[2] + CAM;
    const f = (Math.min(W, H * 1.25) * 0.5) * 2.1 / z;
    return [W * (compact ? 0.5 : 0.52) + q[0] * f, H * 0.5 - q[1] * f, z, f];
  };

  // ---------- globe: points on a sphere + traffic arcs ----------
  const G = { c: [0.25, 0.05, 1.4], r: compact ? 1.6 : 1.85 };
  const N = compact ? 380 : 620;
  const globe = Array.from({ length: N }, (_, i) => {
    const y = 1 - (2 * (i + 0.5)) / N, rr = Math.sqrt(1 - y * y), th = i * Math.PI * (3 - Math.sqrt(5));
    return [Math.cos(th) * rr, y, Math.sin(th) * rr];
  });
  const hubs = Array.from({ length: 12 }, (_, i) => globe[Math.floor((i * 97.3) % N)]);
  const arcs = Array.from({ length: 9 }, (_, i) => ({ a: hubs[i], b: hubs[(i * 5 + 3) % hubs.length], t: Math.random() }));
  const onGlobe = (u, spin) => add(G.c, mul(rotY(u, spin), G.r));
  const slerp = (a, b, t) => {
    const om = Math.acos(Math.max(-1, Math.min(1, dot(a, b))));
    if (om < 1e-3) return a;
    const s = Math.sin(om);
    return add(mul(a, Math.sin((1 - t) * om) / s), mul(b, Math.sin(t * om) / s));
  };

  // ---------- shield: the EMCON mark, extruded ----------
  const S = { c: [-0.15, 0, -0.55], size: compact ? 0.72 : 0.8, depth: 0.3, field: compact ? 1.0 : 1.12 };
  const outline = (() => {
    // unit mark: flat top at y=+0.86, straight sides to the shoulder, elliptical curve to the point
    const half = 0.82, top = 0.86, shoulder = -0.04, bottom = -0.9, pts = [[-half, top], [half, top], [half, shoulder]];
    for (let i = 1; i <= 14; i++) { const a = (i / 14) * (Math.PI / 2); pts.push([half * Math.cos(a), shoulder - (shoulder - bottom) * Math.sin(a)]); }
    for (let i = 13; i >= 0; i--) { const a = (i / 14) * (Math.PI / 2); pts.push([-half * Math.cos(a), shoulder - (shoulder - bottom) * Math.sin(a)]); }
    return pts;
  })();
  const inner = outline.map(([x, y]) => [x * 0.8, y * 0.8 + 0.02]);
  const bar = [[-0.4, 0.06], [0.4, 0.06], [0.4, -0.12], [-0.4, -0.12]];
  let shieldRot = { yaw: 0, pitch: 0 };
  const shieldPt = ([x, y], zOff) => add(S.c, rotX(rotY([x * S.size, y * S.size, zOff], shieldRot.yaw), shieldRot.pitch));

  // ---------- link traffic ----------
  const SCAMS = ['Fake KYC update', 'Parcel fee scam', 'paypa1-secure.com', 'Prize SMS link', 'Fake bank login', 'Crypto doubling site', 'Look-alike login', 'Digital arrest scam'];
  const parts = [], ripples = [], tags = [];
  let lastTag = 0, nextSpawn = 0;
  function spawn(now) {
    const bad = Math.random() < 0.62;
    const ang = Math.random() * Math.PI * 2;
    const dir = norm([Math.cos(ang) * 1.6, (Math.random() - 0.5) * 1.4, -1.2 - Math.random() * 0.8]);
    const p = add(S.c, mul(dir, 3.6 + Math.random()));
    const target = add(S.c, [(Math.random() - 0.5) * 0.5, (Math.random() - 0.5) * 0.5, 0]);
    parts.push({ p, v: mul(norm(sub(target, p)), 1.25 + Math.random() * 0.5), bad, hit: false, born: now, trail: [] });
  }

  // ---------- pointer ----------
  let mx = 0, my = 0, tmx = 0, tmy = 0;
  addEventListener('pointermove', (e) => { tmx = (e.clientX / innerWidth - 0.5) * 2; tmy = (e.clientY / innerHeight - 0.5) * 2; }, { passive: true });

  // ---------- frame ----------
  let visible = true, last = performance.now(), t = 0;
  new IntersectionObserver(([e]) => { visible = e.isIntersecting; }).observe(canvas);
  const LIGHT = norm([-0.5, 0.7, -1]);

  function frame(now) {
    const dt = Math.min(0.05, (now - last) / 1000);
    last = now;
    if (visible && !document.hidden) { t += reduce ? 0 : dt; draw(now, reduce ? 0 : dt); }
    if (!reduce) requestAnimationFrame(frame);
  }

  function draw(now, dt) {
    const dark = onDark || darkQ.matches;
    const C = dark
      ? { dot: '200,214,255', arc: '96,140,255', body: [30, 41, 72], side: [96, 112, 156], bar: '#f97316', line: '#e7ecf6', field: '82,139,255', bad: '#f97066', good: '#47cd89', text: '#f5f5f6', tagBg: 'rgba(22,27,38,.92)' }
      : { dot: '29,78,216', arc: '29,78,216', body: [23, 23, 26], side: [74, 88, 124], bar: '#f97316', line: '#f5f2eb', field: '29,78,216', bad: '#d92d20', good: '#067647', text: '#101828', tagBg: 'rgba(255,255,255,.95)' };
    mx += (tmx - mx) * 0.05; my += (tmy - my) * 0.05;
    view = { yaw: mx * 0.18, pitch: -my * 0.1 + 0.04 };
    shieldRot = { yaw: Math.sin(t * 0.55) * 0.32 + mx * 0.35, pitch: Math.sin(t * 0.4) * 0.06 - my * 0.15 };
    ctx.clearRect(0, 0, W, H);

    // globe
    const spin = t * 0.12;
    for (const u of globe) {
      const p = onGlobe(u, spin);
      const [x, y, z, f] = project(p);
      const facing = cam(sub(p, G.c))[2]; // < 0: front half
      const a = facing < 0 ? 0.55 : 0.14;
      ctx.fillStyle = `rgba(${C.dot},${a})`;
      const r = Math.max(0.6, f * 0.012);
      ctx.fillRect(x - r / 2, y - r / 2, r, r);
    }
    // traffic arcs with pulses
    for (const arc of arcs) {
      arc.t = (arc.t + dt * 0.35) % 1;
      ctx.beginPath();
      for (let i = 0; i <= 24; i++) {
        const u = norm(slerp(arc.a, arc.b, i / 24));
        const lift = 1 + Math.sin((i / 24) * Math.PI) * 0.22;
        const [x, y] = project(add(G.c, mul(rotY(u, spin), G.r * lift)));
        i ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      }
      ctx.strokeStyle = `rgba(${C.arc},0.18)`;
      ctx.lineWidth = 1;
      ctx.stroke();
      const u = norm(slerp(arc.a, arc.b, arc.t));
      const [x, y] = project(add(G.c, mul(rotY(u, spin), G.r * (1 + Math.sin(arc.t * Math.PI) * 0.22))));
      ctx.fillStyle = `rgba(${C.arc},0.8)`;
      ctx.beginPath(); ctx.arc(x, y, 2, 0, 7); ctx.fill();
    }

    // shield field (a soft disc that lights up where scams hit)
    const [fx, fy, , ff] = project(S.c);
    const fr = S.field * ff;
    const grad = ctx.createRadialGradient(fx, fy, fr * 0.2, fx, fy, fr);
    grad.addColorStop(0, `rgba(${C.field},0.10)`);
    grad.addColorStop(0.85, `rgba(${C.field},0.05)`);
    grad.addColorStop(1, `rgba(${C.field},0)`);
    ctx.fillStyle = grad;
    ctx.beginPath(); ctx.arc(fx, fy, fr, 0, 7); ctx.fill();
    ctx.strokeStyle = `rgba(${C.field},0.22)`;
    ctx.setLineDash([3, 6]); ctx.lineWidth = 1;
    ctx.beginPath(); ctx.arc(fx, fy, fr * 0.97, 0, 7); ctx.stroke();
    ctx.setLineDash([]);

    // traffic
    if (!reduce && now > nextSpawn) { spawn(now); nextSpawn = now + (compact ? 520 : 380) + Math.random() * 300; }
    const behind = [], front = [];
    for (let i = parts.length - 1; i >= 0; i--) {
      const q = parts[i];
      q.p = add(q.p, mul(q.v, dt));
      const off = sub(q.p, S.c), d = len(off);
      if (q.bad && !q.hit && d < S.field) {
        const n = norm(off);
        q.v = mul(sub(q.v, mul(n, 2 * dot(q.v, n))), 0.85);
        q.hit = true;
        ripples.push({ p: q.p, t: 0 });
        if (now - lastTag > 1300) { tags.push({ p: q.p, t: 0, text: SCAMS[Math.floor(Math.random() * SCAMS.length)] }); lastTag = now; }
      }
      q.trail.push(q.p);
      if (q.trail.length > 14) q.trail.shift();
      const age = (now - q.born) / 1000;
      if (age > 6 || (!q.bad && d < 0.25) || d > 7) { parts.splice(i, 1); continue; }
      (cam(off)[2] > 0 ? behind : front).push(q);
    }
    const drawPart = (q) => {
      const col = q.bad ? C.bad : C.good;
      ctx.strokeStyle = col;
      ctx.lineCap = 'round';
      for (let k = 1; k < q.trail.length; k++) {
        const [x0, y0] = project(q.trail[k - 1]), [x1, y1] = project(q.trail[k]);
        ctx.globalAlpha = (k / q.trail.length) * (q.hit ? 0.35 : 0.6);
        ctx.lineWidth = 2;
        ctx.beginPath(); ctx.moveTo(x0, y0); ctx.lineTo(x1, y1); ctx.stroke();
      }
      const [x, y, , f] = project(q.p);
      ctx.globalAlpha = q.hit ? 0.55 : 1;
      ctx.fillStyle = col;
      ctx.beginPath(); ctx.arc(x, y, Math.max(2, f * 0.03), 0, 7); ctx.fill();
      ctx.globalAlpha = 1;
    };
    behind.forEach(drawPart);

    // shield faces, back to front, flat shaded
    const faces = [];
    const n = outline.length;
    const front3 = outline.map((p) => shieldPt(p, -S.depth / 2)), back3 = outline.map((p) => shieldPt(p, S.depth / 2));
    for (let i = 0; i < n; i++) {
      const j = (i + 1) % n;
      faces.push({ pts: [front3[i], front3[j], back3[j], back3[i]], kind: 'side' });
    }
    faces.push({ pts: back3.slice().reverse(), kind: 'back' });
    faces.push({ pts: front3, kind: 'front' });
    for (const f of faces) {
      const c = f.pts.reduce((a, p) => add(a, p), [0, 0, 0]).map((v) => v / f.pts.length);
      f.z = cam(c)[2];
      const nn = norm(cross(sub(f.pts[1], f.pts[0]), sub(f.pts[2], f.pts[0])));
      f.n = cam(nn);
    }
    faces.sort((a, b) => b.z - a.z);
    for (const f of faces) {
      if (f.kind !== 'front' && f.kind !== 'back' && f.n[2] > 0.05) continue; // cull far side walls
      const base = f.kind === 'side' ? C.side : C.body;
      const lum = 0.55 + 0.6 * Math.max(0, -dot(f.n, LIGHT));
      ctx.fillStyle = `rgb(${base.map((v) => Math.min(255, Math.round(v * lum + (f.kind === 'side' ? 18 : 6)))).join(',')})`;
      ctx.beginPath();
      f.pts.forEach((p, k) => { const [x, y] = project(p); k ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.closePath(); ctx.fill();
    }
    // front details: inner line + orange bar, plus a light sweep
    const poly = (pts, z) => { ctx.beginPath(); pts.forEach((p, k) => { const [x, y] = project(shieldPt(p, z)); k ? ctx.lineTo(x, y) : ctx.moveTo(x, y); }); ctx.closePath(); };
    poly(inner, -S.depth / 2 - 0.001);
    ctx.strokeStyle = C.line; ctx.lineWidth = Math.max(1.5, ff * 0.03); ctx.stroke();
    poly(bar, -S.depth / 2 - 0.002);
    ctx.fillStyle = C.bar; ctx.fill();
    const sweep = (t * 0.25) % 1.6 - 0.3;
    if (sweep > 0 && sweep < 1) {
      ctx.save();
      poly(outline, -S.depth / 2 - 0.003); ctx.clip();
      const [sx, sy] = project(shieldPt([-1 + sweep * 2, 0.9], -S.depth / 2));
      const g2 = ctx.createLinearGradient(sx - 40, sy, sx + 40, sy + 120);
      g2.addColorStop(0, 'rgba(255,255,255,0)'); g2.addColorStop(0.5, 'rgba(255,255,255,0.10)'); g2.addColorStop(1, 'rgba(255,255,255,0)');
      ctx.fillStyle = g2; ctx.fillRect(0, 0, W, H);
      ctx.restore();
    }

    front.forEach(drawPart);

    // impact ripples + "Blocked" tags
    for (let i = ripples.length - 1; i >= 0; i--) {
      const r = ripples[i];
      r.t += dt;
      if (r.t > 0.9) { ripples.splice(i, 1); continue; }
      const [x, y, , f] = project(r.p);
      ctx.strokeStyle = C.bad; ctx.globalAlpha = 1 - r.t / 0.9; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.arc(x, y, f * (0.05 + r.t * 0.35), 0, 7); ctx.stroke();
      ctx.globalAlpha = 1;
    }
    ctx.font = `600 ${compact ? 11 : 12.5}px "Segoe UI Variable Text","Segoe UI",system-ui,sans-serif`;
    for (let i = tags.length - 1; i >= 0; i--) {
      const g = tags[i];
      g.t += dt;
      if (g.t > 2.2) { tags.splice(i, 1); continue; }
      const [x, y] = project(g.p);
      const label = `Blocked · ${g.text}`;
      const w = ctx.measureText(label).width + 22, h = compact ? 22 : 26;
      const a = g.t < 0.2 ? g.t / 0.2 : g.t > 1.7 ? (2.2 - g.t) / 0.5 : 1;
      const tx = Math.max(6, Math.min(W - w - 6, x + 10)), ty = Math.max(6, y - h - 10 - g.t * 14);
      ctx.globalAlpha = a;
      ctx.fillStyle = C.tagBg;
      ctx.beginPath(); ctx.roundRect(tx, ty, w, h, h / 2); ctx.fill();
      ctx.strokeStyle = C.bad; ctx.lineWidth = 1; ctx.stroke();
      ctx.fillStyle = C.bad; ctx.beginPath(); ctx.arc(tx + 11, ty + h / 2, 3.5, 0, 7); ctx.fill();
      ctx.fillStyle = C.text; ctx.fillText(label, tx + 19, ty + h / 2 + 4.5);
      ctx.globalAlpha = 1;
    }
  }

  // reduced motion: one still frame with a blocked scam shown
  // for screenshots and tests: fast-forward the animation
  canvas.__advance = (sec) => { let now = performance.now(); for (let i = 0; i < sec * 60; i++) { now += 1000 / 60; t += 1 / 60; draw(now, 1 / 60); } };
  ready = true;
  if (reduce) { for (let k = 0; k < 6; k++) spawn(performance.now()); draw(performance.now(), 0.016); }
  else { spawn(performance.now()); draw(performance.now(), 0.016); requestAnimationFrame(frame); }
}
