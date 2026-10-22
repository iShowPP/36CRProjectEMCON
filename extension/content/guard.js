// EMCON page guard: runs in the page's MAIN world at document_start, BEFORE any page
// script (registered by the service worker; its flags come from the content/cfg/*.js
// files listed before it). Two jobs, sharing one set of wrappers that look native
// (native toString, no prototype, not constructible):
//
//  1. Anti-fingerprinting (cfg.noise):
//     * noise comes from a secret random seed made here, kept in this closure and never
//       exposed, so a tracker can't undo it; it is stable for the page (reading twice
//       matches) and different on every site and every visit
//     * high-entropy values are bucketed to the most common value ("hide in the crowd")
//     * screen size / locale / timezone are never faked (that breaks sites and is easy to detect)
//     * same-origin iframes are patched the moment the page touches them, so a fresh
//       about:blank frame can't be used to read untouched canvas functions
//  2. Privacy monitor (cfg.watch): counts uses of fingerprinting and sensitive browser
//     features and reports them as `emcon:feature` events to the content script.
//  Plus Global Privacy Control (cfg.gpc): navigator.globalPrivacyControl = true.
(() => {
  const cfg = window.__emconGuardCfg || {};
  try { delete window.__emconGuardCfg; } catch { /* non-configurable in odd frames */ }
  const noise = !!cfg.noise, watch = !!cfg.watch, gpc = !!cfg.gpc;
  if (!noise && !watch && !gpc) return;
  const seed = noise ? crypto.getRandomValues(new Uint32Array(1))[0] : 0;
  const mix = (x) => {
    x = Math.imul(x ^ (x >>> 16), 0x85ebca6b);
    x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35);
    return (x ^ (x >>> 16)) >>> 0;
  };
  const noisify = (data) => {
    if (!noise) return;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i + 3] === 0) continue;
      const h = mix(seed ^ (i >>> 2));
      if (h % 53 === 0) data[i + ((h >>> 8) % 3)] ^= 1;
    }
  };
  const isBytes = (x) => Object.prototype.toString.call(x) === '[object Uint8Array]';

  // --- privacy monitor channel ---
  const counts = Object.create(null);
  const emit = (f) => {
    if (!watch) return;
    const n = (counts[f] = (counts[f] || 0) + 1);
    if (n > 20 && n % 25) return; // keep noisy APIs from flooding the channel
    document.dispatchEvent(new CustomEvent('emcon:feature', { detail: JSON.stringify({ f, n }) }));
  };
  if (watch) {
    // The content script loads later: let it ask for the totals so far.
    document.addEventListener('emcon:feature-dump', () => {
      document.dispatchEvent(new CustomEvent('emcon:feature-snapshot', { detail: JSON.stringify(counts) }));
    });
  }

  // --- wrappers that look native ---
  const nativeToString = Function.prototype.toString;
  const masks = new WeakMap();
  // A method (not a `function`) has no .prototype and can't be `new`ed, like the real thing.
  const fakeOf = (real, body) => {
    const fake = { [real.name](...a) { return body.call(this, real, a); } }[real.name];
    masks.set(fake, nativeToString.call(real));
    Object.defineProperty(fake, 'length', { value: real.length, configurable: true });
    return fake;
  };
  const wrap = (obj, name, body) => {
    const d = obj && Object.getOwnPropertyDescriptor(obj, name);
    if (d && typeof d.value === 'function') Object.defineProperty(obj, name, { ...d, value: fakeOf(d.value, body) });
  };
  const wrapGetter = (obj, name, body) => {
    const d = obj && Object.getOwnPropertyDescriptor(obj, name);
    if (d?.get) Object.defineProperty(obj, name, { ...d, get: fakeOf(d.get, body) });
  };
  const observe = (obj, name, feature) => wrap(obj, name, function (orig, a) { emit(feature); return orig.apply(this, a); });

  const rawGetImageData = window.CanvasRenderingContext2D?.prototype.getImageData;
  const noisyCopy = (canvas) => {
    const w = canvas.width, h = canvas.height;
    if (!noise || !w || !h || w * h > 4e6 || !rawGetImageData) return canvas;
    const c = document.createElement('canvas');
    c.width = w; c.height = h;
    const ctx = c.getContext('2d');
    ctx.drawImage(canvas, 0, 0);
    const img = rawGetImageData.call(ctx, 0, 0, w, h);
    noisify(img.data);
    ctx.putImageData(img, 0, 0);
    return c;
  };
  const plat = navigator.platform || '';
  const gpu = plat.startsWith('Win')
    ? ['Google Inc. (Intel)', 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)']
    : plat.startsWith('Mac')
      ? ['Google Inc. (Apple)', 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)']
      : null;

  const done = new WeakSet();
  const guard = (w) => { try { protect(w); } catch { /* cross-origin: its own copy of this script protects it */ } };

  function protect(w) {
    const FP = w.Function?.prototype;
    if (!FP || done.has(FP)) return;
    done.add(FP);
    wrap(FP, 'toString', function (orig, a) { return masks.has(this) ? masks.get(this) : orig.apply(this, a); });

    // --- Global Privacy Control ---
    const NavP = w.Navigator?.prototype;
    if (gpc && NavP && !('globalPrivacyControl' in NavP)) {
      const get = Object.getOwnPropertyDescriptor({ get globalPrivacyControl() { return true; } }, 'globalPrivacyControl').get;
      masks.set(get, 'function get globalPrivacyControl() { [native code] }');
      Object.defineProperty(NavP, 'globalPrivacyControl', { get, enumerable: true, configurable: true });
    }
    if (!noise && !watch) return;

    // --- iframes: patch a same-origin child window before the page can use it ---
    for (const El of [w.HTMLIFrameElement, w.HTMLFrameElement]) {
      wrapGetter(El?.prototype, 'contentWindow', function (orig, a) { const cw = orig.apply(this, a); if (cw) guard(cw); return cw; });
      wrapGetter(El?.prototype, 'contentDocument', function (orig, a) { const cd = orig.apply(this, a); if (cd?.defaultView) guard(cd.defaultView); return cd; });
    }

    // --- Canvas 2D ---
    const readback = function (orig, a) { emit('canvas-readback'); const img = orig.apply(this, a); noisify(img.data); return img; };
    wrap(w.CanvasRenderingContext2D?.prototype, 'getImageData', readback);
    wrap(w.OffscreenCanvasRenderingContext2D?.prototype, 'getImageData', readback);
    const exportNoisy = function (orig, a) { emit('canvas-readback'); return orig.apply(noisyCopy(this), a); };
    wrap(w.HTMLCanvasElement?.prototype, 'toDataURL', exportNoisy);
    wrap(w.HTMLCanvasElement?.prototype, 'toBlob', exportNoisy);

    // --- WebGL: bucket GPU strings, noise readPixels ---
    for (const GL of [w.WebGLRenderingContext, w.WebGL2RenderingContext]) {
      wrap(GL?.prototype, 'getParameter', function (orig, a) {
        const p = a[0];
        if (p === 0x9245 || p === 0x9246) { // UNMASKED_VENDOR / UNMASKED_RENDERER
          emit('gpu-query');
          if (noise && gpu) return gpu[p === 0x9245 ? 0 : 1];
        }
        return orig.apply(this, a);
      });
      wrap(GL?.prototype, 'readPixels', function (orig, a) {
        emit('canvas-readback');
        const r = orig.apply(this, a);
        const buf = a.find(isBytes);
        if (buf) noisify(buf);
        return r;
      });
    }

    // --- Audio ---
    const touched = new WeakSet();
    wrap(w.AudioBuffer?.prototype, 'getChannelData', function (orig, a) {
      const data = orig.apply(this, a);
      if (!touched.has(data)) {
        touched.add(data);
        emit('audio-fingerprint');
        if (noise) for (let i = 0; i < data.length; i += 97) data[i] += ((mix(seed ^ i) & 0xff) - 128) * 1e-9;
      }
      return data;
    });
    wrap(w.AnalyserNode?.prototype, 'getFloatFrequencyData', function (orig, a) {
      emit('audio-fingerprint');
      orig.apply(this, a);
      const arr = a[0];
      if (noise && arr) for (let i = 0; i < arr.length; i++) arr[i] += ((mix(seed ^ i) & 0xff) - 128) * 1e-5;
    });

    // --- Hardware: bucket high-entropy values ---
    if (noise) wrapGetter(NavP, 'hardwareConcurrency', function (orig, a) { return orig.apply(this, a) >= 8 ? 8 : 4; });

    // --- Sensitive features (observed only) ---
    if (watch) {
      observe(w.FontFaceSet?.prototype, 'check', 'font-probing');
      observe(w.Geolocation?.prototype, 'getCurrentPosition', 'location');
      observe(w.Geolocation?.prototype, 'watchPosition', 'location');
      observe(w.MediaDevices?.prototype, 'getUserMedia', 'camera-mic');
      observe(w.MediaDevices?.prototype, 'enumerateDevices', 'device-list');
      observe(w.Clipboard?.prototype, 'readText', 'clipboard-read');
      observe(w.Clipboard?.prototype, 'read', 'clipboard-read');
      observe(NavP, 'getBattery', 'battery');
      observe(NavP, 'sendBeacon', 'beacon');
      observe(w.Notification, 'requestPermission', 'notifications');
    }
  }

  protect(window);
})();
