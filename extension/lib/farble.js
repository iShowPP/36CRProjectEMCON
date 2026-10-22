// Runs in the page's MAIN world before page scripts. Two jobs, sharing one set of
// disguised wrappers so neither can be spotted by toString() checks:
//
//  1. Anti-fingerprinting ("farbling"), when `seedHex` is given:
//     * noise is a pure function of (secret seed, pixel index): stable on a site, different across sites
//     * high-entropy values are bucketed to the most common value ("hide in the crowd")
//     * screen size / locale / timezone are never faked (that breaks sites and is easy to detect)
//
//  2. Privacy monitor, when `watch` is true: counts uses of fingerprinting and sensitive
//     browser features and reports them as `emcon:feature` events to the content script.
//
// Serialised by chrome.scripting.executeScript, so it must be self-contained.
export function farble(seedHex, watch) {
  const noise = !!seedHex;
  const seed = noise ? parseInt(seedHex.slice(0, 8), 16) >>> 0 : 0;
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

  // --- privacy monitor channel ---
  const counts = Object.create(null);
  const emit = (f) => {
    if (!watch) return;
    const n = (counts[f] = (counts[f] || 0) + 1);
    if (n > 20 && n % 25) return; // keep noisy APIs from flooding the channel
    document.dispatchEvent(new CustomEvent('emcon:feature', { detail: JSON.stringify({ f, n }) }));
  };
  if (watch) {
    // The content script may load after page scripts already ran: let it ask for the totals so far.
    document.addEventListener('emcon:feature-dump', () => {
      document.dispatchEvent(new CustomEvent('emcon:feature-snapshot', { detail: JSON.stringify(counts) }));
    });
  }

  // --- wrappers that look native ---
  const nativeToString = Function.prototype.toString;
  const masks = new WeakMap();
  const toString = function toString() { return masks.has(this) ? masks.get(this) : nativeToString.call(this); };
  masks.set(toString, nativeToString.call(nativeToString));
  Object.defineProperty(Function.prototype, 'toString', { ...Object.getOwnPropertyDescriptor(Function.prototype, 'toString'), value: toString });
  const disguise = (fake, real) => {
    masks.set(fake, nativeToString.call(real));
    Object.defineProperty(fake, 'name', { value: real.name, configurable: true });
    Object.defineProperty(fake, 'length', { value: real.length, configurable: true });
    return fake;
  };
  const wrap = (proto, name, make) => {
    const d = proto && Object.getOwnPropertyDescriptor(proto, name);
    if (!d || typeof d.value !== 'function') return;
    Object.defineProperty(proto, name, { ...d, value: disguise(make(d.value), d.value) });
  };
  const wrapGetter = (proto, name, make) => {
    const d = proto && Object.getOwnPropertyDescriptor(proto, name);
    if (!d || !d.get) return;
    Object.defineProperty(proto, name, { ...d, get: disguise(make(d.get), d.get) });
  };
  const observe = (proto, name, feature) => wrap(proto, name, (orig) => function (...a) { emit(feature); return orig.apply(this, a); });

  // --- Canvas 2D ---
  const C2D = window.CanvasRenderingContext2D?.prototype;
  const rawGetImageData = C2D?.getImageData;
  const readback = (orig) => function (...a) { emit('canvas-readback'); const img = orig.apply(this, a); noisify(img.data); return img; };
  wrap(C2D, 'getImageData', readback);
  wrap(window.OffscreenCanvasRenderingContext2D?.prototype, 'getImageData', readback);
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
  const CanvasP = window.HTMLCanvasElement?.prototype;
  wrap(CanvasP, 'toDataURL', (orig) => function (...a) { emit('canvas-readback'); return orig.apply(noisyCopy(this), a); });
  wrap(CanvasP, 'toBlob', (orig) => function (...a) { emit('canvas-readback'); return orig.apply(noisyCopy(this), a); });

  // --- WebGL: bucket GPU strings, noise readPixels ---
  const plat = navigator.platform || '';
  const gpu = plat.startsWith('Win')
    ? ['Google Inc. (Intel)', 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)']
    : plat.startsWith('Mac')
      ? ['Google Inc. (Apple)', 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)']
      : null;
  for (const GL of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
    if (!GL) continue;
    wrap(GL.prototype, 'getParameter', (orig) => function (p) {
      if (p === 0x9245 || p === 0x9246) { // UNMASKED_VENDOR / UNMASKED_RENDERER
        emit('gpu-query');
        if (noise && gpu) return gpu[p === 0x9245 ? 0 : 1];
      }
      return orig.call(this, p);
    });
    wrap(GL.prototype, 'readPixels', (orig) => function (...a) {
      emit('canvas-readback');
      const r = orig.apply(this, a);
      const buf = a.find((x) => x instanceof Uint8Array);
      if (buf) noisify(buf);
      return r;
    });
  }

  // --- Audio ---
  const touched = new WeakSet();
  wrap(window.AudioBuffer?.prototype, 'getChannelData', (orig) => function (...a) {
    const data = orig.apply(this, a);
    if (!touched.has(data)) {
      touched.add(data);
      emit('audio-fingerprint');
      if (noise) for (let i = 0; i < data.length; i += 97) data[i] += ((mix(seed ^ i) & 0xff) - 128) * 1e-9;
    }
    return data;
  });
  wrap(window.AnalyserNode?.prototype, 'getFloatFrequencyData', (orig) => function (arr) {
    emit('audio-fingerprint');
    orig.call(this, arr);
    if (noise) for (let i = 0; i < arr.length; i++) arr[i] += ((mix(seed ^ i) & 0xff) - 128) * 1e-5;
  });

  // --- Hardware: bucket high-entropy values ---
  if (noise) wrapGetter(window.Navigator?.prototype, 'hardwareConcurrency', (orig) => function () { return orig.call(this) >= 8 ? 8 : 4; });

  // --- Sensitive features (observed only) ---
  if (watch) {
    observe(window.FontFaceSet?.prototype, 'check', 'font-probing');
    observe(window.Geolocation?.prototype, 'getCurrentPosition', 'location');
    observe(window.Geolocation?.prototype, 'watchPosition', 'location');
    observe(window.MediaDevices?.prototype, 'getUserMedia', 'camera-mic');
    observe(window.MediaDevices?.prototype, 'enumerateDevices', 'device-list');
    observe(window.Clipboard?.prototype, 'readText', 'clipboard-read');
    observe(window.Clipboard?.prototype, 'read', 'clipboard-read');
    observe(window.Navigator?.prototype, 'getBattery', 'battery');
    observe(window.Navigator?.prototype, 'sendBeacon', 'beacon');
    if (window.Notification?.requestPermission) {
      const orig = window.Notification.requestPermission;
      Object.defineProperty(window.Notification, 'requestPermission', { configurable: true, writable: true, value: disguise(function (...a) { emit('notifications'); return orig.apply(this, a); }, orig) });
    }
  }
}
