// Anti-fingerprinting ("farbling"), injected into the page's MAIN world.
//
// Fixes for the naive "inject random dummy metadata" idea:
//  * Random-per-read noise is itself a fingerprint (trackers read twice and compare)
//    -> noise here is a pure function of (secret seed, pixel index): stable per site.
//  * Different per site (and per top-site/iframe pair) -> trackers can't link you
//    across sites, but the site you're on sees a stable, app-safe device.
//  * Faking screen size / locale / timezone breaks layouts and is trivially caught
//    (CSS media queries, Intl) -> we never touch those. High-entropy values are
//    *bucketed* to the most common value instead of randomised ("hide in the crowd").
//
// This function is serialised by chrome.scripting.executeScript, so it must be self-contained.
export function farble(seedHex) {
  const seed = parseInt(seedHex.slice(0, 8), 16) >>> 0;
  const mix = (x) => {
    x = Math.imul(x ^ (x >>> 16), 0x85ebca6b);
    x = Math.imul(x ^ (x >>> 13), 0xc2b2ae35);
    return (x ^ (x >>> 16)) >>> 0;
  };
  const noisify = (data) => {
    for (let i = 0; i < data.length; i += 4) {
      if (data[i + 3] === 0) continue;
      const h = mix(seed ^ (i >>> 2));
      if (h % 53 === 0) data[i + ((h >>> 8) % 3)] ^= 1;
    }
  };

  // Make wrappers indistinguishable from native functions via toString().
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

  // --- Canvas 2D ---
  const C2D = window.CanvasRenderingContext2D?.prototype;
  const rawGetImageData = C2D?.getImageData;
  wrap(C2D, 'getImageData', (orig) => function (...a) { const img = orig.apply(this, a); noisify(img.data); return img; });
  wrap(window.OffscreenCanvasRenderingContext2D?.prototype, 'getImageData', (orig) => function (...a) { const img = orig.apply(this, a); noisify(img.data); return img; });
  const noisyCopy = (canvas) => {
    const w = canvas.width, h = canvas.height;
    if (!w || !h || w * h > 4e6 || !rawGetImageData) return canvas;
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
  wrap(CanvasP, 'toDataURL', (orig) => function (...a) { return orig.apply(noisyCopy(this), a); });
  wrap(CanvasP, 'toBlob', (orig) => function (...a) { return orig.apply(noisyCopy(this), a); });

  // --- WebGL: bucket GPU strings to the most common value for the platform, noise readPixels ---
  const plat = navigator.platform || '';
  const gpu = plat.startsWith('Win')
    ? ['Google Inc. (Intel)', 'ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)']
    : plat.startsWith('Mac')
      ? ['Google Inc. (Apple)', 'ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)']
      : null;
  for (const GL of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
    if (!GL) continue;
    if (gpu) wrap(GL.prototype, 'getParameter', (orig) => function (p) {
      if (p === 0x9245) return gpu[0]; // UNMASKED_VENDOR_WEBGL
      if (p === 0x9246) return gpu[1]; // UNMASKED_RENDERER_WEBGL
      return orig.call(this, p);
    });
    wrap(GL.prototype, 'readPixels', (orig) => function (...a) {
      const r = orig.apply(this, a);
      const buf = a.find((x) => x instanceof Uint8Array);
      if (buf) noisify(buf);
      return r;
    });
  }

  // --- Audio: deterministic sub-audible noise, applied once per buffer ---
  const touched = new WeakSet();
  wrap(window.AudioBuffer?.prototype, 'getChannelData', (orig) => function (...a) {
    const data = orig.apply(this, a);
    if (!touched.has(data)) {
      touched.add(data);
      for (let i = 0; i < data.length; i += 97) data[i] += ((mix(seed ^ i) & 0xff) - 128) * 1e-9;
    }
    return data;
  });
  wrap(window.AnalyserNode?.prototype, 'getFloatFrequencyData', (orig) => function (arr) {
    orig.call(this, arr);
    for (let i = 0; i < arr.length; i++) arr[i] += ((mix(seed ^ i) & 0xff) - 128) * 1e-5;
  });

  // --- Navigator: bucket high-entropy hardware values ---
  wrapGetter(window.Navigator?.prototype, 'hardwareConcurrency', (orig) => function () { return orig.call(this) >= 8 ? 8 : 4; });
}
