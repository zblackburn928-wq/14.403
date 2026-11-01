/* HEN 14.00 payload adapter for the browser (WebKit) side.
 *
 * This file does two things and nothing else:
 *   1. fetches hen.bin and proves it is byte-identical to the image the
 *      BD-J Xlet accepts (size, first byte 0xE9, SHA-256), and
 *   2. exposes the kexec step: copy the payload into kernel memory and jump
 *      to its entry.
 *
 * Step 2 needs a *kernel* write primitive. The browser primitive in
 * rw1400.html is userland-only, so kexec() refuses with an explicit list of
 * what is missing instead of pretending to run. There is no code path in
 * here that turns userland R/W into kernel R/W.
 *
 * Payload provenance: hen.iso -> BDMV/JAR/00000.jar -> bonk/hen.bin
 * (the same SHA-256 is hard-coded in org/bdj/InitXlet.class as HEN_SHA256).
 */
(function () {
  "use strict";

  var HEN14 = {};

  HEN14.meta = {
    url: new URL("hen14/hen.bin", document.baseURI).href,
    size: 562240,
    sha256: "29ec095fbede651e29954de43411599093138791e62105aaee6fdced58edec06",
    firstByte: 0xe9, // crt0 jmp, i.e. a flat payload and not an ELF
    entryOffset: 0,
    source: "hen.iso / BDMV/JAR/00000.jar / bonk/hen.bin",
  };

  // ---------------------------------------------------------------- SHA-256
  var K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function ror(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256Bytes(bytes) {
    var l = bytes.length;
    var total = ((l + 9 + 63) >> 6) << 6;
    var buf = new Uint8Array(total);
    buf.set(bytes);
    buf[l] = 0x80;
    var dv = new DataView(buf.buffer);
    dv.setUint32(total - 8, Math.floor(l / 0x20000000));
    dv.setUint32(total - 4, (l << 3) >>> 0);

    var H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
      0x1f83d9ab, 0x5be0cd19,
    ]);
    var w = new Uint32Array(64);

    for (var off = 0; off < total; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (i = 16; i < 64; i++) {
        var s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3];
      var e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        var S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    var out = "";
    for (i = 0; i < 8; i++) out += ("00000000" + H[i].toString(16)).slice(-8);
    return out;
  }

  HEN14.sha256Hex = function (bytes) {
    // Old WebKit builds may not ship crypto.subtle; the JS path is the
    // reference implementation and is used whenever subtle is absent.
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
      return crypto.subtle.digest("SHA-256", bytes.buffer).then(function (d) {
        var v = new Uint8Array(d), s = "";
        for (var i = 0; i < v.length; i++) s += ("0" + v[i].toString(16)).slice(-2);
        return s;
      }).catch(function () {
        return sha256Bytes(bytes);
      });
    }
    return Promise.resolve(sha256Bytes(bytes));
  };

  // ------------------------------------------------------------- fetch+check
  HEN14.loadPayload = function () {
    return fetch(HEN14.meta.url).then(function (r) {
      if (!r.ok) throw new Error("fetch " + r.status + " " + HEN14.meta.url);
      return r.arrayBuffer();
    }).then(function (buf) {
      var bytes = new Uint8Array(buf);
      if (bytes.length !== HEN14.meta.size)
        throw new Error("size " + bytes.length + " != " + HEN14.meta.size);
      if (bytes[0] !== HEN14.meta.firstByte)
        throw new Error("first byte 0x" + bytes[0].toString(16) + " != 0xe9");
      return HEN14.sha256Hex(bytes).then(function (hex) {
        if (hex !== HEN14.meta.sha256)
          throw new Error("sha256 " + hex.slice(0, 16) + "... != expected");
        return bytes;
      });
    });
  };

  // ---------------------------------------------------------------- kexec
  HEN14.requirements = [
    "kernel=true primitive (not the userland forged view)",
    "kalloc(size) -> kernel address for the 562240-byte image",
    "kwrite(kaddr, bytes) over that whole buffer",
    "kjump(entry) with uid already patched to 0 (HEN expects kernel context)",
  ];

  HEN14.kexec = function (prim, payload) {
    var missing = [];
    if (!prim) {
      missing.push("kernel primitive object");
    } else {
      if (prim.kernel !== true) missing.push("kernel=true (this is userland-only)");
      if (typeof prim.kalloc !== "function") missing.push("kalloc(size)");
      if (typeof prim.kwrite !== "function") missing.push("kwrite(kaddr, bytes)");
      if (typeof prim.kjump !== "function") missing.push("kjump(entry)");
    }
    if (missing.length)
      throw new Error("HEN14-KEXEC-REFUSED missing: " + missing.join("; "));

    var buf = prim.kalloc(payload.length);
    if (!buf) throw new Error("HEN14-KEXEC-REFUSED kalloc returned 0");
    prim.kwrite(buf, payload);
    prim.kjump(buf + HEN14.meta.entryOffset);
    return buf;
  };

  // ------------------------------------------------------------------ driver
  HEN14.run = function (opts) {
    opts = opts || {};
    var log = opts.log || function () {};
    var flush = opts.flush || function () {};

    log("HEN14", opts.note || "payload check");
    flush();

    HEN14.loadPayload().then(function (payload) {
      log("HEN14-PAYLOAD",
        "verified " + payload.length + " bytes" +
        " sha256=" + HEN14.meta.sha256.slice(0, 16) + "..." +
        " first=0x" + payload[0].toString(16));
      flush();
      try {
        HEN14.kexec(opts.primitive || null, payload);
        log("HEN14-KEXEC", "handed to kernel");
      } catch (e) {
        log("HEN14-KEXEC", (e && e.message) || String(e));
      }
      flush();
    }).catch(function (e) {
      log("HEN14-PAYLOAD", "FAIL " + ((e && e.message) || e));
      flush();
    });
  };

  window.HEN14 = HEN14;
})();
