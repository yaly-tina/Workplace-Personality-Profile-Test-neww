/* 授权码校验模块 —— index.html 与 app.html 共用
 * 站点里只存哈希（dist/hashes.js），明文码只在你自己的「授权码.csv」里
 */
(function () {
  var SALT = 'ZYTU#2026renge';
  var XOR_KEY = 'zyrenge2026';
  var LS = 'zy_unlock_v1';
  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];

  function sha256js(msg) {
    var bytes = new TextEncoder().encode(msg), l = bytes.length;
    var total = Math.ceil((l + 9) / 64) * 64;
    var buf = new Uint8Array(total); buf.set(bytes); buf[l] = 0x80;
    var dv = new DataView(buf.buffer), bitLen = l * 8;
    dv.setUint32(total - 4, bitLen >>> 0);
    dv.setUint32(total - 8, Math.floor(bitLen / 4294967296));
    var w = new Uint32Array(64), H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    for (var i = 0; i < total / 64; i++) {
      var off = i * 64, t;
      for (t = 0; t < 16; t++) w[t] = dv.getUint32(off + t * 4);
      for (t = 16; t < 64; t++) {
        var a15 = w[t-15], a2 = w[t-2];
        var s0 = ((a15>>>7)|(a15<<25)) ^ ((a15>>>18)|(a15<<14)) ^ (a15>>>3);
        var s1 = ((a2>>>17)|(a2<<15)) ^ ((a2>>>19)|(a2<<13)) ^ (a2>>>10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (t = 0; t < 64; t++) {
        var S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
        var ch = (e & f) ^ ((~e) & g);
        var t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
        var S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) >>> 0;
        h=g; g=f; f=e; e=(d+t1)>>>0; d=c; c=b; b=a; a=(t1+t2)>>>0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    return H.map(function (x) { return ('00000000' + x.toString(16)).slice(-8); }).join('');
  }

  var _cache = null;
  function loadCodes() {
    if (_cache) return _cache;
    try {
      var bin = atob(window.ZY_PACK || '');
      var arr = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      var out = new Uint8Array(arr.length);
      for (i = 0; i < arr.length; i++) out[i] = arr[i] ^ XOR_KEY.charCodeAt(i % XOR_KEY.length);
      _cache = JSON.parse(new TextDecoder().decode(out));
    } catch (e) { _cache = []; }
    return _cache;
  }

  function hashOf(code) {
    var s = SALT + code;
    if (window.crypto && crypto.subtle && crypto.subtle.digest) {
      return crypto.subtle.digest('SHA-256', new TextEncoder().encode(s))
        .then(function (b) {
          return Array.prototype.map.call(new Uint8Array(b), function (x) {
            return ('0' + x.toString(16)).slice(-2);
          }).join('');
        }).catch(function () { return sha256js(s); });
    }
    return Promise.resolve(sha256js(s));
  }

  function norm(v) {
    var s = String(v || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (/^ZY/.test(s)) s = s.slice(2);          // 带 ZY 前缀则去掉
    s = s.slice(0, 8);                           // 只留 8 位主体
    if (s.length !== 8) return 'ZY-' + s;        // 不完整时也返回可读形式
    return 'ZY-' + s.slice(0, 4) + '-' + s.slice(4);
  }

  window.ZY = {
    norm: norm,
    verify: function (code) {
      var c = norm(code);
      if (!/^ZY-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(c)) {
        return Promise.resolve({ ok: false, msg: '授权码格式不对，应为 ZY-XXXX-XXXX' });
      }
      var list = loadCodes();
      if (!list.length) return Promise.resolve({ ok: false, msg: '校验表未加载，请刷新重试' });
      return hashOf(c).then(function (full) {
        var h = full.slice(0, 20);
        return list.indexOf(h) >= 0
          ? { ok: true, code: c, fp: full.slice(0, 8) }
          : { ok: false, msg: '授权码无效或未售出，请核对后重试' };
      });
    },
    isUnlocked: function () {
      try { return !!JSON.parse(localStorage.getItem(LS) || 'null'); } catch (e) { return false; }
    },
    unlock: function (code) {
      var self = this;
      return this.verify(code).then(function (r) {
        if (r.ok) {
          try {
            localStorage.setItem(LS, JSON.stringify({ t: Date.now(), fp: r.fp, c: r.code.slice(-4) }));
          } catch (e) {}
        }
        return r;
      });
    },
    info: function () {
      try { return JSON.parse(localStorage.getItem(LS) || 'null'); } catch (e) { return null; }
    },
    reset: function () { try { localStorage.removeItem(LS); } catch (e) {} }
  };
})();
