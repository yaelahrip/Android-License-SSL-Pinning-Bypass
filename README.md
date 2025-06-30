# 🔓 Android License + SSL Pinning Bypass (Educational Template)

> ⚠️ For educational and research purposes only. Do not use for malicious intent. This knowledge is meant for ethical reverse engineering and learning.

## 📖 Overview

This repository demonstrates how to bypass:

- ✅ Google License Verification (LVL)
- 🔐 SSL Pinning using Frida

It includes:
- Smali patch examples
- Frida scripts
- APKTool usage guide

---

## 🧠 Tools Required

- [APKTool](https://ibotpeaches.github.io/Apktool/)
- [Frida](https://frida.re/)
- [Jadx](https://github.com/skylot/jadx)
- Android Emulator or Rooted Device

---

## 🧩 Smali Patch – Google LVL

File: `smali/LicenseClient.smali`

### Patch Summary:

| Step | Location | Change | Purpose |
|------|----------|--------|---------|
| 1 | `<clinit>` | Force `licenseCheckState = OK` | Bypass license check |
| 2 | `processResponse()` | Force `responseCode = 0` | Always return LICENSED |

---

## 🔥 SSL Pinning Bypass with Frida

File: `frida/ssl_bypass.js`

```js
Java.perform(function () {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom")
        .implementation = function (key, trust, secure) {
            var TrustManager = Java.registerClass({
                name: 'dev.ssl.UnsafeTrustManager',
                implements: [Java.use('javax.net.ssl.X509TrustManager')],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            this.init(key, [TrustManager.$new()], secure);
        };
});
