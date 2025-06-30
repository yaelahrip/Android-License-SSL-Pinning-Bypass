# 🔓 Android License Verification & SSL Pinning Bypass Template

> **Disclaimer**: This project is solely intended for **educational and research** purposes. Its primary purpose is to help developers, security researchers, and enthusiasts understand how Android protections work internally. **Never use** these techniques on apps you don’t own or without explicit authorization. Unauthorized tampering may be illegal and unethical.

---

## 📁 Project Structure Overview

Before diving into the folder structure, here’s a quick summary of what each directory and file is for and how you should use them in your bypass workflow:

* **`README.md`**: This file. Start here to understand what this project does and how to use it.
* **`LICENSE`**: Standard license information. We recommend MIT for permissive sharing.
* **`images/`**: Contains visual examples (e.g., screenshot of a successful bypass or Frida hook output) to help visualize the attack flow.
* **`frida/`**: Houses Frida-based runtime bypass scripts (like `ssl_bypass.js`) that you attach during dynamic analysis.
* **`smali/`**: Includes patched smali source files (like `LicenseClient.smali`) which demonstrate how static patching can be used to bypass Google LVL checks. Also contains documentation for each modification.
* **`tools/`**: Contains helper instructions and toolchain usage (such as how to use Apktool for decompiling and rebuilding APKs).

```
android-bypass-educational/
├── README.md                   # 🧠 Project documentation
├── LICENSE                     # 📄 License file (MIT recommended)
├── images/
│   └── bypass-example.png      # 📸 Visual example
├── frida/
│   └── ssl_bypass.js           # 🧪 Frida script for SSL Pinning Bypass
├── smali/
│   ├── LicenseClient.smali     # 🧱 Targeted smali patch file (Google LVL)
│   └── README.md               # 📄 Explanation of patches
└── tools/
    └── apktool-instructions.md  # 🛠️ How to decompile and recompile APKs
```

---

## 📌 Background: Android Protections

Most Android apps deploy at least two key defensive layers:

### 1. **Google License Verification Library (LVL)**

Used to verify whether the app was downloaded via a legitimate Google Play account. This uses a service called `com.android.vending.licensing.ILicensingService` to validate purchases.

### 2. **SSL Pinning (Certificate Pinning)**

SSL Pinning restricts the app to only communicate with trusted server certificates. It protects against interception tools like Burp Suite or Charles Proxy by refusing to trust standard root certificates.

---

## 🛠️ Tools & Environment

* [APKTool](https://ibotpeaches.github.io/Apktool/): APK decompilation/recompilation
* [Frida](https://frida.re/): Dynamic instrumentation toolkit
* ADB + Emulator or rooted physical Android device
* Jadx GUI or CLI (optional but helpful for Java source decompilation)

---

## 🧩 Smali Patch: Bypassing Google License Verification

### 🔎 Targeted Smali Class:

`com/pairip/licensecheck/LicenseClient.smali`

### 🎯 Objective:

Trick the application into believing it has a valid license every time, regardless of actual response from Google LVL server.

### 🪛 Patch Breakdown

| Step | Method Name              | Smali Location                 | Patch Action                            | Purpose / Reason                             |
| ---- | ------------------------ | ------------------------------ | --------------------------------------- | -------------------------------------------- |
| 1    | `<clinit>`               | Static class initializer       | Set `licenseCheckState` to `OK`         | Preload state as “licensed” when class loads |
| 2    | `processResponse()`      | Start of method body           | Set `responseCode = 0`                  | Simulates success response from LVL service  |
| 3    | `checkLicenseInternal()` | Binder callback or switch case | Skip logic that handles invalid results | Prevent app from acting on unlicensed state  |

### 🧠 Example Smali Snippets

```smali
# Inside <clinit>
sput-object v0, Lcom/pairip/licensecheck/LicenseClient;->licenseCheckState:Lcom/pairip/licensecheck/LicenseClient$LicenseCheckState;
```

```smali
# Inside processResponse()
const/4 p1, 0x0  # Force responseCode to 0 (LICENSED)
```

### 📌 Alternative Hack:

NOP out entire license-checking logic or inject this method call inside your app’s Application class:

```smali
invoke-static {}, Lcom/pairip/licensecheck/LicenseClient;->initLicenseBypass()V
```

This initializes your patch before any LVL logic triggers.

---

## 🔐 Bypassing SSL Pinning (Frida Approach)

### 🔍 Problem

Apps using certificate pinning will deny connections from MITM tools (like Burp) even if system CA certs are trusted. Frida can dynamically replace the app’s `TrustManager`.

### 🎯 Objective

Inject a fake `TrustManager` that accepts all SSL certificates, bypassing the check in runtime memory without modifying the APK.

### 💉 Frida Script: `frida/ssl_bypass.js`

```js
Java.perform(function () {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    ).implementation = function (k, t, s) {
        console.log("[+] Bypassing SSL Pinning");

        var TrustManager = Java.registerClass({
            name: 'dev.untrusted.TrustManager',
            implements: [Java.use('javax.net.ssl.X509TrustManager')],
            methods: {
                checkClientTrusted: function () {},
                checkServerTrusted: function () {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        this.init(k, [TrustManager.$new()], s);
    };
});
```

### ▶️ Usage

Run the script live against the app process using Frida:

```bash
frida -U -n com.target.app -l ssl_bypass.js
```

### 🧠 Behind the Scenes:

This replaces any `TrustManager` supplied to `SSLContext.init()` with a custom version that does no validation, effectively disabling SSL pinning entirely.

---

## 🔧 Rebuilding Patched APK (APKTool Flow)

```bash
apktool d target.apk -o output_folder
# Edit smali as needed
apktool b output_folder -o patched.apk
jarsigner -keystore debug.keystore patched.apk alias_name
adb install -r patched.apk
```

### ⚠️ Notes:

* Check that `AndroidManifest.xml` remains consistent
* Make sure package name and `smali/` structure are preserved

---

## ⚖️ Responsible Disclosure & Ethics

Reverse engineering can be used for good or bad. This project exists to help you:

✅ Learn internals of APK protections
✅ Enhance your own app’s security
✅ Analyze malware and spyware behavior

🚫 Do NOT:

* Circumvent payment checks for commercial gain
* Redistribute modified apps
* Use techniques on others’ apps without permission

Use your knowledge responsibly.

---

## 📜 License

Released under the [MIT License](LICENSE). Attribution is appreciated if this helped you learn.

---

## 👨‍🔬 Contributions & Extensions

Pull requests and community contributions are welcomed, especially:

* More bypass examples (e.g. root/jailbreak detection, anti-debug)
* Automated smali patching tools
* Tutorials on reversing, malware analysis, or instrumentation

---

## 👤 Author

Crafted by a veteran reverse engineer with 20+ years of experience in software security, instrumentation, and Android internals. Shared here to empower ethical research and knowledge-sharing.
