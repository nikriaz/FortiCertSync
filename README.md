# FortiCertSync

**FortiCertSync** keeps your FortiGate certificates in sync with the certificates renewed on a Windows host (e.g., via Let’s Encrypt / ACME).

When FortiGate features (SSL/SSH inspection, load balancer virtual servers, etc.) depend on the same TLS cert as your Windows services, renewals on Windows do **not** automatically propagate to FortiGate. Neither Windows nor FortiGate provide built-in sync, and existing scripts are often brittle or inconvenient. **FortiCertSync** solves this by automatically detecting the newest matching cert in the Windows store and **updating the corresponding certificate entry on FortiGate in place**—no manual rebinds required.

---

## Features

- Windows-native single EXE (C# / .NET 8 **NativeAOT**)
- Picks the **newest valid** cert for each subject from the Windows Certificate Store
- Compares against FortiGate and **updates in-place** only when newer
- Supports wildcard subjects (e.g., `*.example.com`)
- FortiGate API key stored encrypted with **Windows DPAPI**
- Simple `.ini` config, auto-generated on first run
- Quiet daily run via Task Scheduler, append-only log

---

## Requirements

- Windows Server or Windows 10/11
- FortiOS **6.4+** or **7.x** with REST API and an **API user + key**
- Your ACME client must create **exportable private keys** (needed to export PFX)

> Examples: win-acme (`PrivateKeyExportable=true`), Certify The Web (enable “Private key exportable”).

---

## Configuration

On first run, if no INI is found, a commented sample is created next to the EXE.  
Expected file name: **`<ExeName>.ini`** (auto-matched to the executable name).

```ini
[fortigate]
; Base URL of your FortiGate (GUI address). Use https and the correct port.
; Examples:
;   https://fg1.example.com
;   https://192.168.1.1:4443
baseUrl = https://fgt.example.com

; VDOM name. If VDOMs are OFF, this might be omitted or must be blank or "root".
vdom = root

; API key for the FortiGate API user.
; First run must use the plain text token. The app will verify it and then
; rewrite this value as DPAPI-encrypted: enc:<base64>
; IMPORTANT: The DPAPI encryption is per-user (CurrentUser). Run the app under
; the same account that will execute it on schedule, or switch the code to LocalMachine.
apiKey = PUT_YOUR_PLAIN_API_KEY_HERE_ON_FIRST_RUN

[certificates]
; Default Windows certificate store to search for all subjects below.
; Typical IIS/Win-ACME location is LocalMachine\My. Might be omitted for this default location.
store = LocalMachine\My

; List each subject you want synchronized. One subject per line.
; Wildcards are fine (e.g., *.example.com). The app will pick the newest valid
; certificate for that subject from the Windows store, compare to Forti, and
; if newer/absent it will UPDATE the Forti certificate in place (same name/slot).
subject = *.example.com
subject = *.example.net
```

---

## Usage

### 1) Create an API user and key on FortiGate

> Use a restricted `accprofile` later; `super_admin` is fine for initial testing.  
> If VDOMs are **enabled**, add the relevant VDOMs; if disabled, omit.

```bash
config system api-user
    edit "certsync"
        set accprofile super_admin
        config trusthost
            edit 1
                set ipv4-trusthost 192.168.1.42 255.255.255.255
            next
        end
    next
end

execute api-user generate-key certsync
```

Copy the printed key into `apiKey` in your INI (the app will encrypt it on first run).

> Tip: If you temporarily want to allow from anywhere, remove trust hosts entirely for that user (having **no** trust hosts is the “allow all” state on some builds). Prefer locking it down to a single host/subnet for production.

### 2) Place files and run once

- Put `FortiCertSync.exe` and your `FortiCertSync.ini` side by side.
- Run from an elevated PowerShell/Console (first run will encrypt the key):

```powershell
.\FortiCertSync.exe
```

- Check `<ExeName>.log` for:
  - “API key encrypted…”
  - “Windows newest: …”
  - “Imported into slot ‘<name>’” (only when a newer cert is found)

### 3) Schedule daily

- Use **Task Scheduler**:
  - Trigger: Daily (e.g., 03:30).
  - **Run with highest privileges**.
  - **Run as the same user** that created the encrypted key (DPAPI CurrentUser), or switch the app to DPAPI LocalMachine if you need a service account.

---

## How it works (in short)

1. Reads subjects from `[certificates]`.
2. Finds the newest valid matching cert (with private key) in the Windows store.
3. Queries FortiGate for cert metadata; parses the PEM to get CN/expiry.
4. If Windows cert is newer, exports **PFX** and **updates** the FortiGate certificate **in-place** (same name/slot) via REST API.

This avoids rebinds—FortiGate objects referring to that certificate keep working after renewal.

---

## Logging

- Log file: **`<ExeName>.log`** (append-only).
- Only user-facing messages, no stack traces.
- Built-in Fortinet factory certificates are silently skipped if they don’t parse.

---

## Security notes

- API key is encrypted with **DPAPI (CurrentUser)** by default.  
  Run the app under the same account that will execute it on schedule.
- If you need multiple accounts, consider switching to `LocalMachine` scope (trade-off: any local admin can decrypt).
- Use trust hosts to restrict the API user to your automation host.

---

## License

Released under the **MIT License**. See [LICENSE](LICENSE).


