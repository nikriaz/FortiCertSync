# FortiCertSync

FortiCertSync is a lightweight utility to synchronize renewed TLS certificates from a Windows server (where they are automatically managed by Let's Encrypt / Certify The Web / win-acme or similar) into a FortiGate firewall.

FortiGate can use certificates for SSL inspection, SSL-VPN, virtual servers, etc. When these certificates are renewed in Windows, FortiGate does not update automatically. FortiCertSync bridges this gap.

## How it works

- Finds the latest valid certificate in the Windows certificate store matching Subject and Issuer of the FortiGate slot.
- If a newer certificate is found, imports it into FortiGate under a new unique name (certificate name + renewal date).
- Rebinds all FortiGate objects that referenced the old certificate to the new one.
- If the rebind succeeds and no references to the old certificate remain, the old certificate is deleted from FortiGate.
- Logs all actions to `<AssemblyName>.log`.

This approach avoids fragile in‑place updates (which are not consistently supported by FortiOS API).

## Configuration

Configuration is provided via an INI file placed next to the executable.  
On first run, the app will encrypt your FortiGate API key with Windows DPAPI and rewrite it in place.

### Example configuration

```ini
; ============================
; FortiCertSync configuration
; ============================

[fortigate]
; Base URL of your FortiGate (GUI address). Use https and the correct port.
; Examples:
;   https://fg1.example.com
;   https://192.168.1.1:4443
baseUrl = https://fgt.example.com

; [OPTIONAL] VDOM name.
; If VDOMs are OFF, this may be omitted, blank, or "root".
; If VDOMs are ON, specify the target VDOM here.
vdom = root

; API key for the FortiGate API user.
; First run must use the plain text token. The app will verify it and then
; rewrite this value as DPAPI-encrypted: enc:<base64>
; IMPORTANT: The DPAPI encryption is per-user (CurrentUser). Run the app under
; the same account that will execute it on schedule, or switch the code to LocalMachine.
apiKey = PUT_YOUR_PLAIN_API_KEY_HERE_ON_FIRST_RUN

; Certificate name for automatic renewals.
; Section header must be [cert:<FortiGate_certname>].
; Example: [cert:example_A]
;
; Certificate name can include a suffix with a date in format _ddMMyyyy:
;   example_A_01022025
; The app will ignore the date part when matching.
;
; Workflow:
; - Retrieves the latest valid certificate for this name pattern from Forti.
; - Reads Subject (CN) and Issuer (O) from it.
; - Picks a matching certificate from Windows store.
; - If newer, imports into FortiGate as <name>_<ddMMyyyy>.
; - Rebinds references from the old cert to the new one.
; - Deletes the old cert if rebound was successful and no references remain.

[cert:example_A]

; [OPTIONAL] Windows certificate store to search.
; Default is LocalMachine\My (typical IIS/win-acme location).
store = LocalMachine\My

; [OPTIONAL] Override Subject to search in Windows store.
; Wildcards allowed, e.g. *.example.com.
subject = *.example.com

; [OPTIONAL] Override Issuer to search in Windows store.
; By default, Issuer (O) from Forti cert is matched against Windows Issuer.
; This parameter can override; it matches against Issuer (O) or Issuer (CN).
issuer = R11

; Minimal example:
; [fortigate]
; baseUrl = https://fgt.example.com
; apiKey = PUT_YOUR_PLAIN_API_KEY_HERE_ON_FIRST_RUN
;
; [cert:example_A]
; [cert:example_B]
```

## Usage

1. Create an API user in FortiGate with permission to manage certificates and generate an API key.
2. Place the INI file next to `FortiCertSync.exe`.
3. Schedule it daily via Windows Task Scheduler, run with highest privileges and under an account that has access to Windows store private keys to synchronize.
4. Run once manually via 'Run' in Windows Task Scheduler to ensure that app has access to Forti and the API key got encrypted. 

## Logging

A log file `<AssemblyName>.log` will be created in the working directory and appended to on each run.

## License

Released under the **MIT License**. See [LICENSE](LICENSE).


