//! Mobile security prompt generators

use crate::mcp::prompts::types::{get_arg, Args};

pub fn gen_mobile_security(args: &Args) -> String {
  let platform = get_arg(args, "platform", "both");
  let app_name = get_arg(args, "app_name", "unknown");
  let scope = get_arg(args, "scope", "full");

  format!(
    r#"# Mobile Application Security Assessment

## Platform
{platform}

## Application
{app_name}

## Assessment Scope
{scope}

---

Perform mobile security assessment (OWASP MASTG/MASVS):

1. **Architecture Analysis**
   - App architecture
   - Data flows
   - Backend communication
   - Third-party SDKs

2. **Data Storage**
   - Local storage security
   - Keychain/Keystore usage
   - Database encryption
   - Backup security
   - Sensitive data exposure

3. **Cryptography**
   - Crypto implementation
   - Key management
   - Random number generation
   - Crypto configuration

4. **Authentication**
   - Local authentication
   - Biometric security
   - Session management
   - Token handling

5. **Network Security**
   - TLS configuration
   - Certificate pinning
   - API security
   - Traffic analysis

6. **Platform Security**
   - Platform protections
   - Root/jailbreak detection
   - Code tampering
   - Reverse engineering

7. **Code Security**
   - Obfuscation
   - Anti-debugging
   - Integrity checks
   - Dynamic analysis detection

8. **MASVS Compliance**
   | Requirement | Level | Status | Notes |
   |-------------|-------|--------|-------|
   | MASVS-STORAGE | | | |
   | MASVS-CRYPTO | | | |
   | MASVS-AUTH | | | |
   | MASVS-NETWORK | | | |
   | MASVS-PLATFORM | | | |
   | MASVS-CODE | | | |
   | MASVS-RESILIENCE | | | |

9. **Testing Tools**
   - Frida scripts
   - objection commands
   - Static analysis findings
"#
  )
}

pub fn gen_android_security(args: &Args) -> String {
  let apk = get_arg(args, "apk", "unknown");
  let manifest = get_arg(args, "manifest", "not provided");

  format!(
    r#"# Android Security Testing

## APK
{apk}

## AndroidManifest.xml
{manifest}

---

Perform Android-specific security testing:

1. **Manifest Analysis**
   - Permissions review
   - Exported components
   - Debug flags
   - Backup settings
   - Network security config

2. **Component Security**
   - Activities (exported, intents)
   - Services (bound, started)
   - Broadcast receivers
   - Content providers
   - Deep link handling

3. **Data Storage**
   - SharedPreferences
   - SQLite databases
   - Internal/External storage
   - Keystore usage
   - Backup exclusions

4. **Network Security**
   - Network security config
   - Cleartext traffic
   - Certificate pinning
   - WebView security
   - API communication

5. **Code Analysis**
   - Native libraries
   - ProGuard/R8
   - Reflection usage
   - Dynamic loading
   - JNI security

6. **Root Detection**
   - Detection mechanisms
   - Bypass difficulty
   - Frida detection
   - Magisk Hide

7. **Runtime Testing**
   ```bash
   # Frida commands
   frida -U -f {apk} -l script.js

   # objection commands
   objection -g {apk} explore
   ```

8. **Findings**
   | Component | Vulnerability | Severity | PoC |
   |-----------|--------------|----------|-----|

9. **Recommendations**
   - Code fixes
   - Manifest changes
   - Storage hardening
"#
  )
}

pub fn gen_ios_security(args: &Args) -> String {
  let ipa = get_arg(args, "ipa", "unknown");
  let entitlements = get_arg(args, "entitlements", "not provided");

  format!(
    r#"# iOS Security Testing

## IPA/Bundle
{ipa}

## Entitlements
{entitlements}

---

Perform iOS-specific security testing:

1. **Binary Analysis**
   - PIE enabled
   - ARC usage
   - Stack canaries
   - Code signing
   - Encryption status

2. **Entitlements Review**
   - App groups
   - Keychain access
   - Background modes
   - Push notifications
   - Associated domains

3. **Data Storage**
   - Keychain items
   - NSUserDefaults
   - Core Data/SQLite
   - File protection classes
   - Data backup

4. **Network Security**
   - ATS configuration
   - Certificate pinning
   - URLSession security
   - WebView settings

5. **Authentication**
   - Local authentication
   - TouchID/FaceID
   - Keychain ACLs
   - Token storage

6. **IPC Security**
   - URL schemes
   - Universal links
   - Pasteboard
   - App extensions

7. **Runtime Testing**
   ```bash
   # Frida commands
   frida -U {ipa} -l ios-hooks.js

   # objection commands
   objection -g {ipa} explore
   ```

8. **Static Analysis**
   - Objective-C classes
   - Swift symbols
   - Hardcoded secrets
   - Debug code

9. **Findings**
   | Issue | Class/Method | Severity | PoC |
   |-------|--------------|----------|-----|

10. **Recommendations**
    - Code changes
    - Entitlement fixes
    - Keychain hardening
"#
  )
}
