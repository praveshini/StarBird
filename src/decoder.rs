



use windows::Win32::Networking::WinSock::RtlIpv4StringToAddressA;
use windows::core::PCSTR;

pub unsafe fn ip_to_bytes(ips: &[&str]) -> Vec<u8> {
    let mut shellcode = Vec::with_capacity(ips.len() * 4);
    
    for ip in ips {
        let mut terminator = PCSTR::null();
        let ip_str = format!("{}\0", ip);
        let mut temp_bytes = [0u8; 4]; // Local buffer 
        
        unsafe {
            let _ = RtlIpv4StringToAddressA(
                PCSTR(ip_str.as_ptr()), 
                false, 
                &mut terminator, 
                temp_bytes.as_mut_ptr() as *mut _
            );
        }
        shellcode.extend_from_slice(&temp_bytes);
    }
    shellcode
}

