use stargate::*;
use std::error::Error;

pub struct StargateResolver {
    nt_db: SignatureDatabase,
    k32_db: SignatureDatabase,
}

impl StargateResolver {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // Extract signatures for both core DLLs
        let nt_db = extract_all_signatures("ntdll", 32)
            .map_err(|_| "Failed ntdll signatures")?;
        let k32_db = extract_all_signatures("kernel32", 32)
            .map_err(|_| "Failed kernel32 signatures")?;
            
        Ok(Self { nt_db, k32_db })
    }

    pub fn resolve_nt(&self, name: &str) -> Option<*mut std::ffi::c_void> {
        find_specific_function("ntdll", name, &self.nt_db)
            .map(|res| res.found_address as *mut std::ffi::c_void)
    }

    pub fn resolve_k32(&self, name: &str) -> Option<*mut std::ffi::c_void> {
        find_specific_function("kernel32", name, &self.k32_db)
            .map(|res| res.found_address as *mut std::ffi::c_void)
    }
}

