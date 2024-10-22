use std::mem::transmute;
use std::io::{Error, Result};

use ntapi::ntioapi::{FileEaInformation, NtQueryEaFile, NtQueryInformationFile, NtSetEaFile, FILE_EA_INFORMATION, IO_STATUS_BLOCK};
use winapi::shared::ntdef::*;

pub unsafe fn read_ea(file_handle: HANDLE) -> Result<Vec<u8>> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut ea_info = FILE_EA_INFORMATION::default();
  
    // Query the Extended Attribute length
    let nt_status = NtQueryInformationFile(
        file_handle, 
        transmute(&mut isb), 
        transmute(&mut ea_info), 
        size_of::<FILE_EA_INFORMATION>() as u32, 
        FileEaInformation
    );
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] NtQueryInformationFile: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
    }

    let mut buf = vec![0u8; ea_info.EaSize as usize];

    let nt_status = NtQueryEaFile(
        file_handle,
        transmute(&mut isb), 
        transmute(buf.as_mut_ptr()),
        ea_info.EaSize,
        FALSE, // read all ea entries to buffer
        NULL,
        0,
        transmute(NULL),
        FALSE
    );
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] NtQueryEaFile: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
    }

    return Ok(buf);
}

pub unsafe fn write_ea(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtSetEaFile(
        file_handle,
        transmute(&mut isb), 
        transmute(buf.as_ptr()),
        buf.len() as ULONG,
    );
    if ! NT_SUCCESS(nt_status) {
        println!("[ERROR] NtQueryEaFile: {:#x}", nt_status);
        return Err(Error::from_raw_os_error(nt_status));
    }
    Ok(())
}