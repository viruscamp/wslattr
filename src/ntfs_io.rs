use std::ffi::c_void;
use std::mem::{offset_of, transmute};
use std::io::{Error, Result};
use std::ptr::{addr_of, null_mut};

use windows::core::{PCSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_MORE_DATA, HANDLE, HLOCAL, MAX_PATH, WIN32_ERROR};
use windows::Wdk::Storage::FileSystem::{FileBasicInformation, FileEaInformation, NtQueryEaFile, NtQueryInformationFile, NtSetEaFile, FILE_BASIC_INFORMATION, FILE_EA_INFORMATION, REPARSE_DATA_BUFFER};
use windows::Win32::System::IO::{DeviceIoControl, IO_STATUS_BLOCK};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile, REPARSE_GUID_DATA_BUFFER};
use windows::Win32::System::Ioctl::{FSCTL_DELETE_REPARSE_POINT, FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT};
use windows::Win32::Foundation::GetLastError;
use windows::core::Free;

/// `NtQueryEaFile` can read known EA's, but there are 'LX.LINUX.ATTR.*', so we'd read all.
pub unsafe fn read_ea_all(file_handle: HANDLE) -> Result<Option<Vec<u8>>> {
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
    if nt_status.is_err() {
        println!("[ERROR] NtQueryInformationFile: {:#x}", nt_status.0);
        return Err(Error::from_raw_os_error(nt_status.0));
    }
    if ea_info.EaSize == 0 {
        return Ok(None);
    }

    let mut buf = vec![0u8; ea_info.EaSize as usize];

    let nt_status = NtQueryEaFile(
        file_handle,
        &mut isb,
        transmute(buf.as_mut_ptr()),
        ea_info.EaSize,
        false, // read all ea entries to buffer
        None,
        0,
        None,
        true,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtQueryEaFile: {:#x}", nt_status.0);
        return Err(Error::from_raw_os_error(nt_status.0));
    }

    return Ok(Some(buf));
}

/// It's safe to save only changed EA's.
pub unsafe fn write_ea(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut isb = IO_STATUS_BLOCK::default();
    let nt_status = NtSetEaFile(
        file_handle,
        transmute(&mut isb), 
        transmute(buf.as_ptr()),
        buf.len() as u32,
    );
    if nt_status.is_err() {
        println!("[ERROR] NtSetEaFile: {:#x}", nt_status.0);
        return Err(Error::from_raw_os_error(nt_status.0));
    }
    Ok(())
}

unsafe fn read_reparse_point_inner(file_handle: HANDLE, buf: &mut Vec<u8>) -> Option<WIN32_ERROR> {
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_GET_REPARSE_POINT,
        None,
        0,
        Some(buf.as_mut_ptr() as *mut c_void),
        buf.len() as u32,
        Some(&mut bytes_returned),
        None,
    ).is_ok() {
        //dbg!(buf.len(), bytes_returned);
        buf.truncate(bytes_returned as usize);
        return None;
    }
    let err = GetLastError();
    //dbg!(err.raw_os_error());
    return Some(err);
}

pub unsafe fn read_reparse_point(file_handle: HANDLE) -> Result<Vec<u8>> {
    // a reasonable init buf size 64
    let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + 36;
    let mut buf = vec![0; buf_size];
    match read_reparse_point_inner(file_handle, &mut buf) {
        None => return Ok(buf),
        Some(ERROR_MORE_DATA) => {
            // retry with new buf
            let reparse_buf = buf.as_ptr() as *const REPARSE_GUID_DATA_BUFFER;
            // larger in most case
            let reparse_data_len = (*reparse_buf).ReparseDataLength as usize;
            let buf_size = size_of::<REPARSE_GUID_DATA_BUFFER>() + reparse_data_len;
            let mut buf = vec![0; buf_size];
            match read_reparse_point_inner(file_handle, &mut buf) {
                None => return Ok(buf),
                Some(err) => {
                    println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
                    return Err(Error::from_raw_os_error(err.0 as i32));
                }
            }
        },
        Some(err) => {
            println!("[ERROR] DeviceIoControl, Cannot read symlink from reparse_point data");
            return Err(Error::from_raw_os_error(err.0 as i32));
        },
    }
}

pub unsafe fn write_reparse_point(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_SET_REPARSE_POINT,
        Some(buf.as_ptr() as *const c_void),
        buf.len() as u32,
        None,
        0,
        Some(&mut bytes_returned),
        None,
    ).is_ok() {
        return Ok(());
    }
    let err = GetLastError();
    //dbg!(err.raw_os_error());
    return Err(Error::from_raw_os_error(err.0 as i32));
}

pub unsafe fn delete_reparse_point(file_handle: HANDLE, tag: u32) -> Result<()> {
    let mut buf = REPARSE_DATA_BUFFER::default();
    buf.ReparseTag = tag;
    buf.ReparseDataLength = 0;
    let mut bytes_returned: u32 = 0;
    if DeviceIoControl(
        file_handle,
        FSCTL_DELETE_REPARSE_POINT,
        Some(addr_of!(buf) as *const c_void),
        offset_of!(REPARSE_DATA_BUFFER, Anonymous) as u32,
        None,
        0,
        Some(&mut bytes_returned),
        None,
    ).is_ok() {
        return Ok(());
    }
    let err = GetLastError();
    //dbg!(err.raw_os_error());
    return Err(Error::from_raw_os_error(err.0 as i32));
}

pub unsafe fn read_data(file_handle: HANDLE) -> Result<Vec<u8>> {
    let mut read_size: u32 = 0;
    let mut buf = vec![0u8; MAX_PATH as usize];
    if let Err(err) = ReadFile(
        file_handle,
        Some(buf.as_mut()),
        Some(&mut read_size),
        None,        
    ) {
        println!("[ERROR] ReadFile: {}, Cannot read symlink from file content\n", &err);
        return Err(err.into());
    }
    buf.shrink_to_fit();
    return Ok(buf);
}

pub unsafe fn write_data(file_handle: HANDLE, buf: &[u8]) -> Result<()> {
    let mut write_size: u32 = 0;
    if let Err(err) = WriteFile(
        file_handle,
        Some(buf),
        Some(&mut write_size),
        None,        
    ) {
        println!("[ERROR] WriteFile: {}, Cannot write symlink from file content\n", &err);
        return Err(err.into());
    }
    return Ok(());
}

pub fn query_file_basic_infomation(file_handle: HANDLE) -> Result<FILE_BASIC_INFORMATION> {
    let mut isb = IO_STATUS_BLOCK::default();
    let mut fbi = FILE_BASIC_INFORMATION::default();
    let nt_status = unsafe { NtQueryInformationFile(
        file_handle,
        &mut isb,
        transmute(&mut fbi),
        size_of_val(&fbi) as u32,
        FileBasicInformation,
    ) };
    if nt_status.is_err() {
        println!("[ERROR] NtQueryInformationFile: {:#x}", nt_status.0);
        return Err(Error::from_raw_os_error(nt_status.0));
    }
    Ok(fbi)
}

pub fn error_msg_ntdll(msgid: u32) -> windows::core::Result<String> {
    use windows::Win32::System::Diagnostics::Debug::*;
    use windows::core::Error;
    use windows::Win32::System::LibraryLoader::LoadLibraryA;

    use std::sync::LazyLock;

    struct ModuelWrapper(*const c_void);
    unsafe impl Sync for ModuelWrapper {}
    unsafe impl Send for ModuelWrapper {}

    static NTDLL: LazyLock<ModuelWrapper> = LazyLock::new(|| unsafe {
        ModuelWrapper(LoadLibraryA(PCSTR(c"ntdll.dll".as_ptr() as *const u8)).unwrap().0)
    });

    unsafe {
        let mut lp_allocated_buffer = PWSTR(null_mut());

        let size = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
            Some(NTDLL.0),
            msgid,
            0,
            PWSTR(&mut lp_allocated_buffer as *mut PWSTR as _),
            0,
            None,
        );

        if size > 0 {
            let message_string_result = lp_allocated_buffer.to_string();
            HLOCAL(lp_allocated_buffer.as_ptr() as _).free();
            return Ok(message_string_result?);
        } else {
            return Err(Error::from_thread());
        }
    }
}
