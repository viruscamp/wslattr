use std::{borrow::Cow, mem::{offset_of, transmute}, ptr::{null, slice_from_raw_parts}};

use windows::Wdk::Storage::FileSystem::FILE_FULL_EA_INFORMATION;

pub struct EaEntry<Bytes: AsRef<[u8]>> {
    #[allow(dead_code)]
    pub flags: u8,
    /// should be ASCII only, add or delete
    pub name: Bytes,
    /// may be changed
    pub value: Bytes,
}

impl<Bytes: AsRef<[u8]>> EaEntry<Bytes> {
    fn size(&self) -> usize {
        ea_entry_size_inner(self.name.as_ref().len() as u8, self.value.as_ref().len() as u16)
    }
}

pub fn force_cast<T: Sized>(buf: &[u8]) -> &T {
    assert!(buf.len() >= size_of::<T>());
    let data = buf.as_ptr();
    unsafe { &* (data as *const T) }
}

pub fn get_buffer<T: Sized>(t: &T) -> &[u8] {
    let pt = t as *const T as *const u8;
    unsafe { core::slice::from_raw_parts(pt, size_of::<T>()) }
}

pub type EaEntryRaw<'a> = EaEntry<&'a [u8]>;

impl<'a> EaEntryRaw<'a> {
    pub fn get_ea<T: Sized>(&self) -> &T {
        force_cast(&self.value)
    }
}

pub type EaEntryCow<'a> = EaEntry<Cow<'a, [u8]>>;

pub type EaEntryOwned = EaEntry<[u8]>;

/// 12, aligned size, could not be used
#[allow(dead_code)] 
const EA_BASE_SIZE_RAW_ALIGNED: usize = size_of::<FILE_FULL_EA_INFORMATION>();
/// 9, include NULL at end, use this
const EA_BASE_SIZE_RAW: usize = size_of::<u32>() + size_of::<u8>() + size_of::<u8>() + size_of::<u16>() + size_of::<u8>();
const EA_ALIGN: usize = size_of::<u32>();

// aligned with 4, min data size is 11, min size is 12
fn ea_entry_size(pea: &FILE_FULL_EA_INFORMATION) -> usize {
    ea_entry_size_inner(pea.EaNameLength, pea.EaValueLength)
}

fn ea_entry_size_inner(name_len: u8, value_len: u16) -> usize {
    let data_len = EA_BASE_SIZE_RAW + name_len as usize + value_len as usize;
    let full_len = (data_len + EA_ALIGN - 1) / EA_ALIGN * EA_ALIGN;
    return full_len;
}

#[test]
fn test_ea_entry_size_inner() {
    assert_eq!(ea_entry_size_inner(1, 0), 12); // 10
    assert_eq!(ea_entry_size_inner(1, 1), 12); // 11
    assert_eq!(ea_entry_size_inner(1, 2), 12); // 12
    assert_eq!(ea_entry_size_inner(2, 2), 16); // 13
    assert_eq!(ea_entry_size_inner(2, 3), 16); // 14
}

pub fn parse_ea_to_iter(buf: &[u8]) -> impl Iterator<Item = EaEntry<&[u8]>> {
    struct Iter<'a> {
        buf: &'a [u8],
        ea_ptr: *const u8,
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = EaEntry<&'a [u8]>;
        
        fn next(&mut self) -> Option<Self::Item> {
            if self.ea_ptr == null() {
                return None;
            }

            unsafe {                
                let ea_ptr = self.ea_ptr;
                let buf_range = self.buf.as_ptr_range();

                // 11 is min actual size of EA that can be set with EaNameLength==1 and EaValueLength==1
                // but read buf is 12 in length
                assert!(ea_ptr.add(size_of::<FILE_FULL_EA_INFORMATION>()) <= buf_range.end);
                let pea: &FILE_FULL_EA_INFORMATION = transmute(ea_ptr);
                let pea_end = ea_ptr.add(ea_entry_size(pea));

                //println!("ea_size: {}, buf_size: {}", ea_entry_size(pea), self.buf.len());
                // invalid ea data may cause read overflow
                assert!(pea_end <= buf_range.end);

                if pea.NextEntryOffset == 0 {
                    self.ea_ptr = null();
                } else {
                    self.ea_ptr = ea_ptr.add(pea.NextEntryOffset as usize);
                }

                let pname = &pea.EaName as *const i8 as *const u8;
                let name = &*slice_from_raw_parts(pname, pea.EaNameLength as usize);

                let pvalue =  pname.add(pea.EaNameLength as usize + 1);
                let value = &*slice_from_raw_parts(pvalue, pea.EaValueLength as usize);

                return Some(EaEntry {
                    flags: pea.Flags,
                    name: name,
                    value: value,
                });
            }
        }
    }

    Iter {
        buf,
        ea_ptr: buf.as_ptr(),
    }
}

pub fn parse_ea<'a>(buf: &'a [u8]) -> Vec<EaEntry<&'a [u8]>> {
    parse_ea_to_iter(buf).map(|x| EaEntry {
        flags: x.flags,
        name: x.name.into(),
        value: x.value.into(),
    }).collect()
}

#[derive(Default)]
pub struct EaOut {
    pub buff: Vec<u8>,

    // index, size
    last_ea_info: Option<(usize, usize)>,

    count: usize,
}

impl EaOut {
    pub fn count(&self) -> usize {
        self.count
    }

    pub fn add(&mut self, name: &[u8], value: &[u8]) {
        self.add_entry(&EaEntry { flags: 0, name, value });
    }

    pub fn add_entry<Bytes: AsRef<[u8]>>(&mut self, entry: &EaEntry<Bytes>) {
        unsafe {
            let this_size = entry.size();
            self.buff.resize(self.buff.len() + entry.size(), 0);

            let this_index = if let Some(last_ea_info) = self.last_ea_info {                
                let last_ea_ptr = self.buff.as_mut_ptr().add(last_ea_info.0);
                let last_ea: &mut FILE_FULL_EA_INFORMATION = transmute(last_ea_ptr);
                last_ea.NextEntryOffset = last_ea_info.1 as u32;
                last_ea_info.0 + last_ea_info.1
            } else {
                0
            };

            let pea: *mut u8 = self.buff.as_mut_ptr().add(this_index);
            let ea: &mut FILE_FULL_EA_INFORMATION = transmute(pea);
            ea.NextEntryOffset = 0;
            ea.Flags = 0;

            ea.EaNameLength = entry.name.as_ref().len() as u8;
            let pname: *mut u8 = pea.add(offset_of!(FILE_FULL_EA_INFORMATION, EaName));
            std::ptr::copy_nonoverlapping(entry.name.as_ref().as_ptr(), pname, ea.EaNameLength as usize);

            ea.EaValueLength = entry.value.as_ref().len() as u16;
            let pvalue: *mut u8 = pname.add(ea.EaNameLength as usize + 1);
            std::ptr::copy_nonoverlapping(entry.value.as_ref().as_ptr(), pvalue, ea.EaValueLength as usize);

            self.last_ea_info = Some((this_index, this_size));
            self.count += 1;
        }
    }
}
