use std::{borrow::Cow, mem::transmute, ptr::{null, slice_from_raw_parts}};

use ntapi::ntioapi::FILE_FULL_EA_INFORMATION;
use winapi::shared::ntdef::*;

pub struct EaParsed<'a> {
    entries: Vec<EaEntry<'a>>,
    changed: bool,
}

impl<'a, 'b> IntoIterator for &'b EaParsed<'a> {
    type Item = &'b EaEntry<'a>;
    type IntoIter = std::slice::Iter<'b, EaEntry<'a>>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl<'a> Default for EaParsed<'a> {
    fn default() -> Self {
        EaParsed {
            entries: vec![],
            changed: false,
        }
    }
}

#[macro_export]
macro_rules! get_or_push {
    (ea_parsed, name) => {
        let i = ea_parsed.get_entry(name);
        if i.is_some() {
            i
        } else {
            ea_parsed.entries.push(EaEntry {
                flags: 0,
                name: Cow::Owned(name.to_owned()),
                value: RefCell::new(vec![].into()),
            });
            ea_parsed.entries.last()
        }.unwrap()
    };
}

impl<'a> EaParsed<'a> {
    pub fn get_entry<'b>(&'b self, name: &str) -> Option<&'b EaEntry<'a>> {
        self.entries.iter().find(|e| e.name == name.as_bytes())
    }
}

pub struct EaEntryRaw<Bytes: AsRef<[u8]>> {
    #[allow(dead_code)]
    pub flags: UCHAR,
    /// should be ASCII only, add or delete
    pub name: Bytes,
    /// may be changed
    pub value: Bytes,
}

pub fn force_cast<T: Sized>(buf: &[u8]) -> &T {
    assert!(buf.len() >= size_of::<T>());
    let data = buf.as_ptr();
    unsafe { &* (data as *const T) }
}

pub type EaEntry<'a> = EaEntryRaw<Cow<'a, [u8]>>;

impl<'a> EaEntry<'a> {
    pub fn get_ea<T: Sized>(&self) -> &T {
        force_cast(&self.value)
    }

    pub fn get_ea_raw(&self) -> &[u8] {
        &self.value.as_ref()
    }

    pub fn get_ea_cow<T: Sized + Clone>(&'a self) -> Cow<'a, T> {
        let t = self.get_ea();
        match self.value {
            Cow::Borrowed(_) => Cow::Borrowed(&t),
            Cow::Owned(_) => Cow::Owned(t.clone()),
        }
    }

    fn set_ea_raw(&mut self, value: Vec<u8>) {
        self.value = Cow::Owned(value);
    }

    fn set_ea<T: Sized>(&mut self, value: &T) {
        let data = slice_from_raw_parts(value as *const _ as *const u8, size_of_val(value));
        let data = unsafe { &*data };
        self.set_ea_raw(data.to_vec());
    }
}

/// 12, aligned size, could not be used
#[allow(dead_code)] 
const EA_BASE_SIZE_ALIGNED: usize = size_of::<FILE_FULL_EA_INFORMATION>();
/// 9, use this
const EA_BASE_SIZE_RAW: usize = size_of::<ULONG>() + size_of::<UCHAR>() + size_of::<UCHAR>() + size_of::<USHORT>() + size_of::<UCHAR>();
const EA_ALIGN: usize = size_of::<ULONG>();

// aligned with 4, min data size is 11, min size is 12
fn ea_entry_size(pea: &FILE_FULL_EA_INFORMATION) -> usize {
    ea_entry_size_inner(pea.EaNameLength, pea.EaValueLength)
}

fn ea_entry_size_inner(name_len: UCHAR, value_len: USHORT) -> usize {
    let data_len = EA_BASE_SIZE_RAW + name_len as usize + value_len as usize;
    let full_len = (data_len + 1) / EA_ALIGN * EA_ALIGN;
    return full_len;
}

pub fn parse_ea_to_iter(buf: &[u8]) -> impl Iterator<Item = EaEntryRaw<&[u8]>> {
    struct Iter<'a> {
        buf: &'a [u8],
        ea_ptr: *const u8,
    }

    impl<'a> Iterator for Iter<'a> {
        type Item = EaEntryRaw<&'a [u8]>;
        
        fn next(&mut self) -> Option<Self::Item> {
            if self.ea_ptr == null() {
                return None;
            }

            unsafe {                
                let ea_ptr = self.ea_ptr;
                let buf_range = self.buf.as_ptr_range();

                // 11 is min actual size of EA that can be set with EaNameLength==1 and EaValueLength==1
                // but read buf is 12 in length
                assert!(ea_ptr.add(size_of::<FILE_FULL_EA_INFORMATION>()) < buf_range.end);
                let pea: &FILE_FULL_EA_INFORMATION = transmute(ea_ptr);
                let pea_end = ea_ptr.add(ea_entry_size(pea));

                // invalid ea data may cause read overflow
                assert!(pea_end < buf_range.end);

                if pea.NextEntryOffset == 0 {
                    self.ea_ptr = null();
                } else {
                    self.ea_ptr = ea_ptr.add(pea.NextEntryOffset as usize);
                }

                let pname = &pea.EaName as *const i8 as *const u8;
                let name = &*slice_from_raw_parts(pname, pea.EaNameLength as usize);

                let pvalue =  pname.add(pea.EaNameLength as usize + 1);
                let value = &*slice_from_raw_parts(pvalue, pea.EaValueLength as usize);

                return Some(EaEntryRaw {
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

pub fn parse_ea(buf: &[u8]) -> EaParsed {
    let entries = parse_ea_to_iter(buf).map(|x| EaEntry {
        flags: x.flags,
        name: x.name.into(),
        value: x.value.into(),
    }).collect();
    
    EaParsed{
        entries,
        changed: false,
    }
}
