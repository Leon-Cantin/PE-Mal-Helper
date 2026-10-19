use std::{ffi::c_void};

use strobf::obf_panic;
use windows_sys::Win32::System::{Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER}, SystemServices::{IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR, IMAGE_NT_SIGNATURE}};

pub struct SectionIter{
    first: *const IMAGE_SECTION_HEADER,
    i: usize,
    count: usize
}

impl SectionIter{
    pub fn from_image(image:*const c_void) -> Self{
        let hdr = image as *const IMAGE_DOS_HEADER;
        let img_nt_hdrs = unsafe { image.byte_offset((*hdr).e_lfanew as isize) } as *const IMAGE_NT_HEADERS64;
        SectionIter::from_nt_hdr(img_nt_hdrs)
    }

    pub fn from_nt_hdr( nt_hdr: *const IMAGE_NT_HEADERS64 ) -> Self{
        if unsafe { (*nt_hdr).Signature != IMAGE_NT_SIGNATURE } {
            obf_panic!("[!] This is a not a NT Image!");
        }
        SectionIter::from_image_section_header(
            unsafe { nt_hdr.byte_add(size_of::<IMAGE_NT_HEADERS64>()) } as *const IMAGE_SECTION_HEADER,
            unsafe{ (*nt_hdr).FileHeader.NumberOfSections as _}
        )
    }

    pub fn from_image_section_header( header:*const IMAGE_SECTION_HEADER, count:usize ) -> Self {
        Self {
            first: header,
            i: 0,
            count: count
        }
    }
}

impl Iterator for SectionIter{
    type Item = *const IMAGE_SECTION_HEADER;

    fn next(&mut self) -> Option<Self::Item> {
        if self.i >= self.count{
            return None;
        }
        let section_header = unsafe { self.first.add(self.i as usize) };
        self.i += 1;
        return Some(section_header);
    }
}

pub struct ImportIter{
    head:*const IMAGE_IMPORT_DESCRIPTOR,
    i:usize,
}

impl ImportIter{
    pub fn from_image( image: *const c_void ) -> Self{
        unsafe{
            let dos_hdr = image as *const IMAGE_DOS_HEADER;
            let nt_hdr =
                (image.byte_add((*dos_hdr).e_lfanew as usize)) as *const IMAGE_NT_HEADERS64;
            if (*nt_hdr).Signature != IMAGE_NT_SIGNATURE {
                obf_panic!("[!] This is a not a NT Image!");
            }
            let img_opt_hdr = &(*nt_hdr).OptionalHeader;
            let img_dir_import = &img_opt_hdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
            let head = image.byte_add(img_dir_import.VirtualAddress as usize)
                    as *const IMAGE_IMPORT_DESCRIPTOR;
            Self {
                head,
                i:0,
            }
        }
    }   
}

impl Iterator for ImportIter{
    type Item = *const IMAGE_IMPORT_DESCRIPTOR;

    fn next(&mut self) -> Option<Self::Item> {
        unsafe{
            let cur = self.head.add(self.i);
            if (*cur).Anonymous.OriginalFirstThunk == 0 && (*cur).FirstThunk == 0{
                return None;
            }
            self.i += 1;
            return Some(cur);
        }
    }
}