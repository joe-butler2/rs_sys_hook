#![allow(unused_assignments)]

use std::{mem, ptr::null_mut};

use libc_print::libc_println;
use windows_sys::Win32::System::{
    Diagnostics::Debug::{MAX_SYM_NAME, SYMBOL_INFO},
    Memory::MEMORY_BASIC_INFORMATION,
};

use crate::{
    dynamic_invoke,
    dynimp::{
        get_module_base_addr, get_proc_addr, load_library_a, nt_query_virtual_memory,
        nt_set_information_process,
    },
    structs::{
        medium, ProcessInstrumentationCallbackInformation, HANDLE, PCSTR, PMEMORY_BASIC_INFORMATION,
    },
};

static mut FLAG: bool = false;
extern crate alloc;
use alloc::vec::Vec;

static mut HOOKED: Vec<usize> = Vec::new();

#[allow(unused_attributes)]
#[link_name = "hook"]
#[no_mangle]
unsafe extern "C" fn hook(r10: usize, mut rax: usize) -> usize {
    // This flag is there for prevent recursion
    if !FLAG {
        FLAG = true;
        const SYMBOL_INFO_SIZE: usize = mem::size_of::<SYMBOL_INFO>();
        const MAX_SYM_NAME_SIZE: u32 = MAX_SYM_NAME;
        let buffer: [u8; SYMBOL_INFO_SIZE] = [0; SYMBOL_INFO_SIZE];
        //cast buffer to SYMBOL_INFO
        let mut symbol_info: SYMBOL_INFO = mem::transmute(buffer);
        symbol_info.SizeOfStruct = SYMBOL_INFO_SIZE as u32;
        symbol_info.MaxNameLen = MAX_SYM_NAME_SIZE;
        let dbg_help = get_module_base_addr("dbghelp.dll");
        let sym_from_addr_templ: unsafe extern "system" fn(
            HANDLE,
            usize,
            *mut usize,
            *mut SYMBOL_INFO,
        ) -> bool;
        let mut displacement = 0;
        let ret: Option<bool>;

        dynamic_invoke!(
            dbg_help,
            "SymFromAddrW",
            sym_from_addr_templ,
            ret,
            HANDLE { id: -1 },
            r10,
            &mut displacement,
            &mut symbol_info
        );
        if ret == Some(true) {
            if HOOKED.contains(&(symbol_info.Address as usize)) {
                // printf("[+] function: %s\n\treturn value: 0x%llx\n\treturn address: 0x%llx\n", symbol_info->Name, RAX, R10);
                libc_println!(
                    "[SHOOK] function: {:?}\n\treturn value: 0x{:x}\n\treturn address: 0x{:x}\n",
                    symbol_info.Name,
                    rax,
                    r10
                );
                //  set rax to NT_SUCCESS
                rax = 0;
            }
            FLAG = false;
            return rax;
        }

        FLAG = false;
        return rax;
    }

    rax
}

pub fn hook_query_information() {
    unsafe {
        let _dbg_help = load_library_a("dbghelp.dll");
        let dbg_help = get_module_base_addr("dbghelp.dll");
        let sym_set_options_templ: unsafe extern "system" fn(u32) -> u32;
        let ret: Option<u32>;
        dynamic_invoke!(
            dbg_help,
            "SymSetOptions",
            sym_set_options_templ,
            ret,
            0x00000002
        );
        let sym_initialize_templ: unsafe extern "system" fn(HANDLE, PCSTR, bool) -> bool;
        let ret: Option<bool>;
        dynamic_invoke!(
            dbg_help,
            "SymInitialize",
            sym_initialize_templ,
            ret,
            HANDLE { id: -1 },
            null_mut(),
            true
        );
    }
    let ntdll = get_module_base_addr("ntdll.dll");
    let ntqueryvirtualmemory = get_proc_addr(ntdll, "NtQueryVirtualMemory");
    let ntqueryvirtualmemory_address = ntqueryvirtualmemory.unwrap() as usize;
    unsafe { HOOKED.push(ntqueryvirtualmemory_address) };
    /*
    // Reserved is always 0
    callback.Reserved = 0;
    // x64 = 0, x86 = 1
    callback.Version = CALLBACK_VERSION;
    // Set our asm callback handler
    callback.Callback = medium;
     */
    let mut callback = ProcessInstrumentationCallbackInformation {
        version: 0,
        reserved: 0,
        callback: medium as _,
    };
    let callback_ptr = &mut callback as *mut ProcessInstrumentationCallbackInformation;
    // MEMORY_BASIC_INFORMATION region = {nullptr};
    let memory_basic_information: PMEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
    // const auto status = NtQueryVirtualMemory(GetCurrentProcess(), GetModuleHandle(nullptr), MemoryBasicInformation, &region, sizeof(region), nullptr);
    let handle = HANDLE { id: -1 };

    let status = nt_query_virtual_memory(
        handle,
        0 as _,
        0,
        memory_basic_information as _,
        (mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32)
            .try_into()
            .unwrap(),
        null_mut(),
    );
    // should be 0xc0000005 - STATUS_ACCESS_VIOLATION
    libc_println!("[SHOOK] NtQueryVirtualMemory: 0x{:x}", status);
    // set our callback
    let status = nt_set_information_process(
        handle,
        0x28 as _,
        callback_ptr as _,
        mem::size_of::<ProcessInstrumentationCallbackInformation>() as u32,
    );
    libc_println!(
        "[SHOOK] NtSetInformationProcess - Adding callback: 0x{:x}",
        status
    );
    let status = nt_query_virtual_memory(
        handle,
        0 as _,
        0,
        memory_basic_information as _,
        (mem::size_of::<MEMORY_BASIC_INFORMATION>() as u32)
            .try_into()
            .unwrap(),
        null_mut(),
    );
    libc_println!(
        "[SHOOK] NtQueryVirtualMemory - Modified callback: 0x{:x}",
        status
    );
}
