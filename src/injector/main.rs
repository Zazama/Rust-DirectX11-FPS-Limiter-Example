use std::env;
use std::io::Write;
use std::ffi::CString;
use named_pipe::PipeOptions;
use text_io::read;
use sysinfo::{SystemExt, ProcessExt};
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::um::processthreadsapi::{OpenProcess, CreateRemoteThread};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_WRITE, PROCESS_VM_READ, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE};

fn main() {
    if env::args().nth(1).is_none() {
        println!("Please pass the process name as first argument");
        return;
    }
    let process_name = env::args().nth(1).unwrap();
    inject(&process_name);

    loop {
        print!("FPS limit (0 = unlimited): ");
        // We're on windows, so we have to check for \r\n line ending.
        let fps_limit: u16 = read!("{}\r\n");
        println!("Changing FPS limit to {}", fps_limit);
        write_config(fps_limit);
    }
}

fn write_config(fps_limit: u16) {
    let pipe_name = r"\\.\pipe\fpslimiter_config";
    let mut server = PipeOptions::new(pipe_name).single().unwrap().wait().unwrap();
    let config = ["fps_limit", &fps_limit.to_string()].join("=");
    server.write(config.as_bytes()).unwrap();
}

fn inject(process_name: &str) {
    let s = sysinfo::System::new_all();
    let processes = s.get_process_by_name(process_name);
    if processes.is_empty() {
        println!("process not found");
        return;
    }

    let process = processes.get(0).unwrap();
    let pid = process.pid() as u32;

    unsafe {
        let process_handle = OpenProcess(
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
            0, pid
        );
        if process_handle.is_null() {
            println!("process not found by windows");
            return;
        }

        let kernel_32_ddl_c_string = CString::new("kernel32.dll").unwrap();
        let load_library_a_c_string = CString::new("LoadLibraryA").unwrap();
        let load_library_a_ptr = GetProcAddress(
            GetModuleHandleA(kernel_32_ddl_c_string.as_ptr()),
            load_library_a_c_string.as_ptr()
        );

        let mut dll_name_path_buf = env::current_exe().unwrap();
        dll_name_path_buf.pop();
        dll_name_path_buf.push("fpslimiter_library.dll");
        let dll_name = dll_name_path_buf.into_os_string().into_string().unwrap();
        let ddl_name_c_string = CString::new(dll_name.clone()).unwrap();

        let virtual_alloc_ptr = VirtualAllocEx(
            process_handle,
            std::ptr::null_mut(),
            dll_name.len() + 1,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        );
        WriteProcessMemory(
            process_handle,
            virtual_alloc_ptr,
            ddl_name_c_string.as_ptr() as LPCVOID,
            dll_name.len() + 1,
            std::ptr::null_mut()
        );
        CreateRemoteThread(
            process_handle,
            std::ptr::null_mut(),
            0,
            Some(*(&load_library_a_ptr as *const _
                as *const extern "system" fn(LPVOID) -> u32)
            ),
            virtual_alloc_ptr,
            0,
            std::ptr::null_mut()
        );
    }
}