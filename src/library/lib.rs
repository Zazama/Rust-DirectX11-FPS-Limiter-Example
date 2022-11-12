use std::ffi::{c_void, CString};
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime};
use minhook_sys::{MH_CreateHook, MH_EnableHook, MH_Initialize, MH_OK};
use named_pipe::PipeClient;
use once_cell::sync::OnceCell;
use winapi::um::libloaderapi::{GetProcAddress, DisableThreadLibraryCalls, GetModuleHandleA};
use winapi::um::d3dcommon::{D3D_FEATURE_LEVEL, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0, D3D_DRIVER_TYPE_HARDWARE};
use winapi::shared::dxgitype::{DXGI_RATIONAL, DXGI_MODE_DESC, DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED, DXGI_MODE_SCALING_UNSPECIFIED, DXGI_SAMPLE_DESC, DXGI_USAGE_RENDER_TARGET_OUTPUT};
use winapi::shared::dxgiformat::DXGI_FORMAT_R8G8B8A8_UNORM;
use winapi::shared::dxgi::{DXGI_SWAP_CHAIN_DESC, DXGI_SWAP_EFFECT_DISCARD, DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH, IDXGISwapChain};
use winapi::um::winuser::{WNDCLASSEXA, CS_HREDRAW, CS_VREDRAW, DefWindowProcA, RegisterClassExA, UnregisterClassA, CreateWindowExA, DestroyWindow, WS_OVERLAPPEDWINDOW};
use winapi::um::d3d11::{D3D11CreateDeviceAndSwapChain, D3D11_SDK_VERSION, ID3D11Device, ID3D11DeviceContext};
use winapi::shared::minwindef::{UINT, HINSTANCE, DWORD, LPVOID, HMODULE};
use winapi::um::winnt::{HRESULT, DLL_PROCESS_ATTACH};
use winapi::um::processthreadsapi::CreateThread;

static TRAMPOLINE: OnceCell<unsafe extern "system" fn(
    this: *mut IDXGISwapChain,
    sync_interval: UINT,
    flags: UINT) -> HRESULT> = OnceCell::new();
static FRAME_TIME_NS: AtomicU64 = AtomicU64::new(0);
static TIME_OF_LAST_PRESENT_NS: AtomicU64 = AtomicU64::new(0);

// Tell Rust not to change anything about this function's naming
#[no_mangle]
pub extern "stdcall" fn DllMain(
    hinst_dll: HINSTANCE,
    fdw_reason: DWORD,
    lpv_reserved: LPVOID,
) -> i32 {
    match fdw_reason {
        // The .dll has been loaded
        DLL_PROCESS_ATTACH => {
            unsafe {
                DisableThreadLibraryCalls(hinst_dll);
                // Create a thread that executes our dll_attach function
                CreateThread(
                    std::ptr::null_mut(),
                    0,
                    Some(dll_process_attach_event),
                    hinst_dll as _,
                    0,
                    std::ptr::null_mut(),
                );
                CreateThread(
                    std::ptr::null_mut(),
                    0,
                    Some(read_config_loop),
                    hinst_dll as _,
                    0,
                    std::ptr::null_mut(),
                );
            }
            return 1i32;
        }
        // ignore for now
        _ => 1i32,
    }
}

unsafe extern "system" fn read_config_loop(_base: LPVOID) -> u32 {
    loop {
        read_config();
        thread::sleep(Duration::from_secs(1));
    }

    return 0;
}

unsafe extern "system" fn new_present_function(this: *mut IDXGISwapChain, sync_interval: UINT, flags: UINT) -> HRESULT {
    let frame_time_ns = FRAME_TIME_NS.load(Ordering::Relaxed);
    if frame_time_ns != 0 {
        let current_time_ns = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let time_between_last_present_call =
            current_time_ns - TIME_OF_LAST_PRESENT_NS.load(Ordering::Relaxed);
        if time_between_last_present_call < frame_time_ns {
            std::thread::sleep(
                Duration::from_nanos(
                    frame_time_ns - time_between_last_present_call
                )
            );
        }

        TIME_OF_LAST_PRESENT_NS.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64,
            Ordering::Relaxed
        );
    }

    let trampoline = TRAMPOLINE.get().unwrap();
    return trampoline(this, sync_interval, flags);
}

// CreateThread expects an unsafe extern "system" function.
// We will wrap our real attach function so it is not completely unsafe.
unsafe extern "system" fn dll_process_attach_event(base: LPVOID) -> u32 {
    let result = dll_attach(base);
    return result;
}

fn dll_attach(_base: LPVOID) -> u32 {
    let window_class_name: CString = CString::new("givemeyourswapchain").unwrap();
    let window_class: WNDCLASSEXA = WNDCLASSEXA {
        cbSize: std::mem::size_of::<WNDCLASSEXA>() as u32,
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(DefWindowProcA),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: unsafe { GetModuleHandleA(std::ptr::null()) },
        hIcon: std::ptr::null_mut(),
        hCursor: std::ptr::null_mut(),
        hbrBackground: std::ptr::null_mut(),
        lpszMenuName: std::ptr::null_mut(),
        lpszClassName: window_class_name.as_ptr(),
        hIconSm: std::ptr::null_mut()
    };
    let registered_window_class = unsafe { RegisterClassExA(&window_class) };
    if registered_window_class == 0 {
        return 1;
    }

    let window = unsafe { CreateWindowExA(
        0,
        window_class_name.as_ptr(),
        window_class_name.as_ptr(),
        WS_OVERLAPPEDWINDOW,
        0,
        0,
        100,
        100,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        window_class.hInstance,
        std::ptr::null_mut()
    ) };

    if window == std::ptr::null_mut() {
        return 1;
    }

    let dx_module_name: CString = CString::new("d3d11.dll").unwrap();
    let lib_d3d11: HMODULE = unsafe { GetModuleHandleA(dx_module_name.as_ptr()) };
    if lib_d3d11 == std::ptr::null_mut() {
        return 1;
    }

    let swapchain_function_name: CString = CString::new("D3D11CreateDeviceAndSwapChain").unwrap();
    let d3d11_create_device_and_swap_chain = unsafe { GetProcAddress(lib_d3d11, swapchain_function_name.as_ptr()) };
    if d3d11_create_device_and_swap_chain == std::ptr::null_mut() {
        return 1;
    }

    let refresh_rate: DXGI_RATIONAL = DXGI_RATIONAL { Numerator: 60, Denominator: 1 };
    let buffer_desc = DXGI_MODE_DESC {
        Width: 100,
        Height: 100,
        RefreshRate: refresh_rate,
        Format: DXGI_FORMAT_R8G8B8A8_UNORM,
        ScanlineOrdering: DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED,
        Scaling: DXGI_MODE_SCALING_UNSPECIFIED
    };
    let sample_desc = DXGI_SAMPLE_DESC { Count: 1, Quality: 0};
    let swap_chain_desc = DXGI_SWAP_CHAIN_DESC {
        BufferDesc: buffer_desc,
        SampleDesc: sample_desc,
        BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
        BufferCount: 1,
        OutputWindow: window,
        Windowed: 1,
        SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
        Flags: DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH
    };

    let mut swap_chain: *mut IDXGISwapChain = unsafe { std::mem::zeroed() };
    let mut device: *mut ID3D11Device = unsafe { std::mem::zeroed() };
    let mut context: *mut ID3D11DeviceContext = unsafe { std::mem::zeroed() };
    let mut d3d_feature_level: D3D_FEATURE_LEVEL = unsafe { std::mem::zeroed() };

    unsafe {
        let result = D3D11CreateDeviceAndSwapChain(
            std::ptr::null_mut(),
            D3D_DRIVER_TYPE_HARDWARE,
            std::ptr::null_mut(),
            0,
            [D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_11_0].as_ptr(),
            2,
            D3D11_SDK_VERSION,
            &swap_chain_desc,
            &mut swap_chain,
            &mut device,
            &mut d3d_feature_level,
            &mut context
        );

        if result < 0 {
            return 1;
        }
    };

    let swap_chain = unsafe { swap_chain.as_ref() };
    if swap_chain.is_none() {
        return 1;
    }

    let swap_chain = swap_chain.unwrap();

    let present_function = unsafe { (*swap_chain.lpVtbl).Present };

    unsafe {
        DestroyWindow(window);
        UnregisterClassA(window_class_name.as_ptr(), window_class.hInstance);
    }

    unsafe {
        // Initialize internal buffers of MinHook
        if MH_Initialize() != MH_OK {
            return 1;
        }

        // Create pointer to hold the original function
        let mut detoured_func: *mut c_void = std::mem::zeroed();

        // Create the hook, redirect present_function to new_present_function
        if MH_CreateHook(
            present_function as *mut c_void,
            new_present_function as *mut c_void,
            &mut detoured_func
        ) != MH_OK {
            return 1;
        }

        if TRAMPOLINE.set(std::mem::transmute(detoured_func)).is_err() {
            return 1;
        }

        // Enable the hook
        if MH_EnableHook(present_function as *mut c_void) != MH_OK {
            return 1;
        }
    }

    return 0;
}

fn read_config() {
    let pipe_name = r"\\.\pipe\fpslimiter_config";
    let pipe_client = PipeClient::connect(pipe_name);
    if pipe_client.is_err() { return; }

    let mut pipe_client = pipe_client.unwrap();
    let mut read_buffer: [u8; 1024] = [0; 1024];
    let result = pipe_client.read(&mut read_buffer);
    if result.is_err() { return; }

    let config = String::from_utf8(read_buffer[0..result.unwrap()].to_vec());
    if config.is_err() { return; }
    let config = config.unwrap();

    // Probably unneeded safety measure.
    let split_config: Vec<&str> = config.split("=").collect();
    if split_config.len() != 2 || split_config[0] != "fps_limit" { return; }

    let fps_limit = split_config[1].parse::<u64>();
    if fps_limit.is_err() { return; }

    let new_frame_time_ns =
        (1f64 / fps_limit.unwrap() as f64)
        * 1000f64
        * 1000f64
        * 1000f64;
    FRAME_TIME_NS.store(new_frame_time_ns as u64, Ordering::Relaxed);
}