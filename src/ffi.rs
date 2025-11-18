use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::sync::atomic::Ordering;
use std::thread;

use crate::*; // Import from lib.rs instead of super

// =======================
// FFI Interface Functions
// =======================

/// Initialize and start the Windows redirector with config parameters
/// Returns 1 on success, 0 on failure
#[no_mangle]
pub extern "C" fn start_redirector(
    client_pid: c_uint,
    agent_pid: c_uint,
    proxy_port: c_uint,
    incoming_proxy: c_uint,
) -> c_uint {
    start_redirector_with_dll_path(client_pid, agent_pid, proxy_port, incoming_proxy, std::ptr::null())
}

/// Initialize and start the Windows redirector with config parameters and custom DLL path
/// Returns 1 on success, 0 on failure
/// dll_path: null-terminated string path to WinDivert.dll, or null to use default search
#[no_mangle]
pub extern "C" fn start_redirector_with_dll_path(
    client_pid: c_uint,
    agent_pid: c_uint,
    proxy_port: c_uint,
    incoming_proxy: c_uint,
    dll_path: *const c_char,
) -> c_uint {
    let _ = write_direct_log("FFI start_redirector_with_dll_path called");

    if RUNNING.swap(true, Ordering::SeqCst) {
        let _ = write_direct_log("Redirector already running, returning failure");
        return 0; // already running = failure
    }

    let _ = write_direct_log("RUNNING flag set, initializing logger");

    // Convert dll_path to Option<String>
    let dll_path_str = if dll_path.is_null() {
        None
    } else {
        unsafe {
            match CStr::from_ptr(dll_path).to_str() {
                Ok(s) => {
                    let _ = write_direct_log(&format!("Using custom WinDivert.dll path: {}", s));
                    Some(s.to_string())
                }
                Err(e) => {
                    let _ = write_direct_log(&format!("Invalid dll_path string: {:?}", e));
                    return 0; // failure due to invalid path
                }
            }
        }
    };

    // Initialize simple file logger (safe to call multiple times)
    if init_file_logger().is_err() {
        // fallback - write a direct message to the file so we always have at least one entry
        let _ = write_direct_log("Starting Windows redirector (fallback logger)");
    } else {
        log::info!("Starting Windows redirector changing...");
        // let _ = write_direct_log("Logger initialized successfully");
    }

    // let _ = write_direct_log("Storing configuration values");

    log::info!(
        "Configuration - client_pid: {}, agent_pid: {}, proxy_port: {}, incoming_proxy: {}",
        client_pid,
        agent_pid,
        proxy_port,
        incoming_proxy
    );

    // Store configuration
    CLIENT_PID.store(client_pid, Ordering::SeqCst);
    AGENT_PID.store(agent_pid, Ordering::SeqCst);
    PROXY_PORT.store(proxy_port, Ordering::SeqCst);
    INCOMING_PROXY.store(incoming_proxy, Ordering::SeqCst);

    let _ = write_direct_log("Configuration stored, spawning redirector thread");

    thread::spawn(move || {
        let _ = write_direct_log("Redirector thread started");
        
        // Check if running as administrator first
        let _ = write_direct_log("Checking administrator privileges...");
        
        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                let _ = write_direct_log("Tokio runtime created, calling run_redirector");
                let result = rt.block_on(run_redirector_with_dll_path(dll_path_str.as_deref()));
                if let Err(e) = result {
                    let error_msg = format!("Redirector error: {:?}", e);
                    log::error!("{}", &error_msg);
                    let _ = write_direct_log(&error_msg);
                    
                    // Check if it's a permission error
                    let error_str = format!("{:?}", e);
                    if error_str.contains("Access is denied") || error_str.contains("Operation not permitted") {
                        let _ = write_direct_log("ERROR: Administrator privileges required! Please run as Administrator.");
                    }
                }
                let _ = write_direct_log("run_redirector completed");
            }
            Err(e) => {
                let error_msg = format!("Failed to create Tokio runtime: {:?}", e);
                let _ = write_direct_log(&error_msg);
            }
        }
        let _ = write_direct_log("Redirector thread ending");
    });

    let _ = write_direct_log("Redirector thread spawned successfully, returning success");

    1 // success
}

/// Stop the Windows redirector
/// Returns 1 on success, 0 if not running
#[no_mangle]
pub extern "C" fn stop_redirector() -> c_uint {
    if RUNNING.swap(false, Ordering::SeqCst) {
        1 // was running, now stopped = success
    } else {
        0 // wasn't running = failure
    }
}

/// Get destination info for a source port
/// Returns WinDest with allocated strings (caller must free with free_windest)
/// Returns null pointers if not found
#[no_mangle]
pub extern "C" fn get_destination(src_port: c_uint) -> WinDest {
    if src_port > 65535 {
        return WinDest {
            host: std::ptr::null_mut(),
            port: 0,
            version: std::ptr::null_mut(),
        };
    }

    let map = REDIRECT_MAP.lock().unwrap();
    match map.get(&(src_port as u16)) {
        Some(dest) => {
            let host = CString::new(dest.host.clone()).unwrap_or_default();
            let version = CString::new(dest.version.clone()).unwrap_or_default();
            WinDest {
                host: host.into_raw(),
                port: dest.port as c_uint,
                version: version.into_raw(),
            }
        }
        None => WinDest {
            host: std::ptr::null_mut(),
            port: 0,
            version: std::ptr::null_mut(),
        },
    }
}

/// Delete a destination mapping for a source port
/// Returns 1 on success, 0 if not found
#[no_mangle]
pub extern "C" fn delete_destination(src_port: c_uint) -> c_uint {
    if src_port > 65535 {
        return 0;
    }

    let mut map = REDIRECT_MAP.lock().unwrap();
    if map.remove(&(src_port as u16)).is_some() {
        1 // success
    } else {
        0 // not found
    }
}

/// Free a WinDest structure allocated by get_destination
#[no_mangle]
pub extern "C" fn free_windest(dest: WinDest) {
    if !dest.host.is_null() {
        unsafe {
            let _ = CString::from_raw(dest.host);
        }
    }
    if !dest.version.is_null() {
        unsafe {
            let _ = CString::from_raw(dest.version);
        }
    }
}
