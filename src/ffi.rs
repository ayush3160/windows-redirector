use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};
use std::sync::atomic::Ordering;
use std::thread;
use std::fs::OpenOptions;
use std::io::Write;

use crate::*; // Import from lib.rs

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
    mode: c_uint,
) -> c_uint {
    start_redirector_with_dll_path(client_pid, agent_pid, proxy_port, incoming_proxy, mode, std::ptr::null())
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
    mode: c_uint,
    dll_path: *const c_char,
) -> c_uint {
    // Initialize file-only logger early so subsequent logs go to the file.
    // This will remove any existing windows_redirector.log at startup (per init_file_logger behaviour).
    let logger_ok = init_file_logger().is_ok();

    if RUNNING.swap(true, Ordering::SeqCst) {
        if logger_ok {
            log::error!("Redirector already running, returning failure");
        } else {
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open("windows_redirector.log")
                .and_then(|mut f| writeln!(f, "Redirector already running, returning failure").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
        }
        return 0; // already running = failure
    }

    if !logger_ok {
        // best-effort fallback write if logger init failed
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open("windows_redirector.log")
            .and_then(|mut f| writeln!(f, "RUNNING flag set, logger init failed").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
    } else {
        log::info!("RUNNING flag set, logger initialized");
    }

    // Convert dll_path to Option<String>
    let dll_path_str = if dll_path.is_null() {
        None
    } else {
        unsafe {
            match CStr::from_ptr(dll_path).to_str() {
                Ok(s) => {
                    if logger_ok {
                        log::debug!("Using custom WinDivert.dll path: {}", s);
                    } else {
                        let _ = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("windows_redirector.log")
                            .and_then(|mut f| writeln!(f, "Using custom WinDivert.dll path: {}", s).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                    }
                    Some(s.to_string())
                }
                Err(e) => {
                    if logger_ok {
                        log::error!("Invalid dll_path string: {:?}", e);
                    } else {
                        let _ = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("windows_redirector.log")
                            .and_then(|mut f| writeln!(f, "Invalid dll_path string: {:?}", e).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                    }
                    return 0; // failure due to invalid path
                }
            }
        }
    };

    // Log starting message
    if logger_ok {
        log::info!("Starting Windows redirector changing...");
    } else {
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open("windows_redirector.log")
            .and_then(|mut f| writeln!(f, "Starting Windows redirector (fallback logger)").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
    }

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
    MODE.store(mode, Ordering::SeqCst);

    if logger_ok {
        log::debug!("Configuration stored, spawning redirector thread");
    } else {
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open("windows_redirector.log")
            .and_then(|mut f| writeln!(f, "Configuration stored, spawning redirector thread").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
    }

    thread::spawn(move || {
        if logger_ok {
            log::debug!("Redirector thread started");
        } else {
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open("windows_redirector.log")
                .and_then(|mut f| writeln!(f, "Redirector thread started").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
        }

        // Check if running as administrator first
        if logger_ok {
            log::debug!("Checking administrator privileges...");
        } else {
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open("windows_redirector.log")
                .and_then(|mut f| writeln!(f, "Checking administrator privileges...").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
        }

        match tokio::runtime::Runtime::new() {
            Ok(rt) => {
                if logger_ok {
                    log::debug!("Tokio runtime created, calling run_redirector");
                } else {
                    let _ = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("windows_redirector.log")
                        .and_then(|mut f| writeln!(f, "Tokio runtime created, calling run_redirector").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                }

                let result = rt.block_on(run_redirector_with_dll_path(dll_path_str.as_deref()));
                if let Err(e) = result {
                    let error_msg = format!("Redirector error: {:?}", e);
                    if logger_ok {
                        log::error!("{}", &error_msg);
                    } else {
                        let _ = OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open("windows_redirector.log")
                            .and_then(|mut f| writeln!(f, "{}", &error_msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                    }

                    // Check if it's a permission error
                    let error_str = format!("{:?}", e);
                    if error_str.contains("Access is denied") || error_str.contains("Operation not permitted") {
                        if logger_ok {
                            log::error!("ERROR: Administrator privileges required! Please run as Administrator.");
                        } else {
                            let _ = OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open("windows_redirector.log")
                                .and_then(|mut f| writeln!(f, "ERROR: Administrator privileges required! Please run as Administrator.").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                        }
                    }
                }

                if logger_ok {
                    log::debug!("run_redirector completed");
                } else {
                    let _ = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("windows_redirector.log")
                        .and_then(|mut f| writeln!(f, "run_redirector completed").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                }
            }
            Err(e) => {
                let error_msg = format!("Failed to create Tokio runtime: {:?}", e);
                if logger_ok {
                    log::error!("{}", &error_msg);
                } else {
                    let _ = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("windows_redirector.log")
                        .and_then(|mut f| writeln!(f, "{}", &error_msg).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
                }
            }
        }

        if logger_ok {
            log::debug!("Redirector thread ending");
        } else {
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open("windows_redirector.log")
                .and_then(|mut f| writeln!(f, "Redirector thread ending").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
        }
    });

    if logger_ok {
        log::info!("Redirector thread spawned successfully, returning success");
    } else {
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open("windows_redirector.log")
            .and_then(|mut f| writeln!(f, "Redirector thread spawned successfully, returning success").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)));
    }

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
/// Returns WinDest with destination IP and port info
/// Returns all zeros if not found
#[no_mangle]
pub extern "C" fn get_destination(src_port: c_uint) -> WinDest {
    if src_port > 65535 {
        return WinDest {
            ip_version: 0,
            dest_ip4: 0,
            dest_ip6: [0; 4],
            dest_port: 0,
            kernel_pid: 0,
        };
    }

    println!("FFI get_destination called for src_port {}", src_port);

    unsafe {
        if let Some(ref redirect_map) = REDIRECT_PROXY_MAP {
            let map = redirect_map.lock().unwrap();
            match map.get(&(src_port as u16)) {
                Some(dest_info) => *dest_info,
                None => WinDest {
                    ip_version: 0,
                    dest_ip4: 0,
                    dest_ip6: [0; 4],
                    dest_port: 0,
                    kernel_pid: 0,
                },
            }
        } else {
            WinDest {
                ip_version: 0,
                dest_ip4: 0,
                dest_ip6: [0; 4],
                dest_port: 0,
                kernel_pid: 0,
            }
        }
    }
}

/// Delete a destination mapping for a source port
/// Returns 1 on success, 0 if not found
#[no_mangle]
pub extern "C" fn delete_destination(src_port: c_uint) -> c_uint {
    if src_port > 65535 {
        return 0;
    }

    unsafe {
        if let Some(ref redirect_map) = REDIRECT_PROXY_MAP {
            let mut map = redirect_map.lock().unwrap();
            if map.remove(&(src_port as u16)).is_some() {
                1 // success
            } else {
                0 // not found
            }
        } else {
            0 // map not initialized
        }
    }
}

/// Free a WinDest structure (no-op since WinDest no longer uses allocated memory)
#[no_mangle]
pub extern "C" fn free_windest(_dest: WinDest) {
    // No-op: WinDest now uses fixed-size fields, no dynamic allocation
}

