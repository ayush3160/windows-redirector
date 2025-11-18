use std::ffi::{c_void, CString};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int, c_uint};
use anyhow::{anyhow, Result};
use libloading::{Library, Symbol};

#[cfg(windows)]
extern "system" {
    fn GetLastError() -> u32;
}

#[cfg(windows)]
fn get_last_error_message() -> String {
    let error_code = unsafe { GetLastError() };
    match error_code {
        0 => "No error".to_string(),
        2 => "The system cannot find the file specified".to_string(),
        5 => "Access is denied".to_string(),
        87 => "The parameter is incorrect".to_string(),
        122 => "The data area passed to a system call is too small".to_string(),
        1314 => "A required privilege is not held by the client".to_string(),
        _ => format!("Windows Error Code: {}", error_code),
    }
}

#[cfg(not(windows))]
fn get_last_error_message() -> String {
    "Platform not supported".to_string()
}

// ===== WinDivert public constants =====

// Direction flags (from WINDIVERT_ADDRESS docs) 
pub const WINDIVERT_DIRECTION_OUTBOUND: u8 = 0;
pub const WINDIVERT_DIRECTION_INBOUND: u8 = 1;

// Event codes (WINDIVERT_EVENT_*) 
pub const WINDIVERT_EVENT_NETWORK_PACKET: u8 = 0;
pub const WINDIVERT_EVENT_FLOW_ESTABLISHED: u8 = 1;
pub const WINDIVERT_EVENT_FLOW_DELETED: u8 = 2;
pub const WINDIVERT_EVENT_SOCKET_BIND: u8 = 3;
pub const WINDIVERT_EVENT_SOCKET_CONNECT: u8 = 4;
pub const WINDIVERT_EVENT_SOCKET_LISTEN: u8 = 5;
pub const WINDIVERT_EVENT_SOCKET_ACCEPT: u8 = 6;
pub const WINDIVERT_EVENT_SOCKET_CLOSE: u8 = 7;
pub const WINDIVERT_EVENT_REFLECT_OPEN: u8 = 8;
pub const WINDIVERT_EVENT_REFLECT_CLOSE: u8 = 9;

// Layers (WINDIVERT_LAYER_*) 
pub const WINDIVERT_LAYER_NETWORK: u32 = 0;
pub const WINDIVERT_LAYER_NETWORK_FORWARD: u32 = 1;
pub const WINDIVERT_LAYER_FLOW: u32 = 2;
pub const WINDIVERT_LAYER_SOCKET: u32 = 3;
pub const WINDIVERT_LAYER_REFLECT: u32 = 4;

// Flags (WINDIVERT_FLAG_*) 
pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;
pub const WINDIVERT_FLAG_DROP: u64 = 0x0002;
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
pub const WINDIVERT_FLAG_NO_INSTALL: u64 = 0x0010;
pub const WINDIVERT_FLAG_FRAGMENTS: u64 = 0x0020;

pub type WinDivertHandle = *mut c_void;

// ===== WINDIVERT_ADDRESS & friends – layout must match C header exactly =====
//
// C side (simplified): 
//
// typedef struct
// {
//   UINT32 IfIdx;
//   UINT32 SubIfIdx;
// } WINDIVERT_DATA_NETWORK;
//
// typedef struct { ... } WINDIVERT_DATA_FLOW;
// typedef struct { ... } WINDIVERT_DATA_SOCKET;
// typedef struct { ... } WINDIVERT_DATA_REFLECT;
//
// typedef struct
// {
//   INT64  Timestamp;
//   UINT64 Layer:8;
//   UINT64 Event:8;
//   UINT64 Sniffed:1;
//   UINT64 Outbound:1;
//   UINT64 Loopback:1;
//   UINT64 Impostor:1;
//   UINT64 IPv6:1;
//   UINT64 IPChecksum:1;
//   UINT64 TCPChecksum:1;
//   UINT64 UDPChecksum:1;
//   UINT64 Reserved:40;
//   union {
//     WINDIVERT_DATA_NETWORK Network;
//     WINDIVERT_DATA_FLOW    Flow;
//     WINDIVERT_DATA_SOCKET  Socket;
//     WINDIVERT_DATA_REFLECT Reflect;
//   };
// } WINDIVERT_ADDRESS;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct WINDIVERT_DATA_NETWORK {
    pub IfIdx: u32,
    pub SubIfIdx: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct WINDIVERT_DATA_FLOW {
    pub Endpoint: u64,
    pub ParentEndpoint: u64,
    pub ProcessId: u32,
    pub LocalAddr: [u32; 4],
    pub RemoteAddr: [u32; 4],
    pub LocalPort: u16,
    pub RemotePort: u16,
    pub Protocol: u8,
    // padding is implicit
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct WINDIVERT_DATA_SOCKET {
    pub Endpoint: u64,
    pub ParentEndpoint: u64,
    pub ProcessId: u32,
    pub LocalAddr: [u32; 4],
    pub RemoteAddr: [u32; 4],
    pub LocalPort: u16,
    pub RemotePort: u16,
    pub Protocol: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct WINDIVERT_DATA_REFLECT {
    pub Timestamp: i64,
    pub ProcessId: u32,
    pub Layer: u32,
    pub Flags: u64,
    pub Priority: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union WINDIVERT_DATA_UNION {
    pub Network: WINDIVERT_DATA_NETWORK,
    pub Flow:    WINDIVERT_DATA_FLOW,
    pub Socket:  WINDIVERT_DATA_SOCKET,
    pub Reflect: WINDIVERT_DATA_REFLECT,
}

impl std::fmt::Debug for WINDIVERT_DATA_UNION {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WINDIVERT_DATA_UNION")
            .field("data", &"<union>")
            .finish()
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct WINDIVERT_ADDRESS {
    pub Timestamp: i64,
    pub Bitfields: u64,
    pub Data:      WINDIVERT_DATA_UNION,
}

// Type alias so your code can use WinDivertAddress
pub type WinDivertAddress = WINDIVERT_ADDRESS;

impl Default for WINDIVERT_ADDRESS {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum WinDivertEvent {
    NetworkPacket,
    FlowEstablished,
    FlowDeleted,
    SocketBind,
    SocketConnect,
    SocketListen,
    SocketAccept,
    SocketClose,
    ReflectOpen,
    ReflectClose,
}

impl WINDIVERT_ADDRESS {
    #[inline]
    fn raw_layer(&self) -> u8 {
        (self.Bitfields & 0xFF) as u8
    }

    #[inline]
    fn raw_event(&self) -> u8 {
        ((self.Bitfields >> 8) & 0xFF) as u8
    }

    #[inline]
    fn ipv6_flag(&self) -> bool {
        ((self.Bitfields >> 20) & 0x1) != 0
    }

    pub fn event(&self) -> WinDivertEvent {
        match self.raw_event() {
            WINDIVERT_EVENT_FLOW_ESTABLISHED => WinDivertEvent::FlowEstablished,
            WINDIVERT_EVENT_FLOW_DELETED => WinDivertEvent::FlowDeleted,
            WINDIVERT_EVENT_SOCKET_BIND => WinDivertEvent::SocketBind,
            WINDIVERT_EVENT_SOCKET_CONNECT => WinDivertEvent::SocketConnect,
            WINDIVERT_EVENT_SOCKET_LISTEN => WinDivertEvent::SocketListen,
            WINDIVERT_EVENT_SOCKET_ACCEPT => WinDivertEvent::SocketAccept,
            WINDIVERT_EVENT_SOCKET_CLOSE => WinDivertEvent::SocketClose,
            WINDIVERT_EVENT_REFLECT_OPEN => WinDivertEvent::ReflectOpen,
            WINDIVERT_EVENT_REFLECT_CLOSE => WinDivertEvent::ReflectClose,
            _ => WinDivertEvent::NetworkPacket,
        }
    }

    pub fn layer(&self) -> u32 {
        self.raw_layer() as u32
    }

    pub fn process_id(&self) -> u32 {
        unsafe {
            match self.layer() {
                WINDIVERT_LAYER_FLOW => self.Data.Flow.ProcessId,
                WINDIVERT_LAYER_SOCKET => self.Data.Socket.ProcessId,
                WINDIVERT_LAYER_REFLECT => self.Data.Reflect.ProcessId,
                _ => 0,
            }
        }
    }

    pub fn local_address(&self) -> IpAddr {
        match self.layer() {
            WINDIVERT_LAYER_FLOW | WINDIVERT_LAYER_SOCKET => unsafe {
                let is_ipv6 = self.ipv6_flag();
                let addr_u32 = if self.layer() == WINDIVERT_LAYER_FLOW {
                    &self.Data.Flow.LocalAddr
                } else {
                    &self.Data.Socket.LocalAddr
                };

                let mut bytes = [0u8; 16];
                for (i, part) in addr_u32.iter().enumerate() {
                    bytes[i * 4..(i + 1) * 4].copy_from_slice(&part.to_be_bytes());
                }

                if is_ipv6 {
                    IpAddr::V6(Ipv6Addr::from(bytes))
                } else {
                    // IPv4-mapped IPv6 ::ffff:X.Y.Z.W -> take last 4 bytes
                    let v4 = [bytes[12], bytes[13], bytes[14], bytes[15]];
                    IpAddr::V4(Ipv4Addr::from(v4))
                }
            },
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub fn remote_address(&self) -> IpAddr {
        match self.layer() {
            WINDIVERT_LAYER_FLOW | WINDIVERT_LAYER_SOCKET => unsafe {
                let is_ipv6 = self.ipv6_flag();
                let addr_u32 = if self.layer() == WINDIVERT_LAYER_FLOW {
                    &self.Data.Flow.RemoteAddr
                } else {
                    &self.Data.Socket.RemoteAddr
                };

                let mut bytes = [0u8; 16];
                for (i, part) in addr_u32.iter().enumerate() {
                    bytes[i * 4..(i + 1) * 4].copy_from_slice(&part.to_be_bytes());
                }

                if is_ipv6 {
                    IpAddr::V6(Ipv6Addr::from(bytes))
                } else {
                    let v4 = [bytes[12], bytes[13], bytes[14], bytes[15]];
                    IpAddr::V4(Ipv4Addr::from(v4))
                }
            },
            _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    pub fn local_port(&self) -> u16 {
        unsafe {
            match self.layer() {
                WINDIVERT_LAYER_FLOW => self.Data.Flow.LocalPort,
                WINDIVERT_LAYER_SOCKET => self.Data.Socket.LocalPort,
                _ => 0,
            }
        }
    }

    pub fn remote_port(&self) -> u16 {
        unsafe {
            match self.layer() {
                WINDIVERT_LAYER_FLOW => self.Data.Flow.RemotePort,
                WINDIVERT_LAYER_SOCKET => self.Data.Socket.RemotePort,
                _ => 0,
            }
        }
    }

    pub fn protocol(&self) -> u8 {
        unsafe {
            match self.layer() {
                WINDIVERT_LAYER_FLOW => self.Data.Flow.Protocol,
                WINDIVERT_LAYER_SOCKET => self.Data.Socket.Protocol,
                _ => 0,
            }
        }
    }

    pub fn event_timestamp(&self) -> i64 {
        self.Timestamp
    }
}

// Simple packet wrapper used by your redirector
pub struct WinDivertPacket {
    pub address: WinDivertAddress,
    pub data: Vec<u8>,
}

// ===== Dynamic loader for WinDivert.dll =====
//
// Signatures taken from official docs for WinDivertOpen/RecvEx/SendEx. 

pub struct DynWinDivert {
    _library: Library,
    open: Symbol<
        'static,
        unsafe extern "system" fn(*const c_char, u32, i16, u64) -> WinDivertHandle,
    >,
    recv_ex: Symbol<
        'static,
        unsafe extern "system" fn(
            WinDivertHandle,
            *mut c_void,
            c_uint,
            *mut c_uint,
            u64,
            *mut WinDivertAddress,
            *mut c_uint,
            *mut c_void,
        ) -> c_int,
    >,
    send_ex: Symbol<
        'static,
        unsafe extern "system" fn(
            WinDivertHandle,
            *const c_void,
            c_uint,
            *mut c_uint,
            u64,
            *const WinDivertAddress,
            c_uint,
            *mut c_void,
        ) -> c_int,
    >,
    close: Symbol<'static, unsafe extern "system" fn(WinDivertHandle) -> c_int>,
    set_param: Symbol<'static, unsafe extern "system" fn(WinDivertHandle, u32, u64) -> c_int>,
}

impl DynWinDivert {
    pub fn new() -> Result<Self> {
        Self::with_dll_path(None)
    }

    /// If `dll_path` is `Some`, we load that file; otherwise we rely on standard
    /// DLL search (PATH / current dir).
    pub fn with_dll_path(dll_path: Option<&str>) -> Result<Self> {
        unsafe {
            let library = match dll_path {
                Some(path) => Library::new(path)
                    .map_err(|e| anyhow!("Failed to load WinDivert.dll from '{}': {}", path, e))?,
                None => Library::new("WinDivert.dll")
                    .map_err(|e| anyhow!("Failed to load WinDivert.dll: {}", e))?,
            };

            let open: Symbol<
                unsafe extern "system" fn(*const c_char, u32, i16, u64) -> WinDivertHandle,
            > = library
                .get(b"WinDivertOpen\0")
                .map_err(|e| anyhow!("Failed to get WinDivertOpen: {}", e))?;

            let recv_ex: Symbol<
                unsafe extern "system" fn(
                    WinDivertHandle,
                    *mut c_void,
                    c_uint,
                    *mut c_uint,
                    u64,
                    *mut WinDivertAddress,
                    *mut c_uint,
                    *mut c_void,
                ) -> c_int,
            > = library
                .get(b"WinDivertRecvEx\0")
                .map_err(|e| anyhow!("Failed to get WinDivertRecvEx: {}", e))?;

            let send_ex: Symbol<
                unsafe extern "system" fn(
                    WinDivertHandle,
                    *const c_void,
                    c_uint,
                    *mut c_uint,
                    u64,
                    *const WinDivertAddress,
                    c_uint,
                    *mut c_void,
                ) -> c_int,
            > = library
                .get(b"WinDivertSendEx\0")
                .map_err(|e| anyhow!("Failed to get WinDivertSendEx: {}", e))?;

            let close: Symbol<unsafe extern "system" fn(WinDivertHandle) -> c_int> = library
                .get(b"WinDivertClose\0")
                .map_err(|e| anyhow!("Failed to get WinDivertClose: {}", e))?;

            let set_param: Symbol<unsafe extern "system" fn(WinDivertHandle, u32, u64) -> c_int> =
                library
                    .get(b"WinDivertSetParam\0")
                    .map_err(|e| anyhow!("Failed to get WinDivertSetParam: {}", e))?;

            // Extend lifetimes to 'static – safe because library lives inside Self
            let open = mem::transmute(open);
            let recv_ex = mem::transmute(recv_ex);
            let send_ex = mem::transmute(send_ex);
            let close = mem::transmute(close);
            let set_param = mem::transmute(set_param);

            Ok(Self {
                _library: library,
                open,
                recv_ex,
                send_ex,
                close,
                set_param,
            })
        }
    }

    pub fn open_socket(&self, filter: &str, priority: i16, flags: u64) -> Result<DynWinDivertHandle<'_>> {
        let filter_cstr = CString::new(filter)?;
        let handle = unsafe {
            (self.open)(
                filter_cstr.as_ptr(),
                WINDIVERT_LAYER_SOCKET,
                priority,
                flags,
            )
        };

        if handle.is_null() {
            let error_msg = get_last_error_message();
            return Err(anyhow!("Failed to open WinDivert socket handle: {}", error_msg));
        }

        Ok(DynWinDivertHandle {
            handle,
            windivert: self,
        })
    }

    pub fn open_network(
        &self,
        filter: &str,
        priority: i16,
        flags: u64,
    ) -> Result<DynWinDivertHandle<'_>> {
        let filter_cstr = CString::new(filter)?;
        let handle = unsafe {
            (self.open)(
                filter_cstr.as_ptr(),
                WINDIVERT_LAYER_NETWORK,
                priority,
                flags,
            )
        };

        if handle.is_null() {
            let error_msg = get_last_error_message();
            return Err(anyhow!(
                "Failed to open WinDivert network handle: {}",
                error_msg
            ));
        }

        Ok(DynWinDivertHandle {
            handle,
            windivert: self,
        })
    }

    #[allow(dead_code)]
    pub fn set_param(&self, handle: WinDivertHandle, param: u32, value: u64) -> Result<()> {
        let result = unsafe { (self.set_param)(handle, param, value) };
        if result == 0 {
            return Err(anyhow!("WinDivertSetParam failed: {}", get_last_error_message()));
        }
        Ok(())
    }
}

pub struct DynWinDivertHandle<'a> {
    handle: WinDivertHandle,
    windivert: &'a DynWinDivert,
}

impl<'a> DynWinDivertHandle<'a> {
    /// Simple wrapper: allocates its own buffer (max_packets * 65535),
    /// returns first packet captured.
    pub fn recv_ex(&self, max_packets: usize) -> Result<Vec<WinDivertPacket>> {
        const MAX_PACKET_SIZE: usize = 65535;
        let mut buffer = vec![0u8; MAX_PACKET_SIZE * max_packets];
        self.recv_ex_with_buffer(&mut buffer, max_packets)
    }

    pub fn recv_ex_with_buffer(
        &self,
        buffer: &mut [u8],
        max_packets: usize,
    ) -> Result<Vec<WinDivertPacket>> {
        let mut packets = Vec::new();
        let mut addresses = vec![WinDivertAddress::default(); max_packets];
        let mut recv_len: c_uint = 0;
        let mut addr_len: c_uint =
            (addresses.len() * mem::size_of::<WinDivertAddress>()) as c_uint;

        let ok = unsafe {
            (self.windivert.recv_ex)(
                self.handle,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len() as c_uint,
                &mut recv_len as *mut c_uint,
                0, // flags = 0
                addresses.as_mut_ptr(),
                &mut addr_len as *mut c_uint,
                std::ptr::null_mut(), // lpOverlapped = NULL
            )
        };

        if ok == 0 {
            let error_msg = get_last_error_message();
            return Err(anyhow!("WinDivertRecvEx failed: {}", error_msg));
        }

        if recv_len == 0 {
            return Ok(packets);
        }

        // For your use-case you always call with max_packets = 1,
        // so we just use the first address and entire data buffer.
        let data = buffer[..recv_len as usize].to_vec();
        packets.push(WinDivertPacket {
            address: addresses[0],
            data,
        });

        Ok(packets)
    }

    pub fn send(&self, packet: &WinDivertPacket) -> Result<()> {
        let mut sent_len: c_uint = 0;
        let ok = unsafe {
            (self.windivert.send_ex)(
                self.handle,
                packet.data.as_ptr() as *const c_void,
                packet.data.len() as c_uint,
                &mut sent_len as *mut c_uint,
                0, // flags
                &packet.address as *const WinDivertAddress,
                mem::size_of::<WinDivertAddress>() as c_uint,
                std::ptr::null_mut(), // lpOverlapped
            )
        };

        if ok == 0 {
            let error_msg = get_last_error_message();
            return Err(anyhow!("WinDivertSendEx failed: {}", error_msg));
        }

        Ok(())
    }
}

impl<'a> Drop for DynWinDivertHandle<'a> {
    fn drop(&mut self) {
        unsafe {
            (self.windivert.close)(self.handle);
        }
    }
}