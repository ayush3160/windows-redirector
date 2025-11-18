use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::sync::Mutex;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet, TcpPacket, IpProtocol};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Mutex as StdMutex;
use std::os::raw::{c_char, c_uint};

use anyhow::{Context, Result};
use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
use log::{Record, Metadata, LevelFilter};
use lru_time_cache::LruCache;

// FFI and dynamic WinDivert modules
pub mod ffi;
pub mod dyn_windivert;

use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedSender};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use once_cell::sync::Lazy;

// Import our dynamic WinDivert types
use dyn_windivert::{DynWinDivert, DynWinDivertHandle, WinDivertAddress, WinDivertEvent, WinDivertPacket, WINDIVERT_FLAG_SNIFF, WINDIVERT_FLAG_RECV_ONLY, WINDIVERT_FLAG_SEND_ONLY};

// Local type definitions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IncomingTrafficInfo {
    pub is_open_event_sent: bool,
    pub written_bytes: u32,
    pub read_bytes: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct LocalInterceptConf {
    pub intercept_pids: Vec<u32>,
    pub description: String,
}

impl LocalInterceptConf {
    pub fn disabled() -> Self {
        Self {
            intercept_pids: Vec::new(),
            description: "Disabled".to_string(),
        }
    }
    
    pub fn should_intercept(&self, proc_info: &ProcessInfo) -> bool {
        self.intercept_pids.contains(&proc_info.pid)
    }
    
    pub fn description(&self) -> &str {
        &self.description
    }
}

// Simple file logger implementation
struct SimpleFileLogger {
    file: StdMutex<std::fs::File>,
    level: LevelFilter,
}

impl log::Log for SimpleFileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut f = self.file.lock().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = now.as_secs();
        let millis = now.subsec_millis();
        let _ = writeln!(f, "{}.{} [{}] - {}", secs, millis, record.level(), record.args());
    }

    fn flush(&self) {
        let mut f = self.file.lock().unwrap();
        let _ = f.flush();
    }
}

// C-compatible destination info struct
#[repr(C)]
pub struct WinDest {
    pub host: *mut c_char,
    pub port: c_uint,
    pub version: *mut c_char,
}

// Destination info stored internally
#[derive(Clone, Debug)]
pub struct DestInfo {
    pub host: String,
    pub port: u16,
    pub version: String,
}

// Global runtime state for FFI
pub static RUNNING: AtomicBool = AtomicBool::new(false);
pub static CLIENT_PID: AtomicU32 = AtomicU32::new(0);
pub static AGENT_PID: AtomicU32 = AtomicU32::new(0);
pub static PROXY_PORT: AtomicU32 = AtomicU32::new(0);
pub static INCOMING_PROXY: AtomicU32 = AtomicU32::new(0);


// Redirect map: src_port -> destination info (host, port, version)
pub static REDIRECT_MAP: Lazy<Mutex<HashMap<u16, DestInfo>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn init_file_logger() -> Result<(), ()> {
    let path = "windows_redirector.log";
    let file = OpenOptions::new().create(true).append(true).open(path).map_err(|_| ())?;
    let logger = SimpleFileLogger {
        file: StdMutex::new(file),
        level: LevelFilter::Info,
    };
    match log::set_boxed_logger(Box::new(logger)) {
        Ok(()) => {
            log::set_max_level(LevelFilter::Info);
            Ok(())
        }
        Err(_) => {
            let _ = write_direct_log("logger already initialized, falling back to direct writes");
            Err(())
        }
    }
}

pub fn write_direct_log(msg: &str) -> Result<(), ()> {
    let path = "windows_redirector.log";
    let mut f = OpenOptions::new().create(true).append(true).open(path).map_err(|_| ())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let _ = writeln!(f, "{}.{} [INFO] - {}", secs, millis, msg);
    Ok(())
}

// Main redirector logic that can be called from FFI
pub async fn run_redirector() -> Result<()> {
    run_redirector_with_dll_path(None).await
}

pub async fn run_redirector_with_dll_path(dll_path: Option<&str>) -> Result<()> {
    let _ = write_direct_log("Inside run_redirector main function");

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();

    let _ = write_direct_log("Creating dynamic WinDivert loader...");
    // Create dynamic WinDivert loader
    let windivert = DynWinDivert::with_dll_path(dll_path).map_err(|e| {
        let error_msg = format!("Failed to create WinDivert loader: {:?}", e);
        let _ = write_direct_log(&error_msg);
        let _ = write_direct_log("This usually means WinDivert.dll is not available or the application needs Administrator privileges");
        anyhow::anyhow!(error_msg)
    })?;

    let _ = write_direct_log("Creating WinDivert socket handle...");
    // Create separate WinDivert instances for each thread due to lifetime constraints
    let tx_clone: UnboundedSender<Event> = event_tx.clone();
    let dll_path_clone = dll_path.map(|s| s.to_string());
    std::thread::spawn(move || {
        let windivert = match DynWinDivert::with_dll_path(dll_path_clone.as_deref()) {
            Ok(wd) => wd,
            Err(e) => {
                let _ = write_direct_log(&format!("Failed to create socket WinDivert: {:?}", e));
                return;
            }
        };
        
        let socket_handle = match windivert.open_socket("tcp", 1041, WINDIVERT_FLAG_RECV_ONLY | WINDIVERT_FLAG_SNIFF) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = write_direct_log(&format!("Failed to create socket handle in thread: {:?}", e));
                return;
            }
        };
        
        relay_socket_events(socket_handle, tx_clone);
    });
    let _ = write_direct_log("Spawned socket events thread");

    let tx_clone: UnboundedSender<Event> = event_tx.clone();
    let dll_path_clone = dll_path.map(|s| s.to_string());
    std::thread::spawn(move || {
        let windivert = match DynWinDivert::with_dll_path(dll_path_clone.as_deref()) {
            Ok(wd) => wd,
            Err(e) => {
                let _ = write_direct_log(&format!("Failed to create network WinDivert: {:?}", e));
                return;
            }
        };
        
        let network_handle = match windivert.open_network("tcp", 1040, 0) {
            Ok(handle) => handle,
            Err(e) => {
                let _ = write_direct_log(&format!("Failed to create network handle in thread: {:?}", e));
                return;
            }
        };
        
        relay_network_events(network_handle, tx_clone);
    });
    let _ = write_direct_log("Spawned network events thread");

    let _ = write_direct_log("Creating WinDivert inject handle...");
    let inject_handle = windivert.open_network("tcp", 1039, WINDIVERT_FLAG_SEND_ONLY)
        .map_err(|e| {
            let error_msg = format!("Failed to create inject handle: {:?}", e);
            let _ = write_direct_log(&error_msg);
            let _ = write_direct_log("This usually means the application needs Administrator privileges");
            anyhow::anyhow!(error_msg)
        })?;
        
    let _ = write_direct_log("Created inject handle successfully");

    let state: LocalInterceptConf = LocalInterceptConf::disabled();
    initialize_packet_map();
    let _ = write_direct_log("Initialized packet map and entering main loop");

    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
        Duration::from_secs(60 * 10),
    );
    let mut active_listeners: ActiveListeners = ActiveListeners::new();

    loop {
        // Check if we should stop (for FFI integration)
        if !RUNNING.load(Ordering::SeqCst) {
            let _ = write_direct_log("Stopping redirector as requested");
            break;
        }
        
        let result = event_rx.recv().await.unwrap();
        let _ = write_direct_log("Received event in main loop");
        
        match result {
            Event::NetworkPacket(address, data) => {
                let packet: InternetPacket = match InternetPacket::try_from(data) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = write_direct_log(&format!("Error parsing packet: {:?}", e));
                        continue;
                    }
                };

                let _ = write_direct_log(&format!("Processing network packet: {} {}", packet.connection_id(), packet.tcp_flag_str()));
                
                match connections.get_mut(&packet.connection_id()) {
                    Some(conn_state) => match conn_state {
                        ConnectionState::Known(s) => {
                            process_packet(address, packet, s, &inject_handle, &mut active_listeners)
                            .await?;
                        }
                        ConnectionState::Unknown(packets) => {
                            packets.push((address, packet));
                        }
                    },
                    None => {
                        let _ = write_direct_log(&format!("New connection: {}", packet.connection_id()));
                        
                        let action: ConnectionAction = {
                            unsafe {
                                if packet.dst_port() == APP_PORT {
                                    let _ = write_direct_log("Registering incoming connection");
                                    active_listeners.insert(
                                        packet.connection_id().src,
                                        packet.protocol(),
                                        IncomingTrafficInfo {
                                            is_open_event_sent: false,
                                            written_bytes: 0,
                                            read_bytes: 0,
                                         });
                                   ConnectionAction::InterceptIncoming
                                } else {
                                    ConnectionAction::None
                                }
                            }
                        };
                        insert_into_connections(
                            packet.connection_id(),
                            &action,
                            &address.event(),
                            &mut connections,
                            &inject_handle,
                            &mut active_listeners
                        )
                        .await?;
                        process_packet(address, packet, &action, &inject_handle, &mut active_listeners)
                        .await?;
                    }
                }
            }
            Event::SocketInfo(address) => {
                let _ = write_direct_log("Processing socket info event");
                
                if address.process_id() == 4 {
                    continue; // Skip system process
                }

                let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
                    let _ = write_direct_log(&format!("Unknown transport protocol: {}", address.protocol()));
                    continue;
                };
                
                let connection_id: ConnectionId = ConnectionId {
                    proto,
                    src: SocketAddr::from((address.local_address(), address.local_port())),
                    dst: SocketAddr::from((address.remote_address(), address.remote_port())),
                };

                if connection_id.src.ip().is_multicast() || connection_id.dst.ip().is_multicast() {
                    continue; // Skip multicast
                }

                match address.event() {
                    WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                        let make_entry: bool = match connections.get(&connection_id) {
                            None => true,
                            Some(e) => matches!(e, ConnectionState::Unknown(_)),
                        };

                        if !make_entry {
                            continue;
                        }

                        let proc_info = {
                            let pid: u32 = address.process_id();
                            ProcessInfo {
                                pid,
                                process_name: get_process_name(pid)
                                    .map(|x| x.to_string_lossy().into_owned())
                                    .ok(),
                            }
                        };

                        let action: ConnectionAction = if state.should_intercept(&proc_info) {
                            ConnectionAction::InterceptOutgoing(proc_info)
                        } else {
                            ConnectionAction::None
                        };

                        insert_into_connections(
                            connection_id,
                            &action,
                            &address.event(),
                            &mut connections,
                            &inject_handle,
                            &mut active_listeners
                        )
                        .await?;
                    }
                    WinDivertEvent::SocketListen => {
                        let pid = address.process_id();
                        let process_name: Option<String> = get_process_name(pid)
                            .map(|x: std::path::PathBuf| x.to_string_lossy().into_owned())
                            .ok();

                        let proc_info: ProcessInfo = {
                            let pid: u32 = address.process_id();
                            ProcessInfo {
                                pid,
                                process_name: process_name.clone()
                            }
                        };

                        if state.should_intercept(&proc_info) {
                            unsafe {
                                APP_PORT = address.local_port();
                                let _ = write_direct_log(&format!("Setting app port to {}", APP_PORT));
                            }
                        }
                    }
                    WinDivertEvent::SocketClose => {
                        if let Some(ConnectionState::Unknown(packets)) =
                            connections.get_mut(&connection_id)
                        {
                            packets.clear();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    
    Ok(())
}

// Helper types and functions
#[derive(Debug)]
enum Event {
    NetworkPacket(WinDivertAddress, Vec<u8>),
    SocketInfo(WinDivertAddress),
}

#[derive(Debug)]
enum ConnectionState {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertAddress, InternetPacket)>),
}

#[derive(Debug, Clone)]
enum ConnectionAction {
    None,
    InterceptOutgoing(ProcessInfo),
    InterceptIncoming,
}

// Global state
static mut PACKET_MAP: Option<Mutex<HashMap<u16, PacketInfo>>> = None;
static mut APP_PORT: u16 = 0;

#[derive(Clone, Debug)]
struct PacketInfo {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    dst_port: u16,
}

pub fn initialize_packet_map() {
    unsafe {
        PACKET_MAP = Some(Mutex::new(HashMap::new()));
    }
}

struct ActiveListeners(HashMap<(SocketAddr, TransportProtocol), IncomingTrafficInfo>);

impl ActiveListeners {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
        incoming_traffic_info: IncomingTrafficInfo,
    ) -> Option<IncomingTrafficInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.insert((socket, protocol), incoming_traffic_info)
    }

    pub fn get(&self, mut socket: SocketAddr, protocol: TransportProtocol) -> Option<&IncomingTrafficInfo> {
        if !self.0.contains_key(&(socket, protocol)) {
            socket.set_ip(Ipv4Addr::UNSPECIFIED.into());
        }
        self.0.get(&(socket, protocol))
    }

    pub fn remove(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
    ) -> Option<IncomingTrafficInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.remove(&(socket, protocol))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Repeatedly call WinDivertRecvEx to get socket info and feed them into the channel.
fn relay_socket_events(handle: DynWinDivertHandle, tx: UnboundedSender<Event>) {
    let _ = write_direct_log("Socket events relay thread started");
    loop {
        let packets = handle.recv_ex(1);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx.send(Event::SocketInfo(packet.address)).is_err() {
                        let _ = write_direct_log("Socket events channel closed, exiting thread");
                        return;
                    }
                }
            }
            Err(err) => {
                let error_msg = format!("WinDivert Socket Error: {:?}", err);
                let _ = write_direct_log(&error_msg);
                return;
            }
        };
    }
}

/// Repeatedly call WinDivertRecvEx to get network packets and feed them into the channel.
fn relay_network_events(handle: DynWinDivertHandle, tx: UnboundedSender<Event>) {
    let _ = write_direct_log("Network events relay thread started");
    const MAX_PACKETS: usize = 1;
    const MAX_PACKET_SIZE: usize = 65535;
    let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
    loop {
        let packets = handle.recv_ex_with_buffer(&mut buf, MAX_PACKETS);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx
                        .send(Event::NetworkPacket(packet.address, packet.data))
                        .is_err()
                    {
                        let _ = write_direct_log("Network events channel closed, exiting thread");
                        return;
                    }
                }
            }
            Err(err) => {
                let error_msg = format!("WinDivert Network Error: {:?}", err);
                let _ = write_direct_log(&error_msg);
                return;
            }
        };
    }
}

// Stub function for process name (you'd implement this properly)
fn get_process_name(pid: u32) -> Result<std::path::PathBuf> {
    Ok(std::path::PathBuf::from(format!("process_{}.exe", pid)))
}

// Simple packet wrapper for basic packet manipulation
#[derive(Clone)]
struct SimplePacket {
    data: Vec<u8>,
}

impl SimplePacket {
    fn try_from(data: Vec<u8>) -> Result<Self> {
        Ok(Self { data })
    }
    
    fn fill_ip_checksum(&mut self) {
        // Stub implementation - in real use you'd calculate proper checksums
        // For now, we'll just leave the packet as-is
    }
    
    fn into_inner(self) -> Vec<u8> {
        self.data
    }
}

async fn insert_into_connections(
    connection_id: ConnectionId,
    action: &ConnectionAction,
    _event: &WinDivertEvent,
    connections: &mut LruCache<ConnectionId, ConnectionState>,
    inject_handle: &DynWinDivertHandle<'_>,
    active_listeners: &mut ActiveListeners,
) -> Result<()> {
    let _ = write_direct_log(&format!("Adding connection: {} with action: {:?}", &connection_id, action));

    let mut new_connection_id = connection_id.reverse();
    match action { 
        ConnectionAction::InterceptOutgoing(ProcessInfo { pid: _, process_name: _ }) => {
            if connection_id.src.is_ipv6() {
                new_connection_id.src.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
            } else {
                new_connection_id.src.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            new_connection_id.src.set_port(16789);
        }
        ConnectionAction::None => {
            let _ = write_direct_log("No action needed for connection");
        }
        ConnectionAction::InterceptIncoming => {
            let _ = write_direct_log("Intercepting incoming connection");
        }
    }

    let existing1: Option<ConnectionState> = connections.insert(
        new_connection_id,
        ConnectionState::Known(action.clone()),
    );
    let existing2: Option<ConnectionState> = connections.insert(connection_id, ConnectionState::Known(action.clone()));

    if let Some(ConnectionState::Unknown(packets)) = existing1 {
        for (a, p) in packets {
            process_packet(a, p, action, inject_handle, active_listeners).await?;
        }
    }
    if let Some(ConnectionState::Unknown(packets)) = existing2 {
        for (a, p) in packets {
            process_packet(a, p, action, inject_handle, active_listeners).await?;
        }
    }
    Ok(())
}

async fn process_packet(
    address: WinDivertAddress,
    mut packet: InternetPacket,
    action: &ConnectionAction,
    inject_handle: &DynWinDivertHandle<'_>,
    active_listeners: &mut ActiveListeners,
) -> Result<()> {
    match action {
        ConnectionAction::InterceptIncoming => {
            unsafe {
                let _ = write_direct_log(&format!("Handling InterceptIncoming for {} (dst_port={})", packet.connection_id(), packet.dst_port()));
                if packet.dst_port() == APP_PORT {
                    
                    let mut incoming_traffic_info: IncomingTrafficInfo;
                    if let Some(info) = active_listeners.get(packet.connection_id().src, packet.protocol()) {
                        incoming_traffic_info = info.clone();
                    } else {
                        return Err(anyhow::anyhow!("Failed to get incoming info"));
                    }

                    if !incoming_traffic_info.is_open_event_sent{
                        let _ = write_direct_log(&format!("Sent SocketOpenEvent for {} ts={}", packet.connection_id(), address.event_timestamp()));
                        incoming_traffic_info.is_open_event_sent = true
                    }

                    let mut ip_packet_buffer = packet.clone().inner();
                    let tcp_payload = if let Ok(Some(payload)) = extract_tcp_payload(&packet, &mut ip_packet_buffer[..]) {
                        payload.to_vec()
                    } else {
                        vec![]
                    };

                    if !tcp_payload.is_empty() && !(tcp_payload.len() == 1 && tcp_payload[0] == 0) {
                        let no_of_bytes = tcp_payload.len() as u32;
                        incoming_traffic_info.read_bytes = incoming_traffic_info.read_bytes + no_of_bytes;
                        let _ = write_direct_log(&format!("Sent SocketDataEvent (incoming) for {} bytes={}", packet.connection_id(), no_of_bytes));
                    }
                    active_listeners.insert(packet.connection_id().src, packet.protocol(), incoming_traffic_info);
                }
                if packet.src_port() == APP_PORT {
                    let mut incoming_traffic_info: IncomingTrafficInfo;
                    if let Some(info) = active_listeners.get(packet.connection_id().dst, packet.protocol()) {
                        incoming_traffic_info = info.clone();
                    } else {
                        return Err(anyhow::anyhow!("Failed to get incoming info SRC"));
                    }
                    let mut ip_packet_buffer = packet.clone().inner();
                    let tcp_payload = if let Ok(Some(payload)) = extract_tcp_payload(&packet, &mut ip_packet_buffer[..]) {
                        payload.to_vec()
                    } else {
                        vec![]
                    };
                    if !tcp_payload.is_empty() && !(tcp_payload.len() == 1 && tcp_payload[0] == 0) {
                        let no_of_bytes = tcp_payload.len() as u32;
                        incoming_traffic_info.written_bytes = incoming_traffic_info.written_bytes + no_of_bytes;
                        let _ = write_direct_log(&format!("Sent SocketDataEvent (outgoing) for {} bytes={}", packet.connection_id(), no_of_bytes));
                        incoming_traffic_info.read_bytes = 0;
                        incoming_traffic_info.written_bytes = 0;
                        active_listeners.insert(packet.connection_id().dst, packet.protocol(), incoming_traffic_info);
                    }
                }
            }

            inject_handle
                .send(&WinDivertPacket {
                    address,
                    data: packet.inner().into(),
                })
                .context("failed to re-inject packet")?;
        }
        ConnectionAction::None => {
            inject_handle
                .send(&WinDivertPacket {
                    address,
                    data: packet.inner().into(),
                })
                .context("failed to re-inject packet")?;
        }
        ConnectionAction::InterceptOutgoing(ProcessInfo { pid: _, process_name: _ }) => {
            
            let _ = write_direct_log(&format!("Intercepting: {} {} protocol={}", packet.connection_id(), packet.tcp_flag_str(), packet.protocol()));

            if packet.src_port() != 16789 {
                let src_port = packet.src_port();
                let packet_info: PacketInfo = PacketInfo {
                    src_ip: packet.src_ip(),
                    dst_ip: packet.dst_ip(),
                    dst_port: packet.dst_port(),
                };
                unsafe {
                    if let Some(ref packet_map) = PACKET_MAP {
                        let mut map = packet_map.lock().unwrap();
                        map.insert(src_port, packet_info);
                    }
                }

                match packet.src_ip() {
                    IpAddr::V4(_) => {
                        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
                        packet.set_dst_ip(IpAddr::V4(ipv4_addr));
                        packet.set_src_ip(IpAddr::V4(ipv4_addr));
                    }
                    IpAddr::V6(_) => {
                        let ipv6_addr = Ipv6Addr::LOCALHOST;
                        packet.set_dst_ip(IpAddr::V6(ipv6_addr));
                        packet.set_src_ip(IpAddr::V6(ipv6_addr));
                    }
                }
                packet.set_dst_port(16789);
                packet.recalculate_tcp_checksum();

                let buff = packet.clone().inner();
                let Ok(mut packet1) = SimplePacket::try_from(buff) else {
                    let _ = write_direct_log("Error converting to SimplePacket");
                    return Err(anyhow::anyhow!("Failed to convert to SimplePacket"));
                };

                packet1.fill_ip_checksum();
                let buff1 = packet1.into_inner();

                let packet2 = match InternetPacket::try_from(buff1) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = write_direct_log(&format!("Error parsing packet: {:?}", e));
                        return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                    }
                };

                let winpacket = WinDivertPacket {
                    address,
                    data: packet2.inner().into(),
                };

                if let Err(e) = inject_handle.send(&winpacket) {
                    let _ = write_direct_log(&format!("Failed to send packet: {:?}", e));
                } else {
                    let _ = write_direct_log("Packet sent successfully!");
                }
            } else {
                let src_port = packet.dst_port();
                let packet_info: PacketInfo  = unsafe {
                    if let Some(ref packet_map) = PACKET_MAP {
                        let map = packet_map.lock().unwrap();
                        if let Some(packet_info) = map.get(&src_port) {
                            packet_info.clone()
                        } else {
                            return Err(anyhow::anyhow!("Failed to get info : {}", src_port));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Packet map not initialized."));
                    }
                };

                packet.set_dst_ip(packet_info.src_ip);
                packet.set_src_ip(packet_info.dst_ip);
                packet.set_src_port(packet_info.dst_port);
                packet.recalculate_tcp_checksum();

                let buff = packet.clone().inner();
                let Ok(mut packet1) = SimplePacket::try_from(buff) else {
                    let _ = write_direct_log("Error converting to SimplePacket");
                    return Err(anyhow::anyhow!("Failed to convert to SimplePacket"));
                };

                packet1.fill_ip_checksum();
                let buff1 = packet1.into_inner();

                let packet2 = match InternetPacket::try_from(buff1) {
                    Ok(p) => p,
                    Err(e) => {
                        let _ = write_direct_log(&format!("Error parsing packet: {:?}", e));
                        return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                    }
                };

                let winpacket = WinDivertPacket {
                    address,
                    data: packet2.inner().into(),
                };

                if let Err(e) = inject_handle.send(&winpacket) {
                    let _ = write_direct_log(&format!("Failed to send packet: {:?}", e));
                } else {
                    let _ = write_direct_log("Packet sent successfully!");
                }
            }
        }
    }
    Ok(())
}

fn extract_tcp_payload(packet: &InternetPacket, buff: &mut [u8]) -> Result<Option<Vec<u8>>> {
    let tcp_payload;

    match packet.src_ip() {
        IpAddr::V4(_) => {
            // Handle IPv4 packets
            let mut ipv4_packet = Ipv4Packet::new_unchecked(buff);
            if ipv4_packet.next_header() == IpProtocol::Tcp {
                let payload = ipv4_packet.payload_mut();
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(payload) {
                    tcp_payload = Some(tcp_packet.payload_mut().to_vec());
                } else {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }
        IpAddr::V6(_) => {
            // Handle IPv6 packets
            let mut ipv6_packet: Ipv6Packet<&mut [u8]> = Ipv6Packet::new_unchecked(buff);
            if ipv6_packet.next_header() == IpProtocol::Tcp {
                let payload = ipv6_packet.payload_mut();
                if let Ok(mut tcp_packet) = TcpPacket::new_checked(payload) {
                    tcp_payload = Some(tcp_packet.payload_mut().to_vec());
                } else {
                    return Ok(None);
                }
            } else {
                return Ok(None);
            }
        }
    }

    Ok(tcp_payload)
}