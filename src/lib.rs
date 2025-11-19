use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;
use std::sync::Mutex;
use std::os::raw::{c_char, c_uint};

use anyhow::{Context, Result};
use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
use log::LevelFilter;
use chrono::Local;
// fern used to configure a file-only logger
use fern;
use lru_time_cache::LruCache;
use windivert::address::WinDivertAddress;
use windivert::prelude::*;

// Windows API types
#[cfg(windows)]
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, HANDLE};
#[cfg(windows)]
use winapi::um::processthreadsapi::{OpenProcess};
#[cfg(windows)]
use winapi::um::handleapi::CloseHandle;
#[cfg(windows)]
use winapi::shared::minwindef::DWORD;

// Manual definitions for NTDLL functions and structures
#[cfg(windows)]
#[repr(C)]
#[allow(non_snake_case)]
struct PROCESS_BASIC_INFORMATION {
    ExitStatus: winapi::shared::ntdef::NTSTATUS,
    PebBaseAddress: *mut winapi::ctypes::c_void,
    AffinityMask: usize,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
}

#[cfg(windows)]
extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: u32,
        ProcessInformation: *mut winapi::ctypes::c_void,
        ProcessInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> winapi::shared::ntdef::NTSTATUS;
}

// FFI and dynamic WinDivert modules
pub mod ffi;

use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedSender};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use once_cell::sync::Lazy;

// Type definitions for intercept configuration
#[cfg(windows)]
pub type PID = DWORD;
#[cfg(not(windows))]
pub type PID = u32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Pattern {
    Pid(PID),
    Process(String),
}

impl Pattern {
    pub fn matches(&self, process_info: &ProcessInfo) -> bool {
        match self {
            Pattern::Pid(pid) => process_info.pid == *pid,
            Pattern::Process(name) => {
                if let Some(ref process_name) = process_info.process_name {
                    process_name.to_lowercase().contains(&name.to_lowercase())
                } else {
                    false
                }
            }
        }
    }
}

impl std::fmt::Display for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Pattern::Pid(pid) => write!(f, "PID {}", pid),
            Pattern::Process(name) => write!(f, "Process \"{}\"", name),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Action {
    Include(Pattern),
    Exclude(Pattern),
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Include(pattern) => write!(f, "Include {}", pattern),
            Action::Exclude(pattern) => write!(f, "Exclude {}", pattern),
        }
    }
}

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
    pub default: bool,
    pub actions: Vec<Action>,
    pub client_pid: Option<PID>,
    pub agent_pid: Option<PID>,
}

impl LocalInterceptConf {
    pub fn new(actions: Vec<Action>) -> Self {
        let default = matches!(actions.first(), Some(Action::Exclude(_)));
        Self { 
            default, 
            actions,
            client_pid: None,
            agent_pid: None,
        }
    }

    pub fn new_with_pids(actions: Vec<Action>, client_pid: Option<PID>, agent_pid: Option<PID>) -> Self {
        let default = matches!(actions.first(), Some(Action::Exclude(_)));
        Self { 
            default, 
            actions,
            client_pid,
            agent_pid,
        }
    }

    pub fn disabled() -> Self {
        Self::new(vec![])
    }

    pub fn set_agent_pid(&mut self, agent_pid: PID) {
        self.agent_pid = Some(agent_pid);
    }

    pub fn set_client_pid(&mut self, client_pid: PID) {
        self.client_pid = Some(client_pid);
    }

    pub fn agent_pid(&self) -> Option<PID> {
        self.agent_pid
    }

    pub fn client_pid(&self) -> Option<PID> {
        self.client_pid
    }

    /// Check if the given PID is the agent PID
    pub fn is_agent_pid(&self, pid: PID) -> bool {
        self.agent_pid.map(|agent| agent == pid).unwrap_or(false)
    }

    pub fn actions(&self) -> Vec<String> {
        self.actions.iter().map(|a| a.to_string()).collect()
    }

    pub fn default(&self) -> bool {
        self.default
    }

    pub fn should_intercept(&self, process_info: &ProcessInfo) -> bool {
        
    log::debug!("Checking if should intercept process: {:?}", process_info);

        let mut intercept = false;
        for action in &self.actions {
            match action {
                Action::Include(pattern) => {
                    // if pattern.matches(process_info) || self.matches_parent(pattern, process_info.pid) {
                    if self.matches_parent(pattern, process_info.pid) {
                        intercept = true; // Intercept if it matches or if a parent matches
                    }
                }
                Action::Exclude(pattern) => {
                    intercept = intercept && !pattern.matches(process_info);
                }
            }
        }
        intercept
    }

    // Function to check if any parent of the given PID matches the pattern
    fn matches_parent(&self, pattern: &Pattern, pid: PID) -> bool {
        let mut current_pid = pid;
        let mut counter = 0;

        while let Some(parent) = self.get_parent_pid(current_pid) {
            if pattern.matches(&ProcessInfo {
                pid: parent,
                process_name: None, // Or retrieve the actual process name if needed
            }) {
                return true; // A matching parent was found
            }
            current_pid = parent; // Move up the process tree
            counter += 1; // Increment the counter

            if counter >= 10 {
                break; // Exit the loop if we've reached 10 iterations
            }
        }
        false // No matching parent found
    }

    // Function to get the parent PID of a given PID
    pub fn get_parent_pid(&self, pid: PID) -> Option<PID> {
        #[cfg(windows)]
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
            if handle.is_null() {
                return None; // Failed to open process
            }

            let mut process_basic_info: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
            let mut return_length: DWORD = 0;

            // Query the process information
            let status = NtQueryInformationProcess(
                handle,
                0, // ProcessBasicInformation
                &mut process_basic_info as *mut _ as *mut winapi::ctypes::c_void, // Use winapi's c_void
                std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as DWORD,
                &mut return_length,
            );

            CloseHandle(handle);

            // Check for successful status
            if status == 0 { // This needs to check against STATUS_SUCCESS
                return Some(process_basic_info.InheritedFromUniqueProcessId as DWORD);
            }
        }
        #[cfg(not(windows))]
        {
            let _ = pid; // Suppress unused variable warning
        }
        None // Could not retrieve parent PID
    }

    pub fn description(&self) -> String {
        if self.actions.is_empty() {
            return "Intercept nothing.".to_string();
        }
        let parts: Vec<String> = self
            .actions
            .iter()
            .map(|a| match a {
                Action::Include(Pattern::Pid(pid)) => format!("Include PID {}, Agent PID {}.", pid , self.agent_pid.unwrap_or(0)),
                Action::Include(Pattern::Process(name)) => {
                    format!("Include processes matching \"{}\".", name)
                }
                Action::Exclude(Pattern::Pid(pid)) => format!("Exclude PID {}.", pid),
                Action::Exclude(Pattern::Process(name)) => {
                    format!("Exclude processes matching \"{}\".", name)
                }
            })
            .collect();
        parts.join(" ")
    }
}

// We use `fern` to configure a file-only logger. This keeps logging out of stdout/stderr
// and writes all logs (debug+info) into windows_redirector.log.

// C-compatible destination info struct
#[repr(C)]
pub struct WinDest {
    pub host: *mut c_char,
    pub port: c_uint,
    pub version: *mut c_char,
}

// Global runtime state for FFI
pub static RUNNING: AtomicBool = AtomicBool::new(false);
pub static CLIENT_PID: AtomicU32 = AtomicU32::new(0);
pub static AGENT_PID: AtomicU32 = AtomicU32::new(0);
pub static PROXY_PORT: AtomicU32 = AtomicU32::new(0);
pub static INCOMING_PROXY: AtomicU32 = AtomicU32::new(0);


// Packet map: src_port -> packet info (src_ip, dst_ip, dst_port)
pub static mut PACKET_MAP: Option<Mutex<HashMap<u16, PacketInfo>>> = None;

// Agent ephemeral ports tracking
pub static AGENT_EPHEMERAL_PORTS: Lazy<Mutex<HashSet<u16>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub fn init_file_logger() -> Result<(), ()> {
    let path = "windows_redirector.log";
    // If an old log exists, remove it at startup per request
    if std::path::Path::new(path).exists() {
        let _ = std::fs::remove_file(path);
    }

    // Configure fern to write only to the log file at Debug level (captures debug + info)
    let file = fern::log_file(path).map_err(|_| ())?;
    let dispatch = fern::Dispatch::new()
        .format(move |out, message, record| {
            // timestamp, level, message
            out.finish(format_args!("{} [{}] - {}", Local::now().format("%Y-%m-%d %H:%M:%S%.3f"), record.level(), message))
        })
        .level(LevelFilter::Debug)
        .chain(file);

    match dispatch.apply() {
        Ok(()) => Ok(()),
        Err(_) => Err(()),
    }
}
// write_direct_log removed: logging should use the log macros (debug!, info!, error!, etc.)

// Main redirector logic that can be called from FFI
pub async fn run_redirector() -> Result<()> {
    run_redirector_with_dll_path(None).await
}

pub async fn run_redirector_with_dll_path(_dll_path: Option<&str>) -> Result<()> {
    log::debug!("Inside run_redirector main function");

    // Initialize PACKET_MAP
    unsafe {
        PACKET_MAP = Some(Mutex::new(HashMap::new()));
    }

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();

    log::debug!("Creating dynamic WinDivert loader...");
    // Create dynamic WinDivert loader
    
    let socket_handle: WinDivert<SocketLayer> = WinDivert::socket(
        "tcp",
        1041,
        WinDivertFlags::new().set_recv_only().set_sniff(),
    )?;
    let network_handle: WinDivert<NetworkLayer> = WinDivert::network("tcp", 1040, WinDivertFlags::new())?;
    let inject_handle: WinDivert<NetworkLayer> = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;

    let tx_clone: UnboundedSender<Event> = event_tx.clone();
    thread::spawn(move || relay_socket_events(socket_handle, tx_clone));
    let tx_clone: UnboundedSender<Event> = event_tx.clone();
    thread::spawn(move || relay_network_events(network_handle, tx_clone));


    let client_pid_value = CLIENT_PID.load(Ordering::SeqCst);
    let agent_pid_value = AGENT_PID.load(Ordering::SeqCst);
    
    let client_pid = if client_pid_value != 0 { Some(client_pid_value) } else { None };
    let agent_pid = if agent_pid_value != 0 { Some(agent_pid_value) } else { None };
    
    let state: LocalInterceptConf = if client_pid.is_some() || agent_pid.is_some() {
        // Create configuration with include action for client/agent PIDs
        let mut actions = Vec::new();
        if let Some(pid) = client_pid {
            actions.push(Action::Include(Pattern::Pid(pid)));
        }
        if let Some(pid) = agent_pid {
            actions.push(Action::Include(Pattern::Pid(pid)));
        }
        LocalInterceptConf::new_with_pids(actions, client_pid, agent_pid)
    } else {
        LocalInterceptConf::disabled()
    };
    
    log::debug!("Initialized LocalInterceptConf with client_pid: {:?}, agent_pid: {:?}", client_pid, agent_pid);
    log::debug!("Entering main loop 2");

    log::debug!("Agent PID: {}", state.agent_pid.unwrap());

    let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
        Duration::from_secs(60 * 10),
    );
    let mut active_listeners: ActiveListeners = ActiveListeners::new();

    loop {
        // Check if we should stop (for FFI integration)
        if !RUNNING.load(Ordering::SeqCst) {
            log::info!("Stopping redirector as requested");
            break;
        }
        
        let result = event_rx.recv().await.unwrap();
        // let _ = write_direct_log("Received event in main loop");
        
        match result {
            Event::NetworkPacket(address, data) => {
                let packet: InternetPacket = match InternetPacket::try_from(data) {
                    Ok(p) => p,
                    Err(e) => {
                        log::error!("Error parsing packet: {:?}", e);
                        continue;
                    }
                };

                // let _ = write_direct_log(&format!("Processing network packet: {} {}", packet.connection_id(), packet.tcp_flag_str()));
                
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
                        log::info!("New connection: {}", packet.connection_id());
                        
                        let action: ConnectionAction = {
                            unsafe {
                                if packet.dst_port() == APP_PORT {
                                    log::debug!("Registering incoming connection");
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
                
                log::debug!("Processing socket event: {:?} for PID {}", address.event(), address.process_id());

                if address.process_id() == 4 {
                    continue; // Skip system process
                }

                let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
                    log::debug!("Unknown transport protocol: {}", address.protocol());
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

                        unsafe {
                            log::info!("here it is {} {}", address.remote_port(), APP_PORT);
                            if address.remote_port() == APP_PORT {
                                log::info!("dest");
                                continue;
                            }
                            if address.local_port() == APP_PORT {
                                log::info!("client");
                                continue;
                            }
                        };

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
                                log::debug!("Setting app port to {}", APP_PORT);
                            }
                        }
                    }
                    WinDivertEvent::SocketBind => {
                        let pid = address.process_id();
                        let port = address.local_port();
                        
                        // Check if this PID matches the agent PID
                        if state.is_agent_pid(pid) {
                            let mut agent_ports = AGENT_EPHEMERAL_PORTS.lock().unwrap();
                            agent_ports.insert(port);
                            log::debug!("Agent PID {} bound to port {}, added to ephemeral ports", pid, port);
                        }
                    }
                    WinDivertEvent::SocketClose => {
                        if let Some(ConnectionState::Unknown(packets)) =
                            connections.get_mut(&connection_id)
                        {
                            packets.clear();
                        }
                        
                        // Check if this is an agent port that should be removed
                        let pid = address.process_id();
                        let port = address.local_port();
                        
                        if state.is_agent_pid(pid) {
                            let mut agent_ports = AGENT_EPHEMERAL_PORTS.lock().unwrap();
                            if agent_ports.remove(&port) {
                                log::debug!("Agent PID {} closed port {}, removed from ephemeral ports", pid, port);
                            }
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
    NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
    SocketInfo(WinDivertAddress<SocketLayer>),
}

#[derive(Debug)]
enum ConnectionState {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertAddress<NetworkLayer>, InternetPacket)>),
}

#[derive(Debug, Clone)]
enum ConnectionAction {
    None,
    InterceptOutgoing(ProcessInfo),
    InterceptIncoming,
}

// Global state
static mut APP_PORT: u16 = 0;

#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
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
fn relay_socket_events(handle: WinDivert<SocketLayer>, tx: UnboundedSender<Event>) {
    log::debug!("Socket events relay thread started");
    loop {
        let packets = handle.recv_ex(1);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx.send(Event::SocketInfo(packet.address)).is_err() {
                        log::debug!("Socket events channel closed, exiting thread");
                        return;
                    }
                }
            }
            Err(err) => {
                let error_msg = format!("WinDivert Socket Error: {:?}", err);
                log::error!("{}", error_msg);
                return;
            }
        };
    }
}

/// Repeatedly call WinDivertRecvEx to get network packets and feed them into the channel.
fn relay_network_events(handle: WinDivert<NetworkLayer>, tx: UnboundedSender<Event>) {
    log::debug!("Network events relay thread started");
    const MAX_PACKETS: usize = 1;
    const MAX_PACKET_SIZE: usize = 65535;
    let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
    loop {
        // Use the crate recv_ex with a buffer
    let packets = handle.recv_ex(Some(&mut buf[..]), MAX_PACKETS);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx
                        .send(Event::NetworkPacket(packet.address, packet.data.into_owned()))
                        .is_err()
                    {
                        log::debug!("Network events channel closed, exiting thread");
                        return;
                    }
                }
            }
            Err(err) => {
                let error_msg = format!("WinDivert Network Error: {:?}", err);
                log::error!("{}", error_msg);
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
    inject_handle: &WinDivert<NetworkLayer>,
    active_listeners: &mut ActiveListeners,
) -> Result<()> {
    log::debug!("Adding connection: {} with action: {:?}", &connection_id, action);

    let mut new_connection_id = connection_id.reverse();
    match action { 
        ConnectionAction::InterceptOutgoing(ProcessInfo { pid, process_name }) => {
            log::debug!("Setting up reverse connection for outgoing intercept from PID {} ({:?}) to port 16789", pid, process_name);
            if connection_id.src.is_ipv6() {
                new_connection_id.src.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
            } else {
                new_connection_id.src.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            new_connection_id.src.set_port(16789);
        }
        ConnectionAction::InterceptIncoming => {
            log::debug!("Setting up reverse connection for incoming intercept to port 3000");
            // Redirect incoming connections to port 3000 on localhost
            if connection_id.src.is_ipv6() {
                new_connection_id.src.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
            } else {
                new_connection_id.src.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
                new_connection_id.dst.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
            }
            new_connection_id.src.set_port(3000);
        }
        ConnectionAction::None => {
            // No action needed for None
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
    address: WinDivertAddress<NetworkLayer>,
    mut packet: InternetPacket,
    action: &ConnectionAction,
    inject_handle: &WinDivert<NetworkLayer>,
    _active_listeners: &mut ActiveListeners,
) -> Result<()> {
    match action {
        ConnectionAction::InterceptIncoming => {
            unsafe {
                let incoming_proxy_port = INCOMING_PROXY.load(Ordering::SeqCst) as u16;
                
                log::info!(
                    "Intercepting incoming: {} {} protocol={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.protocol()
                );

                // If this packet is destined to the app port but its source port
                // is one of the agent's ephemeral ports, do not intercept it here.
                if packet.dst_port() == APP_PORT {
                    let agent_ports = AGENT_EPHEMERAL_PORTS.lock().unwrap();
                    if agent_ports.contains(&packet.src_port()) {
                        log::debug!("Skipping intercept for packet from agent ephemeral port {}", packet.src_port());
                        inject_handle
                            .send(&WinDivertPacket {
                                address,
                                data: packet.inner().into(),
                            })
                            .context("failed to re-inject packet")?;
                        return Ok(());
                    }
                }

                if packet.dst_port() == APP_PORT {
                    // Store original packet info for reverse direction
                    let src_port = packet.src_port();
                    let packet_info = PacketInfo {
                        src_ip: packet.src_ip(),
                        dst_ip: packet.dst_ip(),
                        dst_port: packet.dst_port(),
                    };
                    
                    if let Some(ref packet_map) = PACKET_MAP {
                        let mut map = packet_map.lock().unwrap();
                        map.insert(src_port, packet_info);
                    }

                    // Redirect to incoming proxy port on localhost
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
                    packet.set_dst_port(incoming_proxy_port);
                    packet.recalculate_tcp_checksum();

                    log::info!(
                        "Redirected incoming to port {}: {} {}",
                        incoming_proxy_port,
                        packet.connection_id(),
                        packet.tcp_flag_str()
                    );

                    let buff = packet.clone().inner();
                    let Ok(mut packet1) = SimplePacket::try_from(buff) else {
                        log::info!("Error converting to SimplePacket");
                        return Err(anyhow::anyhow!("Failed to convert to SimplePacket"));
                    };

                    packet1.fill_ip_checksum();
                    let buff1 = packet1.into_inner();

                    let packet2 = match InternetPacket::try_from(buff1) {
                        Ok(p) => p,
                        Err(e) => {
                            log::info!("Error parsing packet: {:?}", e);
                            return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                        }
                    };

                    let winpacket = WinDivertPacket {
                        address,
                        data: packet2.inner().into(),
                    };

                    if let Err(e) = inject_handle.send(&winpacket) {
                        eprintln!("Failed to send packet: {:?}", e);
                    } else {
                        println!("Packet sent successfully to port {}!", incoming_proxy_port);
                    }
                } else if packet.src_port() == incoming_proxy_port {
                    // Restore original addresses for response packets from incoming proxy port
                    let dst_port = packet.dst_port();
                    let packet_info = if let Some(ref packet_map) = PACKET_MAP {
                        let map = packet_map.lock().unwrap();
                        if let Some(packet_info) = map.get(&dst_port) {
                            packet_info.clone()
                        } else {
                            return Err(anyhow::anyhow!("Failed to get packet info for port: {}", dst_port));
                        }
                    } else {
                        return Err(anyhow::anyhow!("Packet map not initialized."));
                    };

                    packet.set_src_ip(packet_info.dst_ip);
                    packet.set_dst_ip(packet_info.src_ip);
                    packet.set_src_port(packet_info.dst_port);
                    packet.recalculate_tcp_checksum();

                    log::info!(
                        "Restored response from port {}: {} {}",
                        incoming_proxy_port,
                        packet.connection_id(),
                        packet.tcp_flag_str()
                    );

                    let buff = packet.clone().inner();
                    let Ok(mut packet1) = SimplePacket::try_from(buff) else {
                        log::info!("Error converting to SimplePacket");
                        return Err(anyhow::anyhow!("Failed to convert to SimplePacket"));
                    };

                    packet1.fill_ip_checksum();
                    let buff1 = packet1.into_inner();

                    let packet2 = match InternetPacket::try_from(buff1) {
                        Ok(p) => p,
                        Err(e) => {
                            log::info!("Error parsing packet: {:?}", e);
                            return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                        }
                    };

                    let winpacket = WinDivertPacket {
                        address,
                        data: packet2.inner().into(),
                    };

                    if let Err(e) = inject_handle.send(&winpacket) {
                        eprintln!("Failed to send packet: {:?}", e);
                    } else {
                        println!("Response packet sent successfully!");
                    }
                } else {
                    // Forward other packets unchanged
                    log::debug!(
                        "Forwarding unchanged: {} {}",
                        packet.connection_id(),
                        packet.tcp_flag_str()
                    );
                    inject_handle
                        .send(&WinDivertPacket {
                            address,
                            data: packet.inner().into(),
                        })
                        .context("failed to re-inject packet")?;
                }
            }
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
            
            let proxy_port = PROXY_PORT.load(Ordering::SeqCst) as u16;
            
            log::info!(
                "Intercepting: {} {} protocol={}",
                packet.connection_id(),
                packet.tcp_flag_str(),
                packet.protocol()
            );

            if packet.src_port() != proxy_port {

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
                        // Handle IPv4 packet
                        let ipv4_addr = Ipv4Addr::new(127, 0, 0, 1);
                        packet.set_dst_ip(IpAddr::V4(ipv4_addr));
                        packet.set_src_ip(IpAddr::V4(ipv4_addr));
                    }
                    IpAddr::V6(_) => {
                        // Handle IPv6 packet
                        let ipv6_addr = Ipv6Addr::LOCALHOST;
                        packet.set_dst_ip(IpAddr::V6(ipv6_addr));
                        packet.set_src_ip(IpAddr::V6(ipv6_addr));
                    }
                }
                packet.set_dst_port(proxy_port);
                packet.recalculate_tcp_checksum();

                log::info!(
                    "Intercepting: {} {} protocol={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.protocol()
                );

                let buff = packet.clone().inner();
                let Ok(mut packet1) = SimplePacket::try_from(buff) else {
                    log::info!("Error converting to SimplePacket");
                    return Err(anyhow::anyhow!("Failed to convert to SimplePacket"));
                };

                packet1.fill_ip_checksum();

                let buff1 = packet1.into_inner();

                let packet2 = match InternetPacket::try_from(buff1) {
                    Ok(p) => p,
                    Err(e) => {
                        log::info!("Error parsing packet: {:?}", e);
                        return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                    }
                };

                let winpacket = WinDivertPacket {
                    address,
                    data: packet2.inner().into(),
                };

                if let Err(e) = inject_handle.send(&winpacket) {
                    eprintln!("Failed to send packet: {:?}", e);
                } else {
                    println!("Packet sent successfully!");
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

                log::info!(
                    "Intercepting: {} {} protocol={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    packet.protocol()
                );

                let buff = packet.clone().inner();

                let Ok(mut packet1) = SimplePacket::try_from(buff) else {
                    log::info!("Error converting to SimplePacket");
                    return Err(anyhow::anyhow!("Failed to convert to SimplePacket"));
                };

                packet1.fill_ip_checksum();

                let buff1 = packet1.into_inner();

                let packet2 = match InternetPacket::try_from(buff1) {
                    Ok(p) => p,
                    Err(e) => {
                        log::info!("Error parsing packet: {:?}", e);
                        return Err(anyhow::anyhow!("Failed to parse InternetPacket: {:?}", e));
                    }
                };

                let winpacket = WinDivertPacket {
                    address,
                    data: packet2.inner().into(),
                };

                if let Err(e) = inject_handle.send(&winpacket) {
                    eprintln!("Failed to send packet: {:?}", e);
                } else {
                    println!("Packet sent successfully!");
                }
            }
        }
    }
    Ok(())
}