# Windows Redirector - FFI Library

This is a standalone Windows network traffic redirector library that can be called from Go programs via FFI (Foreign Function Interface). It has been restructured for clarity and simplicity.

## Project Structure

The project now follows a clean separation of concerns:

- **`src/main.rs`** - Contains the core functionality, main logic, and data structures
- **`src/ffi.rs`** - Contains only the FFI (Foreign Function Interface) functions for external integration
- **`Cargo.toml`** - Project configuration and dependencies

## Building the Project

### Debug Build
```bash
cargo build
```

### Release Build  
```bash
cargo build --release
```

### Check for Compilation Errors
```bash
cargo check
```

### Run the Application
```bash
cargo run
```

## Architecture

### Core Logic (`src/main.rs`)
- Windows traffic redirection using WinDivert
- Network packet processing and interception
- Connection state management
- Process information handling
- Async runtime management with Tokio

### FFI Interface (`src/ffi.rs`)
- C-compatible function exports
- Memory management for cross-language data exchange
- Runtime configuration and lifecycle management
- Thread-safe access to core functionality

## Available FFI Functions

The library exposes the following C-compatible functions for external integration:

- **`start_redirector(client_pid, agent_pid, proxy_port, incoming_proxy) -> u32`** - Start the redirector service
- **`stop_redirector() -> u32`** - Stop the redirector service  
- **`get_destination(src_port) -> WinDest`** - Get destination mapping for a source port
- **`delete_destination(src_port) -> u32`** - Remove a destination mapping
- **`free_windest(dest)`** - Free memory allocated for WinDest structures

## Key Components

### Data Structures
- **`ProcessInfo`** - Process identification and metadata
- **`IncomingTrafficInfo`** - Traffic statistics and state
- **`LocalInterceptConf`** - Interception configuration
- **`WinDest`** - C-compatible destination information
- **`DestInfo`** - Internal destination information

### Global State Management
- **`RUNNING`** - Atomic boolean for service state
- **`CLIENT_PID`, `AGENT_PID`** - Process identifiers
- **`PROXY_PORT`, `INCOMING_PROXY`** - Port configurations  
- **`REDIRECT_MAP`** - Thread-safe mapping of redirections

### Logging
- Built-in file logging to `windows_redirector.log`
- Configurable log levels
- Thread-safe logging implementation

## Dependencies

The project uses the following key dependencies:
- **tokio** - Async runtime
- **windivert** - Windows packet interception 
- **anyhow** - Error handling
- **log** - Logging framework
- **serde** - Serialization
- **internet-packet** - Packet parsing
- **lru_time_cache** - Connection caching

## Cross-Language Integration

This library is designed for integration with Go applications through FFI. The FFI functions provide a C-compatible interface that can be called from Go using cgo.

Example Go usage pattern:
```go
import "C"

// Start the redirector
result := C.start_redirector(1234, 5678, 8080, 8081)
if result != 1 {
    // Handle error
}

// Stop the redirector  
C.stop_redirector()
```

## Requirements

### Runtime Requirements
- Windows 10/11 (x64)
- WinDivert kernel driver installed
- Administrator privileges (required for WinDivert)

### Development Requirements  
- Rust 1.70+
- Windows SDK
- Go 1.19+ (for FFI integration)

## WinDivert Installation

1. Download WinDivert from: https://www.reqrypt.org/windivert.html
2. Extract to a location accessible by your application
3. Ensure `WinDivert.dll` and `WinDivert64.sys` are in your application's directory or PATH

## Security Considerations

- Requires administrator privileges
- WinDivert driver must be properly signed on production systems
- Consider implementing proper process validation before interception
- Monitor for potential privilege escalation vectors

## Troubleshooting

### Common Issues

1. **"WinDivert driver not found"**
   - Ensure WinDivert.dll is in the same directory as your executable
   - Check that you have administrator privileges

2. **"Access denied" errors**
   - Run your application as Administrator
   - Check Windows Defender/antivirus settings

3. **Build fails with dependency errors**
   - Try building from a clean environment
   - Run `cargo clean` before building

4. **Go linking errors (if using FFI)**
   - Ensure all required Windows libraries are linked
   - Check that the Rust library is built for the same architecture as your Go binary

## Performance Considerations

- The redirector processes all TCP traffic, so performance depends on network load
- Consider filtering rules to minimize unnecessary packet processing
- Monitor memory usage with long-running instances

## License

LGPL-3.0-or-later (same as parent mitmproxy project)
