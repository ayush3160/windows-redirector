# Windows Redirector FFI API

This document describes the C FFI interface exposed by the `windows-redirector` library.

## Overview

The library provides a minimal set of functions for starting/stopping the redirector and managing destination mappings. It's designed to be called from Go programs via cgo.

## Data Structures

### WinDest

C-compatible struct representing a redirect destination:

```c
typedef struct {
    char* host;           // Destination host (caller must free with free_windest)
    unsigned int port;    // Destination port
    char* version;        // Protocol version (caller must free with free_windest)
} WinDest;
```

## Functions

### start_redirector

Initialize and start the Windows redirector with configuration parameters.

```c
unsigned int start_redirector(
    unsigned int client_pid,
    unsigned int agent_pid,
    unsigned int proxy_port,
    unsigned int incoming_proxy
);
```

**Parameters:**
- `client_pid`: Process ID of the client application
- `agent_pid`: Process ID of the agent
- `proxy_port`: Port number for the proxy
- `incoming_proxy`: Port number for incoming proxy connections

**Returns:**
- `1` on success
- `0` on failure (already running)

### stop_redirector

Stop the Windows redirector.

```c
unsigned int stop_redirector(void);
```

**Returns:**
- `1` on success (was running, now stopped)
- `0` on failure (wasn't running)

### get_destination

Retrieve destination information for a source port.

```c
WinDest get_destination(unsigned int src_port);
```

**Parameters:**
- `src_port`: Source port to look up

**Returns:**
- `WinDest` structure with allocated strings if found
- `WinDest` with null pointers if not found

**Note:** Caller must free the returned structure with `free_windest`.

### delete_destination

Remove a destination mapping for a source port.

```c
unsigned int delete_destination(unsigned int src_port);
```

**Parameters:**
- `src_port`: Source port to remove

**Returns:**
- `1` on success (mapping removed)
- `0` on failure (not found)

### free_windest

Free memory allocated by `get_destination`.

```c
void free_windest(WinDest dest);
```

**Parameters:**
- `dest`: WinDest structure to free

## Go Bindings

Go wrappers are provided in the `go/redirector` package:

```go
// Start redirector with configuration
func StartRedirector(clientPID, agentPID, proxyPort, incomingProxy uint32) error

// Stop redirector
func StopRedirector() error

// Get destination for a source port
func GetDestination(srcPort uint32) (Destination, bool)

// Delete destination mapping
func DeleteDestination(srcPort uint32) error
```

See `go/example/main.go` for usage examples.

## Build Instructions

### Rust Static Library

```powershell
cd C:\Users\keploy\ayush_work\redirect-ffi
cargo build --release
```

Output: `target/release/libwindows_redirector.a`

### Go Example

```powershell
cd go
$env:CGO_ENABLED = "1"
go build ./...
```

Requires MinGW-w64 gcc for cgo linking.
