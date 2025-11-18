package redirector

/*
#cgo windows LDFLAGS: -L${SRCDIR}/../../target/release -l:libwindows_redirector.a -lws2_32 -luserenv -lntdll -ladvapi32 -lole32 -loleaut32
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Rust FFI prototypes (must match the signatures in src/ffi.rs)
typedef struct {
    char* host;
    unsigned int port;
    char* version;
} WinDest;

unsigned int start_redirector(unsigned int client_pid, unsigned int agent_pid, unsigned int proxy_port, unsigned int incoming_proxy);
unsigned int start_redirector_with_dll_path(unsigned int client_pid, unsigned int agent_pid, unsigned int proxy_port, unsigned int incoming_proxy, const char* dll_path);
unsigned int stop_redirector(void);
WinDest get_destination(unsigned int src_port);
unsigned int delete_destination(unsigned int src_port);
void free_windest(WinDest dest);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Destination represents a redirect destination with host, port, and version
type Destination struct {
	Host    string
	Port    uint32
	Version string
}

// StartRedirector initializes and starts the Windows redirector with configuration
// Returns error if already running or startup fails
func StartRedirector(clientPID, agentPID, proxyPort, incomingProxy uint32) error {
	return StartRedirectorWithDllPath(clientPID, agentPID, proxyPort, incomingProxy, "C:\\Users\\keploy\\ayush_work\\keploy\\pkg\\agent\\hooks\\windows\\assets\\WinDivert.dll")
}

// StartRedirectorWithDllPath initializes and starts the Windows redirector with configuration and custom DLL path
// dllPath: path to WinDivert.dll, or empty string to use default search
// Returns error if already running or startup fails
func StartRedirectorWithDllPath(clientPID, agentPID, proxyPort, incomingProxy uint32, dllPath string) error {
	var cDllPath *C.char
	if dllPath == "" {
		cDllPath = nil
	} else {
		cs := C.CString(dllPath)
		defer C.free(unsafe.Pointer(cs))
		cDllPath = cs
	}

	rc := C.start_redirector_with_dll_path(C.uint(clientPID), C.uint(agentPID), C.uint(proxyPort), C.uint(incomingProxy), cDllPath)
	if rc == 0 {
		return fmt.Errorf("start_redirector_with_dll_path failed (already running or error)")
	}
	return nil
}

// StopRedirector stops the Windows redirector
// Returns error if not running
func StopRedirector() error {
	rc := C.stop_redirector()
	if rc == 0 {
		return fmt.Errorf("stop_redirector failed (not running)")
	}
	return nil
}

// GetDestination retrieves destination info for a source port
// Returns (destination, true) if found, or (empty, false) if not found
func GetDestination(srcPort uint32) (Destination, bool) {
	dest := C.get_destination(C.uint(srcPort))
	// defer C.free_windest(dest)

	if dest.host == nil {
		return Destination{}, false
	}

	return Destination{
		Host:    C.GoString(dest.host),
		Port:    uint32(dest.port),
		Version: C.GoString(dest.version),
	}, true
}

// DeleteDestination removes a destination mapping for a source port
// Returns error if not found
func DeleteDestination(srcPort uint32) error {
	rc := C.delete_destination(C.uint(srcPort))
	if rc == 0 {
		return fmt.Errorf("delete_destination failed (not found)")
	}
	return nil
}
