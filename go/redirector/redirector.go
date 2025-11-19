package redirector

/*
#cgo windows LDFLAGS: -L${SRCDIR}/../../target/release -l:libwindows_redirector.a -lws2_32 -luserenv -lntdll -ladvapi32 -lole32 -loleaut32
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Rust FFI prototypes (must match the signatures in src/ffi.rs)
typedef struct {
    uint32_t ip_version;
    uint32_t dest_ip4;
    uint32_t dest_ip6[4];
    uint32_t dest_port;
    uint32_t kernel_pid;
} WinDest;

unsigned int start_redirector(unsigned int client_pid, unsigned int agent_pid, unsigned int proxy_port, unsigned int incoming_proxy, unsigned int mode);
unsigned int start_redirector_with_dll_path(unsigned int client_pid, unsigned int agent_pid, unsigned int proxy_port, unsigned int incoming_proxy, unsigned int mode, const char* dll_path);
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

// Destination represents a redirect destination with IP info
type Destination struct {
	IPVersion uint32
	DestIP4   uint32
	DestIP6   [4]uint32
	DestPort  uint32
	KernelPid uint32
}

// StartRedirector initializes and starts the Windows redirector with configuration
// Returns error if already running or startup fails
func StartRedirector(clientPID, agentPID, proxyPort, incomingProxy, mode uint32) error {
	return StartRedirectorWithDllPath(clientPID, agentPID, proxyPort, incomingProxy, mode, "C:\\Users\\keploy\\ayush_work\\keploy\\pkg\\agent\\hooks\\windows\\assets\\WinDivert.dll")
}

// StartRedirectorWithDllPath initializes and starts the Windows redirector with configuration and custom DLL path
// dllPath: path to WinDivert.dll, or empty string to use default search
// Returns error if already running or startup fails
func StartRedirectorWithDllPath(clientPID, agentPID, proxyPort, incomingProxy, mode uint32, dllPath string) error {
	var cDllPath *C.char
	if dllPath == "" {
		cDllPath = nil
	} else {
		cs := C.CString(dllPath)
		defer C.free(unsafe.Pointer(cs))
		cDllPath = cs
	}

	rc := C.start_redirector_with_dll_path(C.uint(clientPID), C.uint(agentPID), C.uint(proxyPort), C.uint(incomingProxy), C.uint(mode), cDllPath)
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
	// defer C.free_windest(dest) // No longer needed since WinDest doesn't use dynamic allocation

	if dest.ip_version == 0 {
		return Destination{}, false
	}

	// Convert C array to Go array
	var destIP6 [4]uint32
	for i := 0; i < 4; i++ {
		destIP6[i] = uint32(dest.dest_ip6[i])
	}

	return Destination{
		IPVersion: uint32(dest.ip_version),
		DestIP4:   uint32(dest.dest_ip4),
		DestIP6:   destIP6,
		DestPort:  uint32(dest.dest_port),
		KernelPid: uint32(dest.kernel_pid),
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
