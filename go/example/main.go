package main

import (
	"fmt"
	"time"

	"windows_redirector_go/redirector"
)

func main() {
	// Example usage of the Go wrapper around the Rust FFI
	fmt.Println("Starting redirector with client_pid=1234, agent_pid=5678, proxy_port=8080, incoming_proxy=3000")

	// Test with default DLL path (original function)
	if err := redirector.StartRedirector(1234, 5678, 8080, 3000); err != nil {
		fmt.Println("StartRedirector error:", err)
		return
	}

	time.Sleep(5 * time.Second)

	// Example: check destination for a port (will return empty since map is empty initially)
	dest, ok := redirector.GetDestination(8080)
	if !ok {
		fmt.Println("No destination found for port 8080")
	} else {
		fmt.Printf("Destination: host=%s, port=%d, version=%s\n", dest.Host, dest.Port, dest.Version)
	}

	fmt.Println("Stopping redirector")
	if err := redirector.StopRedirector(); err != nil {
		fmt.Println("StopRedirector error:", err)
	} else {
		fmt.Println("Redirector stopped successfully")
	}

	// Test with custom DLL path
	// fmt.Println("\nTesting with custom DLL path...")
	// if err := redirector.StartRedirectorWithDllPath(1234, 5678, 8080, 3000, "C:\\path\\to\\WinDivert.dll"); err != nil {
	// 	fmt.Println("StartRedirectorWithDllPath error (expected - custom path doesn't exist):", err)
	// } else {
	// 	fmt.Println("StartRedirectorWithDllPath succeeded with custom path")
	// 	redirector.StopRedirector()
	// }
}
