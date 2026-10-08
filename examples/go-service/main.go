// Hosted Phase 18 payload. The private stdio transport is not a stable SDK ABI.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
)

func emit(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		os.Exit(2)
	}
}

func main() {
	// These attempts must fail inside the hosted sandbox, even for Go code
	// deliberately using host APIs instead of the Hyber message boundary.
	if _, err := os.ReadFile("/etc/passwd"); err == nil {
		panic("host file accessible")
	}
	if listener, err := net.Listen("tcp", "127.0.0.1:0"); err == nil {
		listener.Close()
		panic("socket accessible")
	}
	if err := exec.Command("/payload").Start(); err == nil {
		panic("child process creation allowed")
	}
	emit(map[string]string{"op": "log", "message": "Go sandbox verified"})
	emit(map[string]string{"op": "ready"})
	input := bufio.NewScanner(os.Stdin)
	input.Buffer(make([]byte, 1024), 8192)
	for input.Scan() {
		var message struct {
			Op string `json:"op"`
		}
		if json.Unmarshal(input.Bytes(), &message) != nil {
			os.Exit(2)
		}
		if message.Op == "stop" {
			return
		}
	}
	if input.Err() != nil {
		fmt.Fprintln(os.Stderr, "control pipe failed")
		os.Exit(2)
	}
}
